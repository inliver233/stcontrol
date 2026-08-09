package agent

import (
	"context"
	"fmt"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

type agentControlModeState struct {
	Mode                        string    `json:"mode"`
	AdapterMode                 string    `json:"adapter_mode"`
	AdapterControllerGeneration int64     `json:"adapter_controller_generation"`
	ModeGeneration              int64     `json:"mode_generation"`
	ControllerGeneration        int64     `json:"controller_generation"`
	ReasonCode                  string    `json:"reason_code"`
	ConsecutiveHeartbeatFails   int       `json:"consecutive_heartbeat_failures"`
	ConsecutiveHealthProbeFails int       `json:"consecutive_health_probe_failures"`
	ConsecutivePeerWitnessFails int       `json:"consecutive_peer_witness_failures"`
	OutageStartedAt             time.Time `json:"outage_started_at,omitempty"`
	ConfirmedOutageStartedAt    time.Time `json:"confirmed_outage_started_at,omitempty"`
	LastControllerSuccessAt     time.Time `json:"last_controller_success_at,omitempty"`
	IndependentSince            time.Time `json:"independent_since,omitempty"`
	ChangedAt                   time.Time `json:"changed_at"`
	ActiveIndependentSessions   int       `json:"active_independent_sessions"`
	PendingUserSyncs            int       `json:"pending_user_syncs"`
}

type normalizedDisasterPolicy struct {
	unreachableAfter time.Duration
	independentAfter time.Duration
	minFailures      int
}

func normalizeDisasterPolicy(policy config.AgentDisasterPolicy) normalizedDisasterPolicy {
	defaults := config.DefaultAgent().Disaster
	if policy.UnreachableAfterSec <= 0 {
		policy.UnreachableAfterSec = defaults.UnreachableAfterSec
	}
	if policy.IndependentAfterSec <= policy.UnreachableAfterSec {
		policy.IndependentAfterSec = defaults.IndependentAfterSec
	}
	if policy.MinFailedHeartbeats < 2 {
		policy.MinFailedHeartbeats = defaults.MinFailedHeartbeats
	}
	return normalizedDisasterPolicy{
		unreachableAfter: time.Duration(policy.UnreachableAfterSec) * time.Second,
		independentAfter: time.Duration(policy.IndependentAfterSec) * time.Second,
		minFailures:      policy.MinFailedHeartbeats,
	}
}

func validNodeControlMode(mode string) bool {
	switch mode {
	case protocol.NodeModeManaged, protocol.NodeModeControllerUnreachable,
		protocol.NodeModeIndependent, protocol.NodeModeIndependentDraining:
		return true
	default:
		return false
	}
}

func (a *Agent) controlModeReport() protocol.NodeControlModeReport {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state := a.state.ControlMode
	confirmedTakeovers := make([]protocol.IndependentTakeover, 0, len(a.state.OwnershipTakeovers))
	for _, operation := range a.state.OwnershipTakeovers {
		if !operation.Succeeded || !operation.Audited {
			continue
		}
		confirmedTakeovers = append(confirmedTakeovers, protocol.IndependentTakeover{
			OperationID: operation.OperationID, Handle: operation.Claim.Handle,
			ParentClaimID: operation.ParentClaimID, ClaimID: operation.Claim.ClaimID,
			ControllerGeneration: operation.Claim.ControllerGeneration,
			ActivityEpoch:        operation.Claim.ActivityEpoch,
			TakeoverSequence:     operation.Claim.TakeoverSequence,
			ConfirmedAt:          operation.UpdatedAt,
		})
	}
	return protocol.NodeControlModeReport{
		Mode: state.Mode, ModeGeneration: state.ModeGeneration,
		ControllerGeneration: a.state.HighestGeneration, ReasonCode: state.ReasonCode,
		ConsecutiveHeartbeatFails:   state.ConsecutiveHeartbeatFails,
		ConsecutiveHealthProbeFails: state.ConsecutiveHealthProbeFails,
		ConsecutivePeerWitnessFails: state.ConsecutivePeerWitnessFails,
		OutageStartedAt:             state.OutageStartedAt,
		ConfirmedOutageStartedAt:    state.ConfirmedOutageStartedAt,
		LastControllerSuccessAt:     state.LastControllerSuccessAt,
		IndependentSince:            state.IndependentSince,
		ActiveIndependentSessions:   state.ActiveIndependentSessions,
		PendingUserSyncs:            state.PendingUserSyncs,
		PendingUsers:                append([]protocol.IndependentSyncUser(nil), a.state.PendingIndependentUsers...),
		ConfirmedTakeovers:          confirmedTakeovers,
	}
}

func (a *Agent) managedCommandsAllowed() bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.state.ControlMode.Mode == protocol.NodeModeManaged
}

func (a *Agent) commandChannelAllowed() bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.state.ControlMode.Mode == protocol.NodeModeManaged ||
		a.state.ControlMode.Mode == protocol.NodeModeIndependentDraining
}

func (a *Agent) commandAllowed(commandType string) bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.state.ControlMode.Mode == protocol.NodeModeManaged {
		return true
	}
	return a.state.ControlMode.Mode == protocol.NodeModeIndependentDraining &&
		independentReconciliationCommand(commandType)
}

// independentReconciliationCommand is deliberately closed rather than a
// prefix rule. A recovered node may only execute the commands needed to freeze,
// preserve, inspect and finally acknowledge independent writes while draining.
func independentReconciliationCommand(commandType string) bool {
	switch commandType {
	case "prepare_snapshot_receive", "start_snapshot", "start_relay_receive", "get_snapshot_receipt",
		"verify_replica_integrity", "verify_replica_integrity_v2", "complete_independent_sync", "freeze_user_data", "capture_conflict_evidence",
		"read_conflict_evidence_page", "start_conflict_evidence_transfer",
		"prepare_conflict_resolution", "apply_conflict_resolution_decisions",
		"publish_conflict_resolution":
		return true
	default:
		return false
	}
}

// recordControllerFailure requires three independently-routed observations
// before an outage may become independent: the signed heartbeat failed, the
// local public-health probe failed, and a majority of configured peer
// witnesses also observed that same Controller unavailable. Missing or
// disagreeing witnesses fail closed.
func (a *Agent) recordControllerFailure(now time.Time, healthProbeFailed, peerQuorumConfirmed bool) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state := &a.state.ControlMode
	state.ConsecutiveHeartbeatFails++
	if healthProbeFailed {
		state.ConsecutiveHealthProbeFails++
	} else {
		state.ConsecutiveHealthProbeFails = 0
	}
	if healthProbeFailed && peerQuorumConfirmed {
		if state.ConsecutivePeerWitnessFails == 0 || state.ConfirmedOutageStartedAt.IsZero() {
			state.ConfirmedOutageStartedAt = now
		}
		state.ConsecutivePeerWitnessFails++
	} else {
		state.ConsecutivePeerWitnessFails = 0
		state.ConfirmedOutageStartedAt = time.Time{}
	}
	if state.OutageStartedAt.IsZero() {
		state.OutageStartedAt = now
	}
	policy := normalizeDisasterPolicy(a.Cfg.Disaster)
	elapsed := now.Sub(state.OutageStartedAt)
	confirmedElapsed := time.Duration(0)
	if !state.ConfirmedOutageStartedAt.IsZero() {
		confirmedElapsed = now.Sub(state.ConfirmedOutageStartedAt)
	}
	mode := state.Mode
	reason := state.ReasonCode
	// Once any independent observation is disputed, immediately stop opening
	// new disaster logins. Existing independent sessions and pending user facts
	// remain behind the draining boundary until an authenticated Controller can
	// reconcile them; a split network must not keep granting new writers.
	if mode == protocol.NodeModeIndependent && (!healthProbeFailed || !peerQuorumConfirmed) {
		mode = protocol.NodeModeIndependentDraining
		reason = "controller_loss_evidence_disputed"
	}
	if mode == protocol.NodeModeManaged && elapsed >= policy.unreachableAfter {
		mode = protocol.NodeModeControllerUnreachable
		reason = "controller_heartbeat_timeout"
	}
	if a.Cfg.Role == "compute" && mode != protocol.NodeModeIndependentDraining &&
		!state.ConfirmedOutageStartedAt.IsZero() && confirmedElapsed >= policy.independentAfter &&
		state.ConsecutiveHeartbeatFails >= policy.minFailures &&
		state.ConsecutiveHealthProbeFails >= policy.minFailures &&
		state.ConsecutivePeerWitnessFails >= policy.minFailures {
		mode = protocol.NodeModeIndependent
		reason = "sustained_peer_confirmed_controller_loss"
		if state.IndependentSince.IsZero() {
			state.IndependentSince = now
		}
	}
	if mode != state.Mode {
		state.Mode = mode
		state.ModeGeneration++
		state.ChangedAt = now
		state.AdapterMode = ""
	}
	state.ReasonCode = reason
	return a.saveRuntimeStateLocked()
}

func (a *Agent) recordControllerSuccess(now time.Time, response protocol.HeartbeatResponse) error {
	if response.ControllerGeneration <= 0 || !a.acceptGeneration(response.ControllerGeneration) {
		return fmt.Errorf("controller generation rollback rejected")
	}
	if !validNodeControlMode(response.DesiredMode) || response.ModeGeneration <= 0 {
		return fmt.Errorf("invalid controller mode response")
	}
	if len(response.AcknowledgedTakeoverOperations) > maxOwnershipTakeovers {
		return fmt.Errorf("invalid takeover acknowledgements")
	}
	seenAcknowledgements := make(map[string]struct{}, len(response.AcknowledgedTakeoverOperations))
	for _, operationID := range response.AcknowledgedTakeoverOperations {
		if !validUUID(operationID) {
			return fmt.Errorf("invalid takeover acknowledgements")
		}
		if _, exists := seenAcknowledgements[operationID]; exists {
			return fmt.Errorf("duplicate takeover acknowledgement")
		}
		seenAcknowledgements[operationID] = struct{}{}
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state := &a.state.ControlMode
	if response.ModeGeneration < state.ModeGeneration {
		return fmt.Errorf("node mode generation rollback rejected")
	}
	desired := response.DesiredMode
	// A recovered controller may not skip the reconciliation boundary even if
	// it accidentally asks an independent Agent to become managed directly.
	if state.Mode == protocol.NodeModeIndependent && desired == protocol.NodeModeManaged {
		desired = protocol.NodeModeIndependentDraining
	}
	if state.Mode == protocol.NodeModeIndependentDraining && desired == protocol.NodeModeManaged &&
		(state.ActiveIndependentSessions > 0 || state.PendingUserSyncs > 0) {
		return fmt.Errorf("controller attempted to skip independent session draining")
	}
	if response.ModeGeneration == state.ModeGeneration && desired != state.Mode {
		return fmt.Errorf("node mode generation reuse rejected")
	}
	if err := a.recordActivityLeaseConfirmations(now, response); err != nil {
		return fmt.Errorf("activity lease confirmations rejected: %w", err)
	}
	for operationID := range seenAcknowledgements {
		operation, exists := a.state.OwnershipTakeovers[operationID]
		if exists && operation.Succeeded && operation.Audited {
			delete(a.state.OwnershipTakeovers, operationID)
		}
	}
	state.LastControllerSuccessAt = now
	state.OutageStartedAt = time.Time{}
	state.ConfirmedOutageStartedAt = time.Time{}
	state.ConsecutiveHeartbeatFails = 0
	state.ConsecutiveHealthProbeFails = 0
	state.ConsecutivePeerWitnessFails = 0
	state.ControllerGeneration = response.ControllerGeneration
	if desired != state.Mode {
		state.Mode = desired
		state.ModeGeneration = response.ModeGeneration
		state.ChangedAt = now
		state.AdapterMode = ""
		switch desired {
		case protocol.NodeModeManaged:
			state.ReasonCode = "controller_reconciled"
			state.IndependentSince = time.Time{}
		case protocol.NodeModeIndependentDraining:
			state.ReasonCode = "controller_recovered"
		}
	}
	return a.saveRuntimeStateLocked()
}

func (a *Agent) syncTavernControlMode(ctx context.Context) error {
	a.stateMu.Lock()
	state := a.state.ControlMode
	controllerGeneration := a.state.HighestGeneration
	a.stateMu.Unlock()
	if state.AdapterMode == state.Mode && state.AdapterControllerGeneration >= controllerGeneration {
		return nil
	}
	if a.Cfg.Role == "storage" {
		a.stateMu.Lock()
		a.state.ControlMode.AdapterMode = state.Mode
		a.state.ControlMode.AdapterControllerGeneration = controllerGeneration
		err := a.saveRuntimeStateLocked()
		a.stateMu.Unlock()
		return err
	}
	var response protocol.ApplyNodeControlModeResponse
	err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/control-mode", protocol.ApplyNodeControlModeRequest{
		Mode: state.Mode, ModeGeneration: state.ModeGeneration,
		ControllerGeneration: controllerGeneration, ReasonCode: state.ReasonCode,
		ChangedAt: state.ChangedAt,
	}, &response)
	if err != nil {
		return err
	}
	if !response.OK || response.AppliedMode != state.Mode || response.ModeGeneration != state.ModeGeneration ||
		response.ActiveIndependentSessions < 0 || response.PendingUserSyncs < 0 {
		return fmt.Errorf("node adapter returned invalid control mode state")
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.state.ControlMode.Mode != state.Mode || a.state.ControlMode.ModeGeneration != state.ModeGeneration {
		return nil
	}
	a.state.ControlMode.AdapterMode = response.AppliedMode
	a.state.ControlMode.AdapterControllerGeneration = controllerGeneration
	a.state.ControlMode.ActiveIndependentSessions = response.ActiveIndependentSessions
	a.state.ControlMode.PendingUserSyncs = response.PendingUserSyncs
	return a.saveRuntimeStateLocked()
}

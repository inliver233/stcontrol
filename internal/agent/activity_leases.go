package agent

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"stcontrol/internal/protocol"
)

const (
	maxActivityLeaseConfirmations = 10_000
	maxConfirmedActivityLease     = 24*time.Hour + 6*time.Minute
)

func validateAgentActivityLeaseState(state agentActivityLeaseState) error {
	if state.ConfirmedAt == 0 {
		if state.ControllerGeneration != 0 || state.AdapterConfirmedAt != 0 || len(state.Leases) != 0 {
			return fmt.Errorf("empty confirmation has state")
		}
		return nil
	}
	if state.ControllerGeneration <= 0 || state.ConfirmedAt < 0 || state.AdapterConfirmedAt < 0 ||
		state.AdapterConfirmedAt > state.ConfirmedAt || len(state.Leases) > maxActivityLeaseConfirmations {
		return fmt.Errorf("invalid confirmation envelope")
	}
	seenHandles := make(map[string]struct{}, len(state.Leases))
	for _, lease := range state.Leases {
		if !validOwnershipHandle(lease.Handle) || !validUUID(lease.SessionID) || lease.ActivityEpoch <= 0 ||
			lease.ControllerGeneration != state.ControllerGeneration || lease.LeaseExpiresAt <= state.ConfirmedAt ||
			lease.LeaseExpiresAt-state.ConfirmedAt > maxConfirmedActivityLease.Milliseconds() {
			return fmt.Errorf("invalid confirmed lease")
		}
		if _, exists := seenHandles[lease.Handle]; exists {
			return fmt.Errorf("duplicate confirmed lease")
		}
		seenHandles[lease.Handle] = struct{}{}
	}
	return nil
}

func (a *Agent) recordActivityLeaseConfirmations(now time.Time, response protocol.HeartbeatResponse) error {
	if response.ActivityLeaseConfirmedAt == 0 {
		if len(response.ActivityLeaseConfirmations) != 0 {
			return fmt.Errorf("activity lease confirmations lack observation time")
		}
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state := agentActivityLeaseState{
		ControllerGeneration: response.ControllerGeneration,
		ConfirmedAt:          response.ActivityLeaseConfirmedAt,
		Leases:               append([]protocol.ActivityLeaseConfirmation(nil), response.ActivityLeaseConfirmations...),
	}
	if response.ActivityLeaseConfirmedAt > now.Add(time.Minute).UnixMilli() {
		return fmt.Errorf("activity lease observation is in the future")
	}
	if err := validateAgentActivityLeaseState(state); err != nil {
		return err
	}
	current := a.state.ActivityLeases
	if state.ConfirmedAt < current.ConfirmedAt {
		return fmt.Errorf("activity lease confirmation rollback rejected")
	}
	if state.ConfirmedAt == current.ConfirmedAt {
		if state.ControllerGeneration != current.ControllerGeneration || !reflect.DeepEqual(state.Leases, current.Leases) {
			return fmt.Errorf("activity lease confirmation time reused")
		}
		return nil
	}
	a.state.ActivityLeases = state
	return nil
}

// syncTavernActivityLeases forwards only the Controller-confirmed snapshot to
// the loopback adapter. A failed local delivery remains durable and is retried;
// an expired cached deadline still usefully revokes writes after a restart.
func (a *Agent) syncTavernActivityLeases(ctx context.Context) error {
	a.stateMu.Lock()
	state := a.state.ActivityLeases
	state.Leases = append([]protocol.ActivityLeaseConfirmation(nil), state.Leases...)
	a.stateMu.Unlock()
	if state.ConfirmedAt == 0 || state.AdapterConfirmedAt == state.ConfirmedAt {
		return nil
	}
	if a.Cfg.Role == "storage" {
		a.stateMu.Lock()
		if a.state.ActivityLeases.ConfirmedAt == state.ConfirmedAt {
			a.state.ActivityLeases.AdapterConfirmedAt = state.ConfirmedAt
		}
		err := a.saveRuntimeStateLocked()
		a.stateMu.Unlock()
		return err
	}
	var response protocol.ApplyActivityLeaseConfirmationsResponse
	err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/activity-leases/confirm",
		protocol.ApplyActivityLeaseConfirmationsRequest{
			ControllerGeneration: state.ControllerGeneration,
			ConfirmedAt:          state.ConfirmedAt,
			Leases:               state.Leases,
		}, &response)
	if err != nil {
		return err
	}
	if !response.OK || response.ConfirmedAt != state.ConfirmedAt ||
		response.AppliedLeases < 0 || response.AppliedLeases > len(state.Leases) {
		return fmt.Errorf("invalid adapter activity lease confirmation response")
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.state.ActivityLeases.ConfirmedAt != state.ConfirmedAt {
		return nil
	}
	a.state.ActivityLeases.AdapterConfirmedAt = state.ConfirmedAt
	return a.saveRuntimeStateLocked()
}

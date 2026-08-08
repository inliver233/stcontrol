package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	NodeModeManaged               = "managed"
	NodeModeControllerUnreachable = "controller-unreachable"
	NodeModeIndependent           = "independent"
	NodeModeIndependentDraining   = "independent-draining"
)

var (
	ErrStaleNodeControlMode = errors.New("stale node control mode generation")
	ErrStaleControllerMode  = errors.New("node report belongs to stale controller generation")
)

type NodeControlModeFact struct {
	Mode                        string
	ModeGeneration              int64
	ControllerGeneration        int64
	ReasonCode                  string
	ConsecutiveHeartbeatFails   int
	ConsecutiveHealthProbeFails int
	OutageStartedAt             time.Time
	LastControllerSuccessAt     time.Time
	IndependentSince            time.Time
	ActiveIndependentSessions   int
	PendingUserSyncs            int
	PendingUsers                []IndependentSyncFact
	ObservedAt                  time.Time
}

type IndependentSyncFact struct {
	Handle    string
	Marker    string
	ChangedAt time.Time
	Reason    string
}

type NodeControlModeDecision struct {
	ControllerGeneration int64
	DesiredMode          string
	ModeGeneration       int64
}

func validControlMode(mode string) bool {
	switch mode {
	case NodeModeManaged, NodeModeControllerUnreachable, NodeModeIndependent, NodeModeIndependentDraining:
		return true
	default:
		return false
	}
}

func validNodeControlModeFact(fact NodeControlModeFact) bool {
	if !validControlMode(fact.Mode) || fact.ModeGeneration <= 0 || fact.ControllerGeneration <= 0 ||
		fact.ConsecutiveHeartbeatFails < 0 || fact.ConsecutiveHealthProbeFails < 0 ||
		fact.ActiveIndependentSessions < 0 || fact.PendingUserSyncs < 0 || fact.ObservedAt.IsZero() ||
		len(fact.ReasonCode) > 128 || strings.ContainsAny(fact.ReasonCode, "\r\n") {
		return false
	}
	if len(fact.PendingUsers) != fact.PendingUserSyncs || len(fact.PendingUsers) > 500 {
		return false
	}
	for _, timestamp := range []time.Time{fact.OutageStartedAt, fact.LastControllerSuccessAt, fact.IndependentSince} {
		if !timestamp.IsZero() && timestamp.After(fact.ObservedAt.Add(time.Minute)) {
			return false
		}
	}
	if fact.Mode == NodeModeIndependent && fact.IndependentSince.IsZero() {
		return false
	}
	return true
}

// ReconcileNodeControlMode records what the Agent has actually applied and
// returns a generation-fenced desired mode. Recovery from independent mode is
// always draining first and cannot become managed while a disaster session or
// pending user reconciliation remains.
func (s *Store) ReconcileNodeControlMode(
	ctx context.Context,
	nodeID int64,
	fact NodeControlModeFact,
) (NodeControlModeDecision, error) {
	return s.reconcileNodeControlModeAuthenticated(ctx, nodeID, fact, fact.ControllerGeneration)
}

// ReconcileNodeControlModeAuthenticated permits a previous-generation Agent
// credential only while the durable controller rebuild explicitly awaits that
// node. This exception is heartbeat-only; command leasing remains fenced until
// the successor credential is activated.
func (s *Store) ReconcileNodeControlModeAuthenticated(
	ctx context.Context,
	nodeID int64,
	fact NodeControlModeFact,
	authenticatedCredentialGeneration int64,
) (NodeControlModeDecision, error) {
	return s.reconcileNodeControlModeAuthenticated(
		ctx, nodeID, fact, authenticatedCredentialGeneration,
	)
}

func (s *Store) reconcileNodeControlModeAuthenticated(
	ctx context.Context,
	nodeID int64,
	fact NodeControlModeFact,
	authenticatedCredentialGeneration int64,
) (NodeControlModeDecision, error) {
	if nodeID <= 0 || !validNodeControlModeFact(fact) {
		return NodeControlModeDecision{}, fmt.Errorf("invalid node control mode fact")
	}
	if authenticatedCredentialGeneration <= 0 {
		return NodeControlModeDecision{}, ErrStaleControllerMode
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return NodeControlModeDecision{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var role, currentMode, currentDesired string
	var currentModeGeneration, currentDesiredGeneration, activeGeneration int64
	err = tx.QueryRowContext(ctx, `
		SELECT n.role,n.control_mode,n.control_mode_generation,
		  n.desired_control_mode,n.desired_mode_generation,ce.generation
		FROM nodes AS n
		JOIN controller_epochs AS ce ON ce.state='active'
		WHERE n.id=$1
		FOR UPDATE OF n`, nodeID).Scan(
		&role, &currentMode, &currentModeGeneration,
		&currentDesired, &currentDesiredGeneration, &activeGeneration,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return NodeControlModeDecision{}, fmt.Errorf("node or active controller not found")
		}
		return NodeControlModeDecision{}, err
	}
	if authenticatedCredentialGeneration > activeGeneration || fact.ControllerGeneration > activeGeneration {
		return NodeControlModeDecision{}, ErrStaleControllerMode
	}
	if authenticatedCredentialGeneration == activeGeneration {
		if fact.ControllerGeneration != activeGeneration {
			return NodeControlModeDecision{}, ErrStaleControllerMode
		}
	} else {
		allowed, err := controllerRebuildAllowsOldCredentialLocked(
			ctx, tx, nodeID, activeGeneration, authenticatedCredentialGeneration,
		)
		if err != nil {
			return NodeControlModeDecision{}, err
		}
		if !allowed || fact.ControllerGeneration < authenticatedCredentialGeneration {
			return NodeControlModeDecision{}, ErrStaleControllerMode
		}
	}
	if fact.ModeGeneration < currentModeGeneration ||
		(fact.ModeGeneration == currentModeGeneration && fact.Mode != currentMode) {
		return NodeControlModeDecision{}, ErrStaleNodeControlMode
	}
	if role != "compute" && (fact.Mode == NodeModeIndependent || fact.Mode == NodeModeIndependentDraining) {
		return NodeControlModeDecision{}, fmt.Errorf("storage node cannot enter independent mode")
	}

	desired := fact.Mode
	switch fact.Mode {
	case NodeModeControllerUnreachable:
		desired = NodeModeManaged
	case NodeModeIndependent:
		desired = NodeModeIndependentDraining
	case NodeModeIndependentDraining:
		if fact.ActiveIndependentSessions == 0 && fact.PendingUserSyncs == 0 {
			desired = NodeModeManaged
		}
	}
	desiredGeneration := fact.ModeGeneration
	if desired != fact.Mode {
		if currentMode == fact.Mode && currentModeGeneration == fact.ModeGeneration &&
			currentDesired == desired && currentDesiredGeneration > fact.ModeGeneration {
			desiredGeneration = currentDesiredGeneration
		} else {
			desiredGeneration = maxInt64(fact.ModeGeneration, currentDesiredGeneration) + 1
		}
	}
	evidence, err := json.Marshal(map[string]any{
		"consecutive_heartbeat_failures":    fact.ConsecutiveHeartbeatFails,
		"consecutive_health_probe_failures": fact.ConsecutiveHealthProbeFails,
		"active_independent_sessions":       fact.ActiveIndependentSessions,
		"pending_user_syncs":                fact.PendingUserSyncs,
		"authenticated_generation":          authenticatedCredentialGeneration,
	})
	if err != nil {
		return NodeControlModeDecision{}, err
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE nodes SET control_mode=$2,control_mode_generation=$3,
		  desired_control_mode=$4,desired_mode_generation=$5,
		  control_mode_reason_code=NULLIF($6,''),control_mode_changed_at=$7,
		  controller_generation=CASE WHEN $16::bigint=$8::bigint
		    THEN $8::bigint ELSE controller_generation END,
		  controller_outage_started_at=$9,
		  last_controller_success_at=$10,independent_since=$11,
		  controller_heartbeat_failures=$12,controller_health_probe_failures=$13,
		  active_independent_sessions=$14,pending_independent_syncs=$15
		WHERE id=$1`,
		nodeID, fact.Mode, fact.ModeGeneration, desired, desiredGeneration,
		fact.ReasonCode, fact.ObservedAt, activeGeneration,
		nullableControlModeTime(fact.OutageStartedAt), nullableControlModeTime(fact.LastControllerSuccessAt),
		nullableControlModeTime(fact.IndependentSince), fact.ConsecutiveHeartbeatFails,
		fact.ConsecutiveHealthProbeFails, fact.ActiveIndependentSessions, fact.PendingUserSyncs,
		authenticatedCredentialGeneration)
	if err != nil {
		return NodeControlModeDecision{}, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO node_control_mode_events (
		  node_id,reported_mode,reported_mode_generation,desired_mode,desired_mode_generation,
		  controller_generation,reason_code,evidence,observed_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`,
		nodeID, fact.Mode, fact.ModeGeneration, desired, desiredGeneration,
		activeGeneration, fact.ReasonCode, evidence, fact.ObservedAt)
	if err != nil {
		return NodeControlModeDecision{}, err
	}
	if err := recordIndependentSyncFactsTx(
		ctx, tx, nodeID, activeGeneration, fact.PendingUsers, fact.ObservedAt,
	); err != nil {
		return NodeControlModeDecision{}, err
	}
	if err := markControllerRebuildHeartbeatLocked(
		ctx, tx, nodeID, activeGeneration, authenticatedCredentialGeneration,
		fact.Mode, desired, fact.ObservedAt,
	); err != nil {
		return NodeControlModeDecision{}, err
	}
	if err := tx.Commit(); err != nil {
		return NodeControlModeDecision{}, err
	}
	return NodeControlModeDecision{
		ControllerGeneration: activeGeneration,
		DesiredMode:          desired,
		ModeGeneration:       desiredGeneration,
	}, nil
}

func nullableControlModeTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

// IsControlPlaneReady fails closed unless exactly one active epoch exists, its
// durable rebuild (when present) is complete, and every compute node has both
// reported and desired managed mode in that generation.
func (s *Store) IsControlPlaneReady(ctx context.Context) (bool, error) {
	var ready bool
	err := s.DB.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM controller_epochs WHERE state='active')
		  AND NOT EXISTS (
		    SELECT 1 FROM controller_rebuild_operations rebuild
		    JOIN controller_epochs epoch ON epoch.generation=rebuild.generation
		    WHERE epoch.state='active' AND rebuild.state<>'succeeded'
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM nodes
		    WHERE role='compute'
		      AND operational_state NOT IN ('decommissioned','retired')
		      AND EXISTS (
		        SELECT 1 FROM agent_credentials credential
		        WHERE credential.node_id=nodes.id AND credential.revoked_at IS NULL
		      )
		      AND (control_mode<>'managed' OR desired_control_mode<>'managed'
		        OR controller_generation<>(SELECT generation FROM controller_epochs WHERE state='active'))
		  )`).Scan(&ready)
	return ready, err
}

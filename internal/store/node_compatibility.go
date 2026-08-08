package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrNodeCompatibilityState = errors.New("node compatibility incident state conflict")
	ErrStaleNodeHeartbeat     = errors.New("stale node heartbeat")
)

const (
	nodeCompatibilityStableObservations = 3
	nodeCompatibilityStableWindow       = 30 * time.Second
)

type NodeCompatibilityIncidentStatus struct {
	State                  string     `json:"state"`
	ReasonCode             string     `json:"reason_code"`
	CompatibleObservations int        `json:"compatible_observations"`
	RequiredObservations   int        `json:"required_observations"`
	AgentVersion           string     `json:"agent_version"`
	TavernVersion          string     `json:"tavern_version"`
	FirstSeenAt            time.Time  `json:"first_seen_at"`
	LastSeenAt             time.Time  `json:"last_seen_at"`
	ResolvedAt             *time.Time `json:"resolved_at,omitempty"`
}

type nodeCompatibilityCursor struct {
	HasHistory             bool
	ConnectivityState      string
	Fingerprint            string
	IncidentID             string
	IncidentState          string
	IncidentReason         string
	IncidentFingerprint    string
	CompatibleObservations int
	VerificationStartedAt  sql.NullTime
	IncidentLastSeenAt     time.Time
}

type nodeCompatibilityDecision struct {
	Action                 string
	IncidentState          string
	IncidentReason         string
	IncidentFingerprint    string
	CompatibleObservations int
	VerificationStartedAt  sql.NullTime
	EffectiveState         string
	EffectiveReasonCode    string
	Notify                 bool
}

func decideNodeCompatibilityIncident(
	cursor nodeCompatibilityCursor,
	facts NodeHeartbeatFacts,
) nodeCompatibilityDecision {
	decision := nodeCompatibilityDecision{
		EffectiveState: facts.CompatibilityState, EffectiveReasonCode: facts.CompatibilityReasonCode,
	}
	compatible := facts.CompatibilityState == "compatible"
	if cursor.IncidentID == "" {
		if !compatible {
			decision.Action = "open"
			decision.IncidentState = "isolated"
			decision.IncidentReason = facts.CompatibilityReasonCode
			decision.IncidentFingerprint = facts.CompatibilityFingerprint
			decision.Notify = true
			return decision
		}
		if !cursor.HasHistory {
			return decision
		}
		reason := ""
		if cursor.ConnectivityState != "online" {
			reason = "node_reconnected"
		} else if cursor.Fingerprint != facts.CompatibilityFingerprint {
			reason = "fingerprint_changed"
		}
		if reason == "" {
			return decision
		}
		decision.Action = "open"
		decision.IncidentState = "verifying"
		decision.IncidentReason = reason
		decision.IncidentFingerprint = facts.CompatibilityFingerprint
		decision.CompatibleObservations = 1
		decision.VerificationStartedAt = sql.NullTime{Time: facts.ObservedAt, Valid: true}
		decision.EffectiveState = "unknown"
		decision.EffectiveReasonCode = "upgrade_verifying"
		decision.Notify = true
		return decision
	}

	if !compatible {
		decision.Action = "update"
		decision.IncidentState = "isolated"
		decision.IncidentReason = facts.CompatibilityReasonCode
		decision.IncidentFingerprint = facts.CompatibilityFingerprint
		decision.Notify = cursor.IncidentState != "isolated" ||
			cursor.IncidentReason != facts.CompatibilityReasonCode
		return decision
	}
	decision.EffectiveState = "unknown"
	decision.EffectiveReasonCode = "upgrade_verifying"
	if cursor.IncidentState != "verifying" ||
		cursor.IncidentFingerprint != facts.CompatibilityFingerprint ||
		!cursor.VerificationStartedAt.Valid {
		decision.Action = "update"
		decision.IncidentState = "verifying"
		decision.IncidentReason = cursor.IncidentReason
		decision.IncidentFingerprint = facts.CompatibilityFingerprint
		decision.CompatibleObservations = 1
		decision.VerificationStartedAt = sql.NullTime{Time: facts.ObservedAt, Valid: true}
		return decision
	}
	if !facts.ObservedAt.After(cursor.IncidentLastSeenAt) {
		return decision
	}

	decision.Action = "update"
	decision.IncidentState = "verifying"
	decision.IncidentReason = cursor.IncidentReason
	decision.IncidentFingerprint = facts.CompatibilityFingerprint
	decision.CompatibleObservations = cursor.CompatibleObservations + 1
	decision.VerificationStartedAt = cursor.VerificationStartedAt
	if decision.CompatibleObservations >= nodeCompatibilityStableObservations &&
		facts.ObservedAt.Sub(cursor.VerificationStartedAt.Time) >= nodeCompatibilityStableWindow {
		decision.Action = "resolve"
		decision.IncidentState = "resolved"
		decision.EffectiveState = "compatible"
		decision.EffectiveReasonCode = ""
	}
	return decision
}

func reconcileNodeCompatibilityIncidentLocked(
	ctx context.Context,
	tx *sql.Tx,
	nodeID int64,
	cursor nodeCompatibilityCursor,
	facts NodeHeartbeatFacts,
) (string, string, error) {
	var verificationStarted sql.NullTime
	err := tx.QueryRowContext(ctx, `
		SELECT id::text,state,reason_code,observed_fingerprint,compatible_observations,
		  verification_started_at,last_seen_at
		FROM node_compatibility_incidents
		WHERE node_id=$1 AND state IN ('isolated','verifying')
		FOR UPDATE`, nodeID).Scan(
		&cursor.IncidentID, &cursor.IncidentState, &cursor.IncidentReason,
		&cursor.IncidentFingerprint, &cursor.CompatibleObservations, &verificationStarted,
		&cursor.IncidentLastSeenAt,
	)
	if err != nil && err != sql.ErrNoRows {
		return "", "", err
	}
	if err == nil {
		cursor.VerificationStartedAt = verificationStarted
	}
	decision := decideNodeCompatibilityIncident(cursor, facts)
	if decision.Action == "" {
		return decision.EffectiveState, decision.EffectiveReasonCode, nil
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `
		SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return "", "", ErrNoActiveController
		}
		return "", "", err
	}
	incidentID := cursor.IncidentID
	switch decision.Action {
	case "open":
		err := tx.QueryRowContext(ctx, `
			INSERT INTO node_compatibility_incidents (
			  node_id,state,reason_code,previous_fingerprint,observed_fingerprint,
			  observed_agent_version,observed_tavern_version,compatible_observations,
			  controller_generation,verification_started_at,first_seen_at,last_seen_at,updated_at
			) VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$11,$11)
			RETURNING id::text`, nodeID, decision.IncidentState, decision.IncidentReason,
			cursor.Fingerprint, decision.IncidentFingerprint, facts.AgentVersion, facts.TavernVersion,
			decision.CompatibleObservations, generation, nullTimeValue(decision.VerificationStartedAt),
			facts.ObservedAt).Scan(&incidentID)
		if err != nil {
			return "", "", err
		}
	case "update":
		result, err := tx.ExecContext(ctx, `
			UPDATE node_compatibility_incidents SET state=$2,reason_code=$3,
			  observed_fingerprint=$4,observed_agent_version=$5,observed_tavern_version=$6,
			  compatible_observations=$7,verification_started_at=$8,last_seen_at=$9,updated_at=$9,
			  controller_generation=$10
			WHERE id=$1 AND state IN ('isolated','verifying')`, incidentID,
			decision.IncidentState, decision.IncidentReason, decision.IncidentFingerprint,
			facts.AgentVersion, facts.TavernVersion, decision.CompatibleObservations,
			nullTimeValue(decision.VerificationStartedAt), facts.ObservedAt, generation)
		if err != nil {
			return "", "", err
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			if err != nil {
				return "", "", err
			}
			return "", "", ErrNodeCompatibilityState
		}
	case "resolve":
		result, err := tx.ExecContext(ctx, `
			UPDATE node_compatibility_incidents SET state='resolved',observed_fingerprint=$2,
			  observed_agent_version=$3,observed_tavern_version=$4,
			  compatible_observations=$5,last_seen_at=$6,resolved_at=$6,updated_at=$6,
			  controller_generation=$7
			WHERE id=$1 AND state='verifying'`, incidentID, decision.IncidentFingerprint,
			facts.AgentVersion, facts.TavernVersion, decision.CompatibleObservations,
			facts.ObservedAt, generation)
		if err != nil {
			return "", "", err
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			if err != nil {
				return "", "", err
			}
			return "", "", ErrNodeCompatibilityState
		}
	}

	if decision.Notify {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO alerts (
			  id,deduplication_key,severity,state,category,node_id,summary,
			  first_seen_at,last_seen_at,notify_after,occurrence_count
			) VALUES (
			  gen_random_uuid(),'node-compatibility:'||$1::bigint::text,'warning','open',
			  'node_compatibility',$1::bigint,'节点升级或兼容性复核尚未通过',$2,$2,$2,1
			) ON CONFLICT (deduplication_key) DO UPDATE SET
			  state='open',severity='warning',last_seen_at=EXCLUDED.last_seen_at,
			  notify_after=EXCLUDED.notify_after,resolved_at=NULL,
			  occurrence_count=alerts.occurrence_count+1`, nodeID, facts.ObservedAt); err != nil {
			return "", "", err
		}
	}
	if decision.Action == "resolve" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE alerts SET state='resolved',resolved_at=$2,last_seen_at=$2
			WHERE deduplication_key='node-compatibility:'||$1::text
			  AND state IN ('open','acknowledged')`, nodeID, facts.ObservedAt); err != nil {
			return "", "", err
		}
	}
	stateChanged := cursor.IncidentState != decision.IncidentState
	fingerprintReset := cursor.IncidentID != "" && cursor.IncidentFingerprint != decision.IncidentFingerprint
	if decision.Action == "open" || decision.Action == "resolve" || decision.Notify || stateChanged || fingerprintReset {
		action := "node-compatibility-" + decision.IncidentState
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_events (
			  actor_type,action,target_type,target_id,operation_id,
			  controller_generation,outcome,detail
			) VALUES ('system',$1,'node',$2::text,$3,$4,'succeeded',
			  jsonb_build_object(
			    'from_state',$5::text,'state',$6::text,'reason_code',$7::text,
			    'compatible_observations',$8::int))`,
			action, nodeID, incidentID, generation, cursor.IncidentState,
			decision.IncidentState, decision.IncidentReason, decision.CompatibleObservations); err != nil {
			return "", "", err
		}
	}
	return decision.EffectiveState, decision.EffectiveReasonCode, nil
}

func (s *Store) GetNodeCompatibilityIncidentStatus(
	ctx context.Context,
	nodeID int64,
) (*NodeCompatibilityIncidentStatus, error) {
	if nodeID <= 0 {
		return nil, ErrNodeCompatibilityState
	}
	var status NodeCompatibilityIncidentStatus
	var resolvedAt sql.NullTime
	err := s.DB.QueryRowContext(ctx, `
		SELECT state,reason_code,compatible_observations,observed_agent_version,
		  observed_tavern_version,first_seen_at,last_seen_at,resolved_at
		FROM node_compatibility_incidents WHERE node_id=$1
		ORDER BY created_at DESC,id DESC LIMIT 1`, nodeID).Scan(
		&status.State, &status.ReasonCode, &status.CompatibleObservations,
		&status.AgentVersion, &status.TavernVersion, &status.FirstSeenAt,
		&status.LastSeenAt, &resolvedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	status.RequiredObservations = nodeCompatibilityStableObservations
	if resolvedAt.Valid {
		status.ResolvedAt = &resolvedAt.Time
	}
	return &status, nil
}

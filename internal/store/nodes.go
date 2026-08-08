package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var ErrNodeLifecycleBlocked = errors.New("node lifecycle transition blocked")

var machineReasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidMachineReasonCode accepts only bounded, language-neutral identifiers.
// Human-readable explanations belong in the UI; durable state transitions keep
// stable codes that can be filtered and audited without recording free text.
func ValidMachineReasonCode(value string) bool {
	return machineReasonCodePattern.MatchString(value)
}

type TransitionNodeLifecycleParams struct {
	OperationID string
	NodeID      int64
	ToState     string
	ReasonCode  string
	AdminID     int64
	Now         time.Time
}

func (s *Store) TransitionNodeLifecycle(ctx context.Context, p TransitionNodeLifecycleParams) (string, error) {
	if !validUUIDText(p.OperationID) || p.NodeID <= 0 || p.AdminID <= 0 || !ValidMachineReasonCode(p.ReasonCode) {
		return "", ErrNodeLifecycleBlocked
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	allowed := map[string]map[string]bool{
		"pending":     {"active": true, "retired": true},
		"active":      {"maintenance": true, "draining": true, "degraded": true, "failed": true},
		"maintenance": {"active": true, "draining": true, "retired": true},
		"draining":    {"active": true, "maintenance": true, "retired": true},
		"degraded":    {"active": true, "maintenance": true, "draining": true, "failed": true},
		"failed":      {"maintenance": true, "retired": true},
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	var replayState, replayReason string
	var replayNodeID, replayAdminID int64
	err = tx.QueryRowContext(ctx, `
		SELECT node_id,to_state,reason_code,COALESCE(actor_admin_id,0)
		FROM node_lifecycle_events WHERE operation_id=$1`, p.OperationID).
		Scan(&replayNodeID, &replayState, &replayReason, &replayAdminID)
	if err == nil {
		if replayNodeID != p.NodeID || replayState != p.ToState ||
			replayReason != p.ReasonCode || replayAdminID != p.AdminID {
			return "", ErrNodeLifecycleBlocked
		}
		return replayState, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
		Scan(&activeGeneration); err != nil {
		if err == sql.ErrNoRows {
			return "", ErrNoActiveController
		}
		return "", err
	}
	var fromState, controlMode, desiredControlMode string
	if err := tx.QueryRowContext(ctx, `
		SELECT operational_state,control_mode,desired_control_mode
		FROM nodes WHERE id=$1 FOR UPDATE`, p.NodeID).
		Scan(&fromState, &controlMode, &desiredControlMode); err != nil {
		return "", err
	}
	if !allowed[fromState][p.ToState] {
		return "", ErrNodeLifecycleBlocked
	}
	if p.ToState == "retired" {
		if controlMode != "managed" || desiredControlMode != "managed" {
			return "", ErrNodeLifecycleBlocked
		}
		var dependent bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM users WHERE home_node_id=$1 AND status='active'
			  UNION ALL
			  SELECT 1 FROM user_replicas
			  WHERE node_id=$1 AND state NOT IN ('empty','stale','error')
			  UNION ALL
			  SELECT 1 FROM replica_copies
			  WHERE node_id=$1 AND state NOT IN ('empty','stale','corrupt','deleting','error')
			  UNION ALL
			  SELECT 1 FROM node_accounts
			  WHERE node_id=$1 AND status IN ('pending','active','conflict')
			  UNION ALL
			  SELECT 1 FROM workflows
			  WHERE (source_node_id=$1 OR target_node_id=$1)
			    AND state NOT IN ('cancelled','failed','succeeded')
			  UNION ALL
			  SELECT 1 FROM backup_jobs
			  WHERE (src_node_id=$1 OR dst_node_id=$1) AND status IN ('pending','running')
			  UNION ALL
			  SELECT 1 FROM user_activity_leases
			  WHERE writer_node_id=$1 AND state<>'ended'
			  UNION ALL
			  SELECT 1 FROM independent_user_reconciliations
			  WHERE node_id=$1 AND state NOT IN ('succeeded','superseded','failed')
			  UNION ALL
			  SELECT 1 FROM relay_transfers
			  WHERE (source_node_id=$1 OR target_node_id=$1)
			    AND state NOT IN ('consumed','expired','failed')
			)`, p.NodeID).Scan(&dependent); err != nil {
			return "", err
		}
		if dependent {
			return "", ErrNodeLifecycleBlocked
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE nodes SET operational_state=$2,
		  allow_register=CASE WHEN $2='retired' THEN false ELSE allow_register END,
		  is_backup_target=CASE WHEN $2='retired' THEN false ELSE is_backup_target END,
		  status=CASE WHEN $2='retired' THEN 'offline' ELSE status END
		WHERE id=$1`, p.NodeID, p.ToState); err != nil {
		return "", err
	}
	if p.ToState == "retired" {
		statements := []struct {
			query string
			args  []any
		}{
			{`UPDATE agent_credentials SET revoked_at=COALESCE(revoked_at,$2) WHERE node_id=$1`, []any{p.NodeID, p.Now}},
			{`UPDATE agent_credential_rotations SET state='revoked' WHERE node_id=$1 AND state='pending'`, []any{p.NodeID}},
			{`DELETE FROM enrollment_tokens WHERE expected_node_id=$1 AND consumed_at IS NULL`, []any{p.NodeID}},
			{`UPDATE agent_commands SET state='expired',updated_at=$2
			 WHERE node_id=$1 AND state IN ('queued','leased','acked','running')`,
				[]any{p.NodeID, p.Now}},
			{`UPDATE admin_node_links SET state='revoked',revoked_at=COALESCE(revoked_at,$2),
			   updated_at=$2,last_error_code='node_retired'
			 WHERE node_id=$1 AND state<>'revoked'`, []any{p.NodeID, p.Now}},
			{`UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$2)
			 WHERE target_node_id=$1 AND consumed_at IS NULL`, []any{p.NodeID, p.Now}},
			{`UPDATE tickets SET expires_at=LEAST(expires_at,$2)
			 WHERE node_id=$1 AND used_at IS NULL`, []any{p.NodeID, p.Now}},
			{`UPDATE snapshot_transfer_capabilities SET state='revoked'
			 WHERE (source_node_id=$1 OR target_node_id=$1) AND state='prepared'`, []any{p.NodeID}},
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
				return "", err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO node_lifecycle_events (
		  operation_id,node_id,from_state,to_state,reason_code,actor_admin_id,controller_generation,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		p.OperationID, p.NodeID, fromState, p.ToState, p.ReasonCode, p.AdminID, activeGeneration, p.Now); err != nil {
		return "", err
	}
	return p.ToState, tx.Commit()
}

const nodeSelectColumns = `
  id,name,role,base_url,transfer_url,region,
  cpu_pct,mem_pct,disk_pct,agent_version,tavern_version,last_seen_at,status,
  connectivity_state,operational_state,control_mode,control_mode_generation,
  desired_control_mode,desired_mode_generation,capacity_state,capacity_reason_code,
  capacity_changed_at,capacity_cooldown_until,compatibility_state,compatibility_reason_code,
  compatibility_fingerprint,compatibility_reported_at,metrics_observed_at,
  cpu_window_avg,cpu_window_peak,mem_window_avg,mem_window_peak,
  disk_window_avg,disk_window_peak,disk_total_bytes,disk_available_bytes,
  disk_quota_bytes,allocated_disk_bytes,online_users,task_queue_depth,telemetry_source,
  allow_register,is_backup_target,registration_policy_state,
  registration_policy_version,registration_policy_expires_at,
  registration_policy_observed_at,registration_policy_error_code,created_at`

type nodeScanner interface {
	Scan(dest ...any) error
}

func scanNode(scanner nodeScanner, n *Node) error {
	return scanner.Scan(
		&n.ID, &n.Name, &n.Role, &n.BaseURL, &n.TransferURL, &n.Region,
		&n.CPUPct, &n.MemPct, &n.DiskPct, &n.AgentVersion, &n.TavernVersion, &n.LastSeenAt, &n.Status,
		&n.ConnectivityState, &n.OperationalState, &n.ControlMode, &n.ControlModeGeneration,
		&n.DesiredControlMode, &n.DesiredModeGeneration, &n.CapacityState, &n.CapacityReasonCode,
		&n.CapacityChangedAt, &n.CapacityCooldownUntil, &n.CompatibilityState, &n.CompatibilityReasonCode,
		&n.CompatibilityFingerprint, &n.CompatibilityReportedAt, &n.MetricsObservedAt,
		&n.CPUWindowAvg, &n.CPUWindowPeak, &n.MemWindowAvg, &n.MemWindowPeak,
		&n.DiskWindowAvg, &n.DiskWindowPeak, &n.DiskTotalBytes, &n.DiskAvailableBytes,
		&n.DiskQuotaBytes, &n.AllocatedDiskBytes, &n.OnlineUsers, &n.TaskQueueDepth, &n.TelemetrySource,
		&n.AllowRegister, &n.IsBackupTarget, &n.RegistrationPolicyState,
		&n.RegistrationPolicyVersion, &n.RegistrationPolicyExpiresAt,
		&n.RegistrationPolicyObservedAt, &n.RegistrationPolicyErrorCode, &n.CreatedAt,
	)
}

// CreateNode 创建节点。
func (s *Store) CreateNode(ctx context.Context, n *Node) error {
	return s.DB.QueryRowContext(ctx, `
	  INSERT INTO nodes (uuid,name, role, base_url, transfer_url, region,
	    status, allow_register, is_backup_target)
	  VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, created_at`,
		n.Name, n.Role, n.BaseURL, n.TransferURL, n.Region,
		n.Status, n.AllowRegister, n.IsBackupTarget,
	).Scan(&n.ID, &n.CreatedAt)
}

// GetNodeByID 按 ID 查找。
func (s *Store) GetNodeByID(ctx context.Context, id int64) (*Node, error) {
	n := &Node{}
	err := scanNode(s.DB.QueryRowContext(ctx, `SELECT `+nodeSelectColumns+` FROM nodes WHERE id=$1`, id), n)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

// ListNodes 列出全部节点。
func (s *Store) ListNodes(ctx context.Context) ([]*Node, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+nodeSelectColumns+` FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n := &Node{}
		if err := scanNode(rows, n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNodeHeartbeat atomically stores one metric sample, evaluates the
// durable capacity state, and refreshes the independent health dimensions.
func (s *Store) UpdateNodeHeartbeat(
	ctx context.Context,
	id int64,
	facts NodeHeartbeatFacts,
	capacityPolicy NodeCapacityPolicy,
) error {
	if id <= 0 || !validNodeHeartbeatFacts(facts) || !validNodeCapacityPolicy(capacityPolicy) {
		return fmt.Errorf("invalid node heartbeat facts")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var current nodeCapacityCursor
	var currentReason sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT capacity_state,capacity_reason_code,capacity_pressure_since,
		  capacity_recovery_since,capacity_changed_at,capacity_cooldown_until
		FROM nodes WHERE id=$1 FOR UPDATE`, id).Scan(
		&current.State, &currentReason, &current.PressureSince,
		&current.RecoverySince, &current.ChangedAt, &current.CooldownUntil,
	); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("node not found")
		}
		return err
	}
	current.Reason = currentReason.String
	var window nodeMetricWindow
	if facts.MetricsValid {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_metric_samples (
			  node_id,sampled_at,cpu_avg_pct,cpu_peak_pct,memory_avg_pct,memory_peak_pct,
			  disk_used_pct,disk_available_bytes,online_users,task_queue_depth
			) VALUES ($1,$2,$3,$3,$4,$4,$5,$6,$7,$8)
			ON CONFLICT (node_id,sampled_at) DO UPDATE SET
			  cpu_avg_pct=EXCLUDED.cpu_avg_pct,cpu_peak_pct=EXCLUDED.cpu_peak_pct,
			  memory_avg_pct=EXCLUDED.memory_avg_pct,memory_peak_pct=EXCLUDED.memory_peak_pct,
			  disk_used_pct=EXCLUDED.disk_used_pct,disk_available_bytes=EXCLUDED.disk_available_bytes,
			  online_users=EXCLUDED.online_users,task_queue_depth=EXCLUDED.task_queue_depth`,
			id, facts.ObservedAt, facts.CPUPct, facts.MemPct, facts.DiskPct,
			facts.DiskAvailableBytes, facts.OnlineUsers, facts.TaskQueueDepth); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(AVG(cpu_avg_pct),0),COALESCE(MAX(cpu_peak_pct),0),
			  COALESCE(AVG(memory_avg_pct),0),COALESCE(MAX(memory_peak_pct),0),
			  COALESCE(AVG(disk_used_pct),0),COALESCE(MAX(disk_used_pct),0)
			FROM node_metric_samples WHERE node_id=$1 AND sampled_at>=$2`,
			id, facts.ObservedAt.Add(-capacityPolicy.Window)).Scan(
			&window.CPUAvg, &window.CPUPeak, &window.MemAvg, &window.MemPeak,
			&window.DiskAvg, &window.DiskPeak,
		); err != nil {
			return err
		}
	}
	decision := evaluateNodeCapacity(facts.ObservedAt, current, facts, window, capacityPolicy)
	metric := func(value float64) any {
		if !facts.MetricsValid {
			return nil
		}
		return value
	}
	metricInt := func(value int64) any {
		if !facts.MetricsValid {
			return nil
		}
		return value
	}
	_, err = tx.ExecContext(ctx, `
	  UPDATE nodes SET cpu_pct=$2,mem_pct=$3,disk_pct=$4,
	    tavern_version=$5,agent_version=$6,transfer_url=$7,
	    last_seen_at=$8,status='online',connectivity_state='online',
	    operational_state=CASE WHEN operational_state='pending' THEN 'active' ELSE operational_state END,
	    allocated_disk_bytes=$9,disk_available_bytes=$10,disk_total_bytes=$11,disk_quota_bytes=$12,
	    online_users=$13,task_queue_depth=$14,metrics_observed_at=$8,
	    cpu_window_avg=$15,cpu_window_peak=$16,mem_window_avg=$17,mem_window_peak=$18,
	    disk_window_avg=$19,disk_window_peak=$20,capacity_state=$21,
	    capacity_reason_code=NULLIF($22,''),capacity_pressure_since=$23,
	    capacity_recovery_since=$24,capacity_changed_at=$25,capacity_cooldown_until=$26,
	    compatibility_state=$27,compatibility_fingerprint=$28,
	    compatibility_reason_code=NULLIF($29,''),compatibility_reported_at=$8,telemetry_source=$34,
	    registration_policy_state=CASE
	      WHEN $30 IN ('open','invitation_required','closed')
	        AND ($31>registration_policy_version
	          OR ($31=registration_policy_version AND $30=registration_policy_state)) THEN $30
	      ELSE 'error' END,
	    registration_policy_version=GREATEST(registration_policy_version,$31),
	    registration_policy_expires_at=CASE
	      WHEN $30 IN ('open','invitation_required','closed')
	        AND ($31>registration_policy_version
	          OR ($31=registration_policy_version AND $30=registration_policy_state)) THEN $32
	      ELSE $8 END,
	    registration_policy_observed_at=$8,
	    registration_policy_error_code=CASE
	      WHEN $30 IN ('open','invitation_required','closed')
	        AND ($31>registration_policy_version
	          OR ($31=registration_policy_version AND $30=registration_policy_state)) THEN NULL
	      WHEN $31<registration_policy_version THEN 'version_rollback'
	      WHEN $31=registration_policy_version AND $30<>registration_policy_state THEN 'version_reuse'
	      ELSE $33 END
	  WHERE id=$1`,
		id, metric(facts.CPUPct), metric(facts.MemPct), metric(facts.DiskPct),
		facts.TavernVersion, facts.AgentVersion, facts.TransferURL, facts.ObservedAt,
		metricInt(facts.AllocatedDiskBytes), metricInt(facts.DiskAvailableBytes),
		metricInt(facts.DiskTotalBytes), metricInt(facts.DiskQuotaBytes),
		facts.OnlineUsers, facts.TaskQueueDepth,
		metric(window.CPUAvg), metric(window.CPUPeak), metric(window.MemAvg), metric(window.MemPeak),
		metric(window.DiskAvg), metric(window.DiskPeak), decision.State, decision.Reason,
		nullTimeValue(decision.PressureSince), nullTimeValue(decision.RecoverySince), decision.ChangedAt,
		nullTimeValue(decision.CooldownUntil), facts.CompatibilityState, facts.CompatibilityFingerprint,
		facts.CompatibilityReasonCode,
		facts.RegistrationPolicy.State, facts.RegistrationPolicy.Version,
		facts.RegistrationPolicy.ExpiresAt, facts.RegistrationPolicy.ErrorCode, facts.TelemetrySource)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateNodeStatus 更新节点状态。
func (s *Store) UpdateNodeStatus(ctx context.Context, id int64, status string) error {
	if id <= 0 || (status != "online" && status != "offline" && status != "pending") {
		return fmt.Errorf("invalid node status")
	}
	connectivity := "unknown"
	if status == "online" {
		connectivity = "online"
	} else if status == "offline" {
		connectivity = "offline"
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE nodes SET status=$2,connectivity_state=$3,
		  capacity_state=CASE WHEN $2='online' THEN capacity_state ELSE 'unknown' END,
		  capacity_reason_code=CASE WHEN $2='online' THEN capacity_reason_code ELSE 'status_changed' END
		WHERE id=$1`, id, status, connectivity)
	return err
}

// UpdateNodeSettings 更新节点可配置项。
func (s *Store) UpdateNodeSettings(ctx context.Context, n *Node) error {
	_, err := s.DB.ExecContext(ctx, `
	  UPDATE nodes SET name=$2,base_url=$3,region=$4,allow_register=$5,
	    is_backup_target=$6 WHERE id=$1`,
		n.ID, n.Name, n.BaseURL, n.Region, n.AllowRegister,
		n.IsBackupTarget)
	return err
}

// MarkStaleNodesOffline 把超过 timeout 未心跳的节点标记为 offline。
func (s *Store) MarkStaleNodesOffline(ctx context.Context, timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("invalid node heartbeat timeout")
	}
	now := time.Now().UTC()
	_, err := s.DB.ExecContext(ctx, `
	  UPDATE nodes SET status='offline',connectivity_state='offline',capacity_state='unknown',
	    capacity_reason_code='heartbeat_stale',capacity_pressure_since=NULL,
	    capacity_recovery_since=NULL,capacity_cooldown_until=NULL,capacity_changed_at=$2
	  WHERE connectivity_state='online' AND last_seen_at < $1`,
		now.Add(-timeout), now)
	return err
}

func (s *Store) CleanupNodeMetricSamples(ctx context.Context, before time.Time) (int64, error) {
	if before.IsZero() {
		return 0, fmt.Errorf("invalid metric retention boundary")
	}
	result, err := s.DB.ExecContext(ctx, `DELETE FROM node_metric_samples WHERE sampled_at<$1`, before)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func nullTimeValue(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

// ---------- 副本 ----------

// UpsertReplica 创建或更新副本记录。
func (s *Store) UpsertReplica(ctx context.Context, r *UserReplica) error {
	_, err := s.DB.ExecContext(ctx, `
	  INSERT INTO user_replicas (user_id, node_id, kind, data_version, state)
	  VALUES ($1,$2,$3,$4,$5)
	  ON CONFLICT (user_id, node_id) DO UPDATE
	    SET kind=EXCLUDED.kind, state=EXCLUDED.state`,
		r.UserID, r.NodeID, r.Kind, r.DataVersion, r.State)
	return err
}

// GetReplica 查询某用户在某节点的副本。
func (s *Store) GetReplica(ctx context.Context, userID, nodeID int64) (*UserReplica, error) {
	r := &UserReplica{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT id, user_id, node_id, kind, data_version, state, last_sync_at, checksum, size_bytes
	  FROM user_replicas WHERE user_id=$1 AND node_id=$2`, userID, nodeID).
		Scan(&r.ID, &r.UserID, &r.NodeID, &r.Kind, &r.DataVersion, &r.State,
			&r.LastSyncAt, &r.Checksum, &r.SizeBytes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// ListReplicasByUser 列出某用户的所有副本。
func (s *Store) ListReplicasByUser(ctx context.Context, userID int64) ([]*UserReplica, error) {
	rows, err := s.DB.QueryContext(ctx, `
	  SELECT id, user_id, node_id, kind, data_version, state, last_sync_at, checksum, size_bytes
	  FROM user_replicas WHERE user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserReplica
	for rows.Next() {
		r := &UserReplica{}
		if err := rows.Scan(&r.ID, &r.UserID, &r.NodeID, &r.Kind, &r.DataVersion, &r.State,
			&r.LastSyncAt, &r.Checksum, &r.SizeBytes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateReplicaState 更新副本同步状态。
func (s *Store) UpdateReplicaState(ctx context.Context, userID, nodeID int64, state string, version int64, checksum string, size int64) error {
	_, err := s.DB.ExecContext(ctx, `
	  UPDATE user_replicas SET state=$3, data_version=$4, checksum=$5, size_bytes=$6, last_sync_at=$7
	  WHERE user_id=$1 AND node_id=$2`,
		userID, nodeID, state, version, checksum, size, time.Now())
	return err
}

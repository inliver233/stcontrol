package store

import (
	"context"
	"database/sql"
	"time"
)

// CreateNode 创建节点。
func (s *Store) CreateNode(ctx context.Context, n *Node) error {
	return s.DB.QueryRowContext(ctx, `
	  INSERT INTO nodes (name, role, base_url, agent_url, agent_psk, region,
	    status, allow_register, is_backup_target)
	  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, created_at`,
		n.Name, n.Role, n.BaseURL, n.AgentURL, n.AgentPSK, n.Region,
		n.Status, n.AllowRegister, n.IsBackupTarget,
	).Scan(&n.ID, &n.CreatedAt)
}

// GetNodeByID 按 ID 查找。
func (s *Store) GetNodeByID(ctx context.Context, id int64) (*Node, error) {
	n := &Node{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT id, name, role, base_url, agent_url, agent_psk, region,
	    cpu_pct, mem_pct, disk_pct, agent_version, tavern_version, last_seen_at,
	    status, allow_register, is_backup_target, created_at
	  FROM nodes WHERE id=$1`, id).
		Scan(&n.ID, &n.Name, &n.Role, &n.BaseURL, &n.AgentURL, &n.AgentPSK, &n.Region,
			&n.CPUPct, &n.MemPct, &n.DiskPct, &n.AgentVersion, &n.TavernVersion, &n.LastSeenAt,
			&n.Status, &n.AllowRegister, &n.IsBackupTarget, &n.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

// ListNodes 列出全部节点。
func (s *Store) ListNodes(ctx context.Context) ([]*Node, error) {
	rows, err := s.DB.QueryContext(ctx, `
	  SELECT id, name, role, base_url, agent_url, agent_psk, region,
	    cpu_pct, mem_pct, disk_pct, agent_version, tavern_version, last_seen_at,
	    status, allow_register, is_backup_target, created_at
	  FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n := &Node{}
		if err := rows.Scan(&n.ID, &n.Name, &n.Role, &n.BaseURL, &n.AgentURL, &n.AgentPSK, &n.Region,
			&n.CPUPct, &n.MemPct, &n.DiskPct, &n.AgentVersion, &n.TavernVersion, &n.LastSeenAt,
			&n.Status, &n.AllowRegister, &n.IsBackupTarget, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNodeHeartbeat 更新节点心跳与负载。
func (s *Store) UpdateNodeHeartbeat(ctx context.Context, id int64, cpu, mem, disk float64, tavernVer, agentVer string) error {
	_, err := s.DB.ExecContext(ctx, `
	  UPDATE nodes SET cpu_pct=$2, mem_pct=$3, disk_pct=$4,
	    tavern_version=$5, agent_version=$6, last_seen_at=$7, status='online'
	  WHERE id=$1`,
		id, cpu, mem, disk, tavernVer, agentVer, time.Now())
	return err
}

// UpdateNodeStatus 更新节点状态。
func (s *Store) UpdateNodeStatus(ctx context.Context, id int64, status string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE nodes SET status=$2 WHERE id=$1`, id, status)
	return err
}

// UpdateNodeSettings 更新节点可配置项。
func (s *Store) UpdateNodeSettings(ctx context.Context, n *Node) error {
	_, err := s.DB.ExecContext(ctx, `
	  UPDATE nodes SET name=$2, base_url=$3, region=$4, allow_register=$5,
	    is_backup_target=$6, role=$7 WHERE id=$1`,
		n.ID, n.Name, n.BaseURL, n.Region, n.AllowRegister, n.IsBackupTarget, n.Role)
	return err
}

// MarkStaleNodesOffline 把超过 timeout 未心跳的节点标记为 offline。
func (s *Store) MarkStaleNodesOffline(ctx context.Context, timeout time.Duration) error {
	_, err := s.DB.ExecContext(ctx, `
	  UPDATE nodes SET status='offline'
	  WHERE status='online' AND last_seen_at < $1`, time.Now().Add(-timeout))
	return err
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

package controller

import (
	"context"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// scheduleOfflineBackups 扫描所有用户副本, 找出"已离线且数据有变化、配置了备份目标"的用户, 触发备份。
// 触发条件: 家节点在线 + 用户在节点上 isOnline=false 且 lastActivity 超过保护期 + 当前无 running 备份。
func (s *Server) scheduleOfflineBackups(ctx context.Context) {
	grace := time.Duration(s.Cfg.Backup.OfflineGraceMin) * time.Minute
	nowMs := time.Now().UnixMilli()

	s.actMu.Lock()
	activity := s.activity
	s.actMu.Unlock()

	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return
	}
	for _, u := range users {
		if u.Status != "active" || !u.HomeNodeID.Valid {
			continue
		}
		nodeID := u.HomeNodeID.Int64
		// 找到家节点上该用户的在线状态
		st, ok := activity[nodeID][u.Username]
		if !ok {
			continue
		}
		if st.IsOnline {
			continue // 在线不备份
		}
		if nowMs-st.LastActivity < grace.Milliseconds() {
			continue // 离线时间不足保护期
		}
		// 已有 running 备份则跳过
		if job, _ := s.Store.FindRunningBackupForUserOnNode(ctx, u.ID, nodeID); job != nil {
			continue
		}
		// 触发备份
		_ = s.TriggerUserBackup(ctx, u.ID, nodeID, "offline")
	}
}

// TriggerUserBackup 为某用户在家节点触发一次备份到配置的备份目标。
// 目标选择: 优先该用户已配置的热备/存储副本; 否则系统默认存储节点。
func (s *Server) TriggerUserBackup(ctx context.Context, userID, srcNodeID int64, trigger string) error {
	user, err := s.Store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return err
	}
	srcNode, err := s.Store.GetNodeByID(ctx, srcNodeID)
	if err != nil || srcNode == nil {
		return err
	}

	// 选择备份目标节点
	dstNode, dstKind := s.pickBackupTarget(ctx, userID, srcNodeID)
	if dstNode == nil {
		return nil // 无可用备份目标, 跳过
	}

	// 创建任务
	job := &store.BackupJob{
		UserID: userID, SrcNodeID: srcNodeID, DstNodeID: dstNode.ID,
		Trigger: trigger, Status: "pending",
	}
	if err := s.Store.CreateBackupJob(ctx, job); err != nil {
		return err
	}

	// 标记目标副本 syncing
	_ = s.Store.UpsertReplica(ctx, &store.UserReplica{
		UserID: userID, NodeID: dstNode.ID, Kind: dstKind, State: "syncing",
	})

	// 下发备份指令给源节点子控
	req := &protocol.BackupStartRequest{
		JobID:       job.ID,
		UserID:      userID,
		Handle:      user.Username,
		DstAgentURL: dstNode.AgentURL,
		DstNodePSK:  dstNode.AgentPSK,
		DstNodeID:   dstNode.ID,
		DstKind:     dstKind,
	}
	if err := s.agent.startBackup(ctx, srcNodeID, srcNode.AgentPSK, srcNode.AgentURL, req); err != nil {
		_ = s.Store.UpdateBackupJobStatus(ctx, job.ID, "failed", 0, 0, 0, "下发备份指令失败: "+err.Error())
		return err
	}
	_ = s.Store.UpdateBackupJobStatus(ctx, job.ID, "running", 0, 0, 0, "")
	return nil
}

// pickBackupTarget 为用户选备份目标。
// 优先: 该用户已存在的 hot_standby/archive 副本节点(且节点在线)。
// 否则: 系统内第一台 is_backup_target 且在线的节点。
func (s *Server) pickBackupTarget(ctx context.Context, userID, srcNodeID int64) (*store.Node, string) {
	replicas, _ := s.Store.ListReplicasByUser(ctx, userID)
	for _, rep := range replicas {
		if rep.Kind == "hot_standby" || rep.Kind == "archive" {
			if rep.NodeID == srcNodeID {
				continue
			}
			n, err := s.Store.GetNodeByID(ctx, rep.NodeID)
			if err == nil && n != nil && n.Status == "online" {
				return n, rep.Kind
			}
		}
	}
	// 默认存储节点
	nodes, _ := s.Store.ListNodes(ctx)
	for _, n := range nodes {
		if n.ID == srcNodeID {
			continue
		}
		if n.IsBackupTarget && n.Status == "online" {
			kind := "archive"
			if n.Role == "compute" {
				kind = "hot_standby"
			}
			return n, kind
		}
	}
	return nil, ""
}

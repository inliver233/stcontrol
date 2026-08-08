package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type userProtectionResponse struct {
	State                string     `json:"state"`
	Label                string     `json:"label"`
	Risk                 string     `json:"risk"`
	CurrentNodeID        int64      `json:"current_node_id,omitempty"`
	CurrentNodeName      string     `json:"current_node_name,omitempty"`
	RecoveryNodeID       int64      `json:"recovery_node_id,omitempty"`
	RecoveryNodeName     string     `json:"recovery_node_name,omitempty"`
	ActiveWriterNodeID   int64      `json:"active_writer_node_id,omitempty"`
	ActiveWriterNodeName string     `json:"active_writer_node_name,omitempty"`
	LatestRecoveryAt     *time.Time `json:"latest_recovery_at,omitempty"`
	TakeoverAvailable    bool       `json:"takeover_available"`
	StorageRestoreNeeded bool       `json:"storage_restore_needed"`
	DataFaultState       string     `json:"data_fault_state,omitempty"`
	DataFaultReasonCode  string     `json:"data_fault_reason_code,omitempty"`
	Version              int64      `json:"version"`
}

type confirmTakeoverRequest struct {
	OperationID         string `json:"operation_id"`
	TargetNodeID        int64  `json:"target_node_id"`
	ExpectedRecoveryAt  string `json:"expected_recovery_at"`
	AcknowledgeDataLoss bool   `json:"acknowledge_data_loss"`
}

func (s *Server) protectionAlertGrace() time.Duration {
	if s.Cfg == nil {
		return time.Hour
	}
	minutes := s.Cfg.Backup.UnprotectedAlertMin
	if minutes <= 0 {
		minutes = 60
	}
	return time.Duration(minutes) * time.Minute
}

func (s *Server) handleMyProtection(w http.ResponseWriter, r *http.Request) {
	legacyUserID, _ := CurrentUser(r)
	user, err := s.Store.GetUserByID(r.Context(), legacyUserID)
	if err != nil || user == nil || user.GlobalID <= 0 {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在或不可用")
		return
	}
	state, err := s.Store.GetUserProtectionState(r.Context(), user.GlobalID)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "读取保护状态失败")
		return
	}
	if state == nil {
		if _, err := s.Store.ReconcileProtectionStates(
			r.Context(), time.Now().UTC(), s.protectionAlertGrace(),
		); err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "计算保护状态失败")
			return
		}
		state, err = s.Store.GetUserProtectionState(r.Context(), user.GlobalID)
		if err != nil || state == nil {
			protocol.WriteError(w, http.StatusInternalServerError, "保护状态尚未就绪")
			return
		}
	}
	response := publicProtectionState(state)
	fault, err := s.Store.GetUserDataFaultByUserUUID(r.Context(), user.UUID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取用户数据冻结状态失败")
		return
	}
	applyUserDataFaultGate(&response, fault)
	protocol.WriteJSON(w, http.StatusOK, response)
}

func applyUserDataFaultGate(response *userProtectionResponse, fault *store.UserDataFaultStatus) {
	if response == nil || fault == nil || fault.State == "resolved" {
		return
	}
	response.DataFaultState = fault.State
	response.DataFaultReasonCode = fault.ReasonCode
	if fault.State == "recovery_available" {
		return
	}
	response.TakeoverAvailable = false
	response.StorageRestoreNeeded = false
	if fault.State == "reported" || fault.State == "freezing" || fault.State == "retry_wait" {
		response.State = "data_fault_freezing"
		response.Label = "权威数据故障已关写"
		response.Risk = "系统正在排空并确认节点冻结；完成前不会开放任何接管或恢复写入。"
	}
}

func publicProtectionState(state *store.UserProtectionState) userProtectionResponse {
	response := userProtectionResponse{
		State: state.State, Version: state.Version,
		CurrentNodeID:        state.AuthoritativeNodeID.Int64,
		CurrentNodeName:      state.AuthoritativeNodeName.String,
		RecoveryNodeID:       state.RecoveryNodeID.Int64,
		RecoveryNodeName:     state.RecoveryNodeName.String,
		ActiveWriterNodeID:   state.ActiveWriterNodeID.Int64,
		ActiveWriterNodeName: state.ActiveWriterNodeName.String,
		TakeoverAvailable:    state.State == "takeover_available",
		StorageRestoreNeeded: state.State == "restore_required",
	}
	if state.LatestRecoveryAt.Valid {
		observed := state.LatestRecoveryAt.Time
		response.LatestRecoveryAt = &observed
	}
	switch state.State {
	case "protected":
		response.Label = "已保护"
		response.Risk = "已有可验证的纯存储恢复副本。"
	case "temporary":
		response.Label = "临时保护"
		response.Risk = "当前只有计算节点热备；纯存储保护恢复前不会自动清理该副本。"
	case "unprotected":
		response.Label = "未保护"
		response.Risk = "当前没有合格恢复副本；不会为此中断正在使用的家节点。"
	case "takeover_available":
		response.Label = "可接管"
		response.Risk = "家节点当前不可用；确认后将从最近热备接管，副本时间之后的数据可能丢失。"
	case "restore_required":
		response.Label = "需要恢复"
		response.Risk = "只有纯存储副本可用，请选择合格计算节点执行恢复。"
	case "conflict":
		response.Label = "冲突已冻结"
		response.Risk = "检测到副本冲突，系统不会自动覆盖任何一份数据。"
	default:
		response.Label = "暂不可恢复"
		response.Risk = "家节点不可用，且当前没有合格恢复副本。"
	}
	return response
}

func (s *Server) handleConfirmReplicaTakeover(w http.ResponseWriter, r *http.Request) {
	var req confirmTakeoverRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !isUUID(req.OperationID) ||
		req.TargetNodeID <= 0 || !req.AcknowledgeDataLoss {
		protocol.WriteError(w, http.StatusBadRequest, "必须确认可能丢失最近未同步的数据")
		return
	}
	expectedRecoveryAt, err := time.Parse(time.RFC3339Nano, req.ExpectedRecoveryAt)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "恢复时间已失效，请刷新后重新确认")
		return
	}
	legacyUserID, _ := CurrentUser(r)
	user, err := s.Store.GetUserByID(r.Context(), legacyUserID)
	if err != nil || user == nil || user.GlobalID <= 0 || user.Status != "active" {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在或不可用")
		return
	}
	digest, err := s.replicaTakeoverDigest(
		user.GlobalID, req.TargetNodeID, expectedRecoveryAt, req.AcknowledgeDataLoss,
	)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成接管请求失败")
		return
	}
	result, err := s.Store.ConfirmReplicaTakeover(r.Context(), store.ConfirmReplicaTakeoverParams{
		OperationID: req.OperationID, RequestDigest: digest,
		GlobalUserID: user.GlobalID, TargetNodeID: req.TargetNodeID,
		ExpectedRecoveryAt: expectedRecoveryAt, Now: time.Now().UTC(),
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrUserDataFaultState):
			protocol.WriteError(w, http.StatusConflict, "节点冻结尚未确认，暂不能执行接管")
		case errors.Is(err, store.ErrReplicaTakeoverLeaseActive):
			protocol.WriteError(w, http.StatusConflict, "旧节点写入租约仍在有效期内，请稍后重试")
		case errors.Is(err, store.ErrReplicaTakeoverUnavailable):
			protocol.WriteError(w, http.StatusConflict, "热备副本不完整、不可用或已不再是接管目标")
		case errors.Is(err, store.ErrReplicaTakeoverConflict):
			protocol.WriteError(w, http.StatusConflict, "该操作与已有接管记录不一致")
		case errors.Is(err, store.ErrNoActiveController):
			protocol.WriteError(w, http.StatusServiceUnavailable, "总控当前为只读状态")
		default:
			protocol.WriteError(w, http.StatusInternalServerError, "接管失败")
		}
		return
	}
	_, _ = s.Store.ReconcileProtectionStates(r.Context(), time.Now().UTC(), s.protectionAlertGrace())
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "target_node_id": result.TargetNodeID,
		"latest_recovery_at": result.SnapshotPublishedAt, "replayed": result.Replayed,
	})
}

func (s *Server) replicaTakeoverDigest(
	globalUserID, targetNodeID int64,
	recoveryAt time.Time,
	acknowledged bool,
) ([]byte, error) {
	encoded, err := json.Marshal(struct {
		UserID       int64  `json:"user_id"`
		TargetNodeID int64  `json:"target_node_id"`
		RecoveryAt   string `json:"recovery_at"`
		Acknowledged bool   `json:"acknowledged"`
	}{globalUserID, targetNodeID, recoveryAt.UTC().Format(time.RFC3339Nano), acknowledged})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-replica-takeover:v1\n"))
	_, _ = mac.Write(encoded)
	return mac.Sum(nil), nil
}

func (s *Server) handleAdminProtectionAlerts(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	alerts, err := s.Store.ListVisibleProtectionAlerts(r.Context(), limit, time.Now().UTC())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "读取保护告警失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

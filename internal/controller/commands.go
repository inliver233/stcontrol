package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	agentCommandLeaseTTL = 45 * time.Second
	agentCommandRunTTL   = 60 * time.Minute
	agentCommandTTL      = 10 * time.Minute
)

type encryptedCommandEnvelope struct {
	Version    int    `json:"version"`
	Ciphertext string `json:"ciphertext"`
}

type agentCommandSummary struct {
	OK               bool                              `json:"ok"`
	Code             string                            `json:"code,omitempty"`
	LocalUserID      string                            `json:"local_user_id,omitempty"`
	Users            []protocol.ScanExistingUser       `json:"users,omitempty"`
	Snapshot         *protocol.SnapshotTransferReceipt `json:"snapshot,omitempty"`
	ConflictEvidence *protocol.ConflictEvidenceReceipt `json:"conflict_evidence,omitempty"`
	Ciphertext       string                            `json:"ciphertext,omitempty"`
}

func (s *Server) handleAgentLeaseCommand(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "未知节点")
		return
	}
	var req protocol.LeaseCommandRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || len(req.WorkerID) < 16 || len(req.WorkerID) > 128 {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	generation, err := s.Store.GetActiveControllerGeneration(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "总控当前为只读状态")
		return
	}
	w.Header().Set("X-Controller-Generation", strconv.FormatInt(generation, 10))
	if req.HighestGeneration > generation {
		protocol.WriteError(w, http.StatusConflict, "总控世代低于节点已确认世代")
		return
	}

	deadline := time.NewTimer(20 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		command, err := s.Store.LeaseAgentCommand(
			r.Context(), node.ID, req.WorkerID, time.Now().UTC(), agentCommandLeaseTTL,
		)
		if err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "命令队列暂不可用")
			return
		}
		if command != nil {
			protocol.WriteJSON(w, http.StatusOK, protocol.AgentCommand{
				ID: command.ID, OperationID: command.OperationID,
				CommandType: command.CommandType, EncryptedPayload: command.EncryptedPayload,
				PayloadSHA256: hex.EncodeToString(command.PayloadSHA256), Attempt: command.Attempt,
				ControllerGeneration: command.ControllerGeneration,
				LeaseUntil:           command.LeaseUntil, ExpiresAt: command.ExpiresAt,
			})
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) handleAgentAckCommand(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	if node == nil || !isUUID(chi.URLParam(r, "id")) {
		protocol.WriteError(w, http.StatusBadRequest, "命令 ID 无效")
		return
	}
	var req protocol.AckCommandRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ok, err := s.Store.AckAgentCommand(
		r.Context(), chi.URLParam(r, "id"), node.ID, req.WorkerID,
		req.ControllerGeneration, time.Now().UTC(), agentCommandRunTTL,
	)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "命令确认失败")
		return
	}
	if !ok {
		protocol.WriteError(w, http.StatusConflict, "命令租约已失效")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAgentFinishCommand(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	if node == nil || !isUUID(chi.URLParam(r, "id")) {
		protocol.WriteError(w, http.StatusBadRequest, "命令 ID 无效")
		return
	}
	var req protocol.FinishCommandRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !json.Valid(req.Result) {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	digest := sha256.Sum256(req.Result)
	ok, err := s.Store.FinishAgentCommand(r.Context(), store.FinishAgentCommandParams{
		ID: chi.URLParam(r, "id"), NodeID: node.ID, WorkerID: req.WorkerID,
		ControllerGeneration: req.ControllerGeneration, Succeeded: req.Succeeded,
		ResultSummary: req.Result, ResultDigest: digest[:], Now: time.Now().UTC(),
	})
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "命令结果保存失败")
		return
	}
	if !ok {
		protocol.WriteError(w, http.StatusConflict, "命令租约已失效")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSnapshotProgress(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "未知节点")
		return
	}
	var req protocol.SnapshotProgressRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !isUUID(req.WorkflowID) || !isUUID(req.SnapshotID) {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.Store.SetSnapshotWorkflowProgress(
		r.Context(), req.WorkflowID, req.SnapshotID, node.ID, req.State, time.Now().UTC(),
	); err != nil {
		protocol.WriteError(w, http.StatusConflict, "快照阶段冲突")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) enqueueAgentCommand(
	ctx context.Context,
	node *store.Node,
	commandType string,
	payload any,
	operationID string,
) (int64, error) {
	if node == nil || commandType == "" || !isUUID(operationID) {
		return 0, store.ErrInvalidAgentCommand
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	psk, err := s.agentPSK(ctx, node)
	if err != nil || psk == "" {
		return 0, errors.New("agent credential unavailable")
	}
	ciphertext, err := controlcrypto.Encrypt(controlcrypto.DeriveAgentCommandKey(psk), plaintext)
	if err != nil {
		return 0, err
	}
	envelope, err := json.Marshal(encryptedCommandEnvelope{Version: 2, Ciphertext: ciphertext})
	if err != nil {
		return 0, err
	}
	payloadAuthenticator := hmac.New(sha256.New, controlcrypto.DeriveAgentCommandAuthKey(psk))
	_, _ = payloadAuthenticator.Write(plaintext)
	payloadDigest := payloadAuthenticator.Sum(nil)
	commandID, err := newUUID()
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	return s.Store.EnqueueAgentCommand(ctx, store.EnqueueAgentCommandParams{
		ID: commandID, OperationID: operationID, NodeID: node.ID,
		CommandType: commandType, EncryptedPayload: envelope, PayloadSHA256: payloadDigest,
		ExpiresAt: now.Add(agentCommandTTL), Now: now,
	})
}

func (s *Server) waitAgentCommand(ctx context.Context, operationID string, timeout time.Duration) (*store.AgentCommandResult, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, err := s.Store.GetAgentCommandResult(waitCtx, operationID)
		if err != nil {
			return nil, err
		}
		if result != nil && (result.State == "succeeded" || result.State == "failed" || result.State == "cancelled" || result.State == "expired") {
			return result, nil
		}
		select {
		case <-waitCtx.Done():
			return nil, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Server) runAgentCommand(
	ctx context.Context,
	node *store.Node,
	commandType string,
	payload any,
	timeout time.Duration,
) (agentCommandSummary, error) {
	operationID, err := newUUID()
	if err != nil {
		return agentCommandSummary{}, err
	}
	return s.runAgentCommandWithOperation(ctx, node, commandType, payload, operationID, timeout)
}

func (s *Server) runAgentCommandWithOperation(
	ctx context.Context,
	node *store.Node,
	commandType string,
	payload any,
	operationID string,
	timeout time.Duration,
) (agentCommandSummary, error) {
	if _, err := s.enqueueAgentCommand(ctx, node, commandType, payload, operationID); err != nil {
		return agentCommandSummary{}, err
	}
	result, err := s.waitAgentCommand(ctx, operationID, timeout)
	if err != nil {
		return agentCommandSummary{}, err
	}
	var summary agentCommandSummary
	if result == nil || result.State != "succeeded" || json.Unmarshal(result.ResultSummary, &summary) != nil || !summary.OK {
		return agentCommandSummary{}, errors.New("agent command failed")
	}
	return summary, nil
}

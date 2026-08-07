package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

type encryptedCommandEnvelope struct {
	Version    int    `json:"version"`
	Ciphertext string `json:"ciphertext"`
}

type safeCommandResult struct {
	OK          bool                        `json:"ok"`
	Code        string                      `json:"code,omitempty"`
	LocalUserID string                      `json:"local_user_id,omitempty"`
	Users       []protocol.ScanExistingUser `json:"users,omitempty"`
}

// StartCommandLoop maintains the Agent-initiated control channel. It never
// opens an inbound controller callback path.
func (a *Agent) StartCommandLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := a.pollAndRunCommand(ctx); err != nil {
			log.Printf("命令通道暂不可用: %v", err)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (a *Agent) pollAndRunCommand(ctx context.Context) error {
	workerID, highestGeneration := a.commandIdentity()
	status, headers, data, err := a.doControllerRequest(ctx, http.MethodPost, "/api/agent/commands/lease", protocol.LeaseCommandRequest{
		WorkerID: workerID, HighestGeneration: highestGeneration,
	})
	if err != nil {
		return err
	}
	if rawGeneration := headers.Get("X-Controller-Generation"); rawGeneration != "" {
		generation, parseErr := strconv.ParseInt(rawGeneration, 10, 64)
		if parseErr != nil || !a.acceptGeneration(generation) {
			return fmt.Errorf("controller generation rollback rejected")
		}
	}
	if status == http.StatusNoContent {
		return nil
	}
	if status != http.StatusOK {
		return fmt.Errorf("command lease returned status %d", status)
	}
	var command protocol.AgentCommand
	if err := json.Unmarshal(data, &command); err != nil {
		return fmt.Errorf("decode command: %w", err)
	}
	if !a.acceptGeneration(command.ControllerGeneration) {
		return fmt.Errorf("stale command generation rejected")
	}

	if err := a.callController(ctx, http.MethodPost, "/api/agent/commands/"+command.ID+"/ack", protocol.AckCommandRequest{
		WorkerID: workerID, ControllerGeneration: command.ControllerGeneration,
	}, nil); err != nil {
		return err
	}

	result, ok := a.cachedResult(command.ID)
	if !ok {
		succeeded, summary := a.executeCommand(ctx, command)
		result = cachedCommandResult{
			Succeeded: succeeded, Result: summary,
			ControllerGeneration: command.ControllerGeneration, CompletedAt: time.Now().UTC(),
		}
		a.rememberResult(command.ID, result)
	}
	return a.callController(ctx, http.MethodPost, "/api/agent/commands/"+command.ID+"/result", protocol.FinishCommandRequest{
		WorkerID: workerID, ControllerGeneration: result.ControllerGeneration,
		Succeeded: result.Succeeded, Result: result.Result,
	}, nil)
}

func (a *Agent) executeCommand(ctx context.Context, command protocol.AgentCommand) (bool, json.RawMessage) {
	plaintext, err := a.decryptCommand(command)
	if err != nil {
		return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
	}
	switch command.CommandType {
	case "scan_existing":
		var payload struct{}
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		users, err := a.ScanExistingUsers()
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "scan_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, Users: users})
	case "abort_backup":
		var payload struct {
			JobID int64 `json:"job_id"`
		}
		if err := json.Unmarshal(plaintext, &payload); err != nil || payload.JobID <= 0 {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		a.AbortBackup(payload.JobID)
		return true, marshalSafeResult(safeCommandResult{OK: true})
	case "provision_user":
		var payload protocol.ProvisionUserRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || !validProvisionRequest(payload) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		provisioned, err := a.provisionUser(ctx, &payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "provision_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, LocalUserID: provisioned.LocalUserID})
	case "set_password":
		var payload protocol.SetPasswordRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || payload.Handle == "" ||
			payload.PasswordHash == "" || payload.PasswordSalt == "" || payload.Version <= 0 {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		if err := a.setPassword(ctx, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "password_update_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true})
	default:
		return false, marshalSafeResult(safeCommandResult{OK: false, Code: "unsupported_command"})
	}
}

func validProvisionRequest(req protocol.ProvisionUserRequest) bool {
	if req.Handle == "" || req.Name == "" {
		return false
	}
	passwordMode := req.PasswordHash != "" && req.PasswordSalt != "" && req.OAuthProvider == "" && req.OAuthSubject == ""
	oauthMode := req.PasswordHash == "" && req.PasswordSalt == "" &&
		(req.OAuthProvider == "discord" || req.OAuthProvider == "linuxdo") && req.OAuthSubject != ""
	return passwordMode || oauthMode
}

func (a *Agent) decryptCommand(command protocol.AgentCommand) ([]byte, error) {
	var envelope encryptedCommandEnvelope
	if err := json.Unmarshal(command.EncryptedPayload, &envelope); err != nil || envelope.Version != 1 || envelope.Ciphertext == "" {
		return nil, fmt.Errorf("invalid envelope")
	}
	plaintext, err := controlcrypto.Decrypt(controlcrypto.DeriveAgentCommandKey(a.Cfg.AgentPSK), envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	want, err := hex.DecodeString(command.PayloadSHA256)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("invalid payload digest")
	}
	got := sha256.Sum256(plaintext)
	if !hmac.Equal(got[:], want) {
		return nil, fmt.Errorf("payload digest mismatch")
	}
	return plaintext, nil
}

func marshalSafeResult(result safeCommandResult) json.RawMessage {
	data, err := json.Marshal(result)
	if err != nil {
		return json.RawMessage(`{"ok":false,"code":"result_encoding_failed"}`)
	}
	return data
}

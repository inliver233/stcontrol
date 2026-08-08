package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const maxLocalAuditBytes = 10 << 20

type localAuditEvent struct {
	At                   time.Time `json:"at"`
	Event                string    `json:"event"`
	CommandID            string    `json:"command_id,omitempty"`
	OperationID          string    `json:"operation_id,omitempty"`
	CommandType          string    `json:"command_type,omitempty"`
	ControllerGeneration int64     `json:"controller_generation,omitempty"`
	Succeeded            *bool     `json:"succeeded,omitempty"`
	Cached               bool      `json:"cached,omitempty"`
}

func (a *Agent) appendLocalAudit(event localAuditEvent) error {
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	root := a.Cfg.DataDir
	if root == "" {
		return fmt.Errorf("agent data directory is required for local audit")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	path := filepath.Join(root, "audit.jsonl")
	if info, err := os.Stat(path); err == nil && info.Size() >= maxLocalAuditBytes {
		previous := path + ".1"
		_ = os.Remove(previous)
		if err := os.Rename(path, previous); err != nil {
			return fmt.Errorf("rotate local audit: %w", err)
		}
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	return file.Sync()
}

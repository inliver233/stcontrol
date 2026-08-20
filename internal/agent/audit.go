package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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

// LocalAuditQuery selects safe Agent-local audit metadata. Query values are
// exact matches; the result contains at most Limit most-recent matching events
// in chronological order. The audit schema deliberately has no user handle,
// request payload, credential, token or filesystem path fields.
type LocalAuditQuery struct {
	Event       string
	CommandID   string
	OperationID string
	Since       time.Time
	Limit       int
}

// LocalAuditEvent is the public, read-only form returned by QueryLocalAudit.
type LocalAuditEvent struct {
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

// QueryLocalAudit reads the one retained rotated file followed by the current
// file. It fails closed on malformed JSON/symlinks rather than silently
// omitting evidence during incident review.
func QueryLocalAudit(dataDir string, query LocalAuditQuery) ([]LocalAuditEvent, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("agent data directory is required for local audit query")
	}
	if query.Limit <= 0 {
		query.Limit = 100
	}
	if query.Limit > 1000 {
		return nil, fmt.Errorf("local audit query limit must not exceed 1000")
	}
	path := filepath.Join(dataDir, "audit.jsonl")
	paths := []string{path + ".1", path}
	result := make([]LocalAuditEvent, 0, query.Limit)
	foundFile := false
	for _, candidate := range paths {
		info, err := os.Lstat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect local audit: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("local audit is not a regular file")
		}
		if info.Size() > maxLocalAuditBytes+(64<<10) {
			return nil, fmt.Errorf("local audit exceeds the bounded query size")
		}
		foundFile = true
		file, err := os.Open(candidate)
		if err != nil {
			return nil, fmt.Errorf("open local audit: %w", err)
		}
		scanner := bufio.NewScanner(io.LimitReader(file, maxLocalAuditBytes+(64<<10)))
		scanner.Buffer(make([]byte, 4096), 64<<10)
		line := 0
		for scanner.Scan() {
			line++
			var event LocalAuditEvent
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil || event.At.IsZero() || event.Event == "" {
				_ = file.Close()
				return nil, fmt.Errorf("decode local audit line %d", line)
			}
			if !matchesLocalAuditQuery(event, query) {
				continue
			}
			if len(result) == query.Limit {
				copy(result, result[1:])
				result[len(result)-1] = event
			} else {
				result = append(result, event)
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read local audit: %w", scanErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close local audit: %w", closeErr)
		}
	}
	if !foundFile {
		return []LocalAuditEvent{}, nil
	}
	return result, nil
}

func matchesLocalAuditQuery(event LocalAuditEvent, query LocalAuditQuery) bool {
	return (query.Event == "" || event.Event == query.Event) &&
		(query.CommandID == "" || event.CommandID == query.CommandID) &&
		(query.OperationID == "" || event.OperationID == query.OperationID) &&
		(query.Since.IsZero() || !event.At.Before(query.Since))
}

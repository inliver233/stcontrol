package agent

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type cachedCommandResult struct {
	Succeeded            bool            `json:"succeeded"`
	Result               json.RawMessage `json:"result"`
	ControllerGeneration int64           `json:"controller_generation"`
	CompletedAt          time.Time       `json:"completed_at"`
}

type agentRuntimeState struct {
	WorkerID          string                         `json:"worker_id"`
	HighestGeneration int64                          `json:"highest_generation"`
	Completed         map[string]cachedCommandResult `json:"completed"`
}

func (a *Agent) runtimeStatePath() string {
	directory := a.Cfg.DataDir
	if directory == "" {
		directory = "./agent-data"
	}
	return filepath.Join(directory, "runtime-state.json")
}

func (a *Agent) loadRuntimeState() error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	path := a.runtimeStatePath()
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &a.state); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if a.state.Completed == nil {
		a.state.Completed = make(map[string]cachedCommandResult)
	}
	if a.state.WorkerID == "" {
		workerID, err := newWorkerID()
		if err != nil {
			return err
		}
		a.state.WorkerID = workerID
	}
	if a.Cfg.ControllerGeneration > a.state.HighestGeneration {
		a.state.HighestGeneration = a.Cfg.ControllerGeneration
	}
	return a.saveRuntimeStateLocked()
}

func (a *Agent) saveRuntimeStateLocked() error {
	path := a.runtimeStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".runtime-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func newWorkerID() (string, error) {
	data := make([]byte, 24)
	if _, err := cryptorand.Read(data); err != nil {
		return "", fmt.Errorf("generate worker identity: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (a *Agent) commandIdentity() (string, int64) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.state.WorkerID, a.state.HighestGeneration
}

func (a *Agent) acceptGeneration(generation int64) bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if generation < a.state.HighestGeneration {
		return false
	}
	if generation > a.state.HighestGeneration {
		a.state.HighestGeneration = generation
		_ = a.saveRuntimeStateLocked()
	}
	return true
}

func (a *Agent) cachedResult(commandID string) (cachedCommandResult, bool) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	result, ok := a.state.Completed[commandID]
	return result, ok
}

func (a *Agent) rememberResult(commandID string, result cachedCommandResult) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.state.Completed[commandID] = result
	if len(a.state.Completed) > 1000 {
		type entry struct {
			id string
			at time.Time
		}
		entries := make([]entry, 0, len(a.state.Completed))
		for id, cached := range a.state.Completed {
			entries = append(entries, entry{id: id, at: cached.CompletedAt})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
		for _, old := range entries[:len(entries)-1000] {
			delete(a.state.Completed, old.id)
		}
	}
	_ = a.saveRuntimeStateLocked()
}

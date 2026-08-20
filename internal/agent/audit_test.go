package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
)

func TestLocalAuditPersistsOnlySafeCommandMetadata(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	agent := &Agent{Cfg: &config.AgentConfig{DataDir: root}}
	succeeded := true
	if err := agent.appendLocalAudit(localAuditEvent{
		Event: "command_completed", CommandID: "command-1", OperationID: "operation-1",
		CommandType: "verify_node_admin", ControllerGeneration: 3, Succeeded: &succeeded,
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{"command_completed", "command-1", "verify_node_admin"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("audit=%s", text)
		}
	}
	for _, forbidden := range []string{"password", "ciphertext", "agent_psk", "payload"} {
		if strings.Contains(text, `"`+forbidden+`"`) {
			t.Fatalf("audit leaked forbidden field %q: %s", forbidden, text)
		}
	}
}

func TestQueryLocalAuditFiltersRotatedAndCurrentFilesWithBoundedNewestResults(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	base := time.Date(2026, 8, 16, 2, 0, 0, 0, time.UTC)
	writeEvents := func(name string, events ...LocalAuditEvent) {
		file, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		encoder := json.NewEncoder(file)
		for _, event := range events {
			if err := encoder.Encode(event); err != nil {
				t.Fatal(err)
			}
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	writeEvents("audit.jsonl.1",
		LocalAuditEvent{At: base, Event: "command_completed", CommandID: "old", OperationID: "op-1", CommandType: "health_probe"},
		LocalAuditEvent{At: base.Add(time.Minute), Event: "takeover", OperationID: "op-2"},
	)
	writeEvents("audit.jsonl",
		LocalAuditEvent{At: base.Add(2 * time.Minute), Event: "command_completed", CommandID: "new-1", OperationID: "op-1", CommandType: "set_password"},
		LocalAuditEvent{At: base.Add(3 * time.Minute), Event: "command_completed", CommandID: "new-2", OperationID: "op-1", CommandType: "set_oauth_identity"},
	)
	events, err := QueryLocalAudit(root, LocalAuditQuery{
		Event: "command_completed", OperationID: "op-1", Since: base.Add(time.Minute), Limit: 1,
	})
	if err != nil || len(events) != 1 || events[0].CommandID != "new-2" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if events[0].CommandType != "set_oauth_identity" {
		t.Fatalf("event=%+v", events[0])
	}
}

func TestQueryLocalAuditReturnsEmptyArrayWhenAuditDoesNotExist(t *testing.T) {
	t.Parallel()
	events, err := QueryLocalAudit(t.TempDir(), LocalAuditQuery{})
	if err != nil || events == nil || len(events) != 0 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestQueryLocalAuditFailsClosedOnMalformedOrSymlinkedEvidence(t *testing.T) {
	t.Parallel()
	t.Run("malformed", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "audit.jsonl"), []byte("not-json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := QueryLocalAudit(root, LocalAuditQuery{}); err == nil {
			t.Fatal("malformed audit evidence was silently accepted")
		}
	})
	t.Run("excessive limit", func(t *testing.T) {
		if _, err := QueryLocalAudit(t.TempDir(), LocalAuditQuery{Limit: 1001}); err == nil {
			t.Fatal("unbounded audit query was accepted")
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("symlink", func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte(`{"at":"2026-08-16T02:00:00Z","event":"x"}`+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(root, "audit.jsonl")); err != nil {
				t.Fatal(err)
			}
			if _, err := QueryLocalAudit(root, LocalAuditQuery{}); err == nil {
				t.Fatal("symlinked audit evidence was accepted")
			}
		})
	}
}

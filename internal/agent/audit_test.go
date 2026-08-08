package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

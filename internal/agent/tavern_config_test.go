package agent

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
	"stcontrol/internal/config"
)

func TestConfigureTavernAdapterPreservesUnrelatedConfiguration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	original := []byte("port: 8000\nfederated:\n  enabled: true\n  other: keep\nfeature:\n  nested: value\n")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.AgentConfig{
		Role: "compute", TavernDir: root, ControllerURL: "https://controller.example",
		Listen: "127.0.0.1:9100", NodeID: 7, AgentPSK: "node-secret", ControllerGeneration: 4,
	}
	if err := ConfigureTavernAdapter(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	adapter := decoded["stcontrol"].(map[string]any)
	legacy := decoded["federated"].(map[string]any)
	feature := decoded["feature"].(map[string]any)
	if adapter["enabled"] != true || adapter["nodeId"] != 7 || adapter["agentPsk"] != "node-secret" ||
		adapter["agentUrl"] != "http://127.0.0.1:9100" || adapter["controllerGeneration"] != 4 ||
		legacy["enabled"] != false || legacy["other"] != "keep" ||
		feature["nested"] != "value" {
		t.Fatalf("decoded=%+v", decoded)
	}
	backup, err := os.ReadFile(filepath.Join(root, "config.yaml.pre-stcontrol"))
	if err != nil || string(backup) != string(original) {
		t.Fatalf("backup=%q err=%v", backup, err)
	}
}

func TestConfigureTavernAdapterRejectsSymlinkedConfiguration(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("symlink privilege is not guaranteed")
	}
	root := t.TempDir()
	target := filepath.Join(root, "real.yaml")
	if err := os.WriteFile(target, []byte("port: 8000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "config.yaml")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	err := ConfigureTavernAdapter(&config.AgentConfig{
		Role: "compute", TavernDir: root, ControllerURL: "https://controller.example",
		Listen: "127.0.0.1:9100", NodeID: 7, AgentPSK: "node-secret", ControllerGeneration: 4,
	})
	if err == nil {
		t.Fatal("symlinked config was accepted")
	}
}

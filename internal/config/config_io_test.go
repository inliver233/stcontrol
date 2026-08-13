package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadWritesTemplateWhenFileMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.yaml")
	cfg := DefaultController()
	if err := Load(path, cfg); err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("template not written: %v", err)
	}
	if !strings.Contains(string(data), "controller_backup:") {
		t.Fatalf("template missing controller_backup section: %s", data)
	}
	if !strings.Contains(string(data), "import_scan:") {
		t.Fatalf("template missing import_scan section: %s", data)
	}
}

func TestLoadRoundTripPreservesBackupAndImportScanPolicies(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.yaml")
	cfg := DefaultController()
	cfg.ControllerBackup = ControllerDisasterBackupPolicy{
		Enabled: true, IntervalSec: 3600, RetryMax: 5, KeepLatestOnly: false, PgDump: false,
		RecoveryPassphraseEnv: "CONTROLLER_RECOVERY_PASSPHRASE",
	}
	cfg.ImportScan = ImportScanPolicy{Enabled: true, IntervalSec: 300, MaxNodesPerRun: 4}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var loaded ControllerConfig
	if err := Load(path, &loaded); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := loaded.ControllerBackup
	if !got.Enabled || got.IntervalSec != 3600 || got.RetryMax != 5 || got.KeepLatestOnly ||
		got.PgDump || got.RecoveryPassphraseEnv != "CONTROLLER_RECOVERY_PASSPHRASE" {
		t.Fatalf("backup policy round-trip mismatch: %+v", got)
	}
	if !loaded.ImportScan.Enabled || loaded.ImportScan.IntervalSec != 300 || loaded.ImportScan.MaxNodesPerRun != 4 {
		t.Fatalf("import scan round-trip mismatch: %+v", loaded.ImportScan)
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("listen: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg ControllerConfig
	if err := Load(path, &cfg); err == nil {
		t.Fatal("malformed YAML unexpectedly parsed")
	}
}

func TestLoadPropagatesReadError(t *testing.T) {
	t.Parallel()
	var cfg ControllerConfig
	// A directory path is not a missing file: ReadFile fails with a real
	// error (EISDIR) instead of the not-exist template path.
	dir := t.TempDir()
	if err := Load(dir, &cfg); err == nil {
		t.Fatal("unreadable path unexpectedly succeeded")
	}
}

func TestSaveAndLoadAgentConfigRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	agent := DefaultAgent()
	agent.ControllerURL = "https://ctl.example"
	agent.NodeID = 7
	agent.AgentPSK = "psk-material"
	agent.CredentialVersion = 2
	agent.ControllerGeneration = 11
	agent.DiskQuotaBytes = 1 << 40
	agent.Disaster.PeerWitnessURLs = []string{"https://w1.example", "https://w2.example"}
	if err := Save(path, agent); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var loaded AgentConfig
	if err := Load(path, &loaded); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ControllerURL != "https://ctl.example" || loaded.NodeID != 7 ||
		loaded.AgentPSK != "psk-material" || loaded.CredentialVersion != 2 ||
		loaded.ControllerGeneration != 11 || loaded.DiskQuotaBytes != 1<<40 {
		t.Fatalf("agent round-trip mismatch: %+v", loaded)
	}
	if len(loaded.Disaster.PeerWitnessURLs) != 2 ||
		loaded.Disaster.PeerWitnessURLs[0] != "https://w1.example" {
		t.Fatalf("peer witness round-trip mismatch: %+v", loaded.Disaster.PeerWitnessURLs)
	}
}

func TestDefaultControllerHasExplicitDisasterBackupAndImportScanPolicies(t *testing.T) {
	t.Parallel()
	cfg := DefaultController()
	if !cfg.ControllerBackup.Enabled || cfg.ControllerBackup.IntervalSec != 24*3600 ||
		cfg.ControllerBackup.RetryMax != 3 || !cfg.ControllerBackup.KeepLatestOnly ||
		!cfg.ControllerBackup.PgDump {
		t.Fatalf("disaster backup defaults=%+v", cfg.ControllerBackup)
	}
	if cfg.ImportScan.Enabled || cfg.ImportScan.IntervalSec != 6*3600 || cfg.ImportScan.MaxNodesPerRun != 2 {
		t.Fatalf("import scan defaults=%+v", cfg.ImportScan)
	}
}

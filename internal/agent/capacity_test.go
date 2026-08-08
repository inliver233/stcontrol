package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestCompatibilityReportRequiresCompleteAdapterContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		capabilities []string
		wantState    string
		wantReason   string
	}{
		{name: "complete", capabilities: requiredAdapterCapabilities, wantState: "compatible"},
		{name: "missing", capabilities: []string{"registration_policy"}, wantState: "incompatible", wantReason: "missing_capability"},
		{name: "duplicate", capabilities: append(append([]string(nil), requiredAdapterCapabilities...), requiredAdapterCapabilities[0]), wantState: "incompatible", wantReason: "invalid_health"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/stcontrol/internal/health" {
					t.Fatalf("path=%s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(adapterHealth{
					OK: true, ProtocolVersion: 1, TavernVersion: "v1", Capabilities: test.capabilities,
					IntegrationFingerprint: strings.Repeat("a", 64),
				})
			}))
			defer server.Close()
			agent := &Agent{
				Cfg:        &config.AgentConfig{Role: "compute", TavernURL: server.URL, NodeID: 12, AgentPSK: "psk"},
				httpClient: server.Client(),
			}
			report := agent.compatibilityReport(context.Background(), protocol.NodeInfo{
				OS: "linux", Arch: "amd64", TavernVersion: "v1",
			})
			if report.State != test.wantState || report.ErrorCode != test.wantReason || len(report.Fingerprint) != 64 {
				t.Fatalf("report=%+v", report)
			}
		})
	}
}

func TestCompatibilityReportRejectsMissingAdapterVersion(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(adapterHealth{
			OK: true, ProtocolVersion: 1, Capabilities: requiredAdapterCapabilities,
		})
	}))
	defer server.Close()
	agent := &Agent{
		Cfg:        &config.AgentConfig{Role: "compute", TavernURL: server.URL, NodeID: 12, AgentPSK: "psk"},
		httpClient: server.Client(),
	}
	report := agent.compatibilityReport(context.Background(), protocol.NodeInfo{TavernVersion: "v1"})
	if report.State != "incompatible" || report.ErrorCode != "version_unsupported" {
		t.Fatalf("report=%+v", report)
	}
}

func TestStorageCompatibilityUsesAgentContractWithoutTavernAdapter(t *testing.T) {
	t.Parallel()
	agent := &Agent{Cfg: &config.AgentConfig{Role: "storage"}}
	report := agent.compatibilityReport(context.Background(), protocol.NodeInfo{OS: "linux", Arch: "amd64"})
	if report.State != "compatible" || report.ErrorCode != "" || len(report.Fingerprint) != 64 {
		t.Fatalf("report=%+v", report)
	}
}

func TestManagedStorageCapacityCountsOnlyRegularFileBytes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "snapshot"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "snapshot", "data.bin"), []byte("1234567"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent := &Agent{Cfg: &config.AgentConfig{Role: "storage", BackupDir: root}}
	users, size, source, err := agent.managedCapacityFacts(context.Background())
	if err != nil || users != nil || size != 7 || source != "agent" {
		t.Fatalf("users=%+v size=%d source=%q err=%v", users, size, source, err)
	}
}

func TestCollectCapacityMetricsReturnsRealDiskBytes(t *testing.T) {
	metrics, err := CollectCapacityMetrics(t.TempDir())
	if err != nil || metrics.DiskTotalBytes <= 0 || metrics.DiskAvailableBytes < 0 ||
		metrics.DiskAvailableBytes > metrics.DiskTotalBytes || metrics.CPUPct < 0 || metrics.CPUPct > 100 {
		t.Fatalf("metrics=%+v err=%v", metrics, err)
	}
}

func TestNewStorageAgentRequiresAndCreatesPrivateBackupRoot(t *testing.T) {
	t.Parallel()
	if _, err := New(&config.AgentConfig{Role: "storage", DataDir: t.TempDir()}); err == nil {
		t.Fatal("storage agent without backup root was accepted")
	}
	root := t.TempDir()
	backupRoot := filepath.Join(root, "backups")
	if _, err := New(&config.AgentConfig{
		Role: "storage", DataDir: filepath.Join(root, "state"), BackupDir: backupRoot,
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(backupRoot)
	if err != nil || !info.IsDir() {
		t.Fatalf("backup root info=%+v err=%v", info, err)
	}
}

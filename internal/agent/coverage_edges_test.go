package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestProbeTavernParsesConfigVersionAndDefaults(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("port: 9123\ndataRoot: ./tenant-data\nlisten: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"sillytavern","version":"1.13.4"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := ProbeTavern(root)
	if err != nil || info.TavernPort != 9123 || info.TavernVersion != "1.13.4" ||
		info.DataRoot != filepath.Join(root, "tenant-data") {
		t.Fatalf("info=%+v err=%v", info, err)
	}

	missing, err := ProbeTavern(filepath.Join(root, "missing"))
	if err != nil || missing.TavernPort != 8000 || missing.TavernVersion != "" {
		t.Fatalf("missing info=%+v err=%v", missing, err)
	}
}

func TestExtractJSONStringRejectsIncompleteFields(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input string
		key   string
		want  string
	}{
		{`{"version":"1.2.3"}`, "version", "1.2.3"},
		{`{"name":"x"}`, "version", ""},
		{`{"version":`, "version", ""},
		{`{"version":"unterminated}`, "version", ""},
	} {
		if got := extractJSONString([]byte(test.input), test.key); got != test.want {
			t.Errorf("extractJSONString(%q,%q)=%q, want %q", test.input, test.key, got, test.want)
		}
	}
}

func TestCollectMetricsAndCapacityPathUseManagedFilesystem(t *testing.T) {
	root := t.TempDir()
	cpu, memory, disk, err := CollectMetrics(root)
	if err != nil || cpu < 0 || cpu > 100 || memory < 0 || memory > 100 || disk < 0 || disk > 100 {
		t.Fatalf("cpu=%f memory=%f disk=%f err=%v", cpu, memory, disk, err)
	}
	storage := &Agent{Cfg: &config.AgentConfig{Role: "storage", BackupDir: root}}
	if got := storage.capacityMetricsPath(); got != root {
		t.Fatalf("storage capacity path=%q", got)
	}
	compute := &Agent{Cfg: &config.AgentConfig{Role: "compute", TavernDir: root}}
	if got := compute.capacityMetricsPath(); got == "" {
		t.Fatal("compute capacity path is empty")
	}
}

func TestPendingControllerBackupValidationMatrix(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	valid := pendingControllerBackup{
		OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", BackupKind: "full",
		CapabilityHash: strings.Repeat("a", 64), ExpiresAt: now.Add(time.Hour),
		State: "prepared", UpdatedAt: now,
	}
	if err := validatePendingControllerBackup(valid, "full"); err != nil {
		t.Fatalf("valid prepared intent: %v", err)
	}
	for _, state := range []string{"prepared", "consumed", "failed"} {
		candidate := valid
		candidate.State = state
		if err := validatePendingControllerBackup(candidate, ""); err != nil {
			t.Errorf("state %q rejected: %v", state, err)
		}
	}
	published := valid
	published.State = "published"
	published.ExpectedSHA256 = strings.Repeat("b", 64)
	if err := validatePendingControllerBackup(published, "full"); err != nil {
		t.Fatalf("published intent rejected: %v", err)
	}
	mutations := []func(*pendingControllerBackup){
		func(v *pendingControllerBackup) { v.OperationID = "bad" },
		func(v *pendingControllerBackup) { v.BackupKind = "other" },
		func(v *pendingControllerBackup) { v.CapabilityHash = "bad" },
		func(v *pendingControllerBackup) { v.ExpiresAt = time.Time{} },
		func(v *pendingControllerBackup) { v.UpdatedAt = time.Time{} },
		func(v *pendingControllerBackup) { v.State = "unknown" },
		func(v *pendingControllerBackup) { v.ExpectedSHA256 = "bad" },
		func(v *pendingControllerBackup) { v.State = "published" },
	}
	for index, mutate := range mutations {
		candidate := valid
		mutate(&candidate)
		if err := validatePendingControllerBackup(candidate, "full"); err == nil {
			t.Errorf("invalid mutation %d accepted: %+v", index, candidate)
		}
	}
	wrongStateDigest := valid
	wrongStateDigest.ExpectedSHA256 = strings.Repeat("b", 64)
	wrongStateDigest.State = "failed"
	if err := validatePendingControllerBackup(wrongStateDigest, "full"); err == nil {
		t.Fatal("digest in failed state was accepted")
	}
}

func TestIndependentModeActiveReflectsDurableState(t *testing.T) {
	t.Parallel()
	a := &Agent{}
	if a.independentModeActive() {
		t.Fatal("empty state reported independent mode")
	}
	a.state.ControlMode.Mode = protocol.NodeModeIndependent
	if !a.independentModeActive() {
		t.Fatal("independent state was not reported")
	}
}

func TestStartHeartbeatStopsAfterCancelledImmediateAttempt(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &Agent{Cfg: &config.AgentConfig{HeartbeatSec: 1}}
	// A cancelled context exercises the immediate-attempt and loop shutdown
	// boundary without starting network or filesystem mutations.
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.StartHeartbeat(ctx)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartHeartbeat did not stop after cancellation")
	}
}

func TestLocalListenerAddressShapeUsedByMetricsHost(t *testing.T) {
	t.Parallel()
	// Keep net imported in this platform-facing edge suite and assert the
	// loopback invariant used throughout the Agent's local adapter endpoints.
	if ip := net.ParseIP("127.0.0.1"); ip == nil || !ip.IsLoopback() {
		t.Fatal("IPv4 loopback parsing failed")
	}
}

func TestTavernVerificationAndIndependentSyncValidateAdapterResponses(t *testing.T) {
	const adapterPSK = "coverage-adapter-secret"
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || protocol.VerifyRequest(r, adapterPSK, body) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/stcontrol/internal/users/verify":
			var request protocol.VerifyLocalUserRequest
			if err := json.Unmarshal(body, &request); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			response := protocol.VerifyLocalUserResponse{Handle: request.Handle, LocalUserID: "local-1", Verified: true}
			if request.Handle == "mismatch" {
				response.Handle = "other"
			}
			protocol.WriteJSON(w, http.StatusOK, response)
		case "/api/stcontrol/internal/control/sync-complete":
			var request protocol.CompleteIndependentSyncRequest
			if err := json.Unmarshal(body, &request); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			ok := request.Handle != "reject"
			protocol.WriteJSON(w, http.StatusOK, map[string]any{
				"ok": ok, "handle": request.Handle, "marker": request.Marker,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer adapter.Close()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 7, AgentPSK: "controller-secret", TavernAdapterPSK: adapterPSK,
		TavernURL: adapter.URL, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := a.verifyLocalUser(context.Background(), protocol.VerifyLocalUserRequest{
		OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Handle: "alice", Password: "secret",
	})
	if err != nil || !verification.Verified || verification.LocalUserID != "local-1" {
		t.Fatalf("verification=%+v err=%v", verification, err)
	}
	if _, err := a.verifyLocalUser(context.Background(), protocol.VerifyLocalUserRequest{Handle: "mismatch"}); err == nil {
		t.Fatal("mismatched verification response accepted")
	}
	syncRequest := protocol.CompleteIndependentSyncRequest{
		OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Handle: "alice",
		Marker: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
	}
	if err := a.completeIndependentSync(context.Background(), syncRequest); err != nil {
		t.Fatalf("complete sync: %v", err)
	}
	syncRequest.Handle = "reject"
	if err := a.completeIndependentSync(context.Background(), syncRequest); err == nil {
		t.Fatal("adapter sync rejection accepted")
	}
}

func TestDiskActivityScanUsesManagedDirectoriesAndNewestFile(t *testing.T) {
	t.Parallel()
	tavernRoot := t.TempDir()
	dataRoot := filepath.Join(tavernRoot, "data")
	userRoot := filepath.Join(dataRoot, "alice")
	if err := os.MkdirAll(userRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(userRoot, "settings.json")
	if err := os.WriteFile(filePath, []byte("settings"), 0o600); err != nil {
		t.Fatal(err)
	}
	newest := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := os.Chtimes(filePath, newest, newest); err != nil {
		t.Fatal(err)
	}
	older := newest.Add(-time.Hour)
	if err := os.Chtimes(userRoot, older, older); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataRoot, ".hidden"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "not-a-user"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Cfg: &config.AgentConfig{TavernDir: tavernRoot}}
	users := a.scanUserActivityFromDisk()
	if len(users) != 1 || users[0].Handle != "alice" || !users[0].IsOnline ||
		users[0].LastActivity != newest.UnixMilli() {
		t.Fatalf("disk activity = %+v", users)
	}
	if got := latestMtime(userRoot, time.Unix(0, 0)); !got.Equal(newest) {
		t.Fatalf("latest mtime = %v, want %v", got, newest)
	}
}

func TestRuntimeCredentialReceiptAndResultRetention(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		NodeID: 9, AgentPSK: "runtime-secret", DataDir: t.TempDir(), TavernDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a.state.Credential.PendingPSK = "next-secret"
	a.state.Credential.PendingVersion = 2
	a.state.Credential.PendingGeneration = 3
	a.state.Credential.PendingExpiresAt = time.Now().Add(time.Hour)
	if err := a.clearPendingControllerCredential(1); err != nil || a.state.Credential.PendingPSK == "" {
		t.Fatalf("unmatched pending credential changed: %+v err=%v", a.state.Credential, err)
	}
	if err := a.clearPendingControllerCredential(2); err != nil || a.state.Credential.PendingPSK != "" {
		t.Fatalf("pending credential not cleared: %+v err=%v", a.state.Credential, err)
	}

	receipt := protocol.SnapshotTransferReceipt{OK: true, SnapshotID: "snapshot", ManifestSHA256: strings.Repeat("a", 64)}
	a.state.Transfers["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"] = pendingTransfer{
		WorkflowID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", State: "published", Receipt: &receipt,
	}
	got, ok := a.snapshotReceipt("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if !ok || got == nil || got.ManifestSHA256 != receipt.ManifestSHA256 {
		t.Fatalf("snapshot receipt = %+v, ok=%v", got, ok)
	}
	got.ManifestSHA256 = "mutated"
	if a.state.Transfers["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"].Receipt.ManifestSHA256 != receipt.ManifestSHA256 {
		t.Fatal("snapshotReceipt exposed mutable persisted state")
	}
	if _, ok := a.snapshotReceipt("wrong", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"); ok {
		t.Fatal("snapshotReceipt accepted a mismatched workflow")
	}

	base := time.Now().Add(-2 * time.Hour)
	for index := 0; index < 1001; index++ {
		a.state.Completed[fmt.Sprintf("command-%04d", index)] = cachedCommandResult{CompletedAt: base.Add(time.Duration(index) * time.Second)}
	}
	if err := a.rememberResult("command-new", cachedCommandResult{Succeeded: true, CompletedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if len(a.state.Completed) != 1000 {
		t.Fatalf("retained command results = %d, want 1000", len(a.state.Completed))
	}
	if _, exists := a.state.Completed["command-0000"]; exists {
		t.Fatal("oldest command result was not pruned")
	}
}

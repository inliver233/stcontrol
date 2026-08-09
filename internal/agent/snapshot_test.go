package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

const (
	testWorkflowID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testSnapshotID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func TestTransferCapabilityIsScopedSingleUseAndCrashRecoverable(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	a, err := New(&config.AgentConfig{DataDir: dataDir, NodeID: 9})
	if err != nil {
		t.Fatal(err)
	}
	token := "one-use-transfer-token"
	digest := sha256.Sum256([]byte(token))
	transfer := pendingTransfer{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70, TargetNodeID: 9,
		Handle: "alice", DestinationKind: "archive", SourceNodeID: 8, ActivityEpoch: 4,
		CapabilityHash: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := a.prepareTransfer(transfer); err != nil {
		t.Fatal(err)
	}
	consumed, err := a.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now())
	if err != nil || consumed.SourceNodeID != 8 {
		t.Fatalf("transfer=%+v err=%v", consumed, err)
	}
	if _, err := a.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now()); err == nil {
		t.Fatal("transfer capability replay was accepted")
	}
	reloaded, err := New(&config.AgentConfig{DataDir: dataDir, NodeID: 9})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now()); err != nil {
		t.Fatalf("exact interrupted transfer was not re-armed after restart: %v", err)
	}
	if _, err := reloaded.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now()); err == nil {
		t.Fatal("recovered transfer capability was accepted twice")
	}
	newDigest := sha256.Sum256([]byte("new-token"))
	transfer.CapabilityHash = hex.EncodeToString(newDigest[:])
	if err := reloaded.prepareTransfer(transfer); err == nil {
		t.Fatal("consumed transfer was reopened with a replacement capability")
	}
}

func TestFailedTransferRequiresAReplacedCapability(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{DataDir: t.TempDir(), NodeID: 9})
	if err != nil {
		t.Fatal(err)
	}
	token := "failed-transfer-token"
	digest := sha256.Sum256([]byte(token))
	transfer := pendingTransfer{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70, TargetNodeID: 9,
		Handle: "alice", DestinationKind: "archive", SourceNodeID: 8, ActivityEpoch: 4,
		CapabilityHash: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := a.prepareTransfer(transfer); err != nil {
		t.Fatal(err)
	}
	if _, err := a.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.finishTransfer(testSnapshotID, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := a.prepareTransfer(transfer); err == nil {
		t.Fatal("consumed capability was re-enabled after a failed transfer")
	}
	replacement := sha256.Sum256([]byte("replacement-token"))
	transfer.CapabilityHash = hex.EncodeToString(replacement[:])
	if err := a.prepareTransfer(transfer); err != nil {
		t.Fatalf("replacement capability rejected: %v", err)
	}
}

func TestRestartRearmsInterruptedTransferAndRemovesPartialTargetTask(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	backupDir := filepath.Join(t.TempDir(), "backups")
	newTarget := func() *Agent {
		target, err := New(&config.AgentConfig{
			Role: "storage", NodeID: 9, DataDir: dataDir, BackupDir: backupDir,
		})
		if err != nil {
			t.Fatalf("New target: %v", err)
		}
		return target
	}
	token := "interrupted-transfer-token"
	digest := sha256.Sum256([]byte(token))
	transfer := pendingTransfer{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70, TargetNodeID: 9,
		Handle: "alice", DestinationKind: "archive", SourceNodeID: 8, ActivityEpoch: 4,
		CapabilityHash: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(time.Minute),
	}
	target := newTarget()
	if err := target.prepareTransfer(transfer); err != nil {
		t.Fatal(err)
	}
	if _, err := target.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now()); err != nil {
		t.Fatal(err)
	}
	taskRoot, _, err := target.targetSnapshotPaths(target.state.Transfers[testSnapshotID])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(taskRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(taskRoot, "incoming.tar.zst"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	restarted := newTarget()
	if _, err := os.Stat(taskRoot); !os.IsNotExist(err) {
		t.Fatalf("partial task survived target restart: %v", err)
	}
	if _, err := restarted.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now()); err != nil {
		t.Fatalf("exact interrupted capability was not recoverable: %v", err)
	}
}

func TestRestoreTransferAllowsControllerFencedCapabilityReplacement(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{DataDir: t.TempDir(), NodeID: 9, Role: "compute"})
	if err != nil {
		t.Fatal(err)
	}
	first := sha256.Sum256([]byte("first-restore-token"))
	transfer := pendingTransfer{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70, TargetNodeID: 9,
		Handle: "alice", DestinationKind: "restore", SourceNodeID: 8, ActivityEpoch: 4,
		CapabilityHash: hex.EncodeToString(first[:]), ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := a.prepareTransfer(transfer); err != nil {
		t.Fatal(err)
	}
	replacement := sha256.Sum256([]byte("replacement-restore-token"))
	transfer.CapabilityHash = hex.EncodeToString(replacement[:])
	if err := a.prepareTransfer(transfer); err != nil {
		t.Fatalf("prepared restore capability replacement rejected: %v", err)
	}
	if _, err := a.consumeTransfer(testSnapshotID, testWorkflowID, "replacement-restore-token", time.Now()); err != nil {
		t.Fatal(err)
	}
	third := sha256.Sum256([]byte("third-restore-token"))
	transfer.CapabilityHash = hex.EncodeToString(third[:])
	if err := a.prepareTransfer(transfer); err == nil {
		t.Fatal("unexpired consumed restore capability was replaced")
	}
	a.stateMu.Lock()
	existing := a.state.Transfers[testSnapshotID]
	existing.ExpiresAt = time.Now().Add(-time.Second)
	a.state.Transfers[testSnapshotID] = existing
	a.stateMu.Unlock()
	if err := a.prepareTransfer(transfer); err != nil {
		t.Fatalf("expired consumed restore capability was not recoverable: %v", err)
	}
}

func TestAgentHTTPClientRejectsRedirects(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{DataDir: t.TempDir(), NodeID: 9})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.httpClient.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy error=%v", err)
	}
}

func TestReportSnapshotProgressRetriesLostResponseWithFreshNonce(t *testing.T) {
	t.Parallel()
	const psk = "snapshot-progress-test-secret"
	var mu sync.Mutex
	var bodies [][]byte
	var nonces []string
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || protocol.VerifyRequest(r, psk, body) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), body...))
		nonces = append(nonces, r.Header.Get(protocol.HeaderNonce))
		call := len(bodies)
		mu.Unlock()
		if call == 1 {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server cannot simulate a lost response")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("hijack first progress response: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	defer controller.Close()
	a := &Agent{
		Cfg:        &config.AgentConfig{ControllerURL: controller.URL, NodeID: 8, AgentPSK: psk},
		httpClient: controller.Client(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.reportSnapshotProgress(ctx, testWorkflowID, testSnapshotID, "drained"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("progress calls=%d bodies_equal=%v", len(bodies), len(bodies) == 2 && bytes.Equal(bodies[0], bodies[1]))
	}
	if nonces[0] == "" || nonces[0] == nonces[1] {
		t.Fatalf("progress retries did not use fresh nonces: %q %q", nonces[0], nonces[1])
	}
}

func TestReportSnapshotProgressDoesNotRetryStateConflict(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	calls := 0
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Error(w, "state conflict", http.StatusConflict)
	}))
	defer controller.Close()
	a := &Agent{
		Cfg:        &config.AgentConfig{ControllerURL: controller.URL, NodeID: 8, AgentPSK: "secret"},
		httpClient: controller.Client(),
	}
	err := a.reportSnapshotProgress(context.Background(), testWorkflowID, testSnapshotID, "drained")
	if err == nil {
		t.Fatal("state conflict was accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("non-retryable progress calls=%d, want 1", calls)
	}
}

func TestReportSnapshotProgressBackoffHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	calls := 0
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		cancel()
	}))
	defer controller.Close()
	a := &Agent{
		Cfg:        &config.AgentConfig{ControllerURL: controller.URL, NodeID: 8, AgentPSK: "secret"},
		httpClient: controller.Client(),
	}
	err := a.reportSnapshotProgress(ctx, testWorkflowID, testSnapshotID, "drained")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("cancelled progress calls=%d, want 1", calls)
	}
}

func TestRelayPreparationReplacesDirectCapabilityAndKeepsStableTargetKey(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	a, err := New(&config.AgentConfig{DataDir: dataDir, NodeID: 9})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("relay-capability"))
	transfer := pendingTransfer{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70, TargetNodeID: 9,
		Handle: "alice", DestinationKind: "archive", SourceNodeID: 8, ActivityEpoch: 4,
		CapabilityHash: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := a.prepareTransfer(transfer); err != nil {
		t.Fatal(err)
	}
	taskID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	publicKey, err := a.prepareRelayTransfer(transfer, taskID)
	if err != nil || publicKey == "" {
		t.Fatalf("publicKey=%q err=%v", publicKey, err)
	}
	reloaded, err := New(&config.AgentConfig{DataDir: dataDir, NodeID: 9})
	if err != nil {
		t.Fatal(err)
	}
	replayedPublicKey, err := reloaded.prepareRelayTransfer(transfer, taskID)
	if err != nil || replayedPublicKey != publicKey {
		t.Fatalf("replayedPublicKey=%q err=%v", replayedPublicKey, err)
	}
	persisted, err := reloaded.relayTransfer(testSnapshotID, testWorkflowID, taskID)
	if err != nil || persisted.RelayPrivateKey == "" || persisted.RelayPublicKey != publicKey {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
}

func TestSnapshotRelayUploadStreamsAuthenticatedCiphertext(t *testing.T) {
	t.Parallel()
	taskID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	privateKey, publicKey, err := controlcrypto.GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	archiveData := bytes.Repeat([]byte("private-snapshot-data"), 1000)
	archivePath := filepath.Join(t.TempDir(), "snapshot.tar.zst")
	if err := os.WriteFile(archivePath, archiveData, 0o600); err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(archiveData)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/relay/v1/transfers/"+taskID ||
			r.Header.Get("Authorization") != "Bearer upload-token" {
			t.Errorf("unexpected relay request: %s %s headers=%v", r.Method, r.URL.Path, r.Header)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var plaintext bytes.Buffer
		if _, err := controlcrypto.DecryptRelayStream(
			r.Context(), &plaintext, r.Body, privateKey,
			controlcrypto.RelayCipherContext{TaskID: taskID, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID},
		); err != nil || !bytes.Equal(plaintext.Bytes(), archiveData) {
			t.Errorf("relay body failed authentication: bytes=%d err=%v", plaintext.Len(), err)
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	a := &Agent{}
	err = a.streamSnapshotRelay(context.Background(), protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, RelayTaskID: taskID,
		RelayUploadURL:   server.URL + "/relay/v1/transfers/" + taskID,
		RelayUploadToken: "upload-token", RelayTargetKey: publicKey,
	}, archivePath, archiveDigest)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDirectSnapshotConnectivityFailureIsClassifiedForRelayFallback(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	archivePath := filepath.Join(t.TempDir(), "snapshot.tar.zst")
	if err := os.WriteFile(archivePath, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("archive"))
	_, err := (&Agent{}).streamSnapshot(context.Background(), protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		TargetTransferURL: server.URL, TransferCapability: "capability",
	}, archivePath, digest)
	if err == nil || !errors.Is(err, errSnapshotDirectUnreachable) {
		t.Fatalf("error=%v", err)
	}
}

func TestUserSnapshotBoundaryExcludesNodeGlobalsAndCarriesPrivatePluginData(t *testing.T) {
	t.Parallel()
	tavernDir := t.TempDir()
	dataRoot := filepath.Join(tavernDir, "data")
	privateFiles := map[string][]byte{
		"chats/session.jsonl":                              []byte(`{"mes":"private chat"}`),
		"extensions/example-plugin/settings.json":          []byte(`{"enabled":true}`),
		"user/extensions/example-plugin/private-data.json": []byte(`{"state":"private"}`),
		"secrets.json": []byte(`{"api_key":"private"}`),
	}
	for relative, content := range privateFiles {
		path := filepath.Join(dataRoot, "alice", filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	nodeGlobalDirectories := []string{
		"_storage", "_uploads", "_cache", "_exports", "_webpack", "_global", "_stcontrol",
		"default-user", "default-template", "announcements", "forum_data", "public_characters", "system-monitor", "backups",
	}
	sourceGlobal := make(map[string][]byte, len(nodeGlobalDirectories))
	for _, name := range nodeGlobalDirectories {
		content := []byte("source-global:" + name)
		path := filepath.Join(dataRoot, name, "node-global.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		sourceGlobal[name] = content
	}

	a := &Agent{Cfg: &config.AgentConfig{TavernDir: tavernDir, DataDir: t.TempDir(), NodeID: 8}}
	immutableDir := filepath.Join(t.TempDir(), "immutable")
	req := protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70,
		Handle: "alice", ActivityEpoch: 4, TargetNodeID: 9, DestinationKind: "archive",
	}
	manifest, totalBytes, err := a.copySnapshotTree(context.Background(), req, immutableDir)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"chats/session.jsonl",
		"extensions/example-plugin/settings.json",
		"secrets.json",
		"user/extensions/example-plugin/private-data.json",
	}
	if len(manifest.Files) != len(wantPaths) {
		t.Fatalf("manifest files=%+v", manifest.Files)
	}
	var wantBytes int64
	for index, wantPath := range wantPaths {
		if manifest.Files[index].Path != wantPath {
			t.Fatalf("manifest[%d]=%q want %q", index, manifest.Files[index].Path, wantPath)
		}
		wantBytes += int64(len(privateFiles[wantPath]))
	}
	if totalBytes != wantBytes {
		t.Fatalf("snapshot bytes=%d want %d", totalBytes, wantBytes)
	}
	for name := range sourceGlobal {
		if _, err := os.Stat(filepath.Join(immutableDir, name, "node-global.json")); !os.IsNotExist(err) {
			t.Fatalf("node-global directory %q entered immutable snapshot: %v", name, err)
		}
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "snapshot.tar.zst")
	if err := createSnapshotArchive(context.Background(), archivePath, immutableDir, manifestJSON, manifest.Files); err != nil {
		t.Fatal(err)
	}
	archiveDigest, err := hashFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	targetDataRoot := filepath.Join(t.TempDir(), "data")
	targetGlobal := make(map[string][]byte, len(nodeGlobalDirectories))
	for _, name := range nodeGlobalDirectories {
		content := []byte("target-global:" + name)
		path := filepath.Join(targetDataRoot, name, "node-global.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		targetGlobal[name] = content
	}
	finalPath := filepath.Join(targetDataRoot, "alice")
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	taskRoot := filepath.Join(t.TempDir(), "publish-task")
	if err := os.MkdirAll(taskRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := extractVerifyAndPublish(
		context.Background(), archivePath, taskRoot, finalPath,
		pendingTransfer{
			WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70,
			TargetNodeID: 9, Handle: "alice", DestinationKind: "archive",
			SourceNodeID: 8, ActivityEpoch: 4,
		}, archiveDigest[:], func() error { return nil },
	); err != nil {
		t.Fatal(err)
	}
	for relative, want := range privateFiles {
		got, err := os.ReadFile(filepath.Join(finalPath, filepath.FromSlash(relative)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("private file %q=%q err=%v", relative, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(finalPath, "stale.txt")); !os.IsNotExist(err) {
		t.Fatalf("stale user data survived atomic publication: %v", err)
	}
	for name, want := range targetGlobal {
		got, err := os.ReadFile(filepath.Join(targetDataRoot, name, "node-global.json"))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("target node-global directory %q changed: got=%q err=%v", name, got, err)
		}
	}
}

func TestSnapshotArchiveVerificationAndPublish(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	snapshotDir := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(snapshotDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("private-user-data")
	if err := os.WriteFile(filepath.Join(snapshotDir, "nested", "settings.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	fileDigest := sha256.Sum256(content)
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 8, TargetNodeID: 9,
		ActivityEpoch: 4, CreatedAt: time.Now().UTC(),
		Files: []protocol.ManifestEntry{{Path: "nested/settings.json", Size: int64(len(content)), SHA256: hex.EncodeToString(fileDigest[:])}},
	}
	manifestJSON, _ := json.Marshal(manifest)
	archivePath := filepath.Join(root, "snapshot.tar.zst")
	if err := createSnapshotArchive(context.Background(), archivePath, snapshotDir, manifestJSON, manifest.Files); err != nil {
		t.Fatal(err)
	}
	archiveDigest, err := hashFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	taskRoot := filepath.Join(root, "tasks", testSnapshotID)
	if err := os.MkdirAll(taskRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(root, "replicas", "alice")
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	progressed := false
	receipt, err := extractVerifyAndPublish(
		context.Background(), archivePath, taskRoot, finalPath,
		pendingTransfer{
			WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70, TargetNodeID: 9,
			Handle: "alice", DestinationKind: "archive", SourceNodeID: 8, ActivityEpoch: 4,
		}, archiveDigest[:], func() error { progressed = true; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(finalPath, "nested", "settings.json"))
	if err != nil || !bytes.Equal(got, content) || !progressed || receipt.FileCount != 1 {
		t.Fatalf("content=%q progressed=%v receipt=%+v err=%v", got, progressed, receipt, err)
	}
	if _, err := os.Stat(filepath.Join(finalPath, "old.txt")); !os.IsNotExist(err) {
		t.Fatal("previous replica was retained after successful publish")
	}
	metadata, err := readArchiveReplicaMetadata(finalPath)
	if err != nil || metadata.Manifest.SnapshotID != testSnapshotID ||
		metadata.Receipt.ManifestSHA256 != receipt.ManifestSHA256 {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	verifiedBytes, err := verifyArchiveReplica(context.Background(), finalPath, metadata.Manifest.Files)
	if err != nil || verifiedBytes != int64(len(content)) {
		t.Fatalf("verified=%d err=%v", verifiedBytes, err)
	}
}

func TestAgentDataPlaneHandlerPublishesCapabilityOnceEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic snapshot publication is Linux-only")
	}
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/snapshots/progress" {
			t.Errorf("unexpected progress path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	defer controller.Close()

	root := t.TempDir()
	sourceDir := filepath.Join(root, "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("private-user-settings")
	if err := os.WriteFile(filepath.Join(sourceDir, "settings.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	fileDigest := sha256.Sum256(content)
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 8, TargetNodeID: 9,
		ActivityEpoch: 4, CreatedAt: time.Now().UTC(),
		Files: []protocol.ManifestEntry{{
			Path: "settings.json", Size: int64(len(content)), SHA256: hex.EncodeToString(fileDigest[:]),
		}},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(root, "snapshot.tar.zst")
	if err := createSnapshotArchive(context.Background(), archivePath, sourceDir, manifestJSON, manifest.Files); err != nil {
		t.Fatal(err)
	}
	archiveDigest, err := hashFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	token := "one-use-http-transfer-capability"
	tokenDigest := sha256.Sum256([]byte(token))
	target, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 9, AgentPSK: "target-agent-psk",
		ControllerURL: controller.URL, BackupDir: filepath.Join(root, "backups"), DataDir: filepath.Join(root, "runtime"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.prepareTransfer(pendingTransfer{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70,
		TargetNodeID: 9, Handle: "alice", DestinationKind: "archive", SourceNodeID: 8,
		ActivityEpoch: 4, CapabilityHash: hex.EncodeToString(tokenDigest[:]), ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	targetServer := httptest.NewServer(target.Handler())
	defer targetServer.Close()
	source := &Agent{}
	receipt, err := source.streamSnapshot(context.Background(), protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		TargetTransferURL: targetServer.URL, TransferCapability: token,
	}, archivePath, archiveDigest)
	if err != nil || !receipt.OK || receipt.FileCount != 1 {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	published, err := os.ReadFile(filepath.Join(root, "backups", "replicas", "alice", "settings.json"))
	if err != nil || !bytes.Equal(published, content) {
		t.Fatalf("published=%q err=%v", published, err)
	}
	if _, err := source.streamSnapshot(context.Background(), protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		TargetTransferURL: targetServer.URL, TransferCapability: token,
	}, archivePath, archiveDigest); err == nil {
		t.Fatal("published transfer capability replay was accepted")
	}
}

func TestArchiveRestoreVerificationRejectsTamperingAndExtraFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	content := []byte("immutable")
	path := filepath.Join(root, "settings.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	entries := []protocol.ManifestEntry{{
		Path: "settings.json", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
	}}
	if total, err := verifyArchiveReplica(context.Background(), root, entries); err != nil || total != int64(len(content)) {
		t.Fatalf("total=%d err=%v", total, err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra.json"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArchiveReplica(context.Background(), root, entries); err == nil {
		t.Fatal("unlisted archive file was accepted")
	}
	if err := os.Remove(filepath.Join(root, "extra.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArchiveReplica(context.Background(), root, entries); err == nil {
		t.Fatal("tampered archive file was accepted")
	}
}

func TestArchiveRecoveryMetadataRejectsTrailingJSONAndSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	metadataPath := filepath.Join(root, archiveMetadataPath)
	if err := os.WriteFile(metadataPath, []byte(`{"format_version":1} {}`), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := readArchiveReplicaMetadata(root); err == nil {
		t.Fatal("archive metadata with trailing JSON was accepted")
	}
	if err := os.Remove(metadataPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "outside.json")
	if err := os.WriteFile(target, []byte(`{"format_version":1}`), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, metadataPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readArchiveReplicaMetadata(root); err == nil {
		t.Fatal("symlinked archive metadata was accepted")
	}
}

func TestManifestMismatchNeverReplacesPreviousReplica(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	finalPath := filepath.Join(root, "replicas", "alice")
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "old.txt"), []byte("authoritative"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 8, TargetNodeID: 9, ActivityEpoch: 4,
		Files: []protocol.ManifestEntry{{Path: "data.txt", Size: 4, SHA256: hex.EncodeToString(make([]byte, 32))}},
	}
	archivePath := filepath.Join(root, "malicious.tar.zst")
	writeTestSnapshotArchive(t, archivePath, manifest, tar.Header{Name: "data.txt", Typeflag: tar.TypeReg, Size: 4}, []byte("evil"))
	archiveDigest, _ := hashFile(archivePath)
	taskRoot := filepath.Join(root, "tasks", testSnapshotID)
	if err := os.MkdirAll(taskRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := extractVerifyAndPublish(
		context.Background(), archivePath, taskRoot, finalPath,
		pendingTransfer{
			WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70, TargetNodeID: 9,
			Handle: "alice", SourceNodeID: 8, ActivityEpoch: 4,
		}, archiveDigest[:], func() error { return nil },
	)
	if err == nil {
		t.Fatal("manifest digest mismatch was accepted")
	}
	got, readErr := os.ReadFile(filepath.Join(finalPath, "old.txt"))
	if readErr != nil || string(got) != "authoritative" {
		t.Fatalf("previous replica changed: %q err=%v", got, readErr)
	}
}

func TestSnapshotRejectsTraversalAndUnsupportedEntries(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"../escape", "/absolute", `C:\\escape`, `C:\escape`, "C:/escape", "C:relative",
		`\\server\share`, `nested\..\escape`, "nested/file:stream", "nested/\x00file",
		".stcontrol/hidden", archiveMetadataPath, conflictEvidenceMetadataPath, "a/../../b",
	} {
		if safeArchivePath(path) {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
	if !safeArchivePath("nested/settings.json") {
		t.Fatal("safe relative path was rejected")
	}
}

func TestTransferCapabilityNeverAppearsInURL(t *testing.T) {
	t.Parallel()
	endpoint, err := snapshotTransferEndpoint("https://storage.example/data", testSnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://storage.example/data/transfer/v1/snapshots/"+testSnapshotID {
		t.Fatalf("endpoint=%q", endpoint)
	}
	if _, err := snapshotTransferEndpoint("http://storage.example", testSnapshotID); err == nil {
		t.Fatal("remote plaintext transfer URL was accepted")
	}
}

func TestStartSnapshotProtocolContainsNoPermanentTargetCredential(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		TargetTransferURL: "https://storage.example", TransferCapability: "short-lived",
	})
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(payload)
	for _, forbidden := range []string{"dst_node_psk", "agent_psk", "dst_agent_url"} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("snapshot command contains %q: %s", forbidden, serialized)
		}
	}
}

func writeTestSnapshotArchive(t *testing.T, path string, manifest protocol.SnapshotManifest, header tar.Header, body []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := zstd.NewWriter(file)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(encoder)
	manifestJSON, _ := json.Marshal(manifest)
	if err := writer.WriteHeader(&tar.Header{Name: snapshotManifestPath, Typeflag: tar.TypeReg, Size: int64(len(manifestJSON))}); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(manifestJSON)
	if err := writer.WriteHeader(&header); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(body)
	_ = writer.Close()
	_ = encoder.Close()
	_ = file.Close()
}

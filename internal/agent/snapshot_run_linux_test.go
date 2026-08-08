//go:build linux

package agent

import (
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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

const (
	snapshotRunSourceNodeID  = int64(8)
	snapshotRunTargetNodeID  = int64(9)
	snapshotRunRestoreNodeID = int64(10)
	snapshotRunSourcePSK     = "snapshot-source-controller-credential"
	snapshotRunTargetPSK     = "snapshot-target-controller-credential"
	snapshotRunRestorePSK    = "snapshot-restore-controller-credential"
	snapshotRunAdapterPSK    = "snapshot-source-adapter-credential"
	snapshotRunRestoreID     = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

type snapshotRunEvents struct {
	mu     sync.Mutex
	values []string
}

func (events *snapshotRunEvents) add(value string) {
	events.mu.Lock()
	events.values = append(events.values, value)
	events.mu.Unlock()
}

func (events *snapshotRunEvents) snapshot() []string {
	events.mu.Lock()
	defer events.mu.Unlock()
	return append([]string(nil), events.values...)
}

func TestRunSnapshotDirectPublishesAtomicallyAndReleasesUserGate(t *testing.T) {
	root := t.TempDir()
	events := &snapshotRunEvents{}
	adapter := newSnapshotRunAdapter(t, events, nil)
	defer adapter.Close()
	controller := newSnapshotRunController(t, events, "", nil)
	defer controller.Close()

	source := newSnapshotRunSource(t, root, adapter.URL, controller.URL)
	userRoot := filepath.Join(source.Cfg.TavernDir, "data", "alice")
	if err := os.MkdirAll(filepath.Join(userRoot, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := []byte("immutable private user settings")
	if err := os.WriteFile(filepath.Join(userRoot, "nested", "settings.json"), want, 0o600); err != nil {
		t.Fatal(err)
	}

	target := newSnapshotRunTarget(t, root, controller.URL)
	oldReplica := filepath.Join(target.Cfg.BackupDir, "replicas", "alice", "old.txt")
	if err := os.MkdirAll(filepath.Dir(oldReplica), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldReplica, []byte("old replica"), 0o600); err != nil {
		t.Fatal(err)
	}

	request, transfer := snapshotRunRequest(time.Now().UTC().Add(5 * time.Minute))
	if err := target.prepareTransfer(transfer); err != nil {
		t.Fatal(err)
	}
	targetServer := httptest.NewServer(target.Handler())
	defer targetServer.Close()
	request.TargetTransferURL = targetServer.URL

	receipt, err := source.RunSnapshot(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.OK || receipt.SnapshotID != request.SnapshotID || receipt.FileCount != 1 ||
		receipt.TotalBytes != int64(len(want)) || receipt.ManifestSHA256 == "" || receipt.ArchiveSHA256 == "" {
		t.Fatalf("incomplete snapshot receipt: %+v", receipt)
	}
	published, err := os.ReadFile(filepath.Join(target.Cfg.BackupDir, "replicas", "alice", "nested", "settings.json"))
	if err != nil || !bytes.Equal(published, want) {
		t.Fatalf("published=%q err=%v", published, err)
	}
	if _, err := os.Stat(oldReplica); !os.IsNotExist(err) {
		t.Fatalf("old replica survived atomic publication: %v", err)
	}
	metadata, err := readArchiveReplicaMetadata(filepath.Join(target.Cfg.BackupDir, "replicas", "alice"))
	if err != nil || metadata.Manifest.SnapshotID != request.SnapshotID ||
		metadata.Receipt.ManifestSHA256 != receipt.ManifestSHA256 {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	if _, err := os.Stat(filepath.Join(source.Cfg.DataDir, "snapshot-tasks", request.WorkflowID, request.SnapshotID)); !os.IsNotExist(err) {
		t.Fatalf("source task directory was not removed: %v", err)
	}
	wantEvents := []string{
		"adapter:quiesce", "8:drained", "8:snapshotting", "adapter:release", "8:transferring",
		"9:verifying", "9:publishing",
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("snapshot event order=%v want=%v", got, wantEvents)
	}
}

func TestRunSnapshotNetworkFailureStillReleasesGateAndCleansTask(t *testing.T) {
	root := t.TempDir()
	events := &snapshotRunEvents{}
	adapter := newSnapshotRunAdapter(t, events, nil)
	defer adapter.Close()
	controller := newSnapshotRunController(t, events, "", nil)
	defer controller.Close()
	source := newSnapshotRunSource(t, root, adapter.URL, controller.URL)
	userRoot := filepath.Join(source.Cfg.TavernDir, "data", "alice")
	if err := os.MkdirAll(userRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userRoot, "settings.json"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		http.Error(w, "temporary network path failure", http.StatusServiceUnavailable)
	}))
	defer target.Close()

	request, _ := snapshotRunRequest(time.Now().UTC().Add(5 * time.Minute))
	request.TargetTransferURL = target.URL
	if _, err := source.RunSnapshot(context.Background(), request); !errors.Is(err, errSnapshotDirectUnreachable) {
		t.Fatalf("network failure=%v", err)
	}
	if _, err := os.Stat(filepath.Join(source.Cfg.DataDir, "snapshot-tasks", request.WorkflowID, request.SnapshotID)); !os.IsNotExist(err) {
		t.Fatalf("failed source task directory was not removed: %v", err)
	}
	wantEvents := []string{
		"adapter:quiesce", "8:drained", "8:snapshotting", "adapter:release", "8:transferring",
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("failure event order=%v want=%v", got, wantEvents)
	}
}

func TestRunSnapshotRelayEncryptsThenTargetPublishesAndConfirms(t *testing.T) {
	root := t.TempDir()
	events := &snapshotRunEvents{}
	adapter := newSnapshotRunAdapter(t, events, nil)
	defer adapter.Close()
	controller := newSnapshotRunController(t, events, "", nil)
	defer controller.Close()
	source := newSnapshotRunSource(t, root, adapter.URL, controller.URL)
	userRoot := filepath.Join(source.Cfg.TavernDir, "data", "alice")
	if err := os.MkdirAll(userRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("relay-private-user-data"), 200)
	if err := os.WriteFile(filepath.Join(userRoot, "settings.json"), want, 0o600); err != nil {
		t.Fatal(err)
	}

	target := newSnapshotRunTarget(t, root, controller.URL)
	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	request, transfer := snapshotRunRequest(expiresAt)
	relayTaskID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	targetKey, err := target.prepareRelayTransfer(transfer, relayTaskID)
	if err != nil {
		t.Fatal(err)
	}
	relay := &snapshotRunRelay{taskID: relayTaskID, uploadToken: "relay-upload-token", downloadToken: "relay-download-token"}
	relayServer := httptest.NewServer(relay)
	defer relayServer.Close()
	relayURL := relayServer.URL + "/relay/v1/transfers/" + relayTaskID
	request.TransferMode = "relay"
	request.RelayTaskID = relayTaskID
	request.RelayUploadURL = relayURL
	request.RelayUploadToken = relay.uploadToken
	request.RelayTargetKey = targetKey

	pending, err := source.RunSnapshot(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !pending.OK || !pending.RelayPending || pending.FileCount != 1 || pending.TotalBytes != int64(len(want)) {
		t.Fatalf("incomplete relay upload receipt: %+v", pending)
	}
	relay.mu.Lock()
	ciphertext := append([]byte(nil), relay.ciphertext...)
	relay.mu.Unlock()
	if len(ciphertext) == 0 || bytes.Contains(ciphertext, want) || bytes.Contains(ciphertext, []byte("relay-private-user-data")) {
		t.Fatal("relay did not persist opaque ciphertext")
	}

	receipt, err := target.RunRelayReceive(context.Background(), protocol.StartRelayReceiveRequest{
		WorkflowID: request.WorkflowID, SnapshotID: request.SnapshotID, RelayTaskID: relayTaskID,
		RelayDownloadURL: relayURL, RelayDownloadToken: relay.downloadToken,
		TransferCapability: request.TransferCapability, CapabilityExpires: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.OK || receipt.SnapshotID != request.SnapshotID || receipt.ManifestSHA256 != pending.ManifestSHA256 ||
		receipt.ArchiveSHA256 != pending.ArchiveSHA256 {
		t.Fatalf("relay target receipt=%+v pending=%+v", receipt, pending)
	}
	published, err := os.ReadFile(filepath.Join(target.Cfg.BackupDir, "replicas", "alice", "settings.json"))
	if err != nil || !bytes.Equal(published, want) {
		t.Fatalf("relay published=%d bytes err=%v", len(published), err)
	}
	relay.mu.Lock()
	completed, downloads := relay.completed, relay.downloads
	relay.mu.Unlock()
	if !completed || downloads != 1 {
		t.Fatalf("relay completed=%t downloads=%d", completed, downloads)
	}
	if _, err := target.RunRelayReceive(context.Background(), protocol.StartRelayReceiveRequest{
		WorkflowID: request.WorkflowID, SnapshotID: request.SnapshotID, RelayTaskID: relayTaskID,
		RelayDownloadURL: relayURL, RelayDownloadToken: relay.downloadToken,
		TransferCapability: request.TransferCapability, CapabilityExpires: expiresAt,
	}); err == nil {
		t.Fatal("completed relay transfer was replayed")
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.downloads != 1 {
		t.Fatalf("replay reached relay download: %d", relay.downloads)
	}
}

func TestAbortBackupCancelsSnapshotAndEventuallyReleasesUserGate(t *testing.T) {
	root := t.TempDir()
	events := &snapshotRunEvents{}
	released := make(chan struct{})
	adapter := newSnapshotRunAdapter(t, events, released)
	defer adapter.Close()
	blocked := make(chan struct{})
	controller := newSnapshotRunController(t, events, "snapshotting", blocked)
	defer controller.Close()
	source := newSnapshotRunSource(t, root, adapter.URL, controller.URL)
	userRoot := filepath.Join(source.Cfg.TavernDir, "data", "alice")
	if err := os.MkdirAll(userRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userRoot, "settings.json"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.NotFoundHandler())
	defer target.Close()
	request, _ := snapshotRunRequest(time.Now().UTC().Add(5 * time.Minute))
	request.JobID = 902
	request.TargetTransferURL = target.URL

	result := make(chan error, 1)
	go func() {
		_, err := source.RunSnapshot(context.Background(), request)
		result <- err
	}()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot did not reach the cancellable stage")
	}
	source.AbortBackup(request.JobID)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled snapshot succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled snapshot did not stop")
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled snapshot left the user write gate closed")
	}
	wantEvents := []string{"adapter:quiesce", "8:drained", "8:snapshotting", "adapter:release"}
	if got := events.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("cancel event order=%v want=%v", got, wantEvents)
	}
}

func TestRunRestoreTransferReverifiesArchiveAndAtomicallyPublishesComputeData(t *testing.T) {
	root := t.TempDir()
	events := &snapshotRunEvents{}
	controller := newSnapshotRunController(t, events, "", nil)
	defer controller.Close()
	source := newSnapshotRunTarget(t, root, controller.URL)
	sourceRoot := filepath.Join(source.Cfg.BackupDir, "replicas", "alice")
	if err := os.MkdirAll(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	want := []byte("verified archive recovery data")
	if err := os.WriteFile(filepath.Join(sourceRoot, "settings.json"), want, 0o400); err != nil {
		t.Fatal(err)
	}
	fileDigest := sha256.Sum256(want)
	sourceManifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: snapshotRunSourceNodeID,
		TargetNodeID: snapshotRunTargetNodeID, ActivityEpoch: 4, CreatedAt: time.Now().UTC(),
		Files: []protocol.ManifestEntry{{
			Path: "settings.json", Size: int64(len(want)), SHA256: hex.EncodeToString(fileDigest[:]),
		}},
	}
	sourceManifestJSON, err := json.Marshal(sourceManifest)
	if err != nil {
		t.Fatal(err)
	}
	sourceManifestDigest := sha256.Sum256(sourceManifestJSON)
	if err := writeArchiveReplicaMetadata(sourceRoot, sourceManifest, protocol.SnapshotTransferReceipt{
		OK: true, SnapshotID: testSnapshotID, ManifestSHA256: hex.EncodeToString(sourceManifestDigest[:]),
		ArchiveSHA256: hex.EncodeToString(make([]byte, sha256.Size)), FileCount: 1, TotalBytes: int64(len(want)),
	}); err != nil {
		t.Fatal(err)
	}

	target := newSnapshotRunRestoreTarget(t, root, controller.URL)
	oldTarget := filepath.Join(target.Cfg.TavernDir, "data", "alice", "old.txt")
	if err := os.MkdirAll(filepath.Dir(oldTarget), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldTarget, []byte("old target"), 0o600); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	token := "one-use-archive-restore-capability"
	tokenDigest := sha256.Sum256([]byte(token))
	if err := target.prepareTransfer(pendingTransfer{
		WorkflowID: testWorkflowID, SnapshotID: snapshotRunRestoreID, GlobalUserID: 70,
		TargetNodeID: snapshotRunRestoreNodeID, Handle: "alice", DestinationKind: "restore",
		SourceNodeID: snapshotRunTargetNodeID, ActivityEpoch: 4,
		CapabilityHash: hex.EncodeToString(tokenDigest[:]), ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	targetResult := make(chan error, 1)
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receipt, receiveErr := target.ReceiveSnapshot(
			r.Context(), r.Header.Get("X-Workflow-Id"), strings.TrimPrefix(r.URL.Path, "/transfer/v1/snapshots/"),
			strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), r.Header.Get("X-Archive-Sha256"), r.Body,
		)
		targetResult <- receiveErr
		if receiveErr != nil {
			protocol.WriteError(w, http.StatusUnprocessableEntity, "snapshot rejected")
			return
		}
		protocol.WriteJSON(w, http.StatusOK, receipt)
	}))
	defer targetServer.Close()
	receipt, err := source.RunRestoreTransfer(context.Background(), protocol.StartRestoreTransferRequest{
		JobID: 903, WorkflowID: testWorkflowID, SourceSnapshotID: testSnapshotID,
		RestoreSnapshotID: snapshotRunRestoreID, SourceManifestSHA256: hex.EncodeToString(sourceManifestDigest[:]),
		GlobalUserID: 70, Handle: "alice", ActivityEpoch: 4, TargetNodeID: snapshotRunRestoreNodeID,
		TargetTransferURL: targetServer.URL, TransferCapability: token, CapabilityExpires: expiresAt,
	})
	if err != nil {
		t.Fatalf("restore transfer: %v; target: %v", err, <-targetResult)
	}
	if receiveErr := <-targetResult; receiveErr != nil {
		t.Fatalf("target restore receive: %v", receiveErr)
	}
	if !receipt.OK || receipt.SnapshotID != snapshotRunRestoreID || receipt.FileCount != 1 ||
		receipt.TotalBytes != int64(len(want)) {
		t.Fatalf("restore receipt=%+v", receipt)
	}
	published, err := os.ReadFile(filepath.Join(target.Cfg.TavernDir, "data", "alice", "settings.json"))
	if err != nil || !bytes.Equal(published, want) {
		t.Fatalf("restored=%q err=%v", published, err)
	}
	if _, err := os.Stat(oldTarget); !os.IsNotExist(err) {
		t.Fatalf("old compute data survived restore publication: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target.Cfg.TavernDir, "data", "alice", archiveMetadataPath)); !os.IsNotExist(err) {
		t.Fatalf("archive-only metadata leaked into compute data: %v", err)
	}
	if got, wantEvents := events.snapshot(), []string{"10:verifying", "10:publishing"}; !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("restore event order=%v want=%v", got, wantEvents)
	}
}

func newSnapshotRunSource(t *testing.T, root, adapterURL, controllerURL string) *Agent {
	t.Helper()
	tavernDir := filepath.Join(root, "source-tavern")
	if err := os.MkdirAll(tavernDir, 0o700); err != nil {
		t.Fatal(err)
	}
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: snapshotRunSourceNodeID, AgentPSK: snapshotRunSourcePSK,
		TavernAdapterPSK: snapshotRunAdapterPSK, ControllerURL: controllerURL, TavernURL: adapterURL,
		TavernDir: tavernDir, DataDir: filepath.Join(root, "source-runtime"),
		ControllerGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func newSnapshotRunTarget(t *testing.T, root, controllerURL string) *Agent {
	t.Helper()
	agent, err := New(&config.AgentConfig{
		Role: "storage", NodeID: snapshotRunTargetNodeID, AgentPSK: snapshotRunTargetPSK,
		ControllerURL: controllerURL, DataDir: filepath.Join(root, "target-runtime"),
		BackupDir: filepath.Join(root, "target-backups"), ControllerGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func newSnapshotRunRestoreTarget(t *testing.T, root, controllerURL string) *Agent {
	t.Helper()
	tavernDir := filepath.Join(root, "restore-tavern")
	if err := os.MkdirAll(tavernDir, 0o700); err != nil {
		t.Fatal(err)
	}
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: snapshotRunRestoreNodeID, AgentPSK: snapshotRunRestorePSK,
		ControllerURL: controllerURL, DataDir: filepath.Join(root, "restore-runtime"),
		TavernDir: tavernDir, ControllerGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func snapshotRunRequest(expiresAt time.Time) (protocol.StartSnapshotRequest, pendingTransfer) {
	token := "one-use-direct-snapshot-capability"
	digest := sha256.Sum256([]byte(token))
	request := protocol.StartSnapshotRequest{
		JobID: 901, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70,
		Handle: "alice", ActivityEpoch: 4, TargetNodeID: snapshotRunTargetNodeID,
		TransferCapability: token, CapabilityExpires: expiresAt, DestinationKind: "archive", TransferMode: "direct",
	}
	transfer := pendingTransfer{
		WorkflowID: request.WorkflowID, SnapshotID: request.SnapshotID, GlobalUserID: request.GlobalUserID,
		TargetNodeID: request.TargetNodeID, Handle: request.Handle, DestinationKind: request.DestinationKind,
		SourceNodeID: snapshotRunSourceNodeID, ActivityEpoch: request.ActivityEpoch,
		CapabilityHash: hex.EncodeToString(digest[:]), ExpiresAt: expiresAt,
	}
	return request, transfer
}

func newSnapshotRunAdapter(
	t *testing.T,
	events *snapshotRunEvents,
	released chan<- struct{},
) *httptest.Server {
	t.Helper()
	var releaseOnce sync.Once
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil || r.Method != http.MethodPost ||
			r.Header.Get(protocol.HeaderAgentID) != "8" || protocol.VerifyRequest(r, snapshotRunAdapterPSK, body) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/stcontrol/internal/snapshots/quiesce":
			var request snapshotGateRequest
			if json.Unmarshal(body, &request) != nil || request.WorkflowID != testWorkflowID ||
				request.SnapshotID != testSnapshotID || request.Handle != "alice" || request.ActivityEpoch != 4 {
				http.Error(w, "invalid quiesce scope", http.StatusBadRequest)
				return
			}
			events.add("adapter:quiesce")
			protocol.WriteJSON(w, http.StatusOK, snapshotGateResponse{OK: true, Drained: true, FreezeToken: "exact-freeze-token"})
		case "/api/stcontrol/internal/snapshots/release":
			var request snapshotReleaseRequest
			if json.Unmarshal(body, &request) != nil || request.WorkflowID != testWorkflowID ||
				request.SnapshotID != testSnapshotID || request.Handle != "alice" ||
				request.ActivityEpoch != 4 || request.FreezeToken != "exact-freeze-token" {
				http.Error(w, "invalid release scope", http.StatusConflict)
				return
			}
			events.add("adapter:release")
			if released != nil {
				releaseOnce.Do(func() { close(released) })
			}
			protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
}

func newSnapshotRunController(
	t *testing.T,
	events *snapshotRunEvents,
	blockedState string,
	blocked chan<- struct{},
) *httptest.Server {
	t.Helper()
	credentials := map[string]string{
		"8": snapshotRunSourcePSK, "9": snapshotRunTargetPSK, "10": snapshotRunRestorePSK,
	}
	var blockedOnce sync.Once
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		nodeID := r.Header.Get(protocol.HeaderAgentID)
		psk := credentials[nodeID]
		if err != nil || r.Method != http.MethodPost || r.URL.Path != "/api/agent/snapshots/progress" ||
			psk == "" || protocol.VerifyRequest(r, psk, body) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var progress protocol.SnapshotProgressRequest
		if json.Unmarshal(body, &progress) != nil || progress.WorkflowID != testWorkflowID ||
			(progress.SnapshotID != testSnapshotID && progress.SnapshotID != snapshotRunRestoreID) {
			http.Error(w, "invalid progress scope", http.StatusBadRequest)
			return
		}
		events.add(nodeID + ":" + progress.State)
		if progress.State == blockedState && blocked != nil {
			blockedOnce.Do(func() { close(blocked) })
			<-r.Context().Done()
			return
		}
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
}

type snapshotRunRelay struct {
	mu            sync.Mutex
	taskID        string
	uploadToken   string
	downloadToken string
	ciphertext    []byte
	plaintextSize string
	archiveHash   string
	workflowID    string
	snapshotID    string
	downloads     int
	completed     bool
}

func (relay *snapshotRunRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := "/relay/v1/transfers/" + relay.taskID
	switch {
	case r.Method == http.MethodPut && r.URL.Path == path:
		if r.Header.Get("Authorization") != "Bearer "+relay.uploadToken ||
			r.Header.Get("Content-Type") != "application/vnd.stcontrol.relay.v1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ciphertext, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil || len(ciphertext) == 0 || int64(len(ciphertext)) != r.ContentLength {
			http.Error(w, "invalid ciphertext", http.StatusBadRequest)
			return
		}
		plaintextSize := r.Header.Get("X-Plaintext-Length")
		if size, err := strconv.ParseInt(plaintextSize, 10, 64); err != nil || size <= 0 {
			http.Error(w, "invalid plaintext length", http.StatusBadRequest)
			return
		}
		relay.mu.Lock()
		if len(relay.ciphertext) != 0 {
			relay.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		relay.ciphertext = ciphertext
		relay.plaintextSize = plaintextSize
		relay.archiveHash = r.Header.Get("X-Archive-Sha256")
		relay.workflowID = r.Header.Get("X-Workflow-Id")
		relay.snapshotID = r.Header.Get("X-Snapshot-Id")
		relay.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet && r.URL.Path == path:
		if r.Header.Get("Authorization") != "Bearer "+relay.downloadToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		relay.mu.Lock()
		if relay.completed {
			relay.mu.Unlock()
			http.Error(w, "completed", http.StatusGone)
			return
		}
		if len(relay.ciphertext) == 0 {
			relay.mu.Unlock()
			w.WriteHeader(http.StatusTooEarly)
			return
		}
		ciphertext := append([]byte(nil), relay.ciphertext...)
		plaintextSize := relay.plaintextSize
		archiveHash := relay.archiveHash
		workflowID := relay.workflowID
		snapshotID := relay.snapshotID
		relay.downloads++
		relay.mu.Unlock()
		digest := sha256.Sum256(ciphertext)
		w.Header().Set("Content-Type", "application/vnd.stcontrol.relay.v1")
		w.Header().Set("Content-Length", strconv.Itoa(len(ciphertext)))
		w.Header().Set("X-Plaintext-Length", plaintextSize)
		w.Header().Set("X-Archive-Sha256", archiveHash)
		w.Header().Set("X-Ciphertext-Sha256", hex.EncodeToString(digest[:]))
		w.Header().Set("X-Workflow-Id", workflowID)
		w.Header().Set("X-Snapshot-Id", snapshotID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
	case r.Method == http.MethodPost && r.URL.Path == path+"/complete":
		if r.Header.Get("Authorization") != "Bearer "+relay.downloadToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		relay.mu.Lock()
		if relay.completed || relay.downloads != 1 {
			relay.mu.Unlock()
			http.Error(w, "invalid completion", http.StatusConflict)
			return
		}
		relay.completed = true
		relay.mu.Unlock()
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		http.NotFound(w, r)
	}
}

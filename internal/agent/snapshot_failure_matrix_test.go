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
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

const snapshotFailureRelayTaskID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

func validSnapshotFailureRequest() protocol.StartSnapshotRequest {
	return protocol.StartSnapshotRequest{
		JobID:              1,
		WorkflowID:         testWorkflowID,
		SnapshotID:         testSnapshotID,
		GlobalUserID:       70,
		Handle:             "alice",
		ActivityEpoch:      4,
		TargetNodeID:       9,
		TargetTransferURL:  "http://127.0.0.1:1",
		TransferCapability: "short-lived-capability",
		CapabilityExpires:  time.Now().Add(time.Minute),
		DestinationKind:    "archive",
		TransferMode:       "direct",
	}
}

func TestSnapshotRequestEndpointAndPathFailureMatrix(t *testing.T) {
	direct := validSnapshotFailureRequest()
	if err := validateStartSnapshotRequest(direct); err != nil {
		t.Fatalf("valid direct request: %v", err)
	}
	relay := direct
	relay.TransferMode = "relay"
	relay.TargetTransferURL = ""
	relay.RelayTaskID = snapshotFailureRelayTaskID
	relay.RelayUploadURL = "http://127.0.0.1:1/relay/v1/transfers/" + snapshotFailureRelayTaskID
	relay.RelayUploadToken = "upload-token"
	relay.RelayTargetKey = "target-key"
	if err := validateStartSnapshotRequest(relay); err != nil {
		t.Fatalf("valid relay request: %v", err)
	}

	invalidRequests := []protocol.StartSnapshotRequest{
		{},
		func() protocol.StartSnapshotRequest { r := direct; r.DestinationKind = "other"; return r }(),
		func() protocol.StartSnapshotRequest {
			r := direct
			r.TargetTransferURL = "http://remote.example"
			return r
		}(),
		func() protocol.StartSnapshotRequest { r := relay; r.RelayTaskID = "bad"; return r }(),
		func() protocol.StartSnapshotRequest { r := relay; r.RelayUploadToken = ""; return r }(),
		func() protocol.StartSnapshotRequest { r := relay; r.RelayUploadURL += "?secret=1"; return r }(),
	}
	for index, request := range invalidRequests {
		if err := validateStartSnapshotRequest(request); err == nil {
			t.Fatalf("invalid snapshot request %d accepted", index)
		}
	}

	for _, raw := range []string{
		"https://user@example.com",
		"https://example.com/path?query=1",
		"https://example.com/path#fragment",
		"ftp://example.com",
	} {
		if _, err := snapshotTransferEndpoint(raw, testSnapshotID); err == nil {
			t.Fatalf("invalid snapshot endpoint accepted: %q", raw)
		}
	}
	for _, raw := range []string{
		"https://user@example.com/relay/v1/transfers/" + snapshotFailureRelayTaskID,
		"https://example.com/relay/v1/transfers/" + snapshotFailureRelayTaskID + "?query=1",
		"https://example.com/wrong/" + snapshotFailureRelayTaskID,
		"http://example.com/relay/v1/transfers/" + snapshotFailureRelayTaskID,
	} {
		if _, err := relayTransferEndpoint(raw, snapshotFailureRelayTaskID); err == nil {
			t.Fatalf("invalid relay endpoint accepted: %q", raw)
		}
	}

	if validSnapshotFreezeToken("short") || validSnapshotFreezeToken(string(bytes.Repeat([]byte{'a'}, 129))) ||
		validSnapshotFreezeToken("abcdefghijklmnopqrstuvwxyz01234!") {
		t.Fatal("invalid freeze token accepted")
	}
	if !validSnapshotFreezeToken("abcdefghijklmnopqrstuvwxyz012345") {
		t.Fatal("valid freeze token rejected")
	}
	now := time.Now()
	if validSnapshotGateExpiry(now.Add(time.Second).UnixMilli(), now) ||
		validSnapshotGateExpiry(now.Add(7*time.Minute).UnixMilli(), now) ||
		!validSnapshotGateExpiry(now.Add(time.Minute).UnixMilli(), now) {
		t.Fatal("snapshot gate expiry bounds are incorrect")
	}

	agent := &Agent{Cfg: &config.AgentConfig{
		BackupDir: filepath.Join(t.TempDir(), "backup"),
		TavernDir: filepath.Join(t.TempDir(), "tavern"),
	}}
	for _, kind := range []string{"archive", "hot_standby", "restore", "conflict_input"} {
		transfer := pendingTransfer{WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, Handle: "alice", DestinationKind: kind}
		taskRoot, finalPath, err := agent.targetSnapshotPaths(transfer)
		if err != nil || taskRoot == "" || finalPath == "" {
			t.Fatalf("target paths kind=%s task=%q final=%q err=%v", kind, taskRoot, finalPath, err)
		}
	}
	for _, transfer := range []pendingTransfer{
		{},
		{WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, Handle: "alice", DestinationKind: "invalid"},
	} {
		if _, _, err := agent.targetSnapshotPaths(transfer); err == nil {
			t.Fatalf("invalid transfer paths accepted: %+v", transfer)
		}
	}

	if !retryableSnapshotProgressStatus(http.StatusRequestTimeout) ||
		!retryableSnapshotProgressStatus(http.StatusTooEarly) ||
		!retryableSnapshotProgressStatus(http.StatusTooManyRequests) ||
		!retryableSnapshotProgressStatus(http.StatusInternalServerError) ||
		retryableSnapshotProgressStatus(http.StatusConflict) {
		t.Fatal("snapshot progress retry classification is incorrect")
	}
	if err := snapshotHTTPClient().CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy=%v", err)
	}
}

func TestArchiveReplicaMetadataAndTreeFailureMatrix(t *testing.T) {
	t.Run("metadata shapes", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, archiveMetadataPath)
		if _, err := readArchiveReplicaMetadata(root); err == nil {
			t.Fatal("missing metadata accepted")
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := readArchiveReplicaMetadata(root); err == nil {
			t.Fatal("metadata directory accepted")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		for _, payload := range [][]byte{nil, []byte(`{"unknown":true}`), []byte(`not-json`)} {
			if err := os.WriteFile(path, payload, 0o400); err != nil {
				t.Fatal(err)
			}
			if _, err := readArchiveReplicaMetadata(root); err == nil {
				t.Fatalf("invalid metadata accepted: %q", payload)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	})

	digest := sha256.Sum256([]byte("content"))
	validEntry := protocol.ManifestEntry{Path: "data.txt", Size: 7, SHA256: hex.EncodeToString(digest[:])}
	invalidEntries := [][]protocol.ManifestEntry{
		{{Path: "../escape", Size: 1, SHA256: hex.EncodeToString(digest[:])}},
		{{Path: "data.txt", Size: -1, SHA256: hex.EncodeToString(digest[:])}},
		{{Path: "data.txt", Size: maxSnapshotFileBytes + 1, SHA256: hex.EncodeToString(digest[:])}},
		{{Path: "data.txt", Size: 1, SHA256: "bad"}},
		{validEntry, validEntry},
	}
	for index, entries := range invalidEntries {
		if _, err := verifyArchiveReplica(context.Background(), t.TempDir(), entries); err == nil {
			t.Fatalf("invalid archive entries %d accepted", index)
		}
	}

	t.Run("cancel and tree types", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, validEntry.Path), []byte("content"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := verifyArchiveReplica(ctx, root, []protocol.ManifestEntry{validEntry}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error=%v", err)
		}
		if err := os.Remove(filepath.Join(root, validEntry.Path)); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("content"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, validEntry.Path)); err == nil {
			if _, err := verifyArchiveReplica(context.Background(), root, []protocol.ManifestEntry{validEntry}); err == nil {
				t.Fatal("symlinked archive entry accepted")
			}
		}
	})

	t.Run("light verification still checks shape", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, validEntry.Path), []byte("content"), 0o600); err != nil {
			t.Fatal(err)
		}
		wrongDigest := validEntry
		wrongDigest.SHA256 = hex.EncodeToString(make([]byte, sha256.Size))
		if total, err := verifyArchiveReplicaLight(context.Background(), root, []protocol.ManifestEntry{wrongDigest}); err != nil || total != 7 {
			t.Fatalf("light verification total=%d err=%v", total, err)
		}
		wrongSize := wrongDigest
		wrongSize.Size++
		if _, err := verifyArchiveReplicaLight(context.Background(), root, []protocol.ManifestEntry{wrongSize}); err == nil {
			t.Fatal("light verification accepted wrong size")
		}
	})
}

func TestSnapshotArchiveAndTransportFailureMatrix(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("content")
	if err := os.WriteFile(filepath.Join(source, "data.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	entry := protocol.ManifestEntry{Path: "data.txt", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 8, TargetNodeID: 9, ActivityEpoch: 4,
		Files: []protocol.ManifestEntry{entry},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	existing := filepath.Join(root, "existing.tar.zst")
	if err := os.WriteFile(existing, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createSnapshotArchive(context.Background(), existing, source, manifestJSON, manifest.Files); err == nil {
		t.Fatal("existing archive was overwritten")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledPath := filepath.Join(root, "cancelled.tar.zst")
	if err := createSnapshotArchive(cancelled, cancelledPath, source, manifestJSON, manifest.Files); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel archive error=%v", err)
	}
	if _, err := os.Stat(cancelledPath); !os.IsNotExist(err) {
		t.Fatalf("failed archive survived: %v", err)
	}
	missingEntry := entry
	missingEntry.Path = "missing.txt"
	if err := createSnapshotArchive(context.Background(), filepath.Join(root, "missing.tar.zst"), source, manifestJSON, []protocol.ManifestEntry{missingEntry}); err == nil {
		t.Fatal("missing immutable file accepted")
	}
	wrongSize := entry
	wrongSize.Size++
	if err := createSnapshotArchive(context.Background(), filepath.Join(root, "size.tar.zst"), source, manifestJSON, []protocol.ManifestEntry{wrongSize}); err == nil {
		t.Fatal("changed immutable file accepted")
	}

	archivePath := filepath.Join(root, "valid.tar.zst")
	if err := createSnapshotArchive(context.Background(), archivePath, source, manifestJSON, manifest.Files); err != nil {
		t.Fatal(err)
	}
	archiveDigest, err := hashFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Agent{}).streamSnapshot(context.Background(), protocol.StartSnapshotRequest{
		SnapshotID: testSnapshotID, TargetTransferURL: "not-a-url",
	}, archivePath, archiveDigest); err == nil {
		t.Fatal("invalid direct endpoint accepted")
	}
	if _, err := (&Agent{}).streamSnapshot(context.Background(), protocol.StartSnapshotRequest{
		SnapshotID: testSnapshotID, TargetTransferURL: "http://127.0.0.1:1",
	}, filepath.Join(root, "absent"), archiveDigest); err == nil {
		t.Fatal("missing archive accepted")
	}
	emptyPath := filepath.Join(root, "empty")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Agent{}).streamSnapshot(context.Background(), protocol.StartSnapshotRequest{
		SnapshotID: testSnapshotID, TargetTransferURL: "http://127.0.0.1:1",
	}, emptyPath, archiveDigest); err == nil {
		t.Fatal("empty archive accepted")
	}

	for _, testCase := range []struct {
		name        string
		status      int
		body        string
		directError bool
	}{
		{name: "business rejection", status: http.StatusBadRequest, body: `{}`},
		{name: "gateway timeout", status: http.StatusGatewayTimeout, body: `{}`, directError: true},
		{name: "malformed receipt", status: http.StatusOK, body: `not-json`},
		{name: "negative receipt", status: http.StatusOK, body: `{"ok":false}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(testCase.status)
				_, _ = io.WriteString(w, testCase.body)
			}))
			defer server.Close()
			_, err := (&Agent{}).streamSnapshot(context.Background(), protocol.StartSnapshotRequest{
				WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
				TargetTransferURL: server.URL, TransferCapability: "capability",
			}, archivePath, archiveDigest)
			if err == nil || (testCase.directError && !isSnapshotDirectUnreachable(err)) {
				t.Fatalf("transport error=%v", err)
			}
		})
	}
}

func TestRelayPullConfirmAndReceiveFailureMatrix(t *testing.T) {
	if _, err := pullRelayCiphertext(context.Background(), "http://127.0.0.1:1", "token", time.Now().Add(-time.Second)); err == nil {
		t.Fatal("expired relay capability accepted")
	}
	if _, err := pullRelayCiphertext(context.Background(), "://bad", "token", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("invalid relay URL accepted")
	}

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()
	if _, err := pullRelayCiphertext(context.Background(), notFound.URL, "token", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("relay 404 accepted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	retrying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooEarly)
		cancel()
	}))
	defer retrying.Close()
	if _, err := pullRelayCiphertext(ctx, retrying.URL, "token", time.Now().Add(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("relay retry cancellation=%v", err)
	}

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/multipart/manifest" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ciphertext")
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/complete" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ok.Close()
	response, err := pullRelayCiphertext(context.Background(), ok.URL, "token", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if err := completeRelayDownload(context.Background(), ok.URL, "token"); err != nil {
		t.Fatal(err)
	}
	if err := completeRelayDownload(context.Background(), "://bad", "token"); err == nil {
		t.Fatal("invalid completion URL accepted")
	}
	if err := completeRelayDownload(context.Background(), notFound.URL, "token"); err == nil {
		t.Fatal("relay completion 404 accepted")
	}

	dataDir := t.TempDir()
	agent, err := New(&config.AgentConfig{Role: "storage", NodeID: 9, DataDir: dataDir, BackupDir: filepath.Join(dataDir, "backup")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.RunRelayReceive(context.Background(), protocol.StartRelayReceiveRequest{}); err == nil {
		t.Fatal("invalid relay receive accepted")
	}
	if _, err := agent.RunRelayReceive(context.Background(), protocol.StartRelayReceiveRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, RelayTaskID: snapshotFailureRelayTaskID,
		RelayDownloadURL:   ok.URL + "/relay/v1/transfers/" + snapshotFailureRelayTaskID,
		RelayDownloadToken: "download", TransferCapability: "transfer", CapabilityExpires: time.Now().Add(time.Minute),
	}); err == nil {
		t.Fatal("missing relay transfer state accepted")
	}

	archivePath := filepath.Join(t.TempDir(), "archive")
	if err := os.WriteFile(archivePath, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256([]byte("archive"))
	if err := (&Agent{}).streamSnapshotRelay(context.Background(), protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, RelayTaskID: snapshotFailureRelayTaskID,
		RelayUploadURL: "://bad", RelayUploadToken: "token", RelayTargetKey: "key",
	}, archivePath, archiveDigest); err == nil {
		t.Fatal("invalid relay upload URL accepted")
	}
	if err := (&Agent{}).streamSnapshotRelay(context.Background(), protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, RelayTaskID: snapshotFailureRelayTaskID,
		RelayUploadURL:   ok.URL + "/relay/v1/transfers/" + snapshotFailureRelayTaskID,
		RelayUploadToken: "token", RelayTargetKey: "key",
	}, filepath.Join(t.TempDir(), "missing"), archiveDigest); err == nil {
		t.Fatal("missing relay archive accepted")
	}

	_, publicKey, err := controlcrypto.GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rejected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer rejected.Close()
	if err := (&Agent{}).streamSnapshotRelay(context.Background(), protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, RelayTaskID: snapshotFailureRelayTaskID,
		RelayUploadURL:   rejected.URL + "/relay/v1/transfers/" + snapshotFailureRelayTaskID,
		RelayUploadToken: "token", RelayTargetKey: publicKey,
	}, archivePath, archiveDigest); err == nil {
		t.Fatal("relay upload rejection accepted")
	}
}

func TestSnapshotMetadataPublicationAndUtilityFailures(t *testing.T) {
	staging := t.TempDir()
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", TargetNodeID: 9,
	}
	receipt := protocol.SnapshotTransferReceipt{OK: true, SnapshotID: testSnapshotID}
	if err := writeArchiveReplicaMetadata(staging, manifest, receipt); err != nil {
		t.Fatal(err)
	}
	if err := writeArchiveReplicaMetadata(staging, manifest, receipt); err == nil {
		t.Fatal("archive metadata was overwritten")
	}
	if err := writeReplicaIdentityMetadata(staging, manifest, "hot_standby"); err != nil {
		t.Fatal(err)
	}
	if err := writeReplicaIdentityMetadata(staging, manifest, "hot_standby"); err == nil {
		t.Fatal("replica identity metadata was overwritten")
	}

	if _, err := hashFile(filepath.Join(staging, "missing")); err == nil {
		t.Fatal("missing file hash succeeded")
	}
	for _, path := range []string{"", ".", string(filepath.Separator)} {
		if err := resetTaskDirectory(path); err == nil {
			t.Fatalf("unsafe task directory accepted: %q", path)
		}
	}
	if err := publishSnapshotDirectory(staging, filepath.Join(t.TempDir(), "final"), staging); err == nil {
		t.Fatal("unsafe publication path accepted")
	}
	missingStaging := filepath.Join(t.TempDir(), "task", "staging")
	if err := publishSnapshotDirectory(missingStaging, filepath.Join(t.TempDir(), "final"), filepath.Dir(missingStaging)); err == nil {
		t.Fatal("missing staging directory accepted")
	}
	if metadata, err := controllerReplicaMetadataEntry(archiveMetadataPath, nil); !metadata || err == nil {
		t.Fatalf("nil metadata entry classified metadata=%v err=%v", metadata, err)
	}
	info, err := os.Stat(staging)
	if err != nil {
		t.Fatal(err)
	}
	if metadata, err := controllerReplicaMetadataEntry(replicaIdentityPath, info); !metadata || err == nil {
		t.Fatalf("directory metadata classified metadata=%v err=%v", metadata, err)
	}
	if metadata, err := controllerReplicaMetadataEntry("data.txt", info); metadata || err != nil {
		t.Fatalf("ordinary entry classified metadata=%v err=%v", metadata, err)
	}

	filePath := filepath.Join(t.TempDir(), "file")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	badEntry := protocol.ManifestEntry{Path: "file", Size: 4, SHA256: hex.EncodeToString(make([]byte, sha256.Size))}
	if err := copyVerifiedSnapshotFile(file, bytes.NewBufferString("data"), badEntry); err == nil {
		t.Fatal("bad snapshot digest accepted")
	}
	_ = file.Close()
}

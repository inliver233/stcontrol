package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

const (
	testWorkflowID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testSnapshotID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func TestTransferCapabilityIsScopedPersistentAndOneUse(t *testing.T) {
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
	if _, err := reloaded.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now()); err == nil {
		t.Fatal("transfer capability replay was accepted after restart")
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
			Handle: "alice", SourceNodeID: 8, ActivityEpoch: 4,
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
	for _, path := range []string{"../escape", "/absolute", `C:\\escape`, ".stcontrol/hidden", "a/../../b"} {
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

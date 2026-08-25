package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

func TestConflictEvidenceTransferStreamsVerifiedArchiveAndRejectsBadReceipt(t *testing.T) {
	root := t.TempDir()
	tavernDir := filepath.Join(root, "tavern")
	userRoot := filepath.Join(tavernDir, "data", "alice")
	if err := os.MkdirAll(filepath.Join(userRoot, "chats"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userRoot, "settings.json"), []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userRoot, "chats", "one.jsonl"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 8, TavernDir: tavernDir, DataDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := a.captureConflictEvidence(context.Background(), protocol.CaptureConflictEvidenceRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", SourceKind: "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	badReceipt := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			r.URL.Path != "/transfer/v1/snapshots/"+testEvidenceID ||
			r.Header.Get("Authorization") != "Bearer transfer-capability" ||
			r.Header.Get("X-Workflow-Id") != testConflictID {
			http.Error(w, "bad scope", http.StatusForbidden)
			return
		}
		archive, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read archive: %v", readErr)
			return
		}
		archiveDigest := sha256.Sum256(archive)
		if r.Header.Get("X-Archive-Sha256") != hex.EncodeToString(archiveDigest[:]) {
			t.Errorf("archive digest header mismatch")
			return
		}
		decoder, decodeErr := zstd.NewReader(bytes.NewReader(archive))
		if decodeErr != nil {
			t.Errorf("decode archive: %v", decodeErr)
			return
		}
		defer decoder.Close()
		tarReader := tar.NewReader(decoder)
		header, nextErr := tarReader.Next()
		if nextErr != nil || header.Name != snapshotManifestPath {
			t.Errorf("manifest header=%+v err=%v", header, nextErr)
			return
		}
		manifestJSON, readErr := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if readErr != nil || int64(len(manifestJSON)) != header.Size {
			t.Errorf("read manifest: bytes=%d err=%v", len(manifestJSON), readErr)
			return
		}
		var manifest protocol.SnapshotManifest
		if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
			t.Errorf("decode manifest: %v", err)
			return
		}
		if manifest.Handle != "base-alice" {
			t.Errorf("manifest handle=%q, want base resolution handle", manifest.Handle)
			return
		}
		manifestDigest := sha256.Sum256(manifestJSON)
		snapshotID := manifest.SnapshotID
		if badReceipt {
			snapshotID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
		}
		protocol.WriteJSON(w, http.StatusOK, protocol.SnapshotTransferReceipt{
			OK: true, SnapshotID: snapshotID,
			ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
			ArchiveSHA256:  hex.EncodeToString(archiveDigest[:]),
			FileCount:      capture.FileCount,
			TotalBytes:     capture.TotalBytes,
		})
	}))
	defer target.Close()

	request := protocol.StartConflictEvidenceTransferRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", ResolutionHandle: "base-alice", SourceKind: "active",
		EntriesSHA256: capture.EntriesSHA256, FileCount: capture.FileCount,
		TotalBytes: capture.TotalBytes, TargetNodeID: 9,
		TargetTransferURL: target.URL, TransferCapability: "transfer-capability",
		CapabilityExpires: time.Now().Add(time.Minute),
	}
	receipt, err := a.RunConflictEvidenceTransfer(context.Background(), request)
	if err != nil || receipt.SnapshotID != testEvidenceID ||
		receipt.FileCount != 2 || receipt.TotalBytes != capture.TotalBytes {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	badReceipt = true
	if _, err := a.RunConflictEvidenceTransfer(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "receipt mismatch") {
		t.Fatalf("bad receipt error=%v", err)
	}
}

func TestConflictEvidenceTransferClassifiesRetryableTargetFailure(t *testing.T) {
	root := t.TempDir()
	tavernDir := filepath.Join(root, "tavern")
	userRoot := filepath.Join(tavernDir, "data", "alice")
	if err := os.MkdirAll(userRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userRoot, "settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 8, TavernDir: tavernDir, DataDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := a.captureConflictEvidence(context.Background(), protocol.CaptureConflictEvidenceRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", SourceKind: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "retry", http.StatusServiceUnavailable)
	}))
	defer target.Close()
	_, err = a.RunConflictEvidenceTransfer(context.Background(), protocol.StartConflictEvidenceTransferRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", SourceKind: "active",
		EntriesSHA256: capture.EntriesSHA256, FileCount: capture.FileCount,
		TotalBytes: capture.TotalBytes, TargetNodeID: 9,
		TargetTransferURL: target.URL, TransferCapability: "transfer-capability",
		CapabilityExpires: time.Now().Add(time.Minute),
	})
	if err == nil || !isSnapshotDirectUnreachable(err) {
		t.Fatalf("retryable target error=%v", err)
	}
}

func TestConflictEvidenceTransferUsesEncryptedRelayWithoutNodeDataURL(t *testing.T) {
	root := t.TempDir()
	tavernDir := filepath.Join(root, "tavern")
	userRoot := filepath.Join(tavernDir, "data", "alice")
	if err := os.MkdirAll(userRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userRoot, "settings.json"), []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 8, TavernDir: tavernDir, DataDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := a.captureConflictEvidence(context.Background(), protocol.CaptureConflictEvidenceRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", SourceKind: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A damaged immutable copy must be rebuilt only from the still-frozen live
	// source and only when its committed manifest remains identical.
	_, evidenceRoot, _, err := a.conflictEvidencePaths(testConflictID, testEvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidenceRoot, "settings.json"), []byte("damaged"), 0o400); err != nil {
		t.Fatal(err)
	}
	_, targetKey, err := controlcrypto.GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	taskID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/relay/v1/transfers/"+taskID+"/multipart/start" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPut || r.URL.Path != "/relay/v1/transfers/"+taskID ||
			r.Header.Get("Authorization") != "Bearer relay-upload-token" ||
			r.Header.Get("X-Workflow-Id") != testConflictID ||
			r.Header.Get("X-Snapshot-Id") != testEvidenceID {
			http.Error(w, "bad relay scope", http.StatusForbidden)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil || len(body) == 0 || r.Header.Get("X-Archive-Sha256") == "" {
			http.Error(w, "bad ciphertext", http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer relay.Close()

	receipt, err := a.RunConflictEvidenceTransfer(context.Background(), protocol.StartConflictEvidenceTransferRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", SourceKind: "active",
		EntriesSHA256: capture.EntriesSHA256, FileCount: capture.FileCount,
		TotalBytes: capture.TotalBytes, TargetNodeID: 9,
		TransferCapability: "transfer-capability", CapabilityExpires: time.Now().Add(time.Hour),
		TransferMode: "relay", RelayTaskID: taskID,
		RelayUploadURL:   relay.URL + "/relay/v1/transfers/" + taskID,
		RelayUploadToken: "relay-upload-token", RelayTargetKey: targetKey,
	})
	if err != nil || !receipt.RelayPending || receipt.SnapshotID != testEvidenceID {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
}

func TestConflictEvidenceRelayMapsSourceHandleToResolutionHandle(t *testing.T) {
	root := t.TempDir()
	sourceTavern := filepath.Join(root, "source-tavern")
	sourceUserRoot := filepath.Join(sourceTavern, "data", "source-local")
	if err := os.MkdirAll(sourceUserRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceUserRoot, "settings.json"), []byte(`{"source":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 8, TavernDir: sourceTavern, DataDir: filepath.Join(root, "source-state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 9, TavernDir: filepath.Join(root, "target-tavern"),
		DataDir: filepath.Join(root, "target-state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := source.captureConflictEvidence(context.Background(), protocol.CaptureConflictEvidenceRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "source-local", SourceKind: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	capability := "transfer-capability"
	capabilityHash := sha256.Sum256([]byte(capability))
	expiresAt := time.Now().UTC().Add(time.Hour)
	taskID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	targetKey, err := target.prepareRelayTransfer(pendingTransfer{
		WorkflowID: testConflictID, SnapshotID: testEvidenceID, GlobalUserID: 70,
		TargetNodeID: 9, Handle: "base-local", DestinationKind: "conflict_input",
		SourceNodeID: 8, ActivityEpoch: 1, CapabilityHash: hex.EncodeToString(capabilityHash[:]),
		ExpiresAt: expiresAt,
	}, taskID)
	if err != nil {
		t.Fatal(err)
	}
	relay := &snapshotRunRelay{
		taskID: taskID, uploadToken: "relay-upload-token", downloadToken: "relay-download-token",
	}
	relayServer := httptest.NewServer(relay)
	defer relayServer.Close()
	relayURL := relayServer.URL + "/relay/v1/transfers/" + taskID
	pending, err := source.RunConflictEvidenceTransfer(context.Background(), protocol.StartConflictEvidenceTransferRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID, GlobalUserID: 70,
		Handle: "source-local", ResolutionHandle: "base-local", SourceKind: "active",
		EntriesSHA256: capture.EntriesSHA256, FileCount: capture.FileCount, TotalBytes: capture.TotalBytes,
		TargetNodeID: 9, TransferCapability: capability, CapabilityExpires: expiresAt,
		TransferMode: "relay", RelayTaskID: taskID, RelayUploadURL: relayURL,
		RelayUploadToken: relay.uploadToken, RelayTargetKey: targetKey,
	})
	if err != nil || !pending.RelayPending {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	receipt, err := target.RunRelayReceive(context.Background(), protocol.StartRelayReceiveRequest{
		WorkflowID: testConflictID, SnapshotID: testEvidenceID, RelayTaskID: taskID,
		RelayDownloadURL: relayURL, RelayDownloadToken: relay.downloadToken,
		TransferCapability: capability, CapabilityExpires: expiresAt,
	})
	if err != nil || !receipt.OK || receipt.ManifestSHA256 != pending.ManifestSHA256 {
		t.Fatalf("receipt=%+v pending=%+v err=%v", receipt, pending, err)
	}
	remoteRoot := filepath.Join(target.dataRoot(), ".stcontrol-conflict-inputs", testConflictID, testEvidenceID)
	metadata, err := readArchiveReplicaMetadata(remoteRoot)
	if err != nil || metadata.Manifest.Handle != "base-local" {
		t.Fatalf("remote manifest=%+v err=%v", metadata.Manifest, err)
	}
	data, err := os.ReadFile(filepath.Join(remoteRoot, "settings.json"))
	if err != nil || string(data) != `{"source":true}` {
		t.Fatalf("published evidence=%q err=%v", data, err)
	}
}

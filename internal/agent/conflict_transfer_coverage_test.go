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
		GlobalUserID: 70, Handle: "alice", TargetNodeID: 9,
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
	if _, err := a.captureConflictEvidence(context.Background(), protocol.CaptureConflictEvidenceRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", SourceKind: "active",
	}); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "retry", http.StatusServiceUnavailable)
	}))
	defer target.Close()
	_, err = a.RunConflictEvidenceTransfer(context.Background(), protocol.StartConflictEvidenceTransferRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", TargetNodeID: 9,
		TargetTransferURL: target.URL, TransferCapability: "transfer-capability",
		CapabilityExpires: time.Now().Add(time.Minute),
	})
	if err == nil || !isSnapshotDirectUnreachable(err) {
		t.Fatalf("retryable target error=%v", err)
	}
}

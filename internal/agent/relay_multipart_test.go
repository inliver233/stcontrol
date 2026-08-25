package agent

import (
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

func TestRelayMultipartAgentRetriesOnlyFailedBoundedPart(t *testing.T) {
	t.Parallel()
	const taskID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	privateKey, publicKey, err := controlcrypto.GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	archiveData := bytes.Repeat([]byte("large-private-conflict-evidence"), int((33<<20)/31)+1)[:33<<20]
	archivePath := filepath.Join(t.TempDir(), "conflict-evidence.tar.zst")
	if err := os.WriteFile(archivePath, archiveData, 0o600); err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(archiveData)
	ciphertextBytes, err := controlcrypto.RelayCiphertextSize(int64(len(archiveData)))
	if err != nil {
		t.Fatal(err)
	}
	partCount := relayMultipartPartCount(ciphertextBytes)
	if partCount < 3 {
		t.Fatalf("test did not cross multipart boundaries: %d", partCount)
	}

	var mu sync.Mutex
	parts := make(map[int][]byte)
	attempts := make(map[int]int)
	var completed []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/relay/v1/transfers/" + taskID + "/multipart/"
		if r.Header.Get("Authorization") != "Bearer upload-token" ||
			r.Header.Get("X-Ciphertext-Length") != strconv.FormatInt(ciphertextBytes, 10) ||
			r.Header.Get("X-Workflow-Id") != testWorkflowID || r.Header.Get("X-Snapshot-Id") != testSnapshotID ||
			len(r.Header.Get("X-Relay-Upload-Session")) != 32 {
			http.Error(w, "invalid scope", http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == base+"start":
			_ = json.NewEncoder(w).Encode(relayMultipartStartResponse{
				OK: true, State: "uploading", PartBytes: relayMultipartPartBytes,
				PartCount: partCount, CiphertextBytes: ciphertextBytes,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, base+"parts/"):
			part, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, base+"parts/"))
			expected, ok := relayMultipartSize(ciphertextBytes, part)
			data, readErr := io.ReadAll(io.LimitReader(r.Body, relayMultipartPartBytes+1))
			digest := sha256.Sum256(data)
			if err != nil || !ok || readErr != nil || int64(len(data)) != expected ||
				r.ContentLength != expected || r.Header.Get("X-Part-Sha256") != hex.EncodeToString(digest[:]) {
				http.Error(w, "invalid part", http.StatusUnprocessableEntity)
				return
			}
			mu.Lock()
			attempts[part]++
			if existing := parts[part]; existing != nil && !bytes.Equal(existing, data) {
				mu.Unlock()
				http.Error(w, "part changed", http.StatusConflict)
				return
			}
			parts[part] = append([]byte(nil), data...)
			attempt := attempts[part]
			mu.Unlock()
			// Simulate a lost/gateway-failed acknowledgement after the bytes were
			// accepted. The Agent must retry this part, not restart the whole file.
			if part == 1 && attempt == 1 {
				http.Error(w, "temporary gateway failure", http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == base+"complete":
			mu.Lock()
			for part := 0; part < partCount; part++ {
				completed = append(completed, parts[part]...)
			}
			got := sha256.Sum256(completed)
			mu.Unlock()
			if int64(len(completed)) != ciphertextBytes ||
				r.Header.Get("X-Ciphertext-Sha256") != hex.EncodeToString(got[:]) {
				http.Error(w, "invalid completion", http.StatusUnprocessableEntity)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err = (&Agent{}).streamSnapshotRelay(context.Background(), protocol.StartSnapshotRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, RelayTaskID: taskID,
		RelayUploadURL:   server.URL + "/relay/v1/transfers/" + taskID,
		RelayUploadToken: "upload-token", RelayTargetKey: publicKey,
	}, archivePath, archiveDigest)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts[0] != 1 || attempts[1] != 2 || attempts[2] != 1 {
		t.Fatalf("unexpected per-part attempts: %v", attempts)
	}
	var plaintext bytes.Buffer
	if _, err := controlcrypto.DecryptRelayStream(
		context.Background(), &plaintext, bytes.NewReader(completed), privateKey,
		controlcrypto.RelayCipherContext{
			TaskID: taskID, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		},
	); err != nil || !bytes.Equal(plaintext.Bytes(), archiveData) {
		t.Fatalf("reassembled ciphertext failed authentication: bytes=%d err=%v", plaintext.Len(), err)
	}
}

func TestRelayMultipartDownloadRetriesOnlyInterruptedPart(t *testing.T) {
	t.Parallel()
	pattern := []byte("downloaded-opaque-ciphertext")
	ciphertext := bytes.Repeat(pattern, int((33<<20)/len(pattern))+1)[:33<<20]
	ciphertextDigest := sha256.Sum256(ciphertext)
	archiveDigest := sha256.Sum256([]byte("archive"))
	partCount := relayMultipartPartCount(int64(len(ciphertext)))
	var mu sync.Mutex
	attempts := make(map[int]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer download-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/relay/v1/transfers/task/multipart/manifest" {
			_ = json.NewEncoder(w).Encode(relayMultipartManifest{
				OK: true, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
				PlaintextBytes: 1, CiphertextBytes: int64(len(ciphertext)),
				ArchiveSHA256:    hex.EncodeToString(archiveDigest[:]),
				CiphertextSHA256: hex.EncodeToString(ciphertextDigest[:]),
				PartBytes:        relayMultipartPartBytes, PartCount: partCount,
			})
			return
		}
		prefix := "/relay/v1/transfers/task/multipart/parts/"
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		part, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, prefix))
		partBytes, ok := relayMultipartSize(int64(len(ciphertext)), part)
		if err != nil || !ok {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		attempts[part]++
		attempt := attempts[part]
		mu.Unlock()
		if part == 1 && attempt == 1 {
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		offset := int64(part) * relayMultipartPartBytes
		w.Header().Set("Content-Type", "application/vnd.stcontrol.relay.v1")
		w.Header().Set("Content-Length", strconv.FormatInt(partBytes, 10))
		w.Header().Set("X-Part-Index", strconv.Itoa(part))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext[offset : offset+partBytes])
	}))
	defer server.Close()
	response, err := pullRelayCiphertext(
		context.Background(), server.URL+"/relay/v1/transfers/task", "download-token", time.Now().Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || !bytes.Equal(data, ciphertext) {
		t.Fatalf("multipart download bytes=%d err=%v", len(data), err)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts[0] != 1 || attempts[1] != 2 || attempts[2] != 1 {
		t.Fatalf("unexpected per-part download attempts: %v", attempts)
	}
}

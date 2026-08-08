package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/store"
)

type fakeRelayStore struct {
	transfer         *store.RelayTransfer
	completedPath    string
	completedHash    []byte
	completedBytes   int64
	releasedUpload   bool
	releasedDownload bool
}

func (fake *fakeRelayStore) ClaimRelayUpload(
	_ context.Context, _ string, _ []byte, plaintextBytes, ciphertextBytes int64,
	archiveSHA256 []byte, _ time.Time, _ time.Duration,
) (*store.RelayTransfer, error) {
	out := *fake.transfer
	out.State = "uploading"
	out.PlaintextBytes.Valid = true
	out.PlaintextBytes.Int64 = plaintextBytes
	out.ArchiveSHA256 = append([]byte(nil), archiveSHA256...)
	if ciphertextBytes > out.MaxCiphertextBytes {
		return nil, store.ErrRelayTransferState
	}
	return &out, nil
}

func (fake *fakeRelayStore) CompleteRelayUpload(
	_ context.Context, _ string, _ []byte, ciphertextSHA256 []byte,
	ciphertextBytes int64, storagePath string, _ time.Time,
) error {
	fake.completedPath = storagePath
	fake.completedHash = append([]byte(nil), ciphertextSHA256...)
	fake.completedBytes = ciphertextBytes
	return nil
}

func (fake *fakeRelayStore) ReleaseRelayUpload(context.Context, string, []byte, time.Time) error {
	fake.releasedUpload = true
	return nil
}

func (fake *fakeRelayStore) ClaimRelayDownload(
	_ context.Context, _ string, _ []byte, _ time.Time, _ time.Duration,
) (*store.RelayTransfer, error) {
	out := *fake.transfer
	out.State = "downloading"
	out.StoragePath.Valid = true
	out.StoragePath.String = fake.completedPath
	out.PlaintextBytes.Valid = true
	out.PlaintextBytes.Int64 = fake.transfer.PlaintextBytes.Int64
	out.CiphertextBytes.Valid = true
	out.CiphertextBytes.Int64 = fake.completedBytes
	out.ArchiveSHA256 = append([]byte(nil), fake.transfer.ArchiveSHA256...)
	out.CiphertextSHA256 = append([]byte(nil), fake.completedHash...)
	return &out, nil
}

func (fake *fakeRelayStore) ReleaseRelayDownload(context.Context, string, []byte, time.Time) error {
	fake.releasedDownload = true
	return nil
}

func (fake *fakeRelayStore) CompleteRelayDownload(context.Context, string, []byte, time.Time) (string, error) {
	return fake.completedPath, nil
}

func (fake *fakeRelayStore) ExpireRelayTransfers(context.Context, time.Time, int) ([]store.ExpiredRelayTransfer, error) {
	return nil, nil
}

func TestEncryptedRelaySpoolsOpaqueCiphertextOnSeparateHandler(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	taskID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	workflowID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	snapshotID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	privateKey, publicKey, err := controlcrypto.GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte("private-user-archive"), 1000)
	var ciphertext bytes.Buffer
	if _, err := controlcrypto.EncryptRelayStream(
		context.Background(), &ciphertext, bytes.NewReader(plaintext), publicKey,
		controlcrypto.RelayCipherContext{TaskID: taskID, WorkflowID: workflowID, SnapshotID: snapshotID},
	); err != nil {
		t.Fatal(err)
	}
	archiveHash := sha256.Sum256(plaintext)
	fake := &fakeRelayStore{transfer: &store.RelayTransfer{
		ID: taskID, WorkflowID: workflowID, SnapshotID: snapshotID,
		SourceNodeID: 7, TargetNodeID: 9, MaxCiphertextBytes: int64(ciphertext.Len()) + 1024,
		PlaintextBytes: sqlNullInt64(int64(len(plaintext))), ArchiveSHA256: archiveHash[:],
	}}
	relay, err := newRelayDataPlane(configRelayView{
		DataDir: root, MaxBytes: 1 << 30, RetentionMin: 60, MaxConcurrent: 2,
	}, fake)
	if err != nil {
		t.Fatal(err)
	}
	token := "upload-token-with-at-least-thirty-two-random-characters"
	request := httptest.NewRequest(http.MethodPut, "/relay/v1/transfers/"+taskID, bytes.NewReader(ciphertext.Bytes()))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", relayContentType)
	request.Header.Set("X-Workflow-Id", workflowID)
	request.Header.Set("X-Snapshot-Id", snapshotID)
	request.Header.Set("X-Plaintext-Length", strconv.FormatInt(int64(len(plaintext)), 10))
	request.Header.Set("X-Archive-Sha256", hex.EncodeToString(archiveHash[:]))
	request.ContentLength = int64(ciphertext.Len())
	recorder := httptest.NewRecorder()
	relay.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || fake.completedPath == "" || fake.completedBytes != int64(ciphertext.Len()) {
		t.Fatalf("status=%d body=%s path=%q bytes=%d", recorder.Code, recorder.Body.String(), fake.completedPath, fake.completedBytes)
	}
	spooled, err := os.ReadFile(fake.completedPath)
	if err != nil || !bytes.Equal(spooled, ciphertext.Bytes()) || bytes.Contains(spooled, plaintext) {
		t.Fatalf("relay did not preserve opaque ciphertext: equal=%v plaintext_visible=%v err=%v",
			bytes.Equal(spooled, ciphertext.Bytes()), bytes.Contains(spooled, plaintext), err)
	}

	downloadToken := "download-token-with-at-least-thirty-two-random-characters"
	download := httptest.NewRequest(http.MethodGet, "/relay/v1/transfers/"+taskID, nil)
	download.Header.Set("Authorization", "Bearer "+downloadToken)
	downloadRecorder := httptest.NewRecorder()
	relay.Handler().ServeHTTP(downloadRecorder, download)
	if downloadRecorder.Code != http.StatusOK || !bytes.Equal(downloadRecorder.Body.Bytes(), ciphertext.Bytes()) ||
		downloadRecorder.Header().Get("X-Workflow-Id") != workflowID {
		t.Fatalf("status=%d body-bytes=%d headers=%v", downloadRecorder.Code, downloadRecorder.Body.Len(), downloadRecorder.Header())
	}
	var decrypted bytes.Buffer
	if _, err := controlcrypto.DecryptRelayStream(
		context.Background(), &decrypted, bytes.NewReader(downloadRecorder.Body.Bytes()), privateKey,
		controlcrypto.RelayCipherContext{TaskID: taskID, WorkflowID: workflowID, SnapshotID: snapshotID},
	); err != nil || !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("target could not decrypt relay body: err=%v", err)
	}

	complete := httptest.NewRequest(http.MethodPost, "/relay/v1/transfers/"+taskID+"/complete", nil)
	complete.Header.Set("Authorization", "Bearer "+downloadToken)
	completeRecorder := httptest.NewRecorder()
	relay.Handler().ServeHTTP(completeRecorder, complete)
	if completeRecorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", completeRecorder.Code, completeRecorder.Body.String())
	}
	if _, err := os.Stat(fake.completedPath); !os.IsNotExist(err) {
		t.Fatalf("consumed relay ciphertext still exists: %v", err)
	}
}

func TestEncryptedRelayRejectsDatabasePathEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "outside.ciphertext")
	if err := os.WriteFile(external, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRelayStore{transfer: &store.RelayTransfer{
		ID:                 "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		WorkflowID:         "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		SnapshotID:         "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		MaxCiphertextBytes: 1024, PlaintextBytes: sqlNullInt64(10),
		ArchiveSHA256: make([]byte, 32),
	}}
	fake.completedPath = external
	fake.completedBytes = 10
	fake.completedHash = make([]byte, 32)
	relay, err := newRelayDataPlane(configRelayView{DataDir: root, MaxBytes: 1024, RetentionMin: 5, MaxConcurrent: 1}, fake)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/relay/v1/transfers/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", nil)
	request.Header.Set("Authorization", "Bearer download-token-with-at-least-thirty-two-characters")
	recorder := httptest.NewRecorder()
	relay.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity || !fake.releasedDownload {
		t.Fatalf("status=%d released=%v body=%s", recorder.Code, fake.releasedDownload, recorder.Body.String())
	}
}

func TestValidateRelayListenerConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     config.RelayConfig
		wantErr bool
	}{
		{
			name: "loopback plaintext",
			cfg:  config.RelayConfig{Listen: "127.0.0.1:9444", PublicURL: "http://localhost:9444"},
		},
		{
			name:    "remote public url requires tls",
			cfg:     config.RelayConfig{Listen: "127.0.0.1:9444", PublicURL: "http://relay.example:9444"},
			wantErr: true,
		},
		{
			name:    "plaintext listener cannot bind all interfaces",
			cfg:     config.RelayConfig{Listen: ":9444", PublicURL: "http://localhost:9444"},
			wantErr: true,
		},
		{
			name: "remote tls",
			cfg: config.RelayConfig{
				Listen: ":9444", PublicURL: "https://relay.example:9444",
				TLSCertFile: "relay.crt", TLSKeyFile: "relay.key",
			},
		},
		{
			name:    "partial tls pair",
			cfg:     config.RelayConfig{Listen: "127.0.0.1:9444", PublicURL: "https://relay.example", TLSCertFile: "relay.crt"},
			wantErr: true,
		},
		{
			name:    "credentials forbidden in url",
			cfg:     config.RelayConfig{Listen: "127.0.0.1:9444", PublicURL: "https://user@relay.example", TLSCertFile: "relay.crt", TLSKeyFile: "relay.key"},
			wantErr: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateRelayListenerConfig(test.cfg)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateRelayListenerConfig() error = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}

func sqlNullInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: true}
}

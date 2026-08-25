package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
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
	transfer            *store.RelayTransfer
	completedPath       string
	completedHash       []byte
	completedBytes      int64
	releasedUpload      bool
	releasedDownload    bool
	uploadState         string
	claimUploadErr      error
	completeUploadErr   error
	claimDownloadNil    bool
	claimDownloadErr    error
	completeDownloadErr error
	expired             []store.ExpiredRelayTransfer
}

func (fake *fakeRelayStore) ClaimRelayUpload(
	_ context.Context, _ string, _ []byte, plaintextBytes, ciphertextBytes int64,
	archiveSHA256 []byte, _ time.Time, _ time.Duration,
) (*store.RelayTransfer, error) {
	if fake.claimUploadErr != nil {
		return nil, fake.claimUploadErr
	}
	out := *fake.transfer
	out.State = fake.uploadState
	if out.State == "" {
		out.State = "uploading"
	}
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
	if fake.completeUploadErr != nil {
		return fake.completeUploadErr
	}
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
	if fake.claimDownloadErr != nil {
		return nil, fake.claimDownloadErr
	}
	if fake.claimDownloadNil {
		return nil, nil
	}
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

func (fake *fakeRelayStore) ClampRelayDownloadLease(context.Context, string, []byte, time.Time, time.Duration) error {
	return nil
}

func (fake *fakeRelayStore) RenewRelayDownload(context.Context, string, []byte, time.Time, time.Duration) (bool, error) {
	return true, nil
}

func (fake *fakeRelayStore) CompleteRelayDownload(context.Context, string, []byte, time.Time) (string, error) {
	if fake.completeDownloadErr != nil {
		return "", fake.completeDownloadErr
	}
	return fake.completedPath, nil
}

func (fake *fakeRelayStore) ExpireRelayTransfers(context.Context, time.Time, int) ([]store.ExpiredRelayTransfer, error) {
	return fake.expired, nil
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

func TestEncryptedRelayFailsClosedAcrossUploadDownloadAndCleanupErrors(t *testing.T) {
	t.Parallel()
	const (
		taskID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		workflowID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		snapshotID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		token      = "relay-token-with-at-least-thirty-two-characters"
	)
	plaintextBytes := int64(128)
	ciphertextBytes, err := controlcrypto.RelayCiphertextSize(plaintextBytes)
	if err != nil {
		t.Fatal(err)
	}
	archiveHash := sha256.Sum256([]byte("bounded-relay-plaintext"))
	newPlane := func(t *testing.T, fake *fakeRelayStore) *relayDataPlane {
		t.Helper()
		if fake.transfer == nil {
			fake.transfer = &store.RelayTransfer{
				ID: taskID, WorkflowID: workflowID, SnapshotID: snapshotID,
				SourceNodeID: 7, TargetNodeID: 9, MaxCiphertextBytes: ciphertextBytes,
				PlaintextBytes: sqlNullInt64(plaintextBytes), ArchiveSHA256: archiveHash[:],
			}
		}
		plane, err := newRelayDataPlane(configRelayView{
			DataDir: t.TempDir(), MaxBytes: ciphertextBytes + 1024,
			RetentionMin: 5, MaxConcurrent: 1,
		}, fake)
		if err != nil {
			t.Fatal(err)
		}
		return plane
	}
	validUpload := func(body []byte) *http.Request {
		request := httptest.NewRequest(http.MethodPut, "/relay/v1/transfers/"+taskID, bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", relayContentType)
		request.Header.Set("X-Workflow-Id", workflowID)
		request.Header.Set("X-Snapshot-Id", snapshotID)
		request.Header.Set("X-Plaintext-Length", strconv.FormatInt(plaintextBytes, 10))
		request.Header.Set("X-Archive-Sha256", hex.EncodeToString(archiveHash[:]))
		request.ContentLength = ciphertextBytes
		return request
	}

	t.Run("concurrency saturation", func(t *testing.T) {
		plane := newPlane(t, &fakeRelayStore{})
		plane.slots <- struct{}{}
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, validUpload(bytes.Repeat([]byte{1}, int(ciphertextBytes))))
		<-plane.slots
		if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "5" {
			t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
		}
	})

	t.Run("missing bearer", func(t *testing.T) {
		plane := newPlane(t, &fakeRelayStore{})
		request := validUpload(bytes.Repeat([]byte{1}, int(ciphertextBytes)))
		request.Header.Del("Authorization")
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("ciphertext length disagreement", func(t *testing.T) {
		plane := newPlane(t, &fakeRelayStore{})
		request := validUpload(bytes.Repeat([]byte{1}, int(ciphertextBytes)+1))
		request.ContentLength = ciphertextBytes + 1
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("store claim mismatch", func(t *testing.T) {
		fake := &fakeRelayStore{transfer: &store.RelayTransfer{
			ID: taskID, WorkflowID: "different-workflow", SnapshotID: snapshotID,
			MaxCiphertextBytes: ciphertextBytes,
		}}
		plane := newPlane(t, fake)
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, validUpload(bytes.Repeat([]byte{1}, int(ciphertextBytes))))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("stored upload replay", func(t *testing.T) {
		plane := newPlane(t, &fakeRelayStore{uploadState: "stored"})
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, validUpload(bytes.Repeat([]byte{1}, int(ciphertextBytes))))
		if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"state":"stored"`)) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("short body", func(t *testing.T) {
		fake := &fakeRelayStore{}
		plane := newPlane(t, fake)
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, validUpload(bytes.Repeat([]byte{1}, int(ciphertextBytes)-1)))
		if recorder.Code != http.StatusUnprocessableEntity || !fake.releasedUpload {
			t.Fatalf("status=%d released=%v body=%s", recorder.Code, fake.releasedUpload, recorder.Body.String())
		}
	})

	t.Run("completion conflict", func(t *testing.T) {
		fake := &fakeRelayStore{completeUploadErr: errors.New("conflict")}
		plane := newPlane(t, fake)
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, validUpload(bytes.Repeat([]byte{1}, int(ciphertextBytes))))
		if recorder.Code != http.StatusConflict || !fake.releasedUpload {
			t.Fatalf("status=%d released=%v body=%s", recorder.Code, fake.releasedUpload, recorder.Body.String())
		}
	})

	t.Run("download authorization", func(t *testing.T) {
		plane := newPlane(t, &fakeRelayStore{})
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/relay/v1/transfers/"+taskID, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("download not ready", func(t *testing.T) {
		plane := newPlane(t, &fakeRelayStore{claimDownloadNil: true})
		request := httptest.NewRequest(http.MethodGet, "/relay/v1/transfers/"+taskID, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusTooEarly || recorder.Header().Get("Retry-After") != "2" {
			t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
		}
	})

	t.Run("download terminal", func(t *testing.T) {
		plane := newPlane(t, &fakeRelayStore{claimDownloadErr: store.ErrRelayTransferTerminal})
		request := httptest.NewRequest(http.MethodGet, "/relay/v1/transfers/"+taskID, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusGone {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("download file missing", func(t *testing.T) {
		fake := &fakeRelayStore{completedBytes: 5, completedHash: bytes.Repeat([]byte{2}, 32)}
		plane := newPlane(t, fake)
		fake.completedPath = filepath.Join(plane.root, "missing.ciphertext")
		request := httptest.NewRequest(http.MethodGet, "/relay/v1/transfers/"+taskID, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusGone || !fake.releasedDownload {
			t.Fatalf("status=%d released=%v body=%s", recorder.Code, fake.releasedDownload, recorder.Body.String())
		}
	})

	t.Run("download size mismatch", func(t *testing.T) {
		fake := &fakeRelayStore{completedBytes: 5, completedHash: bytes.Repeat([]byte{2}, 32)}
		plane := newPlane(t, fake)
		fake.completedPath = filepath.Join(plane.root, "wrong-size.ciphertext")
		if err := os.WriteFile(fake.completedPath, []byte("four"), 0o600); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/relay/v1/transfers/"+taskID, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		plane.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnprocessableEntity || !fake.releasedDownload {
			t.Fatalf("status=%d released=%v body=%s", recorder.Code, fake.releasedDownload, recorder.Body.String())
		}
	})

	t.Run("complete authorization and state conflict", func(t *testing.T) {
		fake := &fakeRelayStore{completeDownloadErr: errors.New("conflict")}
		plane := newPlane(t, fake)
		unauthorized := httptest.NewRecorder()
		plane.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/relay/v1/transfers/"+taskID+"/complete", nil))
		if unauthorized.Code != http.StatusForbidden {
			t.Fatalf("unauthorized status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
		}
		request := httptest.NewRequest(http.MethodPost, "/relay/v1/transfers/"+taskID+"/complete", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		conflict := httptest.NewRecorder()
		plane.Handler().ServeHTTP(conflict, request)
		if conflict.Code != http.StatusConflict {
			t.Fatalf("conflict status=%d body=%s", conflict.Code, conflict.Body.String())
		}
	})

	t.Run("cleanup removes only expired relay artifacts", func(t *testing.T) {
		fake := &fakeRelayStore{}
		plane := newPlane(t, fake)
		expiredPath := filepath.Join(plane.root, "expired.ciphertext")
		orphanPath := filepath.Join(plane.root, ".relay-upload-orphan.ciphertext")
		preservedPath := filepath.Join(plane.root, "ordinary-file")
		for _, path := range []string{expiredPath, orphanPath, preservedPath} {
			if err := os.WriteFile(path, []byte("opaque"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		old := time.Now().Add(-3 * plane.retention)
		if err := os.Chtimes(orphanPath, old, old); err != nil {
			t.Fatal(err)
		}
		fake.expired = []store.ExpiredRelayTransfer{{
			ID: taskID, StoragePath: sql.NullString{String: expiredPath, Valid: true},
		}}
		plane.Cleanup(context.Background())
		for _, removed := range []string{expiredPath, orphanPath} {
			if _, err := os.Stat(removed); !os.IsNotExist(err) {
				t.Fatalf("relay cleanup preserved %s: %v", removed, err)
			}
		}
		if _, err := os.Stat(preservedPath); err != nil {
			t.Fatalf("relay cleanup removed unrelated file: %v", err)
		}
	})
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
			name: "tls listener requires https advertisement",
			cfg: config.RelayConfig{
				Listen: "127.0.0.1:9444", PublicURL: "http://localhost:9444",
				TLSCertFile: "relay.crt", TLSKeyFile: "relay.key",
			},
			wantErr: true,
		},
		{
			name: "invalid listener with tls",
			cfg: config.RelayConfig{
				Listen: "not-an-address", PublicURL: "https://relay.example:9444",
				TLSCertFile: "relay.crt", TLSKeyFile: "relay.key",
			},
			wantErr: true,
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

func TestEmbeddedRelaySharesControllerOriginWithoutItsOwnTLS(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultController().Relay
	cfg.PublicURL = "https://controller.example"
	cfg.Listen = ""
	if err := validateEmbeddedRelayConfig("https://controller.example", cfg); err != nil {
		t.Fatalf("valid embedded relay rejected: %v", err)
	}
	for _, mutate := range []func(*config.RelayConfig){
		func(cfg *config.RelayConfig) { cfg.PublicURL = "https://other.example" },
		func(cfg *config.RelayConfig) { cfg.TLSCertFile, cfg.TLSKeyFile = "relay.crt", "relay.key" },
		func(cfg *config.RelayConfig) { cfg.MaxConcurrent = 0 },
	} {
		invalid := cfg
		mutate(&invalid)
		if err := validateEmbeddedRelayConfig("https://controller.example", invalid); err == nil {
			t.Fatalf("invalid embedded relay accepted: %+v", invalid)
		}
	}
}

func TestEmbeddedRelayBypassesControlMiddlewareAndKeepsFixedRoute(t *testing.T) {
	t.Parallel()
	server := &Server{
		Cfg:   config.DefaultController(),
		relay: &relayDataPlane{maxBytes: 1 << 20, slots: make(chan struct{}, 1)},
	}
	request := httptest.NewRequest(http.MethodGet, "/relay/v1/transfers/not-a-uuid", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("embedded relay status=%d body=%s", response.Code, response.Body.String())
	}
}

func sqlNullInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: true}
}

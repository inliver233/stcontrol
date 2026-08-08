package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestPasswordLoginCreatesRecoveryOnlySessionForConflictUser(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	passwordHash, err := controlcrypto.HashPassword("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)FROM users u.*WHERE username=\$1`).WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "global_id", "uuid", "username", "display_name", "password_enc", "password_hash",
			"auth_provider", "oauth_id", "avatar_url", "email", "home_node_id", "status", "created_at",
		}).AddRow(int64(7), int64(70), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "alice", "Alice",
			nil, passwordHash, "password", nil, nil, nil, int64(8), "conflict", now))
	mock.ExpectQuery(`INSERT INTO controller_sessions`).
		WithArgs(sqlmock.AnyArg(), int64(70), nil, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(4)))
	server := &Server{
		Cfg:   &config.ControllerConfig{PublicURL: "https://control.example"},
		Store: &store.Store{DB: db}, secretKey: []byte("01234567890123456789012345678901"),
	}
	req := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/login",
		strings.NewReader(`{"username":"Alice","password":"correct-password"}`))
	recorder := httptest.NewRecorder()
	server.handleLogin(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response["recovery_required"] != true {
		t.Fatalf("response=%v err=%v", response, err)
	}
	if len(recorder.Result().Cookies()) != 2 {
		t.Fatalf("cookies=%+v", recorder.Result().Cookies())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildConflictDifferencesKeepsDisjointAndSamePathSeparate(t *testing.T) {
	t.Parallel()
	conflict := &store.ReplicaConflict{
		ID: "conflict",
		Sources: []store.ReplicaConflictSource{
			{NodeID: 8, NodeName: "node-a"},
			{NodeID: 9, NodeName: "node-b"},
		},
	}
	entries := map[int64]map[string]protocol.ManifestEntry{
		8: {
			"same.json":          {Path: "same.json", Size: 5, SHA256: strings.Repeat("1", 64)},
			"only-a.txt":         {Path: "only-a.txt", Size: 3, SHA256: strings.Repeat("2", 64)},
			"chats/thread.jsonl": {Path: "chats/thread.jsonl", Size: 8, SHA256: strings.Repeat("3", 64)},
		},
		9: {
			"same.json":          {Path: "same.json", Size: 5, SHA256: strings.Repeat("1", 64)},
			"only-b.bin":         {Path: "only-b.bin", Size: 4, SHA256: strings.Repeat("4", 64)},
			"chats/thread.jsonl": {Path: "chats/thread.jsonl", Size: 9, SHA256: strings.Repeat("5", 64)},
		},
	}
	response := buildConflictDifferences(conflict, entries)
	if response.Total != 3 || response.OnlyOnSome != 2 || response.Different != 1 {
		t.Fatalf("response=%+v", response)
	}
	if response.Files[0].Path != "chats/thread.jsonl" || response.Files[0].Category != "chat_or_log" ||
		response.Files[0].Policy != "choose_source_or_preserve_both" {
		t.Fatalf("first difference=%+v", response.Files[0])
	}
	if response.Files[1].Policy != "auto_merge_disjoint_path" {
		t.Fatalf("disjoint difference=%+v", response.Files[1])
	}
}

func TestLoadConflictEvidenceEntriesDecryptsAndRevalidates(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{
		Store: &store.Store{DB: db}, secretKey: []byte("01234567890123456789012345678901"),
	}
	evidenceID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	entries := []protocol.ManifestEntry{{Path: "settings.json", Size: 5, SHA256: strings.Repeat("a", 64)}}
	page := protocol.ConflictEvidencePage{
		EvidenceID: evidenceID, Cursor: 0, NextCursor: 1, Complete: true, Entries: entries,
	}
	plaintext, _ := json.Marshal(page)
	ciphertext, err := controlcrypto.Encrypt(server.deriveConflictEvidenceKey("at-rest", evidenceID), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`(?s)FROM replica_conflict_sources source.*replica_conflict_manifest_pages`).
		WithArgs("conflict", int64(8)).
		WillReturnRows(sqlmock.NewRows([]string{"encrypted_payload"}).AddRow(ciphertext))
	entriesJSON, _ := json.Marshal(entries)
	digest := sha256.Sum256(entriesJSON)
	source := store.ReplicaConflictSource{
		NodeID: 8, EvidenceID: evidenceID, EvidenceState: "ready", EvidenceSHA256: digest[:],
		EvidenceFileCount:  sql.NullInt64{Int64: 1, Valid: true},
		EvidenceTotalBytes: sql.NullInt64{Int64: 5, Valid: true},
	}
	got, err := server.loadConflictEvidenceEntries(context.Background(), "conflict", source)
	if err != nil || len(got) != 1 || got[0].Path != "settings.json" {
		t.Fatalf("entries=%+v err=%v", got, err)
	}
	if err := validateConflictEvidenceEntries([]protocol.ManifestEntry{
		{Path: "../escape", Size: 1, SHA256: strings.Repeat("a", 64)},
	}, 1); err == nil {
		t.Fatal("unsafe persisted path was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestConflictSessionCanOnlyReachConflictRoute(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	token := "conflict-session-token"
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := make([]byte, sha256.Size)
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	mock.ExpectQuery(`(?s)FROM controller_sessions s.*gu.status='conflict'.*JOIN replica_conflicts conflict`).
		WithArgs(tokenHash[:], sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "legacy_user_id", "user_id", "admin_id", "username", "is_admin",
			"csrf_hash", "expires_at", "last_seen_at", "controller_generation",
		}).AddRow("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", int64(7), int64(70), int64(0),
			"alice", false, csrfHash, expires, now, int64(4)))
	mock.ExpectQuery(`FROM replica_conflicts`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "state", "protection_version", "generation", "version", "detected", "updated",
		}).AddRow("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "detected", int64(2), int64(4), int64(1), now, now))
	mock.ExpectQuery(`FROM replica_conflict_sources`).WithArgs("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "node_name", "node_role", "snapshot_id", "source_kind", "replica_state",
			"authoritative", "manifest", "files", "bytes", "published", "data_version", "checksum", "captured",
			"evidence_id", "evidence_state", "evidence_basis", "evidence_sha", "evidence_files", "evidence_bytes",
		}).AddRow(int64(8), "compute-a", "compute", nil, "active", "conflict", true,
			nil, nil, nil, nil, int64(8), "legacy", now,
			"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "pending", nil, nil, nil, nil))
	server := &Server{
		Cfg:   &config.ControllerConfig{PublicURL: "https://control.example"},
		Store: &store.Store{DB: db}, secretKey: []byte("01234567890123456789012345678901"),
	}
	req := httptest.NewRequest(http.MethodGet, "https://control.example/api/conflicts/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"capture_required"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	mock.ExpectQuery(`SELECT s.id, gu.legacy_user_id`).WithArgs(tokenHash[:], sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "legacy_user_id", "user_id", "admin_id", "username", "is_admin",
			"csrf_hash", "expires_at", "last_seen_at", "controller_generation",
		}))
	normalReq := httptest.NewRequest(http.MethodGet, "https://control.example/api/users/me", nil)
	normalReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	normalRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(normalRecorder, normalReq)
	if normalRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("normal route status=%d body=%s", normalRecorder.Code, normalRecorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConflictResolutionChoicesRequiresExplicitSourceWhenBaseMissing(t *testing.T) {
	t.Parallel()
	conflict := &store.ReplicaConflict{
		ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Sources: []store.ReplicaConflictSource{
			{NodeID: 8, NodeRole: "compute"},
			{NodeID: 9, NodeRole: "compute"},
			{NodeID: 10, NodeRole: "storage"},
		},
	}
	entries := map[int64]map[string]protocol.ManifestEntry{
		8:  {"only-base.txt": {Path: "only-base.txt", Size: 1, SHA256: strings.Repeat("1", 64)}},
		9:  {"same.json": {Path: "same.json", Size: 2, SHA256: strings.Repeat("2", 64)}},
		10: {"same.json": {Path: "same.json", Size: 3, SHA256: strings.Repeat("3", 64)}},
	}
	req := startConflictResolutionRequest{BaseNodeID: 8, DefaultAction: "preserve_all_originals"}
	if _, err := validateConflictResolutionChoices(conflict, entries, req); err == nil {
		t.Fatal("missing explicit choice for a conflict absent from the base was accepted")
	}
	req.Decisions = []conflictResolutionDecisionRequest{
		{Path: "same.json", SourceNodeID: 9, Action: "preserve_both"},
	}
	decisions, err := validateConflictResolutionChoices(conflict, entries, req)
	if err != nil || len(decisions) != 1 || decisions[0].SourceNodeID != 9 {
		t.Fatalf("decisions=%+v err=%v", decisions, err)
	}
	req.Decisions = []conflictResolutionDecisionRequest{
		{Path: "only-base.txt", SourceNodeID: 8, Action: "use_source"},
	}
	if _, err := validateConflictResolutionChoices(conflict, entries, req); err == nil {
		t.Fatal("decision for a disjoint path was accepted")
	}
}

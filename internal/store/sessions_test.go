package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCreateControllerSessionValidatesPrincipalAndHashes(t *testing.T) {
	t.Parallel()
	store := &Store{}
	_, err := store.CreateControllerSession(context.Background(), CreateControllerSessionParams{})
	if !errors.Is(err, ErrInvalidControllerSession) {
		t.Fatalf("CreateControllerSession error=%v, want ErrInvalidControllerSession", err)
	}
	userID, adminID := int64(1), int64(2)
	_, err = store.CreateControllerSession(context.Background(), CreateControllerSessionParams{
		ID: "session", UserID: &userID, AdminID: &adminID,
		TokenHash: make([]byte, 32), CSRFHash: make([]byte, 32),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if !errors.Is(err, ErrInvalidControllerSession) {
		t.Fatalf("dual-principal session error=%v, want ErrInvalidControllerSession", err)
	}
}

func TestCreateAndGetControllerSession(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 15, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	userID := int64(70)
	tokenHash := make([]byte, 32)
	csrfHash := make([]byte, 32)
	p := CreateControllerSessionParams{
		ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", UserID: &userID,
		TokenHash: tokenHash, CSRFHash: csrfHash, ExpiresAt: expires, Now: now,
	}

	mock.ExpectQuery(`INSERT INTO controller_sessions`).
		WithArgs(p.ID, userID, nil, tokenHash, csrfHash, expires, now).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(4)))
	generation, err := store.CreateControllerSession(context.Background(), p)
	if err != nil || generation != 4 {
		t.Fatalf("CreateControllerSession generation=%d err=%v", generation, err)
	}

	mock.ExpectQuery(`SELECT s.id, gu.legacy_user_id`).
		WithArgs(tokenHash, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "legacy_user_id", "user_id", "admin_id", "username", "is_admin",
			"csrf_hash", "expires_at", "last_seen_at", "controller_generation",
		}).AddRow(p.ID, int64(7), userID, nil, "alice", false, csrfHash, expires, now, int64(4)))
	session, err := store.GetControllerSession(context.Background(), tokenHash, now)
	if err != nil {
		t.Fatalf("GetControllerSession: %v", err)
	}
	if session == nil || session.LegacyUserID != 7 || session.GlobalUserID != 70 || session.Username != "alice" || session.IsAdmin {
		t.Fatalf("unexpected session: %+v", session)
	}
	assertMockExpectations(t, mock)
}

func TestControllerSessionLifecycleOperations(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 15, 0, 0, 0, time.UTC)
	tokenHash := make([]byte, 32)

	mock.ExpectExec(`UPDATE controller_sessions SET last_seen_at=\$2`).
		WithArgs("session-id", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.TouchControllerSession(context.Background(), "session-id", now); err != nil {
		t.Fatalf("TouchControllerSession: %v", err)
	}

	mock.ExpectExec(`UPDATE controller_sessions SET revoked_at=COALESCE`).
		WithArgs(tokenHash, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.RevokeControllerSession(context.Background(), tokenHash, now); err != nil {
		t.Fatalf("RevokeControllerSession: %v", err)
	}

	mock.ExpectExec(`DELETE FROM controller_sessions`).
		WithArgs(now, now.Add(-24*time.Hour)).
		WillReturnResult(sqlmock.NewResult(0, 3))
	removed, err := store.CleanupControllerSessions(context.Background(), now)
	if err != nil || removed != 3 {
		t.Fatalf("CleanupControllerSessions removed=%d err=%v", removed, err)
	}
	assertMockExpectations(t, mock)
}

func TestGetControllerSessionReturnsNilForExpiredOrStaleGeneration(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 15, 0, 0, 0, time.UTC)
	hash := make([]byte, 32)
	mock.ExpectQuery(`SELECT s.id, gu.legacy_user_id`).
		WithArgs(hash, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "legacy_user_id", "user_id", "admin_id", "username", "is_admin",
			"csrf_hash", "expires_at", "last_seen_at", "controller_generation",
		}))
	session, err := store.GetControllerSession(context.Background(), hash, now)
	if err != nil || session != nil {
		t.Fatalf("GetControllerSession session=%+v err=%v, want nil", session, err)
	}
	assertMockExpectations(t, mock)
}

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestOAuthStateIsDurableAndOneUse(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)
	hash := make([]byte, 32)
	nodeID := int64(20)

	mock.ExpectExec(`INSERT INTO oauth_authorization_states`).
		WithArgs(hash, "discord", nodeID, now.Add(10*time.Minute), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.CreateOAuthState(context.Background(), hash, "discord", &nodeID, now.Add(10*time.Minute), now); err != nil {
		t.Fatalf("CreateOAuthState: %v", err)
	}

	mock.ExpectQuery(`UPDATE oauth_authorization_states AS state`).
		WithArgs(hash, "discord", now).
		WillReturnRows(sqlmock.NewRows([]string{"node_id"}).AddRow(nodeID))
	gotNode, consumed, err := store.ConsumeOAuthState(context.Background(), hash, "discord", now)
	if err != nil || !consumed || gotNode == nil || *gotNode != nodeID {
		t.Fatalf("ConsumeOAuthState node=%v consumed=%v err=%v", gotNode, consumed, err)
	}

	mock.ExpectQuery(`UPDATE oauth_authorization_states AS state`).
		WithArgs(hash, "discord", now).
		WillReturnRows(sqlmock.NewRows([]string{"node_id"}))
	gotNode, consumed, err = store.ConsumeOAuthState(context.Background(), hash, "discord", now)
	if err != nil || consumed || gotNode != nil {
		t.Fatalf("replayed state node=%v consumed=%v err=%v", gotNode, consumed, err)
	}
	assertMockExpectations(t, mock)
}

func TestOAuthStateRejectsInvalidProvider(t *testing.T) {
	t.Parallel()
	store := &Store{}
	err := store.CreateOAuthState(context.Background(), make([]byte, 32), "github", nil, time.Now().Add(time.Minute), time.Now())
	if !errors.Is(err, ErrInvalidOAuthFlow) {
		t.Fatalf("CreateOAuthState error=%v, want ErrInvalidOAuthFlow", err)
	}
}

func TestOAuthBindingStateIsSessionAndGenerationBound(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 23, 20, 0, 0, time.UTC)
	hash := make([]byte, 32)
	expires := now.Add(10 * time.Minute)
	mock.ExpectExec(`INSERT INTO oauth_authorization_states`).
		WithArgs(hash, "linuxdo", int64(70), "session-id", expires, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.CreateOAuthBindingState(context.Background(), hash, "linuxdo", 70, "session-id", expires, now); err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`UPDATE oauth_authorization_states AS state`).
		WithArgs(hash, "linuxdo", now, int64(70), "session-id").
		WillReturnRows(sqlmock.NewRows([]string{"consumed"}).AddRow(true))
	consumed, err := st.ConsumeOAuthBindingState(context.Background(), hash, "linuxdo", 70, "session-id", now)
	if err != nil || !consumed {
		t.Fatalf("consumed=%v err=%v", consumed, err)
	}
	mock.ExpectQuery(`UPDATE oauth_authorization_states AS state`).
		WithArgs(hash, "linuxdo", now, int64(71), "other-session").
		WillReturnRows(sqlmock.NewRows([]string{"consumed"}))
	consumed, err = st.ConsumeOAuthBindingState(context.Background(), hash, "linuxdo", 71, "other-session", now)
	if err != nil || consumed {
		t.Fatalf("wrong scope consumed=%v err=%v", consumed, err)
	}
	assertMockExpectations(t, mock)
}

func TestCreateAndClaimOAuthPending(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)
	hash := make([]byte, 32)
	p := CreateOAuthPendingParams{
		ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TokenHash: hash,
		Provider: "linuxdo", ProviderSubject: "subject-1", DisplayName: "Alice",
		ExpiresAt: now.Add(10 * time.Minute), Now: now,
	}
	mock.ExpectExec(`INSERT INTO oauth_pending_enrollments`).
		WithArgs(p.ID, hash, p.Provider, p.ProviderSubject, p.DisplayName, nil, p.ExpiresAt, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.CreateOAuthPending(context.Background(), p); err != nil {
		t.Fatalf("CreateOAuthPending: %v", err)
	}

	claimID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT pending.id, pending.provider`).
		WithArgs(hash, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "provider", "provider_subject", "display_name", "avatar_url", "state",
			"claim_id", "claim_until", "result_user_id",
		}).AddRow(p.ID, p.Provider, p.ProviderSubject, p.DisplayName, nil, "pending", nil, nil, nil))
	mock.ExpectExec(`UPDATE oauth_pending_enrollments`).
		WithArgs(p.ID, claimID, now.Add(2*time.Minute), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	pending, found, err := store.ClaimOAuthPending(context.Background(), hash, claimID, now, 2*time.Minute)
	if err != nil || !found || pending.ClaimID != claimID || pending.ProviderSubject != p.ProviderSubject {
		t.Fatalf("ClaimOAuthPending pending=%+v found=%v err=%v", pending, found, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimOAuthPendingRejectsConcurrentProcessor(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)
	hash := make([]byte, 32)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT pending.id, pending.provider`).
		WithArgs(hash, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "provider", "provider_subject", "display_name", "avatar_url", "state",
			"claim_id", "claim_until", "result_user_id",
		}).AddRow("pending-id", "discord", "subject", "Alice", nil, "processing",
			"other-claim", now.Add(time.Minute), nil))
	mock.ExpectRollback()
	_, found, err := store.ClaimOAuthPending(context.Background(), hash, "new-claim", now, 2*time.Minute)
	if found || !errors.Is(err, ErrOAuthPendingBusy) {
		t.Fatalf("ClaimOAuthPending found=%v err=%v, want busy", found, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimOAuthPendingReplaysCompletedUser(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)
	hash := make([]byte, 32)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT pending.id, pending.provider`).
		WithArgs(hash, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "provider", "provider_subject", "display_name", "avatar_url", "state",
			"claim_id", "claim_until", "result_user_id",
		}).AddRow("pending-id", "discord", "subject", "Alice", "https://avatar", "consumed",
			nil, nil, int64(7)))
	mock.ExpectCommit()
	pending, found, err := store.ClaimOAuthPending(context.Background(), hash, "new-claim", now, 2*time.Minute)
	if err != nil || !found || !pending.AlreadyCompleted || pending.ResultUserID != 7 {
		t.Fatalf("ClaimOAuthPending pending=%+v found=%v err=%v", pending, found, err)
	}
	assertMockExpectations(t, mock)
}

func TestOAuthPendingCompleteReleaseAndCleanup(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)

	mock.ExpectExec(`UPDATE oauth_pending_enrollments`).
		WithArgs("pending", "claim", int64(7), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := store.CompleteOAuthPending(context.Background(), "pending", "claim", 7, now)
	if err != nil || !ok {
		t.Fatalf("CompleteOAuthPending ok=%v err=%v", ok, err)
	}

	mock.ExpectExec(`UPDATE oauth_pending_enrollments`).
		WithArgs("pending", "claim", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.ReleaseOAuthPending(context.Background(), "pending", "claim", now); err != nil {
		t.Fatalf("ReleaseOAuthPending: %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM oauth_authorization_states`).
		WithArgs(now, now.Add(-time.Hour)).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`DELETE FROM oauth_pending_enrollments`).
		WithArgs(now, now.Add(-24*time.Hour)).WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()
	removed, err := store.CleanupOAuthArtifacts(context.Background(), now)
	if err != nil || removed != 5 {
		t.Fatalf("CleanupOAuthArtifacts removed=%d err=%v", removed, err)
	}
	assertMockExpectations(t, mock)
}

package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestReconcileOAuthIdentitySyncIntentsRepairsAddsAndVersionedRemovals(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO node_account_oauth_syncs`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE node_account_oauth_syncs sync SET`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.ReconcileOAuthIdentitySyncIntents(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestListPendingOAuthIdentitySyncsReturnsExactVersionedIntent(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 16, 1, 5, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT sync.global_user_id`).WithArgs(20, now.Add(-oauthIdentitySyncBackoff)).
		WillReturnRows(sqlmock.NewRows([]string{
			"global_user_id", "node_id", "local_handle", "provider", "provider_subject", "account_version", "desired_present",
		}).AddRow(int64(70), int64(12), "alice", "discord", "subject-1", int64(4), true).
			AddRow(int64(70), int64(13), "alice", "linuxdo", "subject-2", int64(7), false))
	syncs, err := st.ListPendingOAuthIdentitySyncs(context.Background(), 20, now)
	if err != nil || len(syncs) != 2 || syncs[0].Provider != "discord" ||
		!syncs[0].DesiredPresent || syncs[1].DesiredPresent || syncs[1].Version != 7 {
		t.Fatalf("syncs=%+v err=%v", syncs, err)
	}
	assertMockExpectations(t, mock)
}

func TestOAuthIdentitySyncCompletionAndFailureAreExactAndVersionFenced(t *testing.T) {
	t.Parallel()
	sync := PendingOAuthIdentitySync{
		GlobalUserID: 70, NodeID: 12, LocalHandle: "alice", Provider: "discord",
		Subject: "subject-1", Version: 4, DesiredPresent: true,
	}
	now := time.Date(2026, 8, 16, 1, 10, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		pattern string
		call    func(*Store) error
	}{
		{
			name: "complete", pattern: `UPDATE node_account_oauth_syncs SET state='completed'`,
			call: func(st *Store) error {
				return st.CompleteOAuthIdentitySync(context.Background(), sync, now)
			},
		},
		{
			name: "retry", pattern: `UPDATE node_account_oauth_syncs SET attempt=attempt\+1`,
			call: func(st *Store) error {
				return st.MarkOAuthIdentitySyncError(context.Background(), sync, now)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectExec(test.pattern).WithArgs(
				sync.GlobalUserID, sync.NodeID, sync.Provider, sync.Subject, sync.LocalHandle,
				sync.Version, sync.DesiredPresent, now,
			).WillReturnResult(sqlmock.NewResult(0, 1))
			if err := test.call(st); err != nil {
				t.Fatal(err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestOAuthIdentitySyncRejectsUnfencedInput(t *testing.T) {
	t.Parallel()
	st := &Store{}
	err := st.CompleteOAuthIdentitySync(context.Background(), PendingOAuthIdentitySync{
		GlobalUserID: 70, NodeID: 12, LocalHandle: "alice", Provider: "discord", Subject: "subject-1",
	}, time.Now())
	if err == nil {
		t.Fatal("zero-version oauth identity sync was accepted")
	}
}

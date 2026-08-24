package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func accountImportClaimParams(now time.Time) CompleteAccountImportClaimParams {
	return CompleteAccountImportClaimParams{
		OperationID:  "11111111-1111-4111-8111-111111111111",
		GlobalUserID: 70, NodeID: 12, LocalHandle: "alice", LocalUserID: "local-alice", Now: now,
	}
}

func TestCompleteAccountImportClaimRejectsInvalidAndConflictingProof(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 45, 0, 0, time.UTC)
	t.Run("invalid", func(t *testing.T) {
		p := accountImportClaimParams(now)
		p.LocalUserID = ""
		if err := (&Store{}).CompleteAccountImportClaim(context.Background(), p); !errors.Is(err, ErrAccountClaimRejected) {
			t.Fatalf("error=%v, want ErrAccountClaimRejected", err)
		}
	})
	for _, conflict := range []bool{false, true} {
		conflict := conflict
		name := "exact replay"
		if conflict {
			name = "conflicting replay"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := accountImportClaimParams(now)
			p.Now = time.Time{}
			storedLocalID := p.LocalUserID
			if conflict {
				storedLocalID = "different-local-user"
			}
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT user_id,node_id,local_user_id FROM account_import_claim_operations`).
				WithArgs(p.OperationID).
				WillReturnRows(sqlmock.NewRows([]string{"user_id", "node_id", "local_user_id"}).
					AddRow(p.GlobalUserID, p.NodeID, storedLocalID))
			if conflict {
				mock.ExpectRollback()
			} else {
				mock.ExpectCommit()
			}
			err := st.CompleteAccountImportClaim(context.Background(), p)
			if conflict && !errors.Is(err, ErrAccountImportConflict) {
				t.Fatalf("error=%v, want ErrAccountImportConflict", err)
			}
			if !conflict && err != nil {
				t.Fatal(err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func expectAccountImportClaimPrefix(
	mock sqlmock.Sqlmock,
	p CompleteAccountImportClaimParams,
	stage string,
	injected error,
) error {
	mock.ExpectBegin()
	replay := mock.ExpectQuery(`SELECT user_id,node_id,local_user_id FROM account_import_claim_operations`).
		WithArgs(p.OperationID)
	if stage == "replay query" {
		replay.WillReturnError(injected)
		return injected
	}
	replay.WillReturnError(sql.ErrNoRows)

	candidate := mock.ExpectQuery(`SELECT candidate.id,candidate.batch_id`).WithArgs(p.NodeID, p.LocalHandle)
	if stage == "candidate missing" {
		candidate.WillReturnError(sql.ErrNoRows)
		return ErrAccountClaimRejected
	}
	localID := p.LocalUserID
	if stage == "candidate proof mismatch" {
		localID = "different-local-user"
	}
	candidate.WillReturnRows(sqlmock.NewRows([]string{
		"id", "batch_id", "local_user_id", "local_handle", "is_admin",
	}).AddRow("candidate-id", "batch-id", localID, "alice", false))
	if stage == "candidate proof mismatch" {
		return ErrAccountClaimRejected
	}

	identity := mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID)
	if stage == "identity query" {
		identity.WillReturnError(injected)
		return ErrAccountClaimRejected
	}
	status := "active"
	if stage == "identity disabled" {
		status = "disabled"
	}
	identity.WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "username", "status"}).
		AddRow(int64(8), "alice", status))
	if stage == "identity disabled" {
		return ErrAccountClaimRejected
	}

	collision := mock.ExpectQuery(`SELECT 1 FROM node_accounts`).WithArgs(p.NodeID, p.GlobalUserID, p.LocalUserID)
	if stage == "account collision" {
		collision.WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
		return ErrAccountClaimRejected
	}
	if stage == "collision query" {
		collision.WillReturnError(injected)
		return injected
	}
	collision.WillReturnError(sql.ErrNoRows)

	account := mock.ExpectExec(`INSERT INTO node_accounts`).
		WithArgs(p.GlobalUserID, p.NodeID, "alice", p.LocalUserID, false, p.Now)
	if stage == "account insert" {
		account.WillReturnError(injected)
		return injected
	}
	account.WillReturnResult(sqlmock.NewResult(1, 1))

	home := mock.ExpectQuery(`SELECT home_node_id FROM users`).WithArgs(int64(8))
	if stage == "home query" {
		home.WillReturnError(injected)
		return injected
	}
	if stage == "home assignment" {
		home.WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(nil))
		mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(8), p.NodeID).WillReturnError(injected)
		return injected
	}
	home.WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(int64(9)))

	replica := mock.ExpectExec(`INSERT INTO user_replicas`).
		WithArgs(int64(8), p.NodeID, "hot_standby", "stale", p.Now)
	if stage == "replica projection" {
		replica.WillReturnError(injected)
		return injected
	}
	replica.WillReturnResult(sqlmock.NewResult(1, 1))
	return nil
}

func expectAccountImportClaimMutation(
	mock sqlmock.Sqlmock,
	expression, stage, current string,
	injected error,
) bool {
	expected := mock.ExpectExec(expression)
	switch stage {
	case current + " exec":
		expected.WillReturnError(injected)
		return true
	case current + " rows":
		expected.WillReturnResult(sqlmock.NewErrorResult(injected))
		return true
	case current + " missing":
		expected.WillReturnResult(sqlmock.NewResult(0, 0))
		return true
	default:
		expected.WillReturnResult(sqlmock.NewResult(0, 1))
		return false
	}
}

func TestCompleteAccountImportClaimRollsBackPreconditionsAndWrites(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 50, 0, 0, time.UTC)
	injected := errors.New("injected account import claim failure")
	stages := []string{
		"replay query", "candidate missing", "candidate proof mismatch", "identity query", "identity disabled",
		"account collision", "collision query", "account insert", "home query", "home assignment", "replica projection",
		"candidate exec", "candidate rows", "candidate missing",
		"batch exec", "batch rows", "batch missing",
		"operation exec", "operation rows", "operation missing", "commit",
	}
	for index, stage := range stages {
		stage := stage
		name := stage
		if stage == "candidate missing" && index > 5 {
			name = "candidate update missing"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := accountImportClaimParams(now)
			prefixStage := stage
			if name == "candidate update missing" {
				prefixStage = ""
			}
			wantErr := expectAccountImportClaimPrefix(mock, p, prefixStage, injected)
			if wantErr == nil {
				mutationStage := stage
				if name == "candidate update missing" {
					mutationStage = "candidate missing"
				}
				if expectAccountImportClaimMutation(mock, `UPDATE account_import_candidates`, mutationStage, "candidate", injected) {
					if mutationStage == "candidate missing" {
						wantErr = ErrAccountClaimRejected
					} else {
						wantErr = injected
					}
				} else if expectAccountImportClaimMutation(mock, `UPDATE account_import_batches`, mutationStage, "batch", injected) {
					if mutationStage == "batch missing" {
						wantErr = ErrAccountClaimRejected
					} else {
						wantErr = injected
					}
				} else if expectAccountImportClaimMutation(mock, `INSERT INTO account_import_claim_operations`, mutationStage, "operation", injected) {
					if mutationStage == "operation missing" {
						wantErr = ErrNoActiveController
					} else {
						wantErr = injected
					}
				} else {
					mock.ExpectCommit().WillReturnError(injected)
					wantErr = injected
				}
			}
			if stage != "commit" {
				mock.ExpectRollback()
			}
			err := st.CompleteAccountImportClaim(context.Background(), p)
			if !errors.Is(err, wantErr) {
				t.Fatalf("stage=%q error=%v, want %v", stage, err, wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}

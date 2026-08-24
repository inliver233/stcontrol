package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func registrationCompletionHeaderRows(
	state, provider string,
	generation, activeGeneration int64,
	resultUserID any,
) *sqlmock.Rows {
	passwordHash, materialHash, materialSalt, oauthSubject := any("bcrypt-hash"), any("node-hash"), any("node-salt"), any(nil)
	if provider != "password" {
		passwordHash, materialHash, materialSalt, oauthSubject = nil, nil, nil, "discord-subject"
	}
	return sqlmock.NewRows([]string{
		"state", "target_node_id", "controller_generation", "active_generation",
		"local_handle", "display_name", "auth_provider", "password_hash",
		"password_material_hash", "password_material_salt", "oauth_subject", "avatar_url", "result_user_id",
	}).AddRow(state, int64(12), generation, activeGeneration, "alice", "Alice", provider,
		passwordHash, materialHash, materialSalt, oauthSubject, nil, resultUserID)
}

func expectRegistrationCompletionPasswordFailureAt(
	mock sqlmock.Sqlmock,
	now time.Time,
	stage string,
	injected error,
) {
	createdAt := now.Add(-time.Second)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow.state,workflow.target_node_id`).WithArgs("workflow", "worker", now).
		WillReturnRows(registrationCompletionHeaderRows("scheduled", "password", 3, 3, nil))
	user := mock.ExpectQuery(`INSERT INTO users`)
	if stage == "legacy user" {
		user.WillReturnError(injected)
		return
	}
	user.WillReturnRows(sqlmock.NewRows([]string{"id", "uuid", "created_at"}).
		AddRow(int64(7), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", createdAt))
	global := mock.ExpectQuery(`INSERT INTO global_users`)
	if stage == "global user" {
		global.WillReturnError(injected)
		return
	}
	global.WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	identity := mock.ExpectExec(`INSERT INTO auth_identities`)
	if stage == "identity" {
		identity.WillReturnError(injected)
		return
	}
	identity.WillReturnResult(sqlmock.NewResult(0, 1))
	account := mock.ExpectExec(`INSERT INTO node_accounts`)
	if stage == "node account" {
		account.WillReturnError(injected)
		return
	}
	account.WillReturnResult(sqlmock.NewResult(0, 1))
	replica := mock.ExpectExec(`INSERT INTO user_replicas`)
	if stage == "replica" {
		replica.WillReturnError(injected)
		return
	}
	replica.WillReturnResult(sqlmock.NewResult(0, 1))
	workflow := mock.ExpectExec(`UPDATE workflows SET user_id`)
	if stage == "workflow" {
		workflow.WillReturnError(injected)
		return
	}
	workflow.WillReturnResult(sqlmock.NewResult(0, 1))
	registration := mock.ExpectExec(`UPDATE registration_workflows SET reservation_state='published'`)
	if stage == "registration" {
		registration.WillReturnError(injected)
		return
	}
	registration.WillReturnResult(sqlmock.NewResult(0, 1))
	step := mock.ExpectExec(`UPDATE workflow_steps SET state='succeeded'`)
	if stage == "step" {
		step.WillReturnError(injected)
		return
	}
	step.WillReturnResult(sqlmock.NewResult(0, 1))
	if stage != "commit" {
		panic("unhandled registration completion failure stage: " + stage)
	}
	mock.ExpectCommit().WillReturnError(injected)
}

func TestCompleteRegistrationWorkflowFencesInputReplayAndGeneration(t *testing.T) {
	t.Parallel()
	if user, err := (&Store{}).CompleteRegistrationWorkflow(context.Background(), "", "worker", "local", time.Now()); user != nil || !errors.Is(err, ErrInvalidRegistration) {
		t.Fatalf("user=%+v error=%v", user, err)
	}
	tests := []struct {
		name             string
		state            string
		generation       int64
		activeGeneration int64
		resultUserID     any
		queryErr         error
		commitErr        error
	}{
		{name: "missing workflow", queryErr: sql.ErrNoRows},
		{name: "workflow query failure", queryErr: errors.New("query failed")},
		{name: "stale generation", state: "scheduled", generation: 2, activeGeneration: 3},
		{name: "completed replay commit failure", state: "succeeded", generation: 3, activeGeneration: 3, resultUserID: int64(7), commitErr: errors.New("commit failed")},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectBegin()
			query := mock.ExpectQuery(`SELECT workflow.state,workflow.target_node_id`).WithArgs("workflow", "worker", sqlmock.AnyArg())
			if tc.queryErr != nil {
				query.WillReturnError(tc.queryErr)
				mock.ExpectRollback()
			} else {
				query.WillReturnRows(registrationCompletionHeaderRows(tc.state, "password", tc.generation, tc.activeGeneration, tc.resultUserID))
				if tc.commitErr != nil {
					mock.ExpectCommit().WillReturnError(tc.commitErr)
				} else {
					mock.ExpectRollback()
				}
			}
			user, err := st.CompleteRegistrationWorkflow(context.Background(), "workflow", "worker", "local", time.Time{})
			if user != nil || err == nil {
				t.Fatalf("user=%+v error=%v", user, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCompleteRegistrationWorkflowRollsBackEveryIdentityPublicationFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	injected := errors.New("injected registration completion failure")
	for _, stage := range []string{
		"legacy user", "global user", "identity", "node account", "replica",
		"workflow", "registration", "step", "commit",
	} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			expectRegistrationCompletionPasswordFailureAt(mock, now, stage, injected)
			if stage != "commit" {
				mock.ExpectRollback()
			}
			user, err := st.CompleteRegistrationWorkflow(context.Background(), "workflow", "worker", "local-alice", now)
			if user != nil || !errors.Is(err, injected) {
				t.Fatalf("stage=%q user=%+v error=%v", stage, user, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCompleteRegistrationWorkflowBuildsOAuthNodeIdentity(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 24, 9, 5, 0, 0, time.UTC)
	createdAt := now.Add(-time.Second)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow.state,workflow.target_node_id`).
		WillReturnRows(registrationCompletionHeaderRows("scheduled", "discord", 3, 3, nil))
	mock.ExpectQuery(`INSERT INTO users`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "uuid", "created_at"}).
			AddRow(int64(7), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", createdAt))
	mock.ExpectQuery(`INSERT INTO global_users`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectExec(`INSERT INTO auth_identities`).
		WithArgs(int64(70), "discord", "discord-subject", nil, createdAt).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_accounts`).
		WithArgs(int64(70), int64(12), "alice", "local-alice", int64(0), nil, nil,
			`{"discord":"discord-subject"}`, now).
		WillReturnError(errors.New("stop after OAuth projection"))
	mock.ExpectRollback()
	user, err := st.CompleteRegistrationWorkflow(context.Background(), "workflow", "worker", "local-alice", now)
	if user != nil || err == nil {
		t.Fatalf("user=%+v error=%v", user, err)
	}
	assertMockExpectations(t, mock)
}

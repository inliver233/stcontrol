package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func registrationParams(now time.Time) CreateRegistrationWorkflowParams {
	return CreateRegistrationWorkflowParams{
		WorkflowID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		OperationID:      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		RequestDigest:    bytes.Repeat([]byte{1}, 32),
		PendingTokenHash: bytes.Repeat([]byte{2}, 32),
		ClientExpiresAt:  now.Add(30 * time.Minute), NodeID: 12, PolicyVersion: 7,
		LocalHandle: "alice", DisplayName: "Alice", AuthProvider: "password",
		PasswordHash: "bcrypt-hash", PasswordMaterialHash: "node-hash",
		PasswordMaterialSalt: "node-salt", InvitationCiphertext: "encrypted-invite", Now: now,
	}
}

func TestCreateRegistrationWorkflowReservesHandleUnderFreshSelectedNodePolicy(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	p := registrationParams(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM workflows workflow`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "state", "local_handle", "result_user_id", "request_digest",
		}))
	mock.ExpectQuery(`SELECT role,status,allow_register`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"role", "status", "allow_register", "registration_policy_state",
			"registration_policy_version", "registration_policy_expires_at",
		}).AddRow("compute", "online", true, "invitation_required", int64(7), now.Add(time.Minute)))
	mock.ExpectQuery(`SELECT 1 FROM users`).WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{"one"}))
	mock.ExpectQuery(`INSERT INTO workflows`).WithArgs(p.WorkflowID, p.OperationID, int64(12), now).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(3)))
	mock.ExpectExec(`INSERT INTO registration_workflows`).WithArgs(
		p.WorkflowID, p.RequestDigest, p.PendingTokenHash, p.ClientExpiresAt,
		"alice", "Alice", "password", "bcrypt-hash", "node-hash", "node-salt",
		nil, nil, "encrypted-invite", int64(7), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO workflow_steps`).WithArgs(p.WorkflowID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	workflow, err := st.CreateRegistrationWorkflow(context.Background(), p)
	if err != nil || workflow.State != "scheduled" || workflow.LocalHandle != "alice" || workflow.Replayed {
		t.Fatalf("workflow=%+v err=%v", workflow, err)
	}
	assertMockExpectations(t, mock)
}

func TestCreateRegistrationWorkflowReplaysOnlyMatchingRequestDigest(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 5, 0, 0, time.UTC)
	p := registrationParams(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM workflows workflow`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "state", "local_handle", "result_user_id", "request_digest",
		}).AddRow(p.WorkflowID, p.OperationID, "retry_wait", "alice", nil, p.RequestDigest))
	mock.ExpectExec(`UPDATE registration_workflows`).WithArgs(
		p.WorkflowID, p.PendingTokenHash, p.ClientExpiresAt, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	workflow, err := st.CreateRegistrationWorkflow(context.Background(), p)
	if err != nil || !workflow.Replayed || workflow.State != "retry_wait" {
		t.Fatalf("workflow=%+v err=%v", workflow, err)
	}
	assertMockExpectations(t, mock)

	st, mock, closeDB = newMockStore(t)
	defer closeDB()
	p.RequestDigest = bytes.Repeat([]byte{9}, 32)
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM workflows workflow`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "state", "local_handle", "result_user_id", "request_digest",
		}).AddRow(p.WorkflowID, p.OperationID, "scheduled", "alice", nil, bytes.Repeat([]byte{1}, 32)))
	mock.ExpectRollback()
	_, err = st.CreateRegistrationWorkflow(context.Background(), p)
	if !errors.Is(err, ErrRegistrationConflict) {
		t.Fatalf("error=%v, want conflict", err)
	}
	assertMockExpectations(t, mock)
}

func TestRegistrationStatusRequiresUnexpiredHashOnlyToken(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 10, 0, 0, time.UTC)
	tokenHash := bytes.Repeat([]byte{2}, 32)
	mock.ExpectQuery(`registration.pending_token_hash`).WithArgs(tokenHash, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "state", "local_handle", "error_code", "result_user_id",
		}).AddRow("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			"succeeded", "alice", nil, int64(7)))
	status, err := st.GetRegistrationWorkflowStatus(
		context.Background(), tokenHash, now,
	)
	if err != nil || status == nil || status.ResultUserID != 7 || status.State != "succeeded" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimAndScheduleRegistrationWorkflowRetryAreLeased(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 15, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE workflows workflow`).WithArgs(
		"workflow", "worker", now, now.Add(time.Minute),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='running'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	claimed, err := st.ClaimRegistrationWorkflow(
		context.Background(), "workflow", "worker", now, time.Minute,
	)
	if err != nil || !claimed {
		t.Fatalf("claimed=%v err=%v", claimed, err)
	}

	next := now.Add(10 * time.Second)
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE workflows SET state='retry_wait'`).WithArgs(
		"workflow", "worker", "command_timeout", next, now,
	).WillReturnRows(sqlmock.NewRows([]string{"attempt"}).AddRow(1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='retry_wait'`).WithArgs(
		"workflow", "command_timeout", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	attempt, err := st.ScheduleRegistrationRetry(
		context.Background(), "workflow", "worker", "command_timeout", next, now,
	)
	if err != nil || attempt != 1 {
		t.Fatalf("attempt=%d err=%v", attempt, err)
	}
	assertMockExpectations(t, mock)
}

func TestRegistrationReconcilerReadsRunnableExecutionAndReleasesItsLease(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 17, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT workflow.id,workflow.state,workflow.attempt`).WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "state", "attempt", "next_attempt_at", "controller_generation",
			"target_node_id", "node_name", "node_status", "node_policy_state",
			"node_policy_version", "node_policy_expires_at", "policy_version",
			"local_handle", "display_name", "auth_provider", "password_hash",
			"password_material_hash", "password_material_salt", "oauth_subject", "avatar_url",
			"invitation_ciphertext",
		}).AddRow(
			"workflow", "scheduled", 0, nil, int64(3), int64(12), "node", "online",
			"open", int64(7), now.Add(time.Minute), int64(7), "alice", "Alice", "password",
			"bcrypt-hash", "node-hash", "node-salt", nil, nil, nil,
		))
	execution, err := st.GetRegistrationWorkflowExecution(context.Background(), "workflow")
	if err != nil || execution == nil || execution.NodeID != 12 || !execution.PasswordHash.Valid {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}

	mock.ExpectQuery(`SELECT workflow.id`).WithArgs(20, now).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("workflow").AddRow("workflow-2"))
	ids, err := st.ListRunnableRegistrationWorkflowIDs(context.Background(), 20, now)
	if err != nil || len(ids) != 2 || ids[1] != "workflow-2" {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	mock.ExpectExec(`UPDATE workflows SET lease_owner=NULL`).WithArgs("workflow", "worker").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.ReleaseRegistrationWorkflow(context.Background(), "workflow", "worker"); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestFailRegistrationWorkflowReleasesReservationAndSecretsAtomically(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 18, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE workflows SET state='failed'`).WithArgs(
		"workflow", "worker", "node_rejected", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE registration_workflows SET reservation_state='released'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='failed'`).WithArgs("workflow", "node_rejected", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.FailRegistrationWorkflow(
		context.Background(), "workflow", "worker", "node_rejected", now,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteRegistrationWorkflowPublishesAllUserFactsAtomically(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 20, 0, 0, time.UTC)
	createdAt := now.Add(-time.Second)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow.state,workflow.target_node_id`).WithArgs("workflow", "worker", now).
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "target_node_id", "controller_generation", "active_generation",
			"local_handle", "display_name", "auth_provider", "password_hash",
			"password_material_hash", "password_material_salt", "oauth_subject", "avatar_url", "result_user_id",
		}).AddRow("scheduled", int64(12), int64(3), int64(3), "alice", "Alice", "password",
			"bcrypt-hash", "node-hash", "node-salt", nil, nil, nil))
	mock.ExpectQuery(`INSERT INTO users`).WithArgs(
		"alice", "Alice", "bcrypt-hash", "password", nil, nil, int64(12),
	).WillReturnRows(sqlmock.NewRows([]string{"id", "uuid", "created_at"}).
		AddRow(int64(7), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", createdAt))
	mock.ExpectQuery(`INSERT INTO global_users`).WithArgs(
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", int64(7), "Alice", createdAt,
	).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectExec(`INSERT INTO auth_identities`).WithArgs(
		int64(70), "password", "alice", "bcrypt-hash", createdAt,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_accounts`).WithArgs(
		int64(70), int64(12), "alice", "local-alice", int64(1), "node-hash", "node-salt", `{}`, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO user_replicas`).WithArgs(int64(7), int64(12), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflows SET user_id`).WithArgs("workflow", int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE registration_workflows SET reservation_state='published'`).WithArgs(
		"workflow", "local-alice", int64(7), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='succeeded'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	user, err := st.CompleteRegistrationWorkflow(context.Background(), "workflow", "worker", "local-alice", now)
	if err != nil || user == nil || user.ID != 7 || user.GlobalID != 70 || user.Status != "active" {
		t.Fatalf("user=%+v err=%v", user, err)
	}
	assertMockExpectations(t, mock)
}

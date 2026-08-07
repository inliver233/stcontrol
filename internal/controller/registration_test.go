package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestRegistrationRequestDigestIsStableKeyedAndInputBound(t *testing.T) {
	t.Parallel()
	server := &Server{secretKey: []byte("01234567890123456789012345678901")}
	input := registrationDigestInput{
		OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", NodeID: 12, PolicyVersion: 7,
		LocalHandle: "alice", DisplayName: "Alice", AuthProvider: "password",
		CredentialProof: "correct horse battery staple", InvitationCode: "short-code",
	}
	first, err := server.registrationRequestDigest(input)
	second, err2 := server.registrationRequestDigest(input)
	if err != nil || err2 != nil || len(first) != sha256.Size || !bytes.Equal(first, second) {
		t.Fatalf("first=%x second=%x err=%v err2=%v", first, second, err, err2)
	}
	input.InvitationCode = "other-code"
	changed, err := server.registrationRequestDigest(input)
	if err != nil || bytes.Equal(first, changed) || bytes.Contains(first, []byte("short-code")) {
		t.Fatalf("digest did not bind secret input: first=%x changed=%x err=%v", first, changed, err)
	}
}

func TestOAuthRegistrationHandleIsStableValidAndSubjectBound(t *testing.T) {
	t.Parallel()
	first := oauthRegistrationHandle("Alice Example", "discord", "subject-one")
	second := oauthRegistrationHandle("Alice Example", "discord", "subject-one")
	other := oauthRegistrationHandle("Alice Example", "discord", "subject-two")
	if first != second || first == other || !isValidHandle(first) {
		t.Fatalf("first=%q second=%q other=%q", first, second, other)
	}
}

func TestRegistrationPendingCookieIsStrictHttpOnlyAndStatusScoped(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{PublicURL: "https://control.example"}}
	req := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/register", nil)
	recorder := httptest.NewRecorder()
	server.setRegistrationPendingCookie(recorder, req, "opaque-token")
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != registrationPendingCookie || !cookies[0].HttpOnly ||
		!cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode ||
		cookies[0].Path != "/api/auth/registration" {
		t.Fatalf("unsafe registration cookie: %+v", cookies)
	}
}

func TestRegistrationStatusReturnsOnlySafePendingState(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{
		Cfg: &config.ControllerConfig{PublicURL: "https://control.example"}, Store: &store.Store{DB: db},
	}
	mock.ExpectQuery(`registration.pending_token_hash`).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "state", "local_handle", "error_code", "result_user_id",
		}).AddRow("workflow", "operation", "retry_wait", "alice", "command_timeout", nil))
	req := httptest.NewRequest(http.MethodGet, "https://control.example/api/auth/registration/status", nil)
	req.AddCookie(&http.Cookie{Name: registrationPendingCookie, Value: "opaque-token"})
	recorder := httptest.NewRecorder()
	server.handleRegistrationStatus(recorder, req)
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil ||
		recorder.Code != http.StatusAccepted || response["state"] != "retrying" || response["error_code"] != nil {
		t.Fatalf("status=%d response=%v err=%v", recorder.Code, response, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationWorkflowFailsClosedWhenPolicyVersionChanges(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: &store.Store{DB: db}, workflowWorkerID: "controller-worker"}
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE workflows workflow`).WithArgs(
		"workflow", "controller-worker", sqlmock.AnyArg(), sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='running'`).WithArgs("workflow", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
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
			"open", int64(8), time.Now().Add(time.Minute), int64(7), "alice", "Alice", "password",
			"bcrypt-hash", "node-hash", "node-salt", nil, nil, nil,
		))
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE workflows SET state='failed'`).WithArgs(
		"workflow", "controller-worker", "policy_changed", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE registration_workflows SET reservation_state='released'`).WithArgs(
		"workflow", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='failed'`).WithArgs(
		"workflow", "policy_changed", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec(`UPDATE workflows SET lease_owner=NULL`).WithArgs("workflow", "controller-worker").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := server.executeRegistrationWorkflow(context.Background(), "workflow"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationUncertainResultKeepsRetryingAfterNominalAttemptLimit(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: &store.Store{DB: db}, workflowWorkerID: "controller-worker"}
	execution := &store.RegistrationWorkflowExecution{WorkflowID: "workflow", Attempt: registrationMaxAttempts + 2}
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE workflows SET state='retry_wait'`).WithArgs(
		"workflow", "controller-worker", "command_uncertain", sqlmock.AnyArg(), sqlmock.AnyArg(),
	).WillReturnRows(sqlmock.NewRows([]string{"attempt"}).AddRow(execution.Attempt + 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='retry_wait'`).WithArgs(
		"workflow", "command_uncertain", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := server.retryRegistrationTransition(context.Background(), execution, "command_uncertain"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationSafePredispatchFailureStopsAtAttemptLimit(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: &store.Store{DB: db}, workflowWorkerID: "controller-worker"}
	execution := &store.RegistrationWorkflowExecution{WorkflowID: "workflow", Attempt: registrationMaxAttempts - 1}
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE workflows SET state='failed'`).WithArgs(
		"workflow", "controller-worker", "node_unavailable", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE registration_workflows SET reservation_state='released'`).WithArgs(
		"workflow", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='failed'`).WithArgs(
		"workflow", "node_unavailable", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := server.retryRegistrationTransition(context.Background(), execution, "node_unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

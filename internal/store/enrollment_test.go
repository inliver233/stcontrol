package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCreateEnrollmentTokenIsNodeAndRoleScoped(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC)
	hash := make([]byte, 32)
	p := CreateEnrollmentTokenParams{
		ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		TokenHash: hash, ExpectedNodeID: 22, ExpectedRole: "compute",
		ExpectedFingerprint: "fingerprint", ExpiresAt: now.Add(15 * time.Minute), Now: now,
	}
	mock.ExpectExec(`INSERT INTO enrollment_tokens`).
		WithArgs(p.ID, p.OperationID, hash, int64(22), "compute", "fingerprint", p.ExpiresAt, nil, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.CreateEnrollmentToken(context.Background(), p); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	assertMockExpectations(t, mock)
}

func TestCreateEnrollmentTokenRejectsInvalidScope(t *testing.T) {
	t.Parallel()
	err := (&Store{}).CreateEnrollmentToken(context.Background(), CreateEnrollmentTokenParams{
		ID: "id", OperationID: "operation", TokenHash: make([]byte, 32),
		ExpectedNodeID: 1, ExpectedRole: "any", ExpiresAt: time.Now().Add(time.Minute),
	})
	if !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("error=%v, want ErrInvalidEnrollment", err)
	}
}

func TestEnrollAgentConsumesTokenAndRotatesCredentialAtomically(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC)
	p := EnrollAgentParams{
		TokenHash: make([]byte, 32), PresentedRole: "compute", PresentedFingerprint: "fp",
		CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CredentialCiphertext: []byte("ciphertext"),
		AgentVersion: "1.2.3", TavernVersion: "1.13.0", BaseURLGuess: "https://node.example", Now: now,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id, expected_node_id, expected_role, expected_fingerprint`).
		WithArgs(p.TokenHash, now).
		WillReturnRows(sqlmock.NewRows([]string{"id", "expected_node_id", "expected_role", "expected_fingerprint"}).
			AddRow("token-id", int64(22), "compute", "fp"))
	mock.ExpectQuery(`SELECT role FROM nodes`).WithArgs(int64(22)).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("compute"))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(credential_version\),0\)\+1`).WithArgs(int64(22)).
		WillReturnRows(sqlmock.NewRows([]string{"credential_version"}).AddRow(int64(3)))
	mock.ExpectExec(`UPDATE agent_credentials SET revoked_at`).WithArgs(int64(22), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO agent_credentials`).
		WithArgs(p.CredentialID, int64(22), int64(3), p.CredentialCiphertext, int64(7), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE enrollment_tokens`).WithArgs("token-id", now, int64(22)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE nodes`).
		WithArgs(int64(22), p.AgentVersion, p.TavernVersion, int64(7), now, p.BaseURLGuess).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := st.EnrollAgent(context.Background(), p)
	if err != nil {
		t.Fatalf("EnrollAgent: %v", err)
	}
	if got.NodeID != 22 || got.CredentialVersion != 3 || got.ControllerGeneration != 7 {
		t.Fatalf("enrollment=%+v", got)
	}
	assertMockExpectations(t, mock)
}

func TestEnrollAgentRejectsFingerprintMismatchWithoutMutation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC)
	p := EnrollAgentParams{
		TokenHash: make([]byte, 32), PresentedRole: "compute", PresentedFingerprint: "wrong",
		CredentialID: "credential", CredentialCiphertext: []byte("ciphertext"), Now: now,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id, expected_node_id, expected_role, expected_fingerprint`).
		WithArgs(p.TokenHash, now).
		WillReturnRows(sqlmock.NewRows([]string{"id", "expected_node_id", "expected_role", "expected_fingerprint"}).
			AddRow("token-id", int64(22), "compute", "expected"))
	mock.ExpectRollback()
	_, err := st.EnrollAgent(context.Background(), p)
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("error=%v, want ErrEnrollmentRejected", err)
	}
	assertMockExpectations(t, mock)
}

func TestGetActiveAgentCredentialIsGenerationBound(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`FROM agent_credentials credential`).WithArgs(int64(22)).
		WillReturnRows(sqlmock.NewRows([]string{"secret_ciphertext", "credential_version", "controller_generation"}).
			AddRow([]byte("ciphertext"), int64(4), int64(9)))
	ciphertext, version, generation, err := st.GetActiveAgentCredential(context.Background(), 22)
	if err != nil || string(ciphertext) != "ciphertext" || version != 4 || generation != 9 {
		t.Fatalf("credential=%q version=%d generation=%d err=%v", ciphertext, version, generation, err)
	}
	assertMockExpectations(t, mock)
}

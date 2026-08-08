package store

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEnsureAgentCredentialRotationAfterGenerationPromotion(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 6, 0, 0, 0, time.UTC)
	p := EnsureAgentCredentialRotationParams{
		ID:          "11111111-1111-4111-8111-111111111111",
		OperationID: "22222222-2222-4222-8222-222222222222",
		NodeID:      12, ProposedCiphertext: []byte("encrypted-successor"),
		ControllerGeneration: 5, Now: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT operational_state FROM nodes`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state"}).AddRow("active"))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(5)))
	mock.ExpectExec(`UPDATE agent_credential_rotations SET state='expired'`).WithArgs(p.NodeID, now).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM agent_credential_rotations WHERE node_id`).WithArgs(p.NodeID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`FROM agent_credentials`).WithArgs(p.NodeID, now).
		WillReturnRows(sqlmock.NewRows([]string{"credential_version", "controller_generation", "created_at"}).
			AddRow(int64(1), int64(4), now.Add(-time.Hour)))
	mock.ExpectQuery(`SELECT GREATEST`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(2)))
	mock.ExpectExec(`INSERT INTO agent_credential_rotations`).WithArgs(
		p.ID, p.OperationID, p.NodeID, int64(2), p.ProposedCiphertext,
		int64(5), p.ExpiresAt, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	rotation, err := st.EnsureAgentCredentialRotation(context.Background(), p)
	if err != nil || rotation == nil || rotation.CredentialVersion != 2 ||
		rotation.ControllerGeneration != 5 || !bytes.Equal(rotation.Ciphertext, p.ProposedCiphertext) {
		t.Fatalf("rotation=%+v err=%v", rotation, err)
	}
	assertMockExpectations(t, mock)
}

func TestEnsureAgentCredentialRotationDoesNotChurnFreshCredential(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 6, 5, 0, 0, time.UTC)
	p := EnsureAgentCredentialRotationParams{
		ID:          "33333333-3333-4333-8333-333333333333",
		OperationID: "44444444-4444-4444-8444-444444444444",
		NodeID:      12, ProposedCiphertext: []byte("unused"),
		ControllerGeneration: 5, Now: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT operational_state FROM nodes`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state"}).AddRow("active"))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(5)))
	mock.ExpectExec(`UPDATE agent_credential_rotations SET state='expired'`).WithArgs(p.NodeID, now).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM agent_credential_rotations WHERE node_id`).WithArgs(p.NodeID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`FROM agent_credentials`).WithArgs(p.NodeID, now).
		WillReturnRows(sqlmock.NewRows([]string{"credential_version", "controller_generation", "created_at"}).
			AddRow(int64(2), int64(5), now.Add(-time.Hour)))
	mock.ExpectCommit()
	rotation, err := st.EnsureAgentCredentialRotation(context.Background(), p)
	if err != nil || rotation != nil {
		t.Fatalf("rotation=%+v err=%v", rotation, err)
	}
	assertMockExpectations(t, mock)
}

func TestActivateAgentCredentialRotationAtomicallyFencesOldCommands(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 6, 10, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(5)))
	mock.ExpectQuery(`SELECT id::text,secret_ciphertext`).WithArgs(int64(12), int64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "secret_ciphertext", "controller_generation", "state", "expires_at"}).
			AddRow("55555555-5555-4555-8555-555555555555", []byte("ciphertext"), int64(5), "pending", now.Add(time.Hour)))
	mock.ExpectExec(`(?s)UPDATE agent_credentials SET revoked_at=.*INSERT INTO agent_credentials.*UPDATE agent_credential_rotations.*UPDATE nodes.*UPDATE agent_commands`).
		WithArgs(int64(12), int64(2), now, "55555555-5555-4555-8555-555555555555", []byte("ciphertext"), int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 5))
	mock.ExpectCommit()
	generation, err := st.ActivateAgentCredentialRotation(context.Background(), 12, 2, now)
	if err != nil || generation != 5 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	assertMockExpectations(t, mock)
}

func TestListAgentAuthenticationCredentialsIncludesBoundedPendingSecret(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 6, 15, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT id::text,secret_ciphertext`).WithArgs(int64(12), now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "secret_ciphertext", "credential_version", "controller_generation", "pending",
		}).AddRow("pending-id", []byte("pending"), int64(2), int64(5), true).
			AddRow("active-id", []byte("active"), int64(1), int64(4), false))
	credentials, err := st.ListAgentAuthenticationCredentials(context.Background(), 12, now)
	if err != nil || len(credentials) != 2 || !credentials[0].Pending || credentials[1].Pending {
		t.Fatalf("credentials=%+v err=%v", credentials, err)
	}
	assertMockExpectations(t, mock)
}

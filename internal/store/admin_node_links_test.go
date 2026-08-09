package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCompleteAdminNodeVerificationPersistsAuditedVerifiedLink(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	digest := make([]byte, 32)
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT request_digest,admin_id,node_id,outcome`).WithArgs(operationID).
		WillReturnRows(sqlmock.NewRows([]string{"request_digest", "admin_id", "node_id", "outcome"}))
	mock.ExpectQuery(`SELECT epoch.generation`).WithArgs(int64(4), int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectExec(`INSERT INTO admin_node_link_operations`).WithArgs(
		operationID, digest, int64(4), int64(12), "node-admin", "verified",
		"local-user-9", int64(3), nil, int64(7), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO admin_node_links`).WithArgs(
		int64(4), int64(12), "node-admin", "local-user-9", int64(3), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		int64(4), int64(12), operationID, int64(7), digest, "verified", "node-admin", int64(3), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery(`SELECT node.id,node.name,node.base_url`).WithArgs(int64(4), int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "base_url", "node_state", "local_handle", "state",
			"permission_version", "last_verified_at", "last_error_code",
		}).AddRow(int64(12), "node-a", "https://node-a.example", "available", "node-admin",
			"verified", int64(3), now, ""))
	link, err := st.CompleteAdminNodeVerification(context.Background(), CompleteAdminNodeVerificationParams{
		OperationID: operationID, RequestDigest: digest, AdminID: 4, NodeID: 12,
		LocalHandle: "node-admin", LocalUserID: "local-user-9", IsAdmin: true,
		PermissionVersion: 3, Now: now,
	})
	if err != nil || link == nil || link.State != "verified" || link.PermissionVersion != 3 {
		t.Fatalf("link=%+v err=%v", link, err)
	}
	assertMockExpectations(t, mock)
}

func TestRejectedAdminNodeVerificationIsDurableAndDoesNotCreateLink(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 5, 0, 0, time.UTC)
	digest := make([]byte, 32)
	operationID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT request_digest,admin_id,node_id,outcome`).WithArgs(operationID).
		WillReturnRows(sqlmock.NewRows([]string{"request_digest", "admin_id", "node_id", "outcome"}))
	mock.ExpectQuery(`SELECT epoch.generation`).WithArgs(int64(4), int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectExec(`INSERT INTO admin_node_link_operations`).WithArgs(
		operationID, digest, int64(4), int64(12), "node-admin", "rejected",
		nil, nil, "not_node_admin", int64(7), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		int64(4), int64(12), operationID, int64(7), digest, "rejected", "node-admin", int64(0), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	_, err := st.CompleteAdminNodeVerification(context.Background(), CompleteAdminNodeVerificationParams{
		OperationID: operationID, RequestDigest: digest, AdminID: 4, NodeID: 12,
		LocalHandle: "node-admin", IsAdmin: false, Now: now,
	})
	if !errors.Is(err, ErrAdminNodeLinkRejected) {
		t.Fatalf("error=%v, want ErrAdminNodeLinkRejected", err)
	}
	assertMockExpectations(t, mock)
}

func TestRevokeAdminNodeLinkAtomicallyRevokesUnusedHandoffs(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 10, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE admin_node_links`).WithArgs(int64(4), int64(12), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(int64(4), int64(12), now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	if err := st.RevokeAdminNodeLink(context.Background(), 4, 12, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestStaleAdminNodeLinkAtomicallyRevokesUnusedHandoffs(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 12, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE admin_node_links`).WithArgs(int64(4), int64(12), "permission_revoked", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(int64(4), int64(12), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.MarkAdminNodeLinkStale(context.Background(), 4, 12, "permission_revoked", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestAdminHandoffIssueAndConsumeUseCurrentAuthorityFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 15, 0, 0, time.UTC)
	operationID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	jti := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	secretHash := make([]byte, 32)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ticket.operation_id::text`).WithArgs(operationID, int64(4), int64(12), now).
		WillReturnRows(sqlmock.NewRows([]string{
			"operation_id", "jti", "admin_id", "target_node_id", "base_url", "subject",
			"permission_version", "controller_generation", "expires_at",
		}))
	mock.ExpectQuery(`SELECT epoch.generation,node.base_url`).WithArgs(int64(4), int64(12), now.Add(-2*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"generation", "base_url", "local_handle", "permission_version",
		}).AddRow(int64(8), "https://node-a.example", "node-admin", int64(5)))
	mock.ExpectExec(`INSERT INTO control_tickets`).WithArgs(
		jti, operationID, secretHash, "controller", "https://node-a.example", "node-admin",
		int64(4), int64(12), "controller-master-v1", int64(8), now, now.Add(time.Minute),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		int64(4), int64(12), operationID, int64(8), now.Add(time.Minute), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	handoff, err := st.CreateAdminHandoff(context.Background(), CreateAdminHandoffParams{
		OperationID: operationID, JTI: jti, SecretHash: secretHash, AdminID: 4, NodeID: 12,
		Issuer: "controller", KeyID: "controller-master-v1", TicketTTL: time.Minute, Now: now,
	})
	if err != nil || handoff.LocalHandle != "node-admin" || handoff.ControllerGeneration != 8 {
		t.Fatalf("handoff=%+v err=%v", handoff, err)
	}
	mock.ExpectQuery(`WITH consumed AS`).WithArgs(
		jti, int64(12), secretHash, now.Add(time.Second), "controller", "controller-master-v1",
	).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "subject", "permission_version", "controller_generation",
		}).AddRow(int64(4), "node-admin", int64(5), int64(8)))
	redemption, consumed, err := st.ConsumeAdminHandoff(
		context.Background(), jti, secretHash, 12, "controller", "controller-master-v1", now.Add(time.Second),
	)
	if err != nil || !consumed || redemption.LocalHandle != "node-admin" || redemption.PermissionVersion != 5 {
		t.Fatalf("redemption=%+v consumed=%v err=%v", redemption, consumed, err)
	}
	assertMockExpectations(t, mock)
}

func TestAdminNodeLinkAndHandoffRejectInvalidPublicInputs(t *testing.T) {
	t.Parallel()
	st, _, closeDB := newMockStore(t)
	defer closeDB()
	if _, err := st.ListAdminNodeLinks(context.Background(), 0); !errors.Is(err, ErrInvalidAdminNodeLink) {
		t.Fatalf("list error=%v", err)
	}
	if err := st.RevokeAdminNodeLink(context.Background(), 1, 0, time.Now()); !errors.Is(err, ErrInvalidAdminNodeLink) {
		t.Fatalf("revoke error=%v", err)
	}
	if _, err := st.CreateAdminHandoff(context.Background(), CreateAdminHandoffParams{}); !errors.Is(err, ErrInvalidAdminHandoff) {
		t.Fatalf("create error=%v", err)
	}
	if _, _, err := st.ConsumeAdminHandoff(
		context.Background(), "", nil, 0, "", "", time.Now(),
	); !errors.Is(err, ErrInvalidAdminHandoff) {
		t.Fatalf("consume error=%v", err)
	}
}

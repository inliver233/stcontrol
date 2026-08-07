package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestUpdateNodeHeartbeatStoresVersionedRegistrationPolicy(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 0, 5, 0, 0, time.UTC)
	policy := NodeRegistrationPolicy{
		State: "invitation_required", Version: 9, ExpiresAt: now.Add(time.Minute), ObservedAt: now,
	}
	mock.ExpectExec(`UPDATE nodes SET cpu_pct`).WithArgs(
		int64(12), 10.0, 20.0, 30.0, "tavern", "agent", "https://transfer.example",
		now, now, "invitation_required", int64(9), now.Add(time.Minute), "",
	).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.UpdateNodeHeartbeat(
		context.Background(), 12, 10, 20, 30, "tavern", "agent", "https://transfer.example", policy,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestGetNodeByIDReadsRegistrationPolicyFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 0, 10, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT id, name, role, base_url`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "role", "base_url", "transfer_url", "region",
			"cpu_pct", "mem_pct", "disk_pct", "agent_version", "tavern_version", "last_seen_at",
			"status", "allow_register", "is_backup_target", "registration_policy_state",
			"registration_policy_version", "registration_policy_expires_at",
			"registration_policy_observed_at", "registration_policy_error_code", "created_at",
		}).AddRow(
			int64(12), "node", "compute", "https://node.example", "", "hk",
			10.0, 20.0, 30.0, "agent", "tavern", now,
			"online", true, false, "open", int64(4), now.Add(time.Minute), now, nil, now,
		))
	node, err := st.GetNodeByID(context.Background(), 12)
	if err != nil || node == nil || node.RegistrationPolicyState != "open" ||
		node.RegistrationPolicyVersion != 4 {
		t.Fatalf("node=%+v err=%v", node, err)
	}
	assertMockExpectations(t, mock)
}

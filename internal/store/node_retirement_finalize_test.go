package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectNodeRetirementFinalizeHeader(
	mock sqlmock.Sqlmock,
	retirementID, state, nodeState, controlMode, desiredMode string,
	generation int64,
) {
	mock.ExpectQuery(`(?s)SELECT operation.node_id,operation.state,operation.controller_generation.*FROM node_retirement_operations operation`).
		WithArgs(retirementID).
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "state", "generation", "admin_id", "node_state", "control_mode", "desired_mode",
		}).AddRow(int64(9), state, generation, int64(3), nodeState, controlMode, desiredMode))
}

func TestFinalizeNodeRetirementFencesStateItemsDependenciesAndGeneration(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	retirementID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	eventID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	tests := []struct {
		name       string
		state      string
		nodeState  string
		unfinished bool
		dependent  bool
		generation int64
		activeGen  int64
		want       error
		committed  bool
	}{
		{name: "already decommissioned", state: "decommissioned", nodeState: "decommissioned", generation: 4, committed: true},
		{name: "node not retiring", state: "migrating", nodeState: "active", generation: 4, want: ErrNodeRetirementState},
		{name: "unfinished items", state: "migrating", nodeState: "retiring", generation: 4, unfinished: true, want: ErrNodeRetirementState},
		{name: "remaining dependencies", state: "verifying", nodeState: "retiring", generation: 4, dependent: true},
		{name: "stale controller generation", state: "blocked", nodeState: "retiring", generation: 3, activeGen: 4, want: ErrNodeRetirementState},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectBegin()
			expectNodeRetirementFinalizeHeader(mock, retirementID, tc.state, tc.nodeState, "managed", "managed", tc.generation)
			if tc.committed {
				mock.ExpectCommit()
			} else if tc.nodeState != "retiring" {
				mock.ExpectRollback()
			} else {
				mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM node_retirement_items`).WithArgs(retirementID).
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(tc.unfinished))
				if tc.unfinished {
					mock.ExpectRollback()
				} else {
					mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM users WHERE home_node_id.*FROM relay_transfers`).WithArgs(int64(9)).
						WillReturnRows(sqlmock.NewRows([]string{"dependent"}).AddRow(tc.dependent))
					if tc.dependent {
						mock.ExpectExec(`UPDATE node_retirement_operations SET state='blocked'`).
							WithArgs(retirementID, now.Add(time.Minute), now).
							WillReturnResult(sqlmock.NewResult(0, 1))
						mock.ExpectCommit()
					} else {
						mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
							WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(tc.activeGen))
						mock.ExpectRollback()
					}
				}
			}
			finalized, err := st.FinalizeNodeRetirement(context.Background(), retirementID, eventID, now)
			if !errors.Is(err, tc.want) || finalized != tc.committed {
				t.Fatalf("finalized=%v err=%v, want finalized=%v err=%v", finalized, err, tc.committed, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}

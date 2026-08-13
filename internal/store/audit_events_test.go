package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestListAuditEventsPageFiltersAndPaginates(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)SELECT id,occurred_at,actor_type.*FROM audit_events.*ORDER BY id DESC LIMIT`).
		WithArgs(int64(0), "admin", "node-settings", "node", "succeeded", 50).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "occurred_at", "actor_type", "actor_id", "action", "target_type", "target_id",
			"operation_id", "controller_generation", "outcome", "detail",
		}).AddRow(
			int64(7), now, "admin", "root", "node-settings", "node", "3",
			"11111111-1111-4111-8111-111111111111", int64(5), "succeeded",
			json.RawMessage(`{"allow_register":true}`),
		))
	events, err := st.ListAuditEventsPage(context.Background(), ListAuditEventsPageParams{
		Limit: 50, ActorType: "admin", Action: "node-settings", TargetType: "node", Outcome: "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != 7 || events[0].ActorType != "admin" ||
		events[0].Action != "node-settings" || events[0].Outcome != "succeeded" ||
		events[0].OperationID.String != "11111111-1111-4111-8111-111111111111" ||
		!events[0].ControllerGeneration.Valid || events[0].ControllerGeneration.Int64 != 5 {
		t.Fatalf("unexpected events: %+v", events)
	}
	var detail map[string]any
	if err := json.Unmarshal(events[0].Detail, &detail); err != nil || detail["allow_register"] != true {
		t.Fatalf("detail=%s err=%v", events[0].Detail, err)
	}
	assertMockExpectations(t, mock)
}

func TestListAuditEventsPageEmptyIsEmptySlice(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`(?s)SELECT id,occurred_at,actor_type.*FROM audit_events.*ORDER BY id DESC LIMIT`).
		WithArgs(int64(0), 50).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "occurred_at", "actor_type", "actor_id", "action", "target_type", "target_id",
			"operation_id", "controller_generation", "outcome", "detail",
		}))
	events, err := st.ListAuditEventsPage(context.Background(), ListAuditEventsPageParams{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if events == nil || len(events) != 0 {
		t.Fatalf("expected empty non-nil slice, got %#v", events)
	}
	assertMockExpectations(t, mock)
}

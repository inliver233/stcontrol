package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAdminEmptyListsEncodeAsJSONArrays(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 2, 0, 0, 0, time.UTC)

	mock.ExpectQuery(`FROM nodes ORDER BY id`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	nodes, err := st.ListNodes(context.Background())
	assertJSONArray(t, "nodes", nodes, err)

	mock.ExpectQuery(`FROM nodes node`).WithArgs(int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"node_id"}))
	links, err := st.ListAdminNodeLinks(context.Background(), 1)
	assertJSONArray(t, "admin node links", links, err)

	mock.ExpectQuery(`FROM alerts alert`).WithArgs(100, now).
		WillReturnRows(sqlmock.NewRows([]string{"severity"}))
	alerts, err := st.ListVisibleProtectionAlerts(context.Background(), 100, now)
	assertJSONArray(t, "protection alerts", alerts, err)

	mock.ExpectQuery(`FROM admins ORDER BY id`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	admins, err := st.ListAdmins(context.Background())
	assertJSONArray(t, "admins", admins, err)

	assertMockExpectations(t, mock)
}

func assertJSONArray(t *testing.T, name string, value any, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	if string(encoded) != "[]" {
		t.Fatalf("%s encoded as %s, want []", name, encoded)
	}
}

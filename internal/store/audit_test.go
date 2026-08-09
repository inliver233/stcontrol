package store

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAuditWritesSQLNullForEmptyDetailAndValidatesStructuredJSON(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()

	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs("actor", "empty-detail", "target", nil).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := st.Audit(context.Background(), "actor", "empty-detail", "target", nil); err != nil {
		t.Fatalf("write empty audit detail: %v", err)
	}

	detail := []byte(`{"reason_code":"operator_test"}`)
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs("actor", "structured-detail", "target", detail).
		WillReturnResult(sqlmock.NewResult(2, 1))
	if err := st.Audit(context.Background(), "actor", "structured-detail", "target", detail); err != nil {
		t.Fatalf("write structured audit detail: %v", err)
	}

	if err := st.Audit(context.Background(), "actor", "invalid-detail", "target", []byte(`{"broken"`)); err == nil {
		t.Fatal("invalid audit detail JSON reached PostgreSQL")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityOperationsRejectInvalidInputBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()
	st, _, closeDB := newMockStore(t)
	defer closeDB()

	if _, err := st.ListUserIdentities(context.Background(), 0); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("list error=%v", err)
	}
	if err := st.BindOAuthIdentity(context.Background(), 70, "password", "subject", time.Time{}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("OAuth bind error=%v", err)
	}
	if err := st.BindPasswordIdentity(context.Background(), 7, 70, "hash", "", "salt", time.Time{}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("password bind error=%v", err)
	}
	if err := st.UnbindUserIdentity(context.Background(), 7, 70, "unsupported", time.Time{}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("unbind error=%v", err)
	}
}

func TestListUserIdentitiesReturnsScanFailure(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT provider,password_version,status,created_at`).
		WillReturnRows(sqlmock.NewRows([]string{"provider"}).AddRow("password"))

	identities, err := st.ListUserIdentities(context.Background(), 70)
	if err == nil || identities != nil {
		t.Fatalf("identities=%v error=%v", identities, err)
	}
	assertMockExpectations(t, mock)
}

func TestIdentityOperationsNormalizeZeroTimeBeforeStartingTransaction(t *testing.T) {
	t.Parallel()
	injected := errors.New("transaction unavailable")
	for _, tc := range []struct {
		name string
		call func(*Store) error
	}{
		{name: "OAuth bind", call: func(st *Store) error {
			return st.BindOAuthIdentity(context.Background(), 70, "discord", "subject", time.Time{})
		}},
		{name: "password bind", call: func(st *Store) error {
			return st.BindPasswordIdentity(context.Background(), 7, 70, "hash", "node-hash", "salt", time.Time{})
		}},
		{name: "unbind", call: func(st *Store) error {
			return st.UnbindUserIdentity(context.Background(), 7, 70, "password", time.Time{})
		}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectBegin().WillReturnError(injected)
			if err := tc.call(st); !errors.Is(err, injected) {
				t.Fatalf("error=%v", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestGetUserByOAuthUsesNormalizedLinkedIdentity(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Now().UTC()
	mock.ExpectQuery(`FROM auth_identities identity`).WithArgs("discord", "linked-subject").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "global_id", "uuid", "username", "display_name", "password_enc", "password_hash",
			"auth_provider", "oauth_id", "avatar_url", "email", "home_node_id", "status", "created_at",
		}).AddRow(int64(7), int64(70), "uuid", "alice", "Alice", nil, "bcrypt-hash",
			"password", nil, nil, nil, int64(12), "active", now))
	user, err := st.GetUserByOAuth(context.Background(), "discord", "linked-subject")
	if err != nil || user == nil || user.GlobalID != 70 || !user.PasswordHash.Valid || user.PasswordHash.String != "bcrypt-hash" {
		t.Fatalf("user=%+v err=%v", user, err)
	}
	assertMockExpectations(t, mock)
}

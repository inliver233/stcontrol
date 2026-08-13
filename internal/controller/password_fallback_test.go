package controller

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/crypto"
	"stcontrol/internal/store"
)

// TestPasswordMatchesAcceptsPreviousVerifierWhileSyncIncomplete verifies that,
// while the password-sync saga is incomplete, login still accepts the
// immediately-previous password as a fallback so a not-yet-converged node does
// not create a split where only some locations recognize the old password.
func TestPasswordMatchesAcceptsPreviousVerifierWhileSyncIncomplete(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := New(config.DefaultController(), &store.Store{DB: db}, []byte("01234567890123456789012345678901"))

	currentHash, err := crypto.HashPassword("brand-new-password")
	if err != nil {
		t.Fatal(err)
	}
	previousHash, err := crypto.HashPassword("previous-password")
	if err != nil {
		t.Fatal(err)
	}
	user := &store.User{
		GlobalID:     70,
		PasswordHash: sql.NullString{String: currentHash, Valid: true},
	}

	// First: current password matches without hitting the fallback.
	if !server.passwordMatches(context.Background(), user, "brand-new-password") {
		t.Fatal("current password was rejected")
	}
	// Second: previous password accepted only while the store reports the
	// fallback is active.
	mock.ExpectQuery(`SELECT identity.previous_password_hash`).
		WithArgs(int64(70)).WillReturnRows(
		sqlmock.NewRows([]string{"previous_password_hash", "password_changed_at", "incomplete"}).
			AddRow(previousHash, time.Now().UTC().Add(-time.Minute), true))
	if !server.passwordMatches(context.Background(), user, "previous-password") {
		t.Fatal("previous password was rejected while sync incomplete")
	}
	// Third: once the store reports convergence, the previous verifier is
	// dropped and the old password fails.
	mock.ExpectQuery(`SELECT identity.previous_password_hash`).
		WithArgs(int64(70)).WillReturnRows(
		sqlmock.NewRows([]string{"previous_password_hash", "password_changed_at", "incomplete"}).
			AddRow(previousHash, time.Now().UTC().Add(-time.Minute), false))
	if server.passwordMatches(context.Background(), user, "previous-password") {
		t.Fatal("previous password was accepted after node convergence")
	}
	// Unknown password never matches.
	if server.passwordMatches(context.Background(), user, "totally-wrong") {
		t.Fatal("unknown password was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

// TestPasswordMatchesRejectsWhenNoPasswordIdentity ensures an OAuth-only user
// is never authenticated through the fallback path.
func TestPasswordMatchesRejectsWhenNoPasswordIdentity(t *testing.T) {
	t.Parallel()
	server := &Server{Store: &store.Store{}, secretKey: []byte("01234567890123456789012345678901")}
	user := &store.User{GlobalID: 70}
	if server.passwordMatches(context.Background(), user, "anything") {
		t.Fatal("passwordless user was authenticated")
	}
}

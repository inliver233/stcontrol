package controller

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/store"
)

type secretFreeJSON struct {
	forbidden string
}

func TestAgentCommandErrorPreservesSafeFailureCode(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("run source: %w", &agentCommandError{Code: "snapshot_direct_unreachable"})
	if got := agentCommandErrorCode(err); got != "snapshot_direct_unreachable" {
		t.Fatalf("code=%q", got)
	}
}

func (m secretFreeJSON) Match(value driver.Value) bool {
	data, ok := value.([]byte)
	return ok && !strings.Contains(string(data), m.forbidden) && strings.Contains(string(data), "ciphertext")
}

func TestEnqueueAgentCommandEncryptsDurablePayload(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := New(config.DefaultController(), &store.Store{DB: db}, make([]byte, 32))
	node := &store.Node{ID: 12}
	ciphertext, err := controlcrypto.Encrypt(make([]byte, 32), []byte("agent-secret"))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`FROM agent_credentials credential`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"secret_ciphertext", "credential_version", "controller_generation"}).
			AddRow([]byte(ciphertext), int64(1), int64(3)))
	mock.ExpectQuery(`INSERT INTO agent_commands`).
		WithArgs(sqlmock.AnyArg(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", int64(12), "set_password",
			secretFreeJSON{forbidden: "plaintext-password"}, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(3)))
	generation, err := server.enqueueAgentCommand(context.Background(), node, "set_password", map[string]string{
		"password_hash": "plaintext-password",
	}, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err != nil || generation != 3 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

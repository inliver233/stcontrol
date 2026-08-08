package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestBuildAccountImportBatchMatchesOnlyNodeScopedOAuthFingerprints(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	secretKey := bytes.Repeat([]byte{7}, 32)
	ciphertext, err := controlcrypto.Encrypt(secretKey, []byte("node-psk"))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`FROM agent_credentials credential`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"secret_ciphertext", "credential_version", "controller_generation"}).
			AddRow([]byte(ciphertext), int64(1), int64(3)))
	mock.ExpectQuery(`SELECT user_id,provider,provider_subject`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "provider", "provider_subject"}).
			AddRow(int64(70), "discord", "stable-subject").
			AddRow(int64(80), "linuxdo", "other-subject"))
	server := New(config.DefaultController(), &store.Store{DB: db}, secretKey)
	fingerprint := controlcrypto.AgentInventoryFingerprint(
		"node-psk", "oauth-subject", "discord", "stable-subject",
	)
	params, err := server.buildAccountImportBatch(
		context.Background(), &store.Node{ID: 12},
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 5,
		[]protocol.ScanExistingUser{{
			LocalUserID: "local-7", Handle: "alice", Size: 123,
			DirectoryFingerprint: strings.Repeat("a", 64), Source: "adapter", AccountKind: "oauth",
			Identities: []protocol.ScanExistingIdentity{{Provider: "discord", Fingerprint: fingerprint}},
		}},
		time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC),
	)
	if err != nil || len(params.Candidates) != 1 ||
		len(params.Candidates[0].MatchedGlobalUserIDs) != 1 ||
		params.Candidates[0].MatchedGlobalUserIDs[0] != 70 || params.Source != "adapter" ||
		len(params.InventoryDigest) != 32 {
		t.Fatalf("params=%+v err=%v", params, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScannedFallbackInventoryCannotAssertIdentityOrAdminFacts(t *testing.T) {
	t.Parallel()
	base := protocol.ScanExistingUser{
		LocalUserID: "alice", Handle: "alice", DirectoryFingerprint: strings.Repeat("a", 64),
		Source: "directory_fallback", AccountKind: "unknown",
	}
	if !validScannedInventoryUser(base) {
		t.Fatal("valid identity-blind fallback was rejected")
	}
	base.IsAdmin = true
	if validScannedInventoryUser(base) {
		t.Fatal("fallback inventory asserted administrator status")
	}
	base.IsAdmin = false
	base.AccountKind = "oauth"
	base.Identities = []protocol.ScanExistingIdentity{{
		Provider: "discord", Fingerprint: strings.Repeat("b", 64),
	}}
	if validScannedInventoryUser(base) {
		t.Fatal("fallback inventory asserted OAuth identity")
	}
}

func TestAccountInventoryScanAcceptsTenThousandUsersInBoundedPages(t *testing.T) {
	t.Parallel()
	state := accountInventoryScan{}
	revision := strings.Repeat("c", 64)
	for cursor := 0; cursor < protocol.MaxAccountInventoryUsers; cursor += protocol.MaxAccountInventoryPageUsers {
		users := make([]protocol.ScanExistingUser, 0, protocol.MaxAccountInventoryPageUsers)
		for index := cursor; index < cursor+protocol.MaxAccountInventoryPageUsers; index++ {
			users = append(users, protocol.ScanExistingUser{
				LocalUserID:          fmt.Sprintf("local-%05d", index),
				Handle:               fmt.Sprintf("user-%05d", index),
				DirectoryFingerprint: strings.Repeat("a", 64),
				Source:               "directory_fallback", AccountKind: "unknown",
			})
		}
		next := cursor + len(users)
		hasMore := next < protocol.MaxAccountInventoryUsers
		if !hasMore {
			next = 0
		}
		complete, err := state.appendPage(cursor, protocol.ScanExistingPageResult{
			Users: users, Cursor: cursor, NextCursor: next,
			TotalUsers:        protocol.MaxAccountInventoryUsers,
			InventoryRevision: revision, HasMore: hasMore,
		})
		if err != nil || complete != !hasMore {
			t.Fatalf("cursor=%d complete=%v err=%v", cursor, complete, err)
		}
	}
	if len(state.users) != protocol.MaxAccountInventoryUsers {
		t.Fatalf("users=%d", len(state.users))
	}
}

func TestAccountInventoryScanRejectsRevisionDriftAndCrossPageDuplicates(t *testing.T) {
	t.Parallel()
	firstUsers := make([]protocol.ScanExistingUser, protocol.MaxAccountInventoryPageUsers)
	for index := range firstUsers {
		firstUsers[index] = protocol.ScanExistingUser{
			LocalUserID: fmt.Sprintf("local-%03d", index), Handle: fmt.Sprintf("user-%03d", index),
			DirectoryFingerprint: strings.Repeat("a", 64), Source: "adapter", AccountKind: "password",
		}
	}
	first := protocol.ScanExistingPageResult{
		Users: firstUsers, Cursor: 0, NextCursor: protocol.MaxAccountInventoryPageUsers,
		TotalUsers:        protocol.MaxAccountInventoryPageUsers + 1,
		InventoryRevision: strings.Repeat("b", 64), HasMore: true,
	}
	state := accountInventoryScan{}
	if complete, err := state.appendPage(0, first); err != nil || complete {
		t.Fatalf("first complete=%v err=%v", complete, err)
	}
	drift := protocol.ScanExistingPageResult{
		Users: []protocol.ScanExistingUser{{
			LocalUserID: "local-999", Handle: "user-999",
			DirectoryFingerprint: strings.Repeat("a", 64), Source: "adapter", AccountKind: "password",
		}},
		Cursor:            protocol.MaxAccountInventoryPageUsers,
		TotalUsers:        protocol.MaxAccountInventoryPageUsers + 1,
		InventoryRevision: strings.Repeat("c", 64),
	}
	if _, err := state.appendPage(protocol.MaxAccountInventoryPageUsers, drift); !errors.Is(err, store.ErrInvalidAccountImport) {
		t.Fatalf("revision drift error=%v", err)
	}
	drift.InventoryRevision = first.InventoryRevision
	drift.Users[0].LocalUserID = firstUsers[len(firstUsers)-1].LocalUserID
	if _, err := state.appendPage(protocol.MaxAccountInventoryPageUsers, drift); !errors.Is(err, store.ErrInvalidAccountImport) {
		t.Fatalf("duplicate error=%v", err)
	}
}

package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestConsumeAgentNonceRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	store := &Store{}
	_, err := store.ConsumeAgentNonce(context.Background(), 0, "", time.Time{}, time.Time{})
	if !errors.Is(err, ErrInvalidAgentNonce) {
		t.Fatalf("ConsumeAgentNonce error=%v, want ErrInvalidAgentNonce", err)
	}
}

func TestConsumeAgentNonceAcceptsOnceThenRejectsReplay(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
	expires := now.Add(2 * time.Minute)
	nonce := "00112233445566778899aabbccddeeff"
	digest := sha256.Sum256([]byte(nonce))

	mock.ExpectQuery(`WITH cleanup AS`).
		WithArgs(int64(20), digest[:], now, expires).
		WillReturnRows(sqlmock.NewRows([]string{"inserted"}).AddRow(1))
	accepted, err := store.ConsumeAgentNonce(context.Background(), 20, nonce, now, expires)
	if err != nil || !accepted {
		t.Fatalf("first nonce accepted=%v err=%v", accepted, err)
	}

	mock.ExpectQuery(`WITH cleanup AS`).
		WithArgs(int64(20), digest[:], now, expires).
		WillReturnRows(sqlmock.NewRows([]string{"inserted"}))
	accepted, err = store.ConsumeAgentNonce(context.Background(), 20, nonce, now, expires)
	if err != nil || accepted {
		t.Fatalf("replayed nonce accepted=%v err=%v, want false", accepted, err)
	}
	assertMockExpectations(t, mock)
}

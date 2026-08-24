package store

import (
	"context"
	"errors"
	"testing"

	"github.com/lib/pq"
)

func TestRetrySerializableRetriesSerializationAndDeadlockFailures(t *testing.T) {
	for _, code := range []pq.ErrorCode{"40001", "40P01"} {
		t.Run(string(code), func(t *testing.T) {
			attempts := 0
			err := retrySerializable(context.Background(), func() error {
				attempts++
				if attempts < 3 {
					return &pq.Error{Code: code}
				}
				return nil
			})
			if err != nil || attempts != 3 {
				t.Fatalf("err=%v attempts=%d, want success after 3 attempts", err, attempts)
			}
		})
	}
}

func TestRetrySerializableDoesNotRetryPermanentFailure(t *testing.T) {
	want := errors.New("permanent")
	attempts := 0
	err := retrySerializable(context.Background(), func() error {
		attempts++
		return want
	})
	if !errors.Is(err, want) || attempts != 1 {
		t.Fatalf("err=%v attempts=%d, want permanent failure after 1 attempt", err, attempts)
	}
}

func TestRetrySerializableIsBoundedAndHonorsCancellation(t *testing.T) {
	attempts := 0
	err := retrySerializable(context.Background(), func() error {
		attempts++
		return &pq.Error{Code: "40001"}
	})
	if err == nil || attempts != serializableRetryLimit {
		t.Fatalf("err=%v attempts=%d, want bounded retry limit %d", err, attempts, serializableRetryLimit)
	}

	ctx, cancel := context.WithCancel(context.Background())
	attempts = 0
	err = retrySerializable(ctx, func() error {
		attempts++
		cancel()
		return &pq.Error{Code: "40001"}
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("err=%v attempts=%d, want cancellation after 1 attempt", err, attempts)
	}
}

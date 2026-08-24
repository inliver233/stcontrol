package store

import (
	"context"
	"errors"
	"time"

	"github.com/lib/pq"
)

const serializableRetryLimit = 8
const serializableRetryBaseDelay = 25 * time.Millisecond
const serializableRetryMaxDelay = 750 * time.Millisecond

func retrySerializable(ctx context.Context, operation func() error) error {
	var err error
	for attempt := 0; attempt < serializableRetryLimit; attempt++ {
		if err = operation(); err == nil || !isRetryableTransactionError(err) {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		delay := serializableRetryBaseDelay << attempt
		if delay > serializableRetryMaxDelay {
			delay = serializableRetryMaxDelay
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func isRetryableTransactionError(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && (pqErr.Code == "40001" || pqErr.Code == "40P01")
}

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConflictResolutionStoreRejectsInvalidPublicInputs(t *testing.T) {
	t.Parallel()
	store := &Store{}
	ctx := context.Background()
	if _, err := store.CreateConflictResolution(ctx, CreateConflictResolutionParams{}); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("CreateConflictResolution error=%v", err)
	}
	if _, err := store.GetConflictResolutionExecution(ctx, ""); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("GetConflictResolutionExecution error=%v", err)
	}
	if _, err := store.GetConflictResolutionExecutionByOperation(ctx, ""); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("GetConflictResolutionExecutionByOperation error=%v", err)
	}
	if _, err := store.ClaimConflictResolution(ctx, "", "", time.Time{}, 0); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("ClaimConflictResolution error=%v", err)
	}
	if err := store.MarkConflictResolutionTransferComplete(ctx, "", "", nil, time.Time{}); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("MarkConflictResolutionTransferComplete error=%v", err)
	}
	if err := store.RotateConflictResolutionTransfer(ctx, "", "", "", nil, time.Time{}, time.Time{}); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("RotateConflictResolutionTransfer error=%v", err)
	}
	if err := store.MarkConflictResolutionPublishing(ctx, "", time.Time{}); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("MarkConflictResolutionPublishing error=%v", err)
	}
	if _, err := store.GetConflictResolutionStatus(ctx, 0, ""); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("GetConflictResolutionStatus error=%v", err)
	}
	if err := store.CompleteConflictResolution(ctx, CompleteConflictResolutionParams{}); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("CompleteConflictResolution error=%v", err)
	}
	if err := store.FailConflictResolution(ctx, "", "", "", time.Time{}); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("FailConflictResolution error=%v", err)
	}
	if _, err := store.RestartConflictResolution(ctx, 0, "", time.Time{}); !errors.Is(err, ErrInvalidConflictResolution) {
		t.Fatalf("RestartConflictResolution error=%v", err)
	}
}

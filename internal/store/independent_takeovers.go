package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func recordIndependentTakeoverFactsTx(
	ctx context.Context,
	tx *sql.Tx,
	nodeID int64,
	facts []IndependentTakeoverFact,
	observedAt time.Time,
) error {
	for _, fact := range facts {
		result, err := tx.ExecContext(ctx, `
			INSERT INTO independent_activity_takeovers (
			  operation_id,node_id,local_handle,parent_claim_id,claim_id,
			  controller_generation,activity_epoch,takeover_sequence,
			  confirmed_at,first_observed_at,last_observed_at
			) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)
			ON CONFLICT (operation_id) DO UPDATE SET
			  last_observed_at=EXCLUDED.last_observed_at
			WHERE independent_activity_takeovers.node_id=EXCLUDED.node_id
			  AND independent_activity_takeovers.local_handle=EXCLUDED.local_handle
			  AND independent_activity_takeovers.parent_claim_id=EXCLUDED.parent_claim_id
			  AND independent_activity_takeovers.claim_id=EXCLUDED.claim_id
			  AND independent_activity_takeovers.controller_generation=EXCLUDED.controller_generation
			  AND independent_activity_takeovers.activity_epoch=EXCLUDED.activity_epoch
			  AND independent_activity_takeovers.takeover_sequence=EXCLUDED.takeover_sequence
			  AND independent_activity_takeovers.confirmed_at=EXCLUDED.confirmed_at`,
			fact.OperationID, nodeID, fact.Handle, fact.ParentClaimID, fact.ClaimID,
			fact.ControllerGeneration, fact.ActivityEpoch, fact.TakeoverSequence,
			fact.ConfirmedAt, observedAt)
		if err != nil {
			return fmt.Errorf("record independent activity takeover: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read independent activity takeover result: %w", err)
		}
		if rows != 1 {
			return fmt.Errorf("independent activity takeover operation conflict")
		}
	}
	return nil
}

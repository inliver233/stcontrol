package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"stcontrol/internal/protocol"
)

var ErrAccountImportScanState = errors.New("account import scan workflow state conflict")

const (
	AccountImportScanQueued            = "queued"
	AccountImportScanRunning           = "running"
	AccountImportScanRetryWait         = "retry_wait"
	AccountImportScanInventoryComplete = "inventory_complete"
	AccountImportScanSucceeded         = "succeeded"
)

type AccountImportScanWorkflow struct {
	OperationID          string
	NodeID               int64
	CreatedByAdminID     sql.NullInt64
	State                string
	ControllerGeneration int64
	Cursor               int
	TotalUsers           sql.NullInt64
	CompletedPages       int
	InventoryRevision    sql.NullString
	InventoryUsers       json.RawMessage
	Attempt              int
	NextAttemptAt        time.Time
	ErrorCode            sql.NullString
	ErrorSummary         sql.NullString
	LeaseOwner           sql.NullString
	LeaseUntil           sql.NullTime
	BatchID              sql.NullString
	CreatedAt            time.Time
	UpdatedAt            time.Time
	FinishedAt           sql.NullTime
}

type CreateAccountImportScanParams struct {
	OperationID      string
	NodeID           int64
	CreatedByAdminID int64
	Now              time.Time
}

func (s *Store) CreateAccountImportScan(
	ctx context.Context,
	p CreateAccountImportScanParams,
) (*AccountImportScanWorkflow, error) {
	if !validUUIDText(p.OperationID) || p.NodeID <= 0 || p.CreatedByAdminID < 0 {
		return nil, ErrInvalidAccountImport
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO account_import_scan_workflows (
		  operation_id,node_id,created_by_admin_id,state,controller_generation,
		  next_attempt_at,created_at,updated_at
		)
		SELECT $1,$2,$3,'queued',generation,$4,$4,$4
		FROM controller_epochs WHERE state='active'
		ON CONFLICT (operation_id) DO NOTHING`,
		p.OperationID, p.NodeID, nullInt64(p.CreatedByAdminID), p.Now)
	if err != nil {
		return nil, err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil {
		return nil, rowsErr
	} else if rows == 0 {
		var active bool
		if err := s.DB.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM controller_epochs WHERE state='active')`).Scan(&active); err != nil {
			return nil, err
		}
		if !active {
			return nil, ErrNoActiveController
		}
	}
	workflow, err := s.GetAccountImportScan(ctx, p.OperationID)
	if err != nil {
		return nil, err
	}
	if workflow == nil || workflow.NodeID != p.NodeID ||
		workflow.CreatedByAdminID.Valid != (p.CreatedByAdminID > 0) ||
		(workflow.CreatedByAdminID.Valid && workflow.CreatedByAdminID.Int64 != p.CreatedByAdminID) {
		return nil, ErrAccountImportConflict
	}
	return workflow, nil
}

func (s *Store) GetAccountImportScan(ctx context.Context, operationID string) (*AccountImportScanWorkflow, error) {
	if !validUUIDText(operationID) {
		return nil, ErrInvalidAccountImport
	}
	workflow := &AccountImportScanWorkflow{}
	err := scanAccountImportScan(s.DB.QueryRowContext(ctx, `
		SELECT operation_id::text,node_id,created_by_admin_id,state,controller_generation,
		  cursor,total_users,completed_pages,inventory_revision,inventory_users,attempt,
		  next_attempt_at,error_code,error_summary,lease_owner::text,lease_until,
		  batch_id::text,created_at,updated_at,finished_at
		FROM account_import_scan_workflows WHERE operation_id=$1`, operationID), workflow)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return workflow, err
}

type accountImportScanRow interface {
	Scan(dest ...any) error
}

func scanAccountImportScan(row accountImportScanRow, workflow *AccountImportScanWorkflow) error {
	return row.Scan(
		&workflow.OperationID, &workflow.NodeID, &workflow.CreatedByAdminID, &workflow.State,
		&workflow.ControllerGeneration, &workflow.Cursor, &workflow.TotalUsers,
		&workflow.CompletedPages, &workflow.InventoryRevision, &workflow.InventoryUsers,
		&workflow.Attempt, &workflow.NextAttemptAt, &workflow.ErrorCode, &workflow.ErrorSummary,
		&workflow.LeaseOwner, &workflow.LeaseUntil, &workflow.BatchID, &workflow.CreatedAt,
		&workflow.UpdatedAt, &workflow.FinishedAt,
	)
}

// AdoptAccountImportScans moves unfinished work to the active Controller
// generation. Page results already durably accepted remain immutable; only
// the next command is regenerated under the new fence.
func (s *Store) AdoptAccountImportScans(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE account_import_scan_workflows workflow
		SET controller_generation=epoch.generation,
		  state=CASE WHEN workflow.state='inventory_complete' THEN workflow.state ELSE 'queued' END,
		  next_attempt_at=$1,lease_owner=NULL,lease_until=NULL,
		  error_code=NULL,error_summary=NULL,updated_at=$1
		FROM controller_epochs epoch
		WHERE epoch.state='active' AND workflow.controller_generation<>epoch.generation
		  AND workflow.state IN ('queued','running','retry_wait','inventory_complete')`, now)
	return err
}

func (s *Store) ListDueAccountImportScans(ctx context.Context, now time.Time, limit int) ([]string, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 || limit > 20 {
		limit = 2
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT workflow.operation_id::text
		FROM account_import_scan_workflows workflow
		JOIN controller_epochs epoch ON epoch.generation=workflow.controller_generation AND epoch.state='active'
		WHERE workflow.state IN ('queued','running','retry_wait','inventory_complete')
		  AND workflow.next_attempt_at<=$1
		  AND (workflow.lease_until IS NULL OR workflow.lease_until<=$1)
		ORDER BY workflow.next_attempt_at,workflow.created_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) ClaimAccountImportScan(
	ctx context.Context,
	operationID, workerID string,
	now time.Time,
	ttl time.Duration,
) (bool, error) {
	if !validUUIDText(operationID) || !validUUIDText(workerID) || ttl <= 0 {
		return false, ErrInvalidAccountImport
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE account_import_scan_workflows workflow
		SET state=CASE WHEN workflow.state='inventory_complete' THEN workflow.state ELSE 'running' END,
		  lease_owner=$2,lease_until=$4,updated_at=$3
		FROM controller_epochs epoch
		WHERE workflow.operation_id=$1 AND workflow.controller_generation=epoch.generation
		  AND epoch.state='active'
		  AND workflow.state IN ('queued','running','retry_wait','inventory_complete')
		  AND workflow.next_attempt_at<=$3
		  AND (workflow.lease_until IS NULL OR workflow.lease_until<=$3)`,
		operationID, workerID, now, now.Add(ttl))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func (s *Store) ReleaseAccountImportScan(ctx context.Context, operationID, workerID string) error {
	_, err := s.DB.ExecContext(ctx, `
		UPDATE account_import_scan_workflows SET lease_owner=NULL,lease_until=NULL
		WHERE operation_id=$1 AND lease_owner=$2`, operationID, workerID)
	return err
}

func (s *Store) DeferAccountImportScan(
	ctx context.Context,
	operationID, workerID string,
	nextAttemptAt, now time.Time,
) error {
	if !validUUIDText(operationID) || !validUUIDText(workerID) || now.IsZero() || !nextAttemptAt.After(now) {
		return ErrInvalidAccountImport
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE account_import_scan_workflows
		SET next_attempt_at=$3,lease_owner=NULL,lease_until=NULL,updated_at=$4
		WHERE operation_id=$1 AND lease_owner=$2 AND lease_until>$4
		  AND state IN ('queued','running','retry_wait','inventory_complete')`,
		operationID, workerID, nextAttemptAt, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAccountImportScanState
	}
	return nil
}

func (s *Store) AppendAccountImportScanPage(
	ctx context.Context,
	operationID, workerID string,
	page protocol.ScanExistingPageResult,
	now time.Time,
) error {
	if !validUUIDText(operationID) || !validUUIDText(workerID) || now.IsZero() {
		return ErrInvalidAccountImport
	}
	encodedUsers, err := json.Marshal(page.Users)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var state string
	var generation int64
	var cursor, completedPages int
	var total sql.NullInt64
	var revision sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT state,controller_generation,cursor,total_users,completed_pages,inventory_revision
		FROM account_import_scan_workflows
		WHERE operation_id=$1 AND lease_owner=$2 AND lease_until>$3 FOR UPDATE`,
		operationID, workerID, now).Scan(
		&state, &generation, &cursor, &total, &completedPages, &revision,
	); err != nil {
		if err == sql.ErrNoRows {
			return ErrAccountImportScanState
		}
		return err
	}
	if state != AccountImportScanRunning || page.Cursor != cursor ||
		(revision.Valid && revision.String != page.InventoryRevision) ||
		(total.Valid && int(total.Int64) != page.TotalUsers) {
		return ErrAccountImportScanState
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx,
		`SELECT generation FROM controller_epochs WHERE state='active'`).Scan(&activeGeneration); err != nil {
		return err
	}
	if generation != activeGeneration {
		return ErrAccountImportScanState
	}
	nextCursor := page.Cursor + len(page.Users)
	nextState := AccountImportScanInventoryComplete
	if page.HasMore {
		nextCursor = page.NextCursor
		nextState = AccountImportScanQueued
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE account_import_scan_workflows
		SET state=$4,cursor=$5,total_users=$6,completed_pages=$7,
		  inventory_revision=$8,inventory_users=inventory_users || $9::jsonb,
		  attempt=0,next_attempt_at=$3,error_code=NULL,error_summary=NULL,
		  lease_owner=NULL,lease_until=NULL,updated_at=$3
		WHERE operation_id=$1 AND lease_owner=$2 AND lease_until>$3`,
		operationID, workerID, now, nextState, nextCursor, page.TotalUsers,
		completedPages+1, page.InventoryRevision, encodedUsers)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAccountImportScanState
	}
	return tx.Commit()
}

func (s *Store) ScheduleAccountImportScanRetry(
	ctx context.Context,
	operationID, workerID, errorCode, errorSummary string,
	nextAttemptAt, now time.Time,
) error {
	if !validUUIDText(operationID) || !validUUIDText(workerID) || errorCode == "" ||
		now.IsZero() || !nextAttemptAt.After(now) {
		return ErrInvalidAccountImport
	}
	if len(errorSummary) > 512 {
		errorSummary = errorSummary[:512]
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE account_import_scan_workflows
		SET state='retry_wait',attempt=attempt+1,next_attempt_at=$4,error_code=$3,
		  error_summary=NULLIF($5,''),lease_owner=NULL,lease_until=NULL,updated_at=$6
		WHERE operation_id=$1 AND lease_owner=$2 AND lease_until>$6
		  AND state IN ('queued','running','retry_wait')`,
		operationID, workerID, errorCode, nextAttemptAt, errorSummary, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAccountImportScanState
	}
	return nil
}

// ResetAccountImportScan discards only the read-only inventory pages when a
// node inventory revision can no longer continue. It never touches an already
// ingested batch or any managed account mapping.
func (s *Store) ResetAccountImportScan(
	ctx context.Context,
	operationID, workerID, errorCode string,
	nextAttemptAt, now time.Time,
) error {
	if !validUUIDText(operationID) || !validUUIDText(workerID) || errorCode == "" ||
		now.IsZero() || !nextAttemptAt.After(now) {
		return ErrInvalidAccountImport
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE account_import_scan_workflows
		SET state='queued',cursor=0,total_users=NULL,completed_pages=0,
		  inventory_revision=NULL,inventory_users='[]'::jsonb,attempt=0,
		  next_attempt_at=$4,error_code=$3,error_summary=NULL,
		  lease_owner=NULL,lease_until=NULL,updated_at=$5
		WHERE operation_id=$1 AND lease_owner=$2 AND lease_until>$5
		  AND state IN ('queued','running','retry_wait')`,
		operationID, workerID, errorCode, nextAttemptAt, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAccountImportScanState
	}
	return nil
}

func (s *Store) CompleteAccountImportScan(
	ctx context.Context,
	operationID, workerID, batchID string,
	now time.Time,
) error {
	if !validUUIDText(operationID) || !validUUIDText(workerID) || !validUUIDText(batchID) || now.IsZero() {
		return ErrInvalidAccountImport
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE account_import_scan_workflows
		SET state='succeeded',batch_id=$3,next_attempt_at=$4,error_code=NULL,error_summary=NULL,
		  lease_owner=NULL,lease_until=NULL,updated_at=$4,finished_at=$4
		WHERE operation_id=$1 AND lease_owner=$2 AND lease_until>$4
		  AND state='inventory_complete'`, operationID, workerID, batchID, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAccountImportScanState
	}
	return nil
}

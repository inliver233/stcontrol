package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

var relayColumns = []string{
	"id", "workflow_id", "snapshot_id", "source_node_id", "target_node_id",
	"attempt", "state", "controller_generation", "max_ciphertext_bytes",
	"plaintext_bytes", "ciphertext_bytes", "archive_sha256", "ciphertext_sha256",
	"storage_path", "expires_at",
}

func relayParams(now time.Time) CreateRelayTransferParams {
	return CreateRelayTransferParams{
		ID:           "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		WorkflowID:   "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		SnapshotID:   "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		SourceNodeID: 7, TargetNodeID: 9, Attempt: 1,
		UploadTokenHash: make([]byte, 32), DownloadTokenHash: bytesOf(1, 32),
		MaxCiphertextBytes: 1 << 30, ExpiresAt: now.Add(time.Hour), Now: now,
	}
}

func relayRow(p CreateRelayTransferParams, state string) *sqlmock.Rows {
	return sqlmock.NewRows(relayColumns).AddRow(
		p.ID, p.WorkflowID, p.SnapshotID, p.SourceNodeID, p.TargetNodeID,
		p.Attempt, state, int64(8), p.MaxCiphertextBytes,
		nil, nil, nil, nil, nil, p.ExpiresAt,
	)
}

func TestCreateRelayTransferBindsWorkflowAndActiveGeneration(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 21, 0, 0, 0, time.UTC)
	p := relayParams(now)
	mock.ExpectQuery(`INSERT INTO relay_transfers`).WithArgs(
		p.ID, p.WorkflowID, p.SnapshotID, p.SourceNodeID, p.TargetNodeID, p.Attempt,
		p.UploadTokenHash, p.DownloadTokenHash, p.MaxCiphertextBytes, p.ExpiresAt, p.Now,
	).WillReturnRows(relayRow(p, "prepared"))
	transfer, err := st.CreateRelayTransfer(context.Background(), p)
	if err != nil || transfer == nil || transfer.State != "prepared" || transfer.ControllerGeneration != 8 {
		t.Fatalf("transfer=%+v err=%v", transfer, err)
	}
	assertMockExpectations(t, mock)
}

func TestRelayUploadLifecycleIsTokenAndLeaseFenced(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 21, 0, 0, 0, time.UTC)
	p := relayParams(now)
	archiveHash := bytesOf(2, 32)
	leaseTTL := 5 * time.Minute
	uploading := relayRow(p, "uploading")
	uploading = sqlmock.NewRows(relayColumns).AddRow(
		p.ID, p.WorkflowID, p.SnapshotID, p.SourceNodeID, p.TargetNodeID,
		p.Attempt, "uploading", int64(8), p.MaxCiphertextBytes,
		int64(900), nil, archiveHash, nil, nil, p.ExpiresAt,
	)
	mock.ExpectQuery(`UPDATE relay_transfers relay SET state='uploading'`).WithArgs(
		p.ID, p.UploadTokenHash, int64(900), int64(1024), archiveHash, now, now.Add(leaseTTL),
	).WillReturnRows(uploading)
	transfer, err := st.ClaimRelayUpload(
		context.Background(), p.ID, p.UploadTokenHash, 900, 1024, archiveHash, now, leaseTTL,
	)
	if err != nil || transfer == nil || transfer.State != "uploading" || transfer.PlaintextBytes.Int64 != 900 {
		t.Fatalf("transfer=%+v err=%v", transfer, err)
	}
	cipherHash := bytesOf(3, 32)
	mock.ExpectExec(`UPDATE relay_transfers relay SET state='stored'`).WithArgs(
		p.ID, p.UploadTokenHash, int64(1024), cipherHash, "relay/task.relay", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.CompleteRelayUpload(
		context.Background(), p.ID, p.UploadTokenHash, cipherHash, 1024, "relay/task.relay", now,
	); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`UPDATE relay_transfers relay SET state='prepared'`).WithArgs(p.ID, p.UploadTokenHash, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.ReleaseRelayUpload(context.Background(), p.ID, p.UploadTokenHash, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestRelayDownloadLifecycleDoesNotConsumeUntilExplicitConfirmation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 21, 0, 0, 0, time.UTC)
	p := relayParams(now)
	leaseTTL := 10 * time.Minute
	downloading := sqlmock.NewRows(relayColumns).AddRow(
		p.ID, p.WorkflowID, p.SnapshotID, p.SourceNodeID, p.TargetNodeID,
		p.Attempt, "downloading", int64(8), p.MaxCiphertextBytes,
		int64(900), int64(1024), bytesOf(2, 32), bytesOf(3, 32), "relay/task.relay", p.ExpiresAt,
	)
	mock.ExpectQuery(`UPDATE relay_transfers relay SET state='downloading'`).WithArgs(
		p.ID, p.DownloadTokenHash, now, now.Add(leaseTTL),
	).WillReturnRows(downloading)
	transfer, err := st.ClaimRelayDownload(context.Background(), p.ID, p.DownloadTokenHash, now, leaseTTL)
	if err != nil || transfer == nil || transfer.State != "downloading" || !transfer.StoragePath.Valid {
		t.Fatalf("transfer=%+v err=%v", transfer, err)
	}
	mock.ExpectExec(`UPDATE relay_transfers relay SET state='stored'`).WithArgs(p.ID, p.DownloadTokenHash, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.ReleaseRelayDownload(context.Background(), p.ID, p.DownloadTokenHash, now); err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`UPDATE relay_transfers relay SET state='consumed'`).WithArgs(p.ID, p.DownloadTokenHash, now).
		WillReturnRows(sqlmock.NewRows([]string{"storage_path"}).AddRow("relay/task.relay"))
	path, err := st.CompleteRelayDownload(context.Background(), p.ID, p.DownloadTokenHash, now)
	if err != nil || path != "relay/task.relay" {
		t.Fatalf("path=%q err=%v", path, err)
	}
	assertMockExpectations(t, mock)
}

func TestExpireRelayTransfersReturnsOnlyCommittedSpoolPaths(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 22, 0, 0, 0, time.UTC)
	id := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id::text,storage_path FROM relay_transfers`).WithArgs(now, 10).
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}).AddRow(id, "relay/task.relay"))
	mock.ExpectExec(`UPDATE relay_transfers SET state='expired'`).WithArgs(id, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expired, err := st.ExpireRelayTransfers(context.Background(), now, 10)
	if err != nil || len(expired) != 1 || !expired[0].StoragePath.Valid {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
	assertMockExpectations(t, mock)
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = value
	}
	return out
}

package controller

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

const controllerBackupLifecycleID = "22222222-2222-4222-8222-222222222222"

func expectControllerBackupClaim(
	mock sqlmock.Sqlmock,
	server *Server,
	backupKind string,
) {
	now := time.Now().UTC()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT backup.id::text,backup.node_id,backup.state.*FROM controller_disaster_backups backup`).
		WithArgs(controllerBackupFailureOperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "node_id", "state", "generation", "kind", "attempt", "next_attempt_at",
		}).AddRow(controllerBackupLifecycleID, int64(9), store.ControllerBackupScheduled,
			int64(3), backupKind, 0, now.Add(-time.Minute)))
	mock.ExpectQuery(`(?s)UPDATE controller_disaster_backups tgt SET.*RETURNING tgt.state`).
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "lease_owner", "lease_until", "started_at", "finished_at", "attempt",
		}).AddRow(store.ControllerBackupSnapshotting, server.workflowWorkerID,
			now.Add(time.Minute), now, nil, 1))
	mock.ExpectCommit()
}

func controllerBackupTargetRows(now time.Time, transferURL string) *sqlmock.Rows {
	columns := []string{
		"id", "name", "role", "base_url", "transfer_url", "region",
		"cpu_pct", "mem_pct", "disk_pct", "agent_version", "tavern_version", "last_seen_at", "status",
		"connectivity_state", "operational_state", "control_mode", "control_mode_generation",
		"desired_control_mode", "desired_mode_generation", "capacity_state", "capacity_reason_code",
		"capacity_changed_at", "capacity_cooldown_until", "compatibility_state", "compatibility_reason_code",
		"compatibility_fingerprint", "compatibility_reported_at", "metrics_observed_at",
		"cpu_window_avg", "cpu_window_peak", "mem_window_avg", "mem_window_peak",
		"disk_window_avg", "disk_window_peak", "disk_total_bytes", "disk_available_bytes",
		"disk_quota_bytes", "expected_disk_quota_bytes", "quota_policy_version", "quota_sync_state",
		"quota_sync_at", "quota_sync_error_code", "allocated_disk_bytes", "online_users", "task_queue_depth", "telemetry_source",
		"client_latency_ms", "client_latency_observed_at",
		"allow_register", "recommendation_weight", "is_backup_target", "registration_policy_state",
		"registration_policy_version", "registration_policy_expires_at",
		"registration_policy_observed_at", "registration_policy_error_code", "created_at",
	}
	return sqlmock.NewRows(columns).AddRow(
		int64(9), "storage-a", "storage", "https://storage-a.example", transferURL, "hk",
		10.0, 20.0, 30.0, "agent", "", now, "online",
		"online", "active", "managed", int64(3), "managed", int64(3),
		"open", nil, now, nil, "compatible", nil, "fingerprint", now, now,
		10.0, 20.0, 10.0, 20.0, 30.0, 30.0,
		int64(200<<30), int64(100<<30), int64(180<<30), int64(0), int64(0), "synced", nil, nil,
		int64(20<<30), 0, 0, "agent", nil, nil,
		false, 0, true, "closed", int64(1), nil, now, nil, now,
	)
}

func expectControllerBackupTarget(mock sqlmock.Sqlmock, now time.Time, transferURL string) {
	mock.ExpectQuery(`(?s)SELECT .*connectivity_state.*capacity_state.* FROM nodes WHERE id=\$1`).
		WithArgs(int64(9)).WillReturnRows(controllerBackupTargetRows(now, transferURL))
}

func expectControllerBackupFailurePersistence(
	mock sqlmock.Sqlmock,
	server *Server,
	code string,
) {
	maxAttempts := controllerBackupMaxAttempts(server.controllerBackupPolicy())
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT attempt FROM controller_disaster_backups`).
		WithArgs(controllerBackupFailureOperationID).
		WillReturnRows(sqlmock.NewRows([]string{"attempt"}).AddRow(1))
	mock.ExpectExec(`UPDATE controller_disaster_backups SET`).
		WithArgs(
			controllerBackupFailureOperationID, code, 1, maxAttempts,
			sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func newControllerBackupLifecycleServer(t *testing.T) (*Server, sqlmock.Sqlmock) {
	t.Helper()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	cfg := config.DefaultController()
	cfg.ControllerBackup.Enabled = true
	return New(cfg, &store.Store{DB: database}, []byte("01234567890123456789012345678901")), mock
}

func TestExecuteControllerBackupClaimAndTargetFailureMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(*Server, sqlmock.Sqlmock)
		err   bool
	}{
		{
			name: "claim failure",
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				mock.ExpectBegin().WillReturnError(errors.New("claim unavailable"))
			},
			err: true,
		},
		{
			name: "nothing claimable",
			setup: func(server *Server, mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM controller_disaster_backups backup`).
					WillReturnError(sql.ErrNoRows)
				mock.ExpectCommit()
				_ = server
			},
		},
		{
			name: "target unavailable",
			setup: func(server *Server, mock sqlmock.Sqlmock) {
				expectControllerBackupClaim(mock, server, store.ControllerBackupKindSnapshot)
				mock.ExpectQuery(`FROM nodes WHERE id=\$1`).WithArgs(int64(9)).WillReturnError(sql.ErrNoRows)
				expectControllerBackupFailurePersistence(mock, server, "target_unavailable")
			},
			err: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, mock := newControllerBackupLifecycleServer(t)
			tc.setup(server, mock)
			err := server.executeControllerBackup(context.Background(), &store.ControllerDisasterBackupRun{
				OperationID: controllerBackupFailureOperationID,
			})
			if (err != nil) != tc.err {
				t.Fatalf("error=%v wantError=%v", err, tc.err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExecuteControllerBackupPersistsSnapshotAndPgDumpFailures(t *testing.T) {
	now := time.Now().UTC()
	t.Run("snapshot progress", func(t *testing.T) {
		server, mock := newControllerBackupLifecycleServer(t)
		expectControllerBackupClaim(mock, server, store.ControllerBackupKindSnapshot)
		expectControllerBackupTarget(mock, now, "https://storage-a.example")
		mock.ExpectExec(`UPDATE controller_disaster_backups SET state=\$2`).
			WillReturnError(errors.New("progress unavailable"))
		expectControllerBackupFailurePersistence(mock, server, "snapshot_progress_failed")
		if err := server.executeControllerBackup(context.Background(), &store.ControllerDisasterBackupRun{
			OperationID: controllerBackupFailureOperationID,
		}); err == nil {
			t.Fatal("snapshot progress failure was accepted")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("pg dump", func(t *testing.T) {
		server, mock := newControllerBackupLifecycleServer(t)
		server.Cfg.DatabaseURL = "postgres://user@localhost"
		expectControllerBackupClaim(mock, server, store.ControllerBackupKindPGDump)
		expectControllerBackupTarget(mock, now, "https://storage-a.example")
		mock.ExpectExec(`UPDATE controller_disaster_backups SET state=\$2`).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectControllerBackupFailurePersistence(mock, server, "pg_dump_failed")
		if err := server.executeControllerBackup(context.Background(), &store.ControllerDisasterBackupRun{
			OperationID: controllerBackupFailureOperationID,
		}); err == nil {
			t.Fatal("pg_dump failure was accepted")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestExecuteControllerBackupBuildsRecoveryArchiveBeforeTransferFence(t *testing.T) {
	server, mock := newControllerBackupLifecycleServer(t)
	now := time.Now().UTC()
	configPath := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(configPath, []byte("listen: 127.0.0.1:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.ConfigPath = configPath
	const passphraseEnvironment = "STCONTROL_TEST_CONTROLLER_BACKUP_RECOVERY_PASSPHRASE"
	t.Setenv(passphraseEnvironment, "bounded-test-recovery-passphrase")
	server.Cfg.ControllerBackup.RecoveryPassphraseEnv = passphraseEnvironment

	expectControllerBackupClaim(mock, server, store.ControllerBackupKindSnapshot)
	expectControllerBackupTarget(mock, now, "https://storage-a.example")
	mock.ExpectExec(`UPDATE controller_disaster_backups SET state=\$2`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE controller_disaster_backups SET state=\$2`).
		WillReturnError(errors.New("transfer fence unavailable"))
	expectControllerBackupFailurePersistence(mock, server, "transfer_progress_failed")

	err := server.executeControllerBackup(context.Background(), &store.ControllerDisasterBackupRun{
		OperationID: controllerBackupFailureOperationID,
	})
	if err == nil {
		t.Fatal("transfer progress failure was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

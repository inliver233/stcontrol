package controller

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/lib/pq"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// TestControllerDisasterBackupRunsRealPgDumpEndToEnd closes the Round-60
// evidence gap flagged by the 2026-08-15 review (M3): the controller disaster
// backup store layer previously had only sqlmock coverage. This test runs the
// full production executor against a REAL PostgreSQL instance and a REAL
// pg_dump binary:
//
//   - a dedicated throwaway database receives all 48 migrations;
//   - the production executeControllerBackup claims the run, invokes
//     pg_dump.exe from PATH, seals the archive and streams it over the real
//     HTTP transfer path (loopback http is the documented test exception);
//   - the durable receive_controller_backup command is executed by the real
//     command-queue harness with a genuine encrypted payload;
//   - the received tar.zst is decompressed and the pg dump is verified to
//     contain the migrated schema plus a seeded audit row.
//
// Skips (never silently passes) when the DSN env var or the bundled pg_dump
// binary is unavailable.
func TestControllerDisasterBackupRunsRealPgDumpEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller disaster-backup pg_dump integration is disabled in short mode")
	}
	baseDSN := strings.TrimSpace(os.Getenv(controllerBackupPostgresDSNEnv))
	if baseDSN == "" {
		t.Skipf("set %s to run the real pg_dump controller backup test", controllerBackupPostgresDSNEnv)
	}
	pgDumpBin := locateTestPgDump(t)

	// A dedicated database (not a schema) keeps pg_dump output bounded to
	// exactly what this test migrated, regardless of concurrent schema tests.
	adminDB, err := sql.Open("postgres", baseDSN)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	dbName := fmt.Sprintf("stcontrol_cbtest_%d_%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := adminDB.ExecContext(ctx, `CREATE DATABASE `+pq.QuoteIdentifier(dbName)); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create throwaway database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_, _ = adminDB.ExecContext(cleanupCtx, `DROP DATABASE `+pq.QuoteIdentifier(dbName)+` WITH (FORCE)`)
		_ = adminDB.Close()
	})

	dsn, err := withDatabaseName(baseDSN, dbName)
	if err != nil {
		t.Fatalf("rewrite dsn: %v", err)
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store on throwaway database (migrations): %v", err)
	}
	defer func() { _ = st.Close() }()

	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read active generation: %v", err)
	}
	// Seed one durable fact so the dump provably carries data, not only DDL.
	if err := st.Audit(ctx, "system", "pgdump-e2e-seed", "controller-backup-test", []byte(`{"marker":"pgdump-e2e"}`)); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	// Real HTTP receive endpoint on loopback (the production transfer guard
	// permits plain http only for loopback; this mirrors an agent data plane).
	var recvMu sync.Mutex
	var received []byte
	var receivedBearer, receivedSHA string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/transfer/v1/controller-backups/") || r.Method != http.MethodPost {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		recvMu.Lock()
		received = append([]byte(nil), body...)
		receivedBearer = r.Header.Get("Authorization")
		receivedSHA = r.Header.Get("X-Archive-Sha256")
		recvMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.ControllerBackupReceipt{
			OK: true, ArchiveSHA256: hex.EncodeToString(digest[:]), TotalBytes: int64(len(body)),
		})
	}))
	defer receiver.Close()

	secretKey := []byte("0123456789abcdef0123456789abcdef")
	target := createControllerBackupNode(t, ctx, st, "controller-backup-target", "storage", true, generation)
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET transfer_url=$2, metrics_observed_at=now(),
		  disk_available_bytes=107374182400, disk_quota_bytes=107374182400, allocated_disk_bytes=0
		WHERE id=$1`,
		target.ID, receiver.URL); err != nil {
		t.Fatalf("point target transfer url at receiver: %v", err)
	}
	psks := map[int64]string{target.ID: "controller-backup-target-agent-psk"}
	seedControllerBackupCredential(t, ctx, st, secretKey, target.ID, generation, psks[target.ID])

	harness := newControllerBackupCommandHarness(ctx, st, target.ID, target.ID, psks)
	defer harness.stop()

	// Production server with the throwaway database as its own control plane
	// and a real config file on disk so the archive carries both artifacts.
	cfg := config.DefaultController()
	cfg.DatabaseURL = dsn
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	configFile := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(configFile, []byte("# stcontrol controller config (pg_dump e2e)\n"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	server := New(cfg, st, secretKey)
	server.ConfigPath = configFile

	// Make the real pg_dump binary visible to runPgDump (LookPath at call time).
	t.Setenv("PATH", filepath.Dir(pgDumpBin)+string(os.PathListSeparator)+os.Getenv("PATH"))

	run, err := st.ScheduleControllerDisasterBackup(ctx, store.ScheduleControllerDisasterBackupParams{
		OperationID: "11111111-2222-4333-8444-555555555555",
		MaxAttempts: 3, Interval: time.Hour,
		LeaseOwner: server.workflowWorkerID, LeaseTTL: controllerBackupLeaseTTL,
		Now: time.Now().UTC(),
	})
	if err != nil || run == nil {
		t.Fatalf("schedule controller disaster backup: run=%v err=%v", run, err)
	}
	if err := server.executeControllerBackup(ctx, run); err != nil {
		t.Fatalf("execute controller disaster backup: %v", err)
	}

	var state, archiveName string
	var manifestJSON []byte
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state, payload_file_name, manifest FROM controller_disaster_backups WHERE operation_id=$1`,
		run.OperationID).Scan(&state, &archiveName, &manifestJSON); err != nil || state != "succeeded" {
		t.Fatalf("controller disaster backup state=%q err=%v", state, err)
	}
	if archiveName != "controller_backup.tar.zst" {
		t.Fatalf("archive name=%q", archiveName)
	}

	// Verify the streamed archive: manifest declares the dump, the dump holds
	// the migrated schema plus the seeded audit row, and the config file made
	// it in. The bearer capability must have been presented.
	recvMu.Lock()
	archiveBytes := append([]byte(nil), received...)
	bearer, wantSHA := receivedBearer, receivedSHA
	recvMu.Unlock()
	if len(archiveBytes) == 0 {
		t.Fatal("receiver captured no archive bytes")
	}
	if !strings.HasPrefix(bearer, "Bearer ") || len(bearer) <= len("Bearer ") {
		t.Fatalf("missing capability bearer: %q", bearer)
	}
	digest := sha256.Sum256(archiveBytes)
	if wantSHA != hex.EncodeToString(digest[:]) {
		t.Fatalf("X-Archive-Sha256 mismatch: header=%q actual=%s", wantSHA, hex.EncodeToString(digest[:]))
	}
	contents := untarControllerBackupArchive(t, archiveBytes)
	dump := string(contents[controllerBackupPgDumpName])
	if !strings.Contains(dump, "CREATE TABLE") {
		t.Fatal("pg dump contains no CREATE TABLE statements")
	}
	for _, table := range []string{"agent_commands", "audit_events", "ai_advisory_requests", "controller_disaster_backups"} {
		if !strings.Contains(dump, table) {
			t.Fatalf("pg dump is missing table %s", table)
		}
	}
	if !strings.Contains(dump, "pgdump-e2e-seed") {
		t.Fatal("pg dump is missing the seeded audit row")
	}
	if !bytes.Contains(contents["controller.yaml"], []byte("pg_dump e2e")) {
		t.Fatal("archive is missing the controller config file")
	}
	var manifest struct {
		DBDump struct {
			Enabled bool   `json:"enabled"`
			Name    string `json:"name"`
		} `json:"db_dump"`
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(contents[controllerBackupManifestName], &manifest); err != nil ||
		!manifest.DBDump.Enabled || manifest.DBDump.Name != controllerBackupPgDumpName ||
		manifest.OperationID != run.OperationID {
		t.Fatalf("manifest=%s err=%v", contents[controllerBackupManifestName], err)
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("durable Agent harness errors: %v", errs)
	}
}

// locateTestPgDump finds the real pg_dump binary bundled with the project's
// test PostgreSQL runtime (or STCONTROL_TEST_PG_BIN), skipping the test when
// neither exists - never inventing a pass.
func locateTestPgDump(t *testing.T) string {
	t.Helper()
	if override := strings.TrimSpace(os.Getenv("STCONTROL_TEST_PG_BIN")); override != "" {
		if _, err := os.Stat(override); err != nil {
			t.Skipf("STCONTROL_TEST_PG_BIN=%q not found: %v", override, err)
		}
		return override
	}
	candidates := []string{
		filepath.Join("..", "..", ".test-postgres", "runtime", "pgsql", "bin", "pg_dump.exe"),
		filepath.Join("..", "..", ".test-postgres", "runtime", "pgsql", "bin", "pg_dump"),
	}
	for _, candidate := range candidates {
		if abs, err := filepath.Abs(candidate); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	t.Skip("no bundled pg_dump binary found under .test-postgres/runtime/pgsql/bin")
	return ""
}

func withDatabaseName(baseDSN, dbName string) (string, error) {
	parsed, err := url.Parse(baseDSN)
	if err != nil {
		return "", err
	}
	parsed.Path = "/" + dbName
	return parsed.String(), nil
}

func untarControllerBackupArchive(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", header.Name, err)
		}
		out[header.Name] = data
	}
	if len(out) == 0 {
		t.Fatal("archive is empty")
	}
	return out
}

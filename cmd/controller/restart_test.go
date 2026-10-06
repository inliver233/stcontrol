package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"stcontrol/internal/config"
)

// A planned stop lets the next process continue the generation; a crash, an
// explicit recovery or a lost leadership lock still promotes a new one.
func TestControllerRestartContinuesGenerationOnlyAfterCleanStop(t *testing.T) {
	baseDSN := strings.TrimSpace(os.Getenv("STCONTROL_TEST_POSTGRES_DSN"))
	if baseDSN == "" {
		t.Skip("set STCONTROL_TEST_POSTGRES_DSN to run the Controller restart integration")
	}
	parsed, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	adminDB, err := sql.Open("postgres", baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	schema := fmt.Sprintf("stcontrol_cmd_restart_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := adminDB.Exec(`CREATE SCHEMA ` + pq.QuoteIdentifier(schema)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := adminDB.Exec(`DROP SCHEMA ` + pq.QuoteIdentifier(schema) + ` CASCADE`); err != nil {
			t.Errorf("drop Controller restart schema: %v", err)
		}
	}()
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()

	port := reserveControllerMainPort(t)
	cfg := config.DefaultController()
	cfg.DatabaseURL = parsed.String()
	cfg.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.PublicURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	cfg.ControllerBackup.Enabled = false
	cfg.Admin.PasswordEnv = "STCONTROL_CONTROLLER_RESTART_TEST_ADMIN_PASSWORD"
	t.Setenv(cfg.Admin.PasswordEnv, "controller-restart-test-password")
	secretKey := bytes.Repeat([]byte{0x42}, 32)

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	type running struct {
		cancel context.CancelFunc
		done   chan error
	}
	start := func(promote bool) running {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runController(ctx, cfg, "", secretKey, false, promote) }()
		client := &http.Client{Timeout: 250 * time.Millisecond}
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
			select {
			case err := <-done:
				cancel()
				t.Fatalf("Controller exited during startup: %v", err)
			default:
			}
			response, requestErr := client.Get(cfg.PublicURL + "/api/health")
			if requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusNoContent {
					return running{cancel: cancel, done: done}
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
		t.Fatal("Controller did not serve health")
		return running{}
	}
	wait := func(r running, within time.Duration) error {
		t.Helper()
		select {
		case err := <-r.done:
			return err
		case <-time.After(within):
			t.Fatalf("Controller did not stop within %s", within)
			return nil
		}
	}
	stop := func(r running) {
		t.Helper()
		started := time.Now()
		r.cancel()
		if err := wait(r, 10*time.Second); err != nil {
			t.Fatalf("Controller stop: %v", err)
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("clean stop took %s", elapsed)
		}
	}
	active := func() (int64, bool) {
		t.Helper()
		var generation int64
		var marked bool
		if err := db.QueryRow(`
			SELECT generation, clean_shutdown_at IS NOT NULL FROM controller_epochs
			WHERE state='active'`).Scan(&generation, &marked); err != nil {
			t.Fatalf("read active generation: %v", err)
		}
		return generation, marked
	}

	first := start(false)
	generation, marked := active()
	if marked {
		t.Fatal("a running Controller must not look cleanly stopped")
	}
	stop(first)
	if got, marked := active(); got != generation || !marked {
		t.Fatalf("after clean stop: generation=%d marked=%v, want %d marked", got, marked, generation)
	}

	// Planned restart: same generation, record consumed.
	second := start(false)
	if got, marked := active(); got != generation || marked {
		t.Fatalf("after clean restart: generation=%d marked=%v, want %d unmarked", got, marked, generation)
	}
	stop(second)

	// Crash: no record, so the next start promotes.
	if _, err := db.Exec(`UPDATE controller_epochs SET clean_shutdown_at=NULL WHERE state='active'`); err != nil {
		t.Fatal(err)
	}
	third := start(false)
	if got, _ := active(); got != generation+1 {
		t.Fatalf("after crash: generation=%d, want %d", got, generation+1)
	}
	stop(third)

	// Explicit recovery promotes even after a clean stop.
	fourth := start(true)
	if got, _ := active(); got != generation+2 {
		t.Fatalf("after explicit recovery: generation=%d, want %d", got, generation+2)
	}

	// Losing the leadership connection stops the process without marking it clean.
	if _, err := db.Exec(`
		SELECT pg_terminate_backend(pid) FROM pg_locks
		WHERE locktype='advisory' AND granted AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=1`,
		int64(0x5354434f), int64(0x4e54524c)); err != nil {
		t.Fatalf("terminate leadership backend: %v", err)
	}
	if err := wait(fourth, 20*time.Second); err != nil {
		t.Fatalf("Controller after losing leadership: %v", err)
	}
	fourth.cancel()
	if got, marked := active(); got != generation+2 || marked {
		t.Fatalf("after lost leadership: generation=%d marked=%v", got, marked)
	}
	fifth := start(false)
	if got, _ := active(); got != generation+3 {
		t.Fatalf("after lost leadership restart: generation=%d, want %d", got, generation+3)
	}
	stop(fifth)
}

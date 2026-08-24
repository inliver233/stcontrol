package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const controllerBackupFailureOperationID = "11111111-1111-4111-8111-111111111111"

func TestBuildControllerBackupArchiveRejectsUnsafeInputsAndCancellation(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing.tar.zst")
	if err := os.WriteFile(existing, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := buildControllerBackupArchive(context.Background(), existing, "", "", []byte(`{}`), ""); err == nil {
		t.Fatal("existing controller backup archive was overwritten")
	}

	for _, payload := range []string{filepath.Join(root, "missing"), root} {
		archivePath := filepath.Join(root, filepath.Base(payload)+".tar.zst")
		if err := buildControllerBackupArchive(context.Background(), archivePath, payload, "", []byte(`{}`), ""); err == nil {
			t.Fatalf("invalid controller backup payload accepted: %q", payload)
		}
		if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
			t.Fatalf("failed archive survived for %q: %v", payload, err)
		}
	}

	payload := filepath.Join(root, "dump.sql")
	if err := os.WriteFile(payload, bytes.Repeat([]byte("database-row\n"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	archivePath := filepath.Join(root, "cancelled.tar.zst")
	if err := buildControllerBackupArchive(cancelled, archivePath, payload, "", []byte(`{}`), ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled archive error=%v", err)
	}
	if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
		t.Fatalf("cancelled archive survived: %v", err)
	}

	reader := controllerBackupContextReader{ctx: cancelled, reader: strings.NewReader("payload")}
	if count, err := reader.Read(make([]byte, 8)); count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled reader count=%d err=%v", count, err)
	}
	reader = controllerBackupContextReader{ctx: context.Background(), reader: strings.NewReader("payload")}
	buffer := make([]byte, 8)
	if count, err := reader.Read(buffer); err != nil || string(buffer[:count]) != "payload" {
		t.Fatalf("reader count=%d payload=%q err=%v", count, buffer[:count], err)
	}
}

func TestControllerBackupTransportFailureMatrix(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "controller.tar.zst")
	if err := os.WriteFile(archivePath, []byte("controller-backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controllerFileSize(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing controller archive size succeeded")
	}
	if _, err := controllerFileSHA256(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing controller archive hash succeeded")
	}

	invalidTargets := []string{
		"not-a-url",
		"https://user@example.com",
		"https://example.com/path?query=1",
		"https://example.com/path#fragment",
		"http://example.com",
	}
	for _, target := range invalidTargets {
		if _, err := controllerBackupTransferEndpoint(target, controllerBackupFailureOperationID); err == nil {
			t.Fatalf("invalid controller backup target accepted: %q", target)
		}
	}
	if _, err := controllerBackupTransferEndpoint("https://example.com", "bad-operation"); err == nil {
		t.Fatal("invalid operation ID accepted")
	}

	if _, err := streamControllerBackup(context.Background(), "not-a-url", controllerBackupFailureOperationID, "cap", "digest", archivePath, 1); err == nil {
		t.Fatal("invalid stream target accepted")
	}
	if _, err := streamControllerBackup(context.Background(), "http://127.0.0.1:1", controllerBackupFailureOperationID, "cap", "digest", filepath.Join(t.TempDir(), "missing"), 1); err == nil {
		t.Fatal("missing stream archive accepted")
	}

	for _, testCase := range []struct {
		name, body string
		status     int
	}{
		{name: "business rejection", status: http.StatusConflict, body: `{}`},
		{name: "malformed receipt", status: http.StatusOK, body: `not-json`},
		{name: "negative receipt", status: http.StatusOK, body: `{"ok":false}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(testCase.status)
				_, _ = io.WriteString(w, testCase.body)
			}))
			defer server.Close()
			if _, err := streamControllerBackup(
				context.Background(), server.URL, controllerBackupFailureOperationID,
				"capability", "digest", archivePath, int64(len("controller-backup")),
			); err == nil {
				t.Fatal("invalid controller backup response accepted")
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := streamControllerBackup(
		cancelled, "http://127.0.0.1:1", controllerBackupFailureOperationID,
		"capability", "digest", archivePath, int64(len("controller-backup")),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stream error=%v", err)
	}
}

func TestRunPgDumpRejectsInvalidConfigurationAndSurfacesFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell pg_dump fixture is Unix-only")
	}
	for _, dsn := range []string{"%", "postgres://user@localhost", "postgres:///database"} {
		if err := runPgDump(context.Background(), dsn, filepath.Join(t.TempDir(), "dump.sql")); err == nil {
			t.Fatalf("invalid pg_dump DSN accepted: %q", dsn)
		}
	}

	t.Setenv("PATH", t.TempDir())
	if err := runPgDump(context.Background(), "postgres://user:pass@localhost/database", filepath.Join(t.TempDir(), "dump.sql")); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing pg_dump error=%v", err)
	}

	binDir := t.TempDir()
	fixture := filepath.Join(binDir, "pg_dump")
	if err := os.WriteFile(fixture, []byte("#!/bin/sh\necho bounded-failure >&2\nexit 9\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runPgDump(ctx, "postgres://user:pass@localhost/database", filepath.Join(t.TempDir(), "dump.sql"))
	if err == nil || !strings.Contains(err.Error(), "bounded-failure") {
		t.Fatalf("pg_dump failure error=%v", err)
	}
	if err := runPgDump(ctx, "postgres://user:pass@localhost/database", filepath.Join(t.TempDir(), "missing", "dump.sql")); err == nil {
		t.Fatal("unwritable pg_dump output accepted")
	}
}

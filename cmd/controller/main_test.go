package main

import (
	"archive/tar"
	"bytes"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/lib/pq"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
)

func TestControllerMainRecoveryCommand(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x35}, 32)
	passphrase := "controller-main-recovery-passphrase"
	envelope, err := controlcrypto.SealMasterKeyRecovery(passphrase, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	envelopeJSON, err := controlcrypto.EncodeMasterKeyRecoveryJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	archive := writeRecoveryArchive(t, []tarEntry{{name: "master_key_recovery.json", body: envelopeJSON}})
	cfg := config.DefaultController()
	configPath := filepath.Join(t.TempDir(), "controller.yaml")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	recoveryEnv := cfg.ControllerBackup.RecoveryPassphraseEnv
	if recoveryEnv == "" {
		recoveryEnv = "CONTROLLER_RECOVERY_PASSPHRASE"
	}
	t.Setenv(recoveryEnv, passphrase)

	previousArgs, previousFlags := os.Args, flag.CommandLine
	defer func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlags
	}()
	os.Args = []string{"controller", "--config", configPath, "--recover-master-key", archive}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	output := captureMainStdout(t, main)
	if strings.TrimSpace(output) != base64.StdEncoding.EncodeToString(masterKey) {
		t.Fatalf("main recovery output=%q", output)
	}
}

func TestControllerMainServesHealthAndStopsOnSignal(t *testing.T) {
	baseDSN := strings.TrimSpace(os.Getenv("STCONTROL_TEST_POSTGRES_DSN"))
	if baseDSN == "" {
		t.Skip("set STCONTROL_TEST_POSTGRES_DSN to run Controller main lifecycle integration")
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
	schema := fmt.Sprintf("stcontrol_cmd_controller_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := adminDB.Exec(`CREATE SCHEMA ` + pq.QuoteIdentifier(schema)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := adminDB.Exec(`DROP SCHEMA ` + pq.QuoteIdentifier(schema) + ` CASCADE`); err != nil {
			t.Errorf("drop Controller main schema: %v", err)
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
	cfg.SecretKeyEnv = "STCONTROL_CONTROLLER_MAIN_TEST_KEY"
	cfg.Admin.PasswordEnv = "STCONTROL_CONTROLLER_MAIN_TEST_ADMIN_PASSWORD"
	configPath := filepath.Join(t.TempDir(), "controller.yaml")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cfg.SecretKeyEnv, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
	t.Setenv(cfg.Admin.PasswordEnv, "controller-main-test-password")

	done := make(chan struct{})
	go func() {
		defer close(done)
		withControllerMainArgs(t, []string{"controller", "--config", configPath}, main)
	}()
	client := &http.Client{Timeout: 250 * time.Millisecond}
	endpoint := cfg.PublicURL + "/api/health"
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		response, requestErr := client.Get(endpoint)
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Controller main did not serve health")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Controller main did not stop after SIGTERM")
	}
}

func withControllerMainArgs(t *testing.T, args []string, action func()) {
	t.Helper()
	previousArgs, previousFlags := os.Args, flag.CommandLine
	defer func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlags
	}()
	os.Args = args
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	action()
}

func reserveControllerMainPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func captureMainStdout(t *testing.T, action func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = previous }()
	action()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRecoverMasterKeyFromArchiveRoundTrip(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x5a}, 32)
	passphrase := "acceptance-recovery-passphrase"
	envelope, err := controlcrypto.SealMasterKeyRecovery(passphrase, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	envelopeJSON, err := controlcrypto.EncodeMasterKeyRecoveryJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	archive := writeRecoveryArchive(t, []tarEntry{
		{name: "controller.sql", body: []byte("select 1")},
		{name: "master_key_recovery.json", body: envelopeJSON},
	})
	got, err := recoverMasterKeyFromArchive(archive, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if got != base64.StdEncoding.EncodeToString(masterKey) {
		t.Fatalf("recovered key=%q", got)
	}
	if _, err := recoverMasterKeyFromArchive(archive, "wrong-recovery-passphrase"); err == nil ||
		!strings.Contains(err.Error(), "unwrap master key") {
		t.Fatalf("wrong passphrase error=%v", err)
	}
}

func TestRecoverMasterKeyFromArchiveRejectsUnsafeInputs(t *testing.T) {
	validJSON := []byte(`{"format_version":1}`)
	tests := []struct {
		name       string
		archive    func(*testing.T) string
		passphrase string
		want       string
	}{
		{"short passphrase", func(t *testing.T) string { return writeRecoveryArchive(t, nil) }, "short", "at least 8"},
		{"missing file", func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.tar.zst") }, "long-enough", "open disaster backup"},
		{"empty archive", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "empty")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}, "long-enough", "invalid disaster backup"},
		{"invalid zstd", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "bad")
			if err := os.WriteFile(path, []byte("not-zstd"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}, "long-enough", "disaster backup"},
		{"missing envelope", func(t *testing.T) string {
			return writeRecoveryArchive(t, []tarEntry{{name: "controller.sql", body: []byte("x")}})
		}, "long-enough", "is absent"},
		{"directory envelope", func(t *testing.T) string {
			return writeRecoveryArchive(t, []tarEntry{{name: "master_key_recovery.json", typeflag: tar.TypeDir}})
		}, "long-enough", "is absent"},
		{"zero envelope", func(t *testing.T) string {
			return writeRecoveryArchive(t, []tarEntry{{name: "master_key_recovery.json"}})
		}, "long-enough", "envelope size"},
		{"oversize envelope", func(t *testing.T) string {
			return writeRecoveryArchive(t, []tarEntry{{name: "master_key_recovery.json", body: make([]byte, (1<<20)+1)}})
		}, "long-enough", "envelope size"},
		{"malformed envelope", func(t *testing.T) string {
			return writeRecoveryArchive(t, []tarEntry{{name: "master_key_recovery.json", body: []byte("{")}})
		}, "long-enough", "decode recovery envelope"},
		{"invalid envelope", func(t *testing.T) string {
			return writeRecoveryArchive(t, []tarEntry{{name: "master_key_recovery.json", body: validJSON}})
		}, "long-enough", "unwrap master key"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := recoverMasterKeyFromArchive(test.archive(t), test.passphrase)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
}

func writeRecoveryArchive(t *testing.T, entries []tarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller-backup.tar.zst")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := zstd.NewWriter(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	tw := tar.NewWriter(encoder)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.body)), Typeflag: typeflag}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) > 0 {
			if _, err := tw.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

//go:build linux

package controller

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	agentpkg "stcontrol/internal/agent"
	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const snapshotAgentProcessHelperEnv = "STCONTROL_SNAPSHOT_AGENT_PROCESS_HELPER"

// TestSnapshotAgentProcessHelper runs one production Agent in a distinct OS
// process. The parent integration test supplies only the same fixed config
// fields used by cmd/agent; no command or data-plane behavior is replaced.
func TestSnapshotAgentProcessHelper(t *testing.T) {
	if os.Getenv(snapshotAgentProcessHelperEnv) != "1" {
		t.Skip("snapshot Agent process helper")
	}
	nodeID, err := strconv.ParseInt(os.Getenv("STCONTROL_HELPER_NODE_ID"), 10, 64)
	if err != nil || nodeID <= 0 {
		t.Fatalf("invalid helper node id")
	}
	cfg := &config.AgentConfig{
		ControllerURL:        os.Getenv("STCONTROL_HELPER_CONTROLLER_URL"),
		Listen:               os.Getenv("STCONTROL_HELPER_LISTEN"),
		Role:                 os.Getenv("STCONTROL_HELPER_ROLE"),
		NodeID:               nodeID,
		AgentPSK:             os.Getenv("STCONTROL_HELPER_AGENT_PSK"),
		TavernAdapterPSK:     os.Getenv("STCONTROL_HELPER_ADAPTER_PSK"),
		TavernDir:            os.Getenv("STCONTROL_HELPER_TAVERN_DIR"),
		TavernURL:            os.Getenv("STCONTROL_HELPER_TAVERN_URL"),
		TransferPublicURL:    os.Getenv("STCONTROL_HELPER_TRANSFER_URL"),
		BackupDir:            os.Getenv("STCONTROL_HELPER_BACKUP_DIR"),
		DataDir:              os.Getenv("STCONTROL_HELPER_DATA_DIR"),
		CredentialVersion:    1,
		ControllerGeneration: 1,
		HeartbeatSec:         3600,
	}
	a, err := agentpkg.New(cfg)
	if err != nil {
		t.Fatalf("initialize helper Agent: %v", err)
	}
	srv, err := agentpkg.NewHTTPServer(cfg, a.Handler())
	if err != nil {
		t.Fatalf("initialize helper Agent server: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go a.StartCommandLoop(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		t.Fatalf("run helper Agent: %v", err)
	}
}

func TestSnapshotWorkflowRecoversSourceAndTargetProcessCrashes(t *testing.T) {
	if testing.Short() {
		t.Skip("snapshot process crash matrix is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open process snapshot store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sourceNode := createControllerBackupNode(t, ctx, st, "process-snapshot-source", "compute", false, generation)
	targetNode := createControllerBackupNode(t, ctx, st, "process-snapshot-target", "storage", true, generation)
	sourcePSK := "process-snapshot-source-agent-psk"
	targetPSK := "process-snapshot-target-agent-psk"
	adapterPSK := "process-snapshot-source-adapter-psk"
	seedControllerBackupCredential(t, ctx, st, secretKey, sourceNode.ID, generation, sourcePSK)
	seedControllerBackupCredential(t, ctx, st, secretKey, targetNode.ID, generation, targetPSK)

	root := t.TempDir()
	sourceTavern := filepath.Join(root, "source-tavern")
	sourceData := filepath.Join(sourceTavern, "data")
	sourceRuntime := filepath.Join(root, "source-agent")
	targetRuntime := filepath.Join(root, "target-agent")
	targetBackup := filepath.Join(root, "target-backups")
	for _, directory := range []string{sourceData, sourceRuntime, targetRuntime, targetBackup} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	user := createControllerBackupUser(t, ctx, st, sourceNode.ID, "process-snapshot-user")
	userRoot := filepath.Join(sourceData, user.Username)
	if err := os.MkdirAll(userRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 8<<20)
	if _, err := io.ReadFull(cryptorand.Reader, payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userRoot, "extension-private-state.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	adapter := newProcessSnapshotAdapter(t, sourceNode.ID, adapterPSK)
	t.Cleanup(adapter.server.Close)
	cfg := config.DefaultController()
	cfg.Backup.RetryMax = 4
	controller := New(cfg, st, secretKey)
	controllerHTTP := httptest.NewServer(controller.Handler())
	t.Cleanup(controllerHTTP.Close)

	sourcePort := reserveSnapshotProcessPort(t)
	targetPort := reserveSnapshotProcessPort(t)
	targetURL := "http://127.0.0.1:" + strconv.Itoa(targetPort)
	var slowFirstTransfer atomic.Bool
	slowFirstTransfer.Store(true)
	proxy := newSlowSnapshotProxy(t, targetURL, &slowFirstTransfer)
	t.Cleanup(proxy.Close)
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET transfer_url=$2 WHERE id=$1`, targetNode.ID, proxy.URL); err != nil {
		t.Fatalf("set target transfer URL: %v", err)
	}
	targetNode.TransferURL = proxy.URL

	target := startSnapshotAgentProcess(t, snapshotAgentProcessConfig{
		nodeID: targetNode.ID, role: "storage", psk: targetPSK,
		controllerURL: controllerHTTP.URL, listenPort: targetPort,
		dataDir: targetRuntime, backupDir: targetBackup, transferURL: targetURL,
	})
	t.Cleanup(target.stopGracefully)
	source := startSnapshotAgentProcess(t, snapshotAgentProcessConfig{
		nodeID: sourceNode.ID, role: "compute", psk: sourcePSK, adapterPSK: adapterPSK,
		controllerURL: controllerHTTP.URL, listenPort: sourcePort,
		dataDir: sourceRuntime, tavernDir: sourceTavern, tavernURL: adapter.server.URL,
	})
	t.Cleanup(source.stopGracefully)

	triggerResult := make(chan error, 1)
	go func() {
		triggerResult <- controller.TriggerUserBackup(ctx, user.ID, sourceNode.ID, "offline")
	}()
	select {
	case <-adapter.firstQuiesce:
	case <-time.After(30 * time.Second):
		t.Fatalf("source never established the durable user gate\n%s", source.logs())
	}
	if !adapter.gateClosed() {
		t.Fatal("adapter did not persist the source write gate before responding")
	}
	source.kill()
	close(adapter.allowFirstQuiesce)
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE agent_commands SET lease_until=now()-interval '1 second'
		WHERE node_id=$1 AND command_type='start_snapshot' AND state IN ('leased','acked','running')`, sourceNode.ID); err != nil {
		t.Fatalf("expire interrupted source command lease: %v", err)
	}
	source = startSnapshotAgentProcess(t, snapshotAgentProcessConfig{
		nodeID: sourceNode.ID, role: "compute", psk: sourcePSK, adapterPSK: adapterPSK,
		controllerURL: controllerHTTP.URL, listenPort: sourcePort,
		dataDir: sourceRuntime, tavernDir: sourceTavern, tavernURL: adapter.server.URL,
	})
	t.Cleanup(source.stopGracefully)

	interruptedSnapshotID := waitForConsumedSnapshotTransfer(t, targetRuntime, 45*time.Second)
	target.kill()
	slowFirstTransfer.Store(false)
	select {
	case err := <-triggerResult:
		if err == nil {
			t.Fatal("target process crash unexpectedly completed the first transfer")
		}
	case <-time.After(45 * time.Second):
		t.Fatal("Controller did not persist a retry after the target process crash")
	}
	if adapter.gateClosed() {
		t.Fatal("failed target transfer left the source user's write gate closed")
	}
	workflowID := controllerBackupWorkflowID(t, ctx, st, user.GlobalID)
	execution, err := st.GetSnapshotWorkflowExecution(ctx, workflowID)
	if err != nil || execution == nil || execution.State != "retry_wait" || execution.SnapshotID != interruptedSnapshotID {
		t.Fatalf("interrupted execution=%+v err=%v", execution, err)
	}

	target = startSnapshotAgentProcess(t, snapshotAgentProcessConfig{
		nodeID: targetNode.ID, role: "storage", psk: targetPSK,
		controllerURL: controllerHTTP.URL, listenPort: targetPort,
		dataDir: targetRuntime, backupDir: targetBackup, transferURL: targetURL,
	})
	t.Cleanup(target.stopGracefully)
	assertRecoveredTransferPreparedAndTaskClean(t, targetRuntime, targetBackup, workflowID, interruptedSnapshotID)
	if _, err := st.DB.ExecContext(ctx, `UPDATE workflows SET next_attempt_at=now()-interval '1 second' WHERE id=$1`, workflowID); err != nil {
		t.Fatal(err)
	}
	restartedController := New(cfg, st, secretKey)
	if err := restartedController.executeSnapshotWorkflow(ctx, workflowID); err != nil {
		t.Fatalf("resume process-crashed snapshot: %v\nsource:\n%s\ntarget:\n%s", err, source.logs(), target.logs())
	}
	execution, err = st.GetSnapshotWorkflowExecution(ctx, workflowID)
	if err != nil || execution == nil || execution.State != "succeeded" || execution.CapabilityState != "consumed" {
		t.Fatalf("completed execution=%+v err=%v", execution, err)
	}
	if adapter.gateClosed() || adapter.releaseCount() < 2 {
		t.Fatalf("gate convergence: closed=%v releases=%d renewals=%d", adapter.gateClosed(), adapter.releaseCount(), adapter.renewCount())
	}
	finalData, err := os.ReadFile(filepath.Join(targetBackup, "replicas", user.Username, "extension-private-state.bin"))
	if err != nil || len(finalData) != len(payload) {
		t.Fatalf("published target data size=%d err=%v", len(finalData), err)
	}
	for index := range payload {
		if finalData[index] != payload[index] {
			t.Fatalf("published data mismatch at byte %d", index)
		}
	}
	if matches, err := filepath.Glob(filepath.Join(targetBackup, ".stcontrol-tasks", "*", "*")); err != nil || len(matches) != 0 {
		t.Fatalf("target task residue=%v err=%v", matches, err)
	}
	var readyCopies, immutableManifests int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE copy.state='ready'),
		       count(*) FILTER (WHERE manifest.state='immutable')
		FROM snapshot_manifests manifest
		LEFT JOIN replica_copies copy ON copy.snapshot_id=manifest.id
		WHERE manifest.workflow_id=$1`, workflowID).Scan(&readyCopies, &immutableManifests); err != nil {
		t.Fatal(err)
	}
	if readyCopies != 1 || immutableManifests != 1 {
		t.Fatalf("published facts: ready=%d immutable=%d", readyCopies, immutableManifests)
	}
}

type snapshotAgentProcessConfig struct {
	nodeID        int64
	role          string
	psk           string
	adapterPSK    string
	controllerURL string
	listenPort    int
	dataDir       string
	backupDir     string
	tavernDir     string
	tavernURL     string
	transferURL   string
}

type snapshotAgentProcess struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan error
	logPath string
	stopped bool
}

func startSnapshotAgentProcess(t *testing.T, cfg snapshotAgentProcessConfig) *snapshotAgentProcess {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), fmt.Sprintf("agent-%d.log", cfg.nodeID))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSnapshotAgentProcessHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		snapshotAgentProcessHelperEnv+"=1",
		"STCONTROL_HELPER_NODE_ID="+strconv.FormatInt(cfg.nodeID, 10),
		"STCONTROL_HELPER_ROLE="+cfg.role,
		"STCONTROL_HELPER_AGENT_PSK="+cfg.psk,
		"STCONTROL_HELPER_ADAPTER_PSK="+cfg.adapterPSK,
		"STCONTROL_HELPER_CONTROLLER_URL="+cfg.controllerURL,
		"STCONTROL_HELPER_LISTEN=127.0.0.1:"+strconv.Itoa(cfg.listenPort),
		"STCONTROL_HELPER_DATA_DIR="+cfg.dataDir,
		"STCONTROL_HELPER_BACKUP_DIR="+cfg.backupDir,
		"STCONTROL_HELPER_TAVERN_DIR="+cfg.tavernDir,
		"STCONTROL_HELPER_TAVERN_URL="+cfg.tavernURL,
		"STCONTROL_HELPER_TRANSFER_URL="+cfg.transferURL,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	process := &snapshotAgentProcess{cmd: cmd, done: make(chan error, 1), logPath: logPath}
	go func() {
		process.done <- cmd.Wait()
		_ = logFile.Close()
	}()
	address := "127.0.0.1:" + strconv.Itoa(cfg.listenPort)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		connection, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return process
		}
		select {
		case <-process.done:
			t.Fatalf("Agent %d exited before listening\n%s", cfg.nodeID, process.logs())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	process.kill()
	t.Fatalf("Agent %d did not listen\n%s", cfg.nodeID, process.logs())
	return nil
}

func (process *snapshotAgentProcess) kill() {
	process.mu.Lock()
	if process.stopped {
		process.mu.Unlock()
		return
	}
	process.stopped = true
	process.mu.Unlock()
	_ = process.cmd.Process.Kill()
	<-process.done
}

func (process *snapshotAgentProcess) stopGracefully() {
	process.mu.Lock()
	if process.stopped {
		process.mu.Unlock()
		return
	}
	process.stopped = true
	process.mu.Unlock()
	_ = process.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-process.done:
	case <-time.After(5 * time.Second):
		_ = process.cmd.Process.Kill()
		<-process.done
	}
}

func (process *snapshotAgentProcess) logs() string {
	data, _ := os.ReadFile(process.logPath)
	return string(data)
}

func reserveSnapshotProcessPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

type processSnapshotAdapter struct {
	server               *httptest.Server
	mu                   sync.Mutex
	nodeID               int64
	psk                  string
	gate                 bool
	token                string
	expiresAt            int64
	quiesces             int
	renews               int
	releases             int
	firstQuiesce         chan struct{}
	allowFirstQuiesce    chan struct{}
	firstQuiesceSignalMu sync.Once
}

func newProcessSnapshotAdapter(t *testing.T, nodeID int64, psk string) *processSnapshotAdapter {
	t.Helper()
	adapter := &processSnapshotAdapter{
		nodeID: nodeID, psk: psk,
		token:        "0123456789abcdef0123456789abcdef0123456789a",
		firstQuiesce: make(chan struct{}), allowFirstQuiesce: make(chan struct{}),
	}
	adapter.server = httptest.NewServer(http.HandlerFunc(adapter.serveHTTP))
	return adapter
}

func (adapter *processSnapshotAdapter) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || r.Method != http.MethodPost || r.Header.Get(protocol.HeaderAgentID) != strconv.FormatInt(adapter.nodeID, 10) ||
		protocol.VerifyRequest(r, adapter.psk, body) != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request struct {
		WorkflowID    string `json:"workflow_id"`
		SnapshotID    string `json:"snapshot_id"`
		Handle        string `json:"handle"`
		ActivityEpoch int64  `json:"activity_epoch"`
		FreezeToken   string `json:"freeze_token"`
	}
	if json.Unmarshal(body, &request) != nil || request.WorkflowID == "" || request.SnapshotID == "" ||
		request.Handle != "process-snapshot-user" || request.ActivityEpoch <= 0 {
		http.Error(w, "invalid scope", http.StatusBadRequest)
		return
	}
	now := time.Now()
	adapter.mu.Lock()
	if adapter.gate && adapter.expiresAt <= now.UnixMilli() {
		adapter.gate = false
	}
	switch r.URL.Path {
	case "/api/stcontrol/internal/snapshots/quiesce":
		adapter.gate = true
		adapter.expiresAt = now.Add(30 * time.Second).UnixMilli()
		adapter.quiesces++
		first := adapter.quiesces == 1
		expiresAt := adapter.expiresAt
		token := adapter.token
		adapter.mu.Unlock()
		if first {
			adapter.firstQuiesceSignalMu.Do(func() { close(adapter.firstQuiesce) })
			select {
			case <-adapter.allowFirstQuiesce:
			case <-r.Context().Done():
				return
			}
		}
		protocol.WriteJSON(w, http.StatusOK, map[string]any{
			"ok": true, "drained": true, "freeze_token": token, "expires_at": expiresAt,
		})
	case "/api/stcontrol/internal/snapshots/renew":
		if !adapter.gate || request.FreezeToken != adapter.token {
			adapter.mu.Unlock()
			http.Error(w, "gate mismatch", http.StatusConflict)
			return
		}
		adapter.renews++
		adapter.expiresAt = now.Add(30 * time.Second).UnixMilli()
		expiresAt := adapter.expiresAt
		adapter.mu.Unlock()
		protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "expires_at": expiresAt})
	case "/api/stcontrol/internal/snapshots/release":
		if !adapter.gate || request.FreezeToken != adapter.token {
			adapter.mu.Unlock()
			http.Error(w, "gate mismatch", http.StatusConflict)
			return
		}
		adapter.gate = false
		adapter.releases++
		adapter.mu.Unlock()
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		adapter.mu.Unlock()
		http.NotFound(w, r)
	}
}

func (adapter *processSnapshotAdapter) gateClosed() bool {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.gate && adapter.expiresAt > time.Now().UnixMilli()
}

func (adapter *processSnapshotAdapter) releaseCount() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.releases
}

func (adapter *processSnapshotAdapter) renewCount() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.renews
}

type conditionalSlowReadCloser struct {
	io.ReadCloser
	slow *atomic.Bool
}

func (reader *conditionalSlowReadCloser) Read(buffer []byte) (int, error) {
	if reader.slow.Load() && len(buffer) > 32<<10 {
		buffer = buffer[:32<<10]
	}
	count, err := reader.ReadCloser.Read(buffer)
	if count > 0 && reader.slow.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	return count, err
}

func newSlowSnapshotProxy(t *testing.T, targetURL string, slow *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL+r.URL.RequestURI(), &conditionalSlowReadCloser{
			ReadCloser: r.Body, slow: slow,
		})
		if err != nil {
			http.Error(w, "proxy request failed", http.StatusBadGateway)
			return
		}
		request.ContentLength = r.ContentLength
		request.Header = r.Header.Clone()
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			http.Error(w, "target unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
}

func waitForConsumedSnapshotTransfer(t *testing.T, runtimeDir string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	path := filepath.Join(runtimeDir, "runtime-state.json")
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var state struct {
				Transfers map[string]struct {
					State string `json:"state"`
				} `json:"transfers"`
			}
			if json.Unmarshal(data, &state) == nil {
				for snapshotID, transfer := range state.Transfers {
					if transfer.State == "consumed" {
						return snapshotID
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("target never persisted a consumed transfer")
	return ""
}

func assertRecoveredTransferPreparedAndTaskClean(
	t *testing.T,
	runtimeDir, backupDir, workflowID, snapshotID string,
) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	statePath := filepath.Join(runtimeDir, "runtime-state.json")
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(statePath)
		if err == nil {
			var state struct {
				Transfers map[string]struct {
					State string `json:"state"`
				} `json:"transfers"`
			}
			if json.Unmarshal(data, &state) == nil && state.Transfers[snapshotID].State == "prepared" {
				taskRoot := filepath.Join(backupDir, ".stcontrol-tasks", workflowID, snapshotID)
				if _, statErr := os.Stat(taskRoot); !os.IsNotExist(statErr) {
					t.Fatalf("partial target task survived restart: %v", statErr)
				}
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("target restart did not re-arm the exact interrupted transfer")
}

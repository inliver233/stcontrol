package agent

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestGoAgentCallsRealSillyTavernAdapter(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-repository adapter test is disabled in short mode")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	tavernRoot := filepath.Clean(filepath.Join(repositoryRoot, "..", "Sillytarven-online"))
	fixture := filepath.Join(tavernRoot, "tests", "fixtures", "stcontrol-adapter-server.mjs")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("Sillytarven adapter fixture is unavailable: %v", err)
	}

	dataRoot := t.TempDir()
	portFile := filepath.Join(dataRoot, "adapter.port")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, fixture)
	command.Dir = tavernRoot
	command.Env = append(os.Environ(),
		"STCONTROL_E2E_DATA_ROOT="+dataRoot,
		"STCONTROL_E2E_PORT_FILE="+portFile,
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatalf("start Sillytarven adapter fixture: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	var port string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(portFile)
		if readErr == nil && strings.TrimSpace(string(data)) != "" {
			port = strings.TrimSpace(string(data))
			break
		}
		select {
		case processErr := <-done:
			t.Fatalf("Sillytarven adapter exited before readiness: %v\n%s", processErr, output.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if port == "" {
		t.Fatalf("Sillytarven adapter readiness timed out\n%s", output.String())
	}

	newAgent := func(psk string) *Agent {
		t.Helper()
		instance, newErr := New(&config.AgentConfig{
			Role: "compute", NodeID: 7, AgentPSK: psk,
			TavernURL: "http://127.0.0.1:" + port,
			DataDir:   t.TempDir(), HeartbeatSec: 15,
		})
		if newErr != nil {
			t.Fatal(newErr)
		}
		return instance
	}

	instance := newAgent("test-agent-psk")
	report := instance.compatibilityReport(ctx, protocol.NodeInfo{OS: runtime.GOOS, Arch: runtime.GOARCH})
	if report.State != "compatible" || report.ErrorCode != "" {
		t.Fatalf("compatibility report=%+v\n%s", report, output.String())
	}
	policy := instance.registrationPolicy(ctx)
	if policy.State != "open" || policy.Version <= 0 {
		t.Fatalf("registration policy=%+v", policy)
	}
	users, err := instance.collectUserStatuses(ctx)
	if err != nil || len(users) != 0 {
		t.Fatalf("session telemetry users=%+v err=%v", users, err)
	}
	var modeResult struct {
		OK bool `json:"ok"`
	}
	if err := instance.callTavernAdapter(ctx, "/api/stcontrol/internal/control-mode", map[string]any{
		"mode": protocol.NodeModeControllerUnreachable, "mode_generation": 2,
		"controller_generation": 1, "reason_code": "e2e_heartbeat_failed",
	}, &modeResult); err != nil || !modeResult.OK {
		t.Fatalf("apply real adapter control mode: result=%+v err=%v", modeResult, err)
	}
	if err := newAgent("forged-agent-secret").callTavernAdapter(
		ctx, "/api/stcontrol/internal/health", struct{}{}, nil,
	); err == nil || !strings.Contains(err.Error(), fmt.Sprint(401)) {
		t.Fatalf("forged Agent credential was not rejected: %v", err)
	}
}

func TestGoAgentCallsFullSillyTavernServerWithCSRF(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-repository full-server test is disabled in short mode")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	tavernRoot := filepath.Clean(filepath.Join(repositoryRoot, "..", "Sillytarven-online"))
	serverScript := filepath.Join(tavernRoot, "server.js")
	configPath := filepath.Join(tavernRoot, "tests", "fixtures", "stcontrol-config.yaml")
	if _, err := os.Stat(serverScript); err != nil {
		t.Skipf("Sillytarven server is unavailable: %v", err)
	}

	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	dataRoot := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, serverScript,
		"--configPath", configPath,
		"--dataRoot", dataRoot,
		"--port", strconv.Itoa(port),
		"--browserLaunchEnabled", "false",
		"--listen", "false",
	)
	command.Dir = tavernRoot
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatalf("start full Sillytarven server: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	readyClient := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(30 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		response, requestErr := readyClient.Get(baseURL + "/api/ping-public")
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				ready = true
				break
			}
		}
		select {
		case processErr := <-done:
			t.Fatalf("full Sillytarven server exited before readiness: %v\n%s", processErr, output.String())
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("full Sillytarven server readiness timed out\n%s", output.String())
	}

	instance, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 7, AgentPSK: "test-agent-psk",
		TavernURL: baseURL, DataDir: t.TempDir(), HeartbeatSec: 15,
	})
	if err != nil {
		t.Fatal(err)
	}
	report := instance.compatibilityReport(ctx, protocol.NodeInfo{OS: runtime.GOOS, Arch: runtime.GOARCH})
	if report.State != "compatible" || report.ErrorCode != "" {
		t.Fatalf("full-server compatibility report=%+v\n%s", report, output.String())
	}
	policy := instance.registrationPolicy(ctx)
	if policy.State != "open" || policy.Version <= 0 {
		t.Fatalf("full-server registration policy=%+v\n%s", policy, output.String())
	}
}

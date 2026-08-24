package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"stcontrol/internal/config"
)

func TestAgentMainAuditCommand(t *testing.T) {
	cfg := config.DefaultAgent()
	cfg.DataDir = t.TempDir()
	configPath := filepath.Join(t.TempDir(), "agent.yaml")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}

	previousArgs, previousFlags := os.Args, flag.CommandLine
	defer func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlags
	}()
	os.Args = []string{
		"agent", "--config", configPath, "--audit", "--audit-event", "command_finished",
		"--audit-command", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"--audit-operation", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"--audit-since", "2026-08-24T00:00:00Z", "--audit-limit", "3",
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	output := captureAgentMainStdout(t, main)
	if strings.TrimSpace(output) != "[]" {
		t.Fatalf("audit output=%q", output)
	}
}

func TestAgentMainConfiguresTavernAndReturns(t *testing.T) {
	tavernDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tavernDir, "config.yaml"), []byte("port: 8000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultAgent()
	cfg.Role = "compute"
	cfg.NodeID = 7
	cfg.AgentPSK = "agent-main-configure-secret"
	cfg.ControllerURL = "https://controller.example.test"
	cfg.Listen = "127.0.0.1:9100"
	cfg.TavernDir = tavernDir
	cfg.DataDir = t.TempDir()
	configPath := filepath.Join(t.TempDir(), "agent.yaml")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}

	withAgentMainArgs(t, []string{"agent", "--config", configPath, "--configure-tavern"}, main)
	configured, err := os.ReadFile(filepath.Join(tavernDir, "config.yaml"))
	if err != nil || !strings.Contains(string(configured), "enabled: true") ||
		!strings.Contains(string(configured), "nodeId: 7") {
		t.Fatalf("configured Tavern=%q err=%v", configured, err)
	}
}

func TestAgentMainServesHealthAndStopsOnSignal(t *testing.T) {
	port := reserveAgentMainPort(t)
	cfg := config.DefaultAgent()
	cfg.Role = "storage"
	cfg.NodeID = 8
	cfg.AgentPSK = "agent-main-runtime-secret"
	cfg.ControllerURL = "http://127.0.0.1:1"
	cfg.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.TransferPublicURL = ""
	cfg.DataDir = t.TempDir()
	cfg.BackupDir = t.TempDir()
	cfg.HeartbeatSec = 1
	configPath := filepath.Join(t.TempDir(), "agent.yaml")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		withAgentMainArgs(t, []string{"agent", "--config", configPath}, main)
	}()
	client := &http.Client{Timeout: 250 * time.Millisecond}
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/agent/health", port)
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get(endpoint)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Agent main did not serve health")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Agent main did not stop after SIGTERM")
	}
}

func withAgentMainArgs(t *testing.T, args []string, action func()) {
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

func reserveAgentMainPort(t *testing.T) int {
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

func captureAgentMainStdout(t *testing.T, action func()) string {
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

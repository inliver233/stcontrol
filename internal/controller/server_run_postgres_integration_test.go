package controller

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestControllerRunStartsWorkersAndShutsDownCleanly(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller lifecycle PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultController()
	cfg.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.PublicURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	cfg.ControllerBackup.Enabled = false
	server := New(cfg, st, []byte("0123456789abcdef0123456789abcdef"))

	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- server.Run(runCtx) }()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, requestErr := client.Get(cfg.PublicURL + "/api/health")
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				ready = true
				break
			}
		}
		select {
		case runErr := <-done:
			t.Fatalf("Controller exited before readiness: %v", runErr)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("Controller did not become ready")
	}
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Controller shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Controller did not stop after cancellation")
	}
}

func TestControllerRunStartsRelayAndShutsDownBothListeners(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller relay lifecycle PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	controlPort := reserveLoopbackPort(t)
	relayPort := reserveLoopbackPort(t)
	cfg := config.DefaultController()
	cfg.Listen = fmt.Sprintf("127.0.0.1:%d", controlPort)
	cfg.PublicURL = fmt.Sprintf("http://127.0.0.1:%d", controlPort)
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = fmt.Sprintf("127.0.0.1:%d", relayPort)
	cfg.Relay.PublicURL = fmt.Sprintf("http://127.0.0.1:%d", relayPort)
	cfg.Relay.DataDir = t.TempDir()
	cfg.ControllerBackup.Enabled = false
	server := New(cfg, st, []byte("0123456789abcdef0123456789abcdef"))

	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- server.Run(runCtx) }()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	waitForHTTPStatus(t, client, done, cfg.PublicURL+"/api/health", http.StatusNoContent)
	waitForHTTPStatus(t, client, done, cfg.Relay.PublicURL+"/relay/v1/transfers/not-a-uuid", http.StatusForbidden)

	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Controller relay shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Controller and relay did not stop after cancellation")
	}
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func waitForHTTPStatus(t *testing.T, client *http.Client, done <-chan error, endpoint string, want int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, requestErr := client.Get(endpoint)
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == want {
				return
			}
		}
		select {
		case runErr := <-done:
			t.Fatalf("Controller exited before %s returned %d: %v", endpoint, want, runErr)
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("%s did not return %d", endpoint, want)
}

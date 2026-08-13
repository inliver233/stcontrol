package controller

import (
	"context"
	"testing"
	"time"

	"stcontrol/internal/config"
)

func TestControllerBackupMaxAttemptsIsBounded(t *testing.T) {
	t.Parallel()
	if got := controllerBackupMaxAttempts(config.ControllerDisasterBackupPolicy{}); got != 3 { t.Fatalf("default max=%d", got) }
	policy := config.ControllerDisasterBackupPolicy{RetryMax: 100}
	if got := controllerBackupMaxAttempts(policy); got != 8 { t.Fatalf("bounded max=%d", got) }
}

func TestControllerBackupIntervalDefaultsTo24h(t *testing.T) {
	t.Parallel()
	if got := controllerBackupInterval(config.ControllerDisasterBackupPolicy{}); got != 24*time.Hour { t.Fatalf("interval=%v", got) }
	if got := controllerBackupInterval(config.ControllerDisasterBackupPolicy{IntervalSec: 3600}); got != time.Hour { t.Fatalf("interval=%v", got) }
}

func TestReconcileControllerBackupOnceReturnsEarlyWhenDisabled(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultController()
	server := &Server{Cfg: cfg}
	// Store nil means the policy gate must return before touching it.
	server.workflowWorkerID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	server.secretKey = []byte("secret")
	server.reconcileControllerBackupOnce(context.Background())
}

func TestControllerBackupTransferEndpointRequiresHTTPS(t *testing.T) {
	t.Parallel()
	_, err := controllerBackupTransferEndpoint("http://storage.example/data", "11111111-1111-4111-8111-111111111111")
	if err == nil { t.Fatal("expected https requirement") }
	ep, err := controllerBackupTransferEndpoint("https://storage.example/data", "11111111-1111-4111-8111-111111111111")
	if err != nil { t.Fatalf("err=%v", err) }
	want := "https://storage.example/data/transfer/v1/controller-backups/11111111-1111-4111-8111-111111111111"
	if ep != want { t.Fatalf("endpoint=%q want %q", ep, want) }
}

func TestControllerBackupPolicyFromDefaultSection(t *testing.T) {
	t.Parallel()
	server := &Server{}
	policy := server.controllerBackupPolicy()
	if !policy.Enabled || policy.RetryMax != 3 { t.Fatalf("policy=%+v", policy) }
}

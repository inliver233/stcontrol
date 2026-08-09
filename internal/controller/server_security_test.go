package controller

import (
	"crypto/tls"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"stcontrol/internal/config"
)

func TestControlListenerRequiresTLSOutsideLoopback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*config.ControllerConfig)
		wantErr bool
	}{
		{name: "loopback development"},
		{name: "remote plaintext listener", wantErr: true, mutate: func(cfg *config.ControllerConfig) {
			cfg.Listen = ":8080"
			cfg.PublicURL = "https://control.example"
		}},
		{name: "remote plaintext public URL", wantErr: true, mutate: func(cfg *config.ControllerConfig) {
			cfg.PublicURL = "http://control.example"
		}},
		{name: "certificate without key", wantErr: true, mutate: func(cfg *config.ControllerConfig) {
			cfg.TLSCertFile = "controller.crt"
		}},
		{name: "userinfo is forbidden", wantErr: true, mutate: func(cfg *config.ControllerConfig) {
			cfg.PublicURL = "https://secret@control.example"
		}},
		{name: "direct TLS", mutate: func(cfg *config.ControllerConfig) {
			cfg.Listen = ":8443"
			cfg.PublicURL = "https://control.example"
			cfg.TLSCertFile = "controller.crt"
			cfg.TLSKeyFile = "controller.key"
		}},
		{name: "loopback behind TLS proxy", mutate: func(cfg *config.ControllerConfig) {
			cfg.PublicURL = "https://control.example"
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.DefaultController()
			if test.mutate != nil {
				test.mutate(cfg)
			}
			err := validateControlListenerConfig(cfg)
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestDockerExampleUsesDirectTLSAndContainerDatabase(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultController()
	if err := config.Load(filepath.Join("..", "..", "controller.docker.yaml.example"), cfg); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeConfig(cfg); err != nil {
		t.Fatalf("docker example is not a valid secure runtime config: %v", err)
	}
	if cfg.Listen != ":8443" || cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" ||
		!strings.Contains(cfg.DatabaseURL, "@db:5432/") {
		t.Fatalf("docker example=%+v", cfg)
	}
}

func TestControlHTTPServerPinsTLS13AndHeaderBounds(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultController()
	cfg.TLSCertFile = "controller.crt"
	cfg.TLSKeyFile = "controller.key"
	cfg.PublicURL = "https://127.0.0.1:8443"
	server := newControlHTTPServer(cfg, http.NotFoundHandler())
	if server.TLSConfig == nil || server.TLSConfig.MinVersion != tls.VersionTLS13 ||
		server.ReadHeaderTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes != 1<<20 {
		t.Fatalf("server=%+v tls=%+v", server, server.TLSConfig)
	}
}

func TestControllerRejectsUnsafeActivityLeaseTTL(t *testing.T) {
	t.Parallel()
	for _, ttl := range []int{0, 59, 24*60*60 + 1} {
		cfg := config.DefaultController()
		cfg.Activity.LeaseTTLSec = ttl
		if err := ValidateRuntimeConfig(cfg); err == nil {
			t.Fatalf("unsafe activity lease TTL %d was accepted", ttl)
		}
	}
	cfg := config.DefaultController()
	cfg.Activity.LeaseTTLSec = 60
	if err := ValidateRuntimeConfig(cfg); err != nil {
		t.Fatalf("minimum safe activity lease TTL rejected: %v", err)
	}
}

func TestControllerRejectsUnsafeOfflineBackupGrace(t *testing.T) {
	t.Parallel()
	for _, grace := range []int{0, 24*60 + 1} {
		cfg := config.DefaultController()
		cfg.Backup.OfflineGraceMin = grace
		if err := ValidateRuntimeConfig(cfg); err == nil {
			t.Fatalf("unsafe offline backup grace %d was accepted", grace)
		}
	}
}

func TestControllerTLSPreflightFailsBeforeDatabaseOrWorkers(t *testing.T) {
	t.Parallel()
	if err := ValidateRuntimeTLSFiles(config.DefaultController()); err != nil {
		t.Fatalf("plaintext loopback preflight failed: %v", err)
	}
	cfg := config.DefaultController()
	cfg.TLSCertFile = "missing-controller.crt"
	cfg.TLSKeyFile = "missing-controller.key"
	if err := ValidateRuntimeTLSFiles(cfg); err == nil || strings.Contains(err.Error(), "missing-controller") {
		t.Fatalf("missing control TLS pair error=%v", err)
	}
	cfg = config.DefaultController()
	cfg.Relay.TLSCertFile = "missing-relay.crt"
	cfg.Relay.TLSKeyFile = "missing-relay.key"
	if err := ValidateRuntimeTLSFiles(cfg); err == nil || strings.Contains(err.Error(), "missing-relay") {
		t.Fatalf("missing relay TLS pair error=%v", err)
	}
}

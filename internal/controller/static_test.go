package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"stcontrol/internal/config"
)

func TestHandleAgentArtifactServesAllowlistedFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary := []byte("linux-agent-fixture")
	if err := os.WriteFile(filepath.Join(dir, "agent-linux-amd64"), binary, 0o600); err != nil {
		t.Fatal(err)
	}
	checksum := []byte("eb952e0d1ad6a046a9d6c96de0e1ee6e4c0ca9a7319f0b0851218341d7228c17  agent-linux-amd64\n")
	if err := os.WriteFile(filepath.Join(dir, "agent-linux-amd64.sha256"), checksum, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultController()
	cfg.AgentDistDir = dir
	server := &Server{Cfg: cfg}
	router := chi.NewRouter()
	router.Get("/dist", http.NotFound)
	router.Get("/dist/*", server.handleAgentArtifact)

	for _, tc := range []struct {
		path        string
		status      int
		body        []byte
		contentType string
	}{
		{"/dist/agent-linux-amd64", http.StatusOK, binary, "application/octet-stream"},
		{"/dist/agent-linux-amd64.sha256", http.StatusOK, checksum, "text/plain; charset=utf-8"},
		{"/dist/agent-linux-arm64", http.StatusNotFound, nil, ""},
		{"/dist/not-an-agent", http.StatusNotFound, nil, ""},
		{"/dist/nested/agent-linux-amd64", http.StatusNotFound, nil, ""},
		{"/dist", http.StatusNotFound, nil, ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status=%d, want %d; body=%q", response.Code, tc.status, response.Body.Bytes())
			}
			if tc.body != nil && !bytes.Equal(response.Body.Bytes(), tc.body) {
				t.Fatalf("body=%q, want %q", response.Body.Bytes(), tc.body)
			}
			if tc.contentType != "" && response.Header().Get("Content-Type") != tc.contentType {
				t.Fatalf("Content-Type=%q, want %q", response.Header().Get("Content-Type"), tc.contentType)
			}
		})
	}
}

func TestEmbeddedInstallScriptMatchesDistributionSource(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installSh, source) {
		t.Fatal("internal/controller/install.sh differs from scripts/install.sh")
	}
}

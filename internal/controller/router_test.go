package controller

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func TestQueryRedactingRequestLoggerPreservesHandlerQueryWithoutLoggingSecrets(t *testing.T) {
	t.Parallel()
	var accessLog bytes.Buffer
	formatter := queryRedactingLogFormatter{delegate: &middleware.DefaultLogFormatter{
		Logger: log.New(&accessLog, "", 0), NoColor: true,
	}}
	var handlerCode, handlerState string
	handler := middleware.RequestLogger(formatter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCode = r.URL.Query().Get("code")
		handlerState = r.URL.Query().Get("state")
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(
		http.MethodGet,
		"https://control.example/api/auth/oauth/linuxdo/callback?code=secret-code&state=secret-state",
		nil,
	)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if handlerCode != "secret-code" || handlerState != "secret-state" {
		t.Fatalf("handler query was changed: code=%q state=%q", handlerCode, handlerState)
	}
	logged := accessLog.String()
	if strings.Contains(logged, "secret-code") || strings.Contains(logged, "secret-state") ||
		!strings.Contains(logged, "?redacted") {
		t.Fatalf("access log was not safely redacted: %q", logged)
	}
}

func TestSecurityHeadersCoverSuccessErrorsAndStaticResponses(t *testing.T) {
	t.Parallel()
	router := newRouter()
	router.Get("/ok", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	router.Get("/error", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "failed", http.StatusInternalServerError)
	})

	for _, path := range []string{"/ok", "/error", "/missing"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://control.example"+path, nil))
		headers := recorder.Header()
		for name, want := range map[string]string{
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"Referrer-Policy":           "no-referrer",
			"Permissions-Policy":        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		} {
			if got := headers.Get(name); got != want {
				t.Errorf("%s %s=%q, want %q", path, name, got, want)
			}
		}
		csp := headers.Get("Content-Security-Policy")
		for _, directive := range []string{
			"default-src 'self'", "base-uri 'none'", "frame-ancestors 'none'",
			"object-src 'none'", "script-src 'self'", "connect-src 'self'",
		} {
			if !strings.Contains(csp, directive) {
				t.Errorf("%s CSP %q does not contain %q", path, csp, directive)
			}
		}
		if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s CSP permits unsafe script execution: %q", path, csp)
		}
	}
}

func TestNodeSourcesAreRestrictedToConfiguredHTTPOrigins(t *testing.T) {
	t.Parallel()
	sources := nodeConnectSources([]string{
		"https://node-b.example/tavern?ignored=yes",
		" https://node-a.example:8443/path ",
		"https://node-b.example/other",
		"http://127.0.0.1:8000",
		"https://user:secret@credential.example",
		"javascript:alert(1)",
		"not a URL",
	})
	want := []string{
		"http://127.0.0.1:8000",
		"https://node-a.example:8443",
		"https://node-b.example",
	}
	if strings.Join(sources, "|") != strings.Join(want, "|") {
		t.Fatalf("node CSP sources = %q, want %q", sources, want)
	}

	policy := contentSecurityPolicy(sources)
	for _, directive := range []string{
		"form-action 'self' http://127.0.0.1:8000 https://node-a.example:8443 https://node-b.example",
		"connect-src 'self' http://127.0.0.1:8000 https://node-a.example:8443 https://node-b.example",
	} {
		if !strings.Contains(policy, directive) {
			t.Fatalf("CSP %q does not contain %q", policy, directive)
		}
	}
	if strings.Contains(policy, "credential.example") || strings.Contains(policy, "javascript:") {
		t.Fatalf("CSP contains an unsafe node source: %q", policy)
	}
}

func TestSPAContentSecurityPolicyIncludesDurableNodeOrigin(t *testing.T) {
	t.Parallel()
	server, mock := newLoginRedirectTestServer(t)
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT .* FROM nodes ORDER BY id`).
		WillReturnRows(loginRedirectNodeRows(now, "compute", "online", "active", "compatible", "managed", "managed"))

	recorder := httptest.NewRecorder()
	server.setSPAContentSecurityPolicy(recorder, httptest.NewRequest(http.MethodGet, "https://control.example/register", nil))
	policy := recorder.Header().Get("Content-Security-Policy")
	for _, directive := range []string{
		"form-action 'self' https://compute-b.example",
		"connect-src 'self' https://compute-b.example",
	} {
		if !strings.Contains(policy, directive) {
			t.Fatalf("SPA CSP %q does not contain %q", policy, directive)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

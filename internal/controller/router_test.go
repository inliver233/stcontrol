package controller

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

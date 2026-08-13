package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPreviousGenerationCredentialCannotReachCommandEndpoints(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 9, 6, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)SELECT .*connectivity_state.*capacity_state.* FROM nodes`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "role", "base_url", "transfer_url", "region",
			"cpu_pct", "mem_pct", "disk_pct", "agent_version", "tavern_version", "last_seen_at", "status",
			"connectivity_state", "operational_state", "control_mode", "control_mode_generation",
			"desired_control_mode", "desired_mode_generation", "capacity_state", "capacity_reason_code",
			"capacity_changed_at", "capacity_cooldown_until", "compatibility_state", "compatibility_reason_code",
			"compatibility_fingerprint", "compatibility_reported_at", "metrics_observed_at",
			"cpu_window_avg", "cpu_window_peak", "mem_window_avg", "mem_window_peak",
			"disk_window_avg", "disk_window_peak", "disk_total_bytes", "disk_available_bytes",
			"disk_quota_bytes", "expected_disk_quota_bytes", "quota_policy_version", "quota_sync_state",
			"quota_sync_at", "quota_sync_error_code", "allocated_disk_bytes", "online_users", "task_queue_depth", "telemetry_source",
			"client_latency_ms", "client_latency_observed_at",
			"allow_register", "recommendation_weight", "is_backup_target", "registration_policy_state", "registration_policy_version",
			"registration_policy_expires_at", "registration_policy_observed_at", "registration_policy_error_code", "created_at",
		}).AddRow(
			int64(12), "node", "compute", "https://node.example", "", "hk",
			10.0, 20.0, 30.0, "agent", "tavern", now, "online",
			"online", "active", "managed", int64(2), "managed", int64(2),
			"open", nil, now, nil, "compatible", nil, strings.Repeat("a", 64),
			now, now, 10.0, 20.0, 10.0, 20.0, 30.0, 30.0,
			int64(200<<30), int64(100<<30), int64(180<<30), int64(0), int64(0), "synced", nil, nil,
			int64(20<<30), 3, 0, "adapter", nil, nil, true, 0, false, "open", int64(1), now.Add(time.Minute), now, nil, now,
		))
	secretKey := bytes.Repeat([]byte{9}, 32)
	psk := "previous-generation-agent-secret"
	ciphertext, err := controlcrypto.Encrypt(secretKey, []byte(psk))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`SELECT id::text,secret_ciphertext`).WithArgs(int64(12), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "secret_ciphertext", "credential_version", "controller_generation", "pending",
		}).AddRow("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", []byte(ciphertext), int64(1), int64(4), false))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs WHERE state='active'`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(5)))

	called := false
	server := &Server{Store: &store.Store{DB: db}, secretKey: secretKey}
	handler := server.agentAuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	body := []byte(`{"worker_id":"worker"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/agent/commands/lease", bytes.NewReader(body))
	protocol.SignRequest(request, 12, psk, body)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if called || recorder.Code != http.StatusUnauthorized ||
		!strings.Contains(recorder.Body.String(), "世代已失效") {
		t.Fatalf("called=%v status=%d body=%s", called, recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

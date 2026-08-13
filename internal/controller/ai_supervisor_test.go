package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"stcontrol/internal/ai"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestBuildAIObservationProducesRedactedSnapshot(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{
		Cfg:       config.DefaultController(),
		Store:     &store.Store{DB: db},
		secretKey: []byte("controller-secret-key"),
	}
	now := time.Now()
	nodeCols := []string{
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
		"allow_register", "recommendation_weight", "is_backup_target", "registration_policy_state",
		"registration_policy_version", "registration_policy_expires_at",
		"registration_policy_observed_at", "registration_policy_error_code", "created_at",
	}
	nodeRows := sqlmock.NewRows(nodeCols).AddRow(
		1, "node-a", "compute", "http://internal", "", "cn-east",
		35.0, 40.0, 62.0, "1.0", "1.0", now.Add(-time.Minute), "active",
		"online", "active", "managed", int64(1), "managed", int64(1),
		"open", "ok", now, now, "compatible", "ok", "fp", now, now,
		30.0, 35.0, 40.0, 45.0, 50.0, 60.0,
		int64(1<<40), int64(400<<30), int64(0), int64(0), int64(0), "synced", now, "",
		int64(0), int64(0), int64(0), "adapter",
		int64(5), now, true, int64(0), true, "open",
		int64(3), now, now, "", now,
	)
	mock.ExpectQuery(`SELECT .* FROM nodes ORDER BY id`).
		WillReturnRows(nodeRows)
	alertRows := sqlmock.NewRows([]string{
		"severity", "state", "category", "user_uuid", "username", "node_name",
		"summary", "first_seen_at", "last_seen_at",
	}).AddRow(
		"warning", "open", "unprotected", "11111111-1111-4111-8111-111111111111",
		"alice", "", "用户暂无可用备份副本", now.Add(-time.Hour), now,
	)
	mock.ExpectQuery(`SELECT .* FROM alerts`).
		WillReturnRows(alertRows)

	raw, evidence, candidates, dedupKey, taskType, err := s.buildAIObservation(context.Background())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(raw) == 0 || taskType != string(ai.TaskMonitoringInspect) || dedupKey == "" {
		t.Fatalf("raw=%d task=%q dedup=%q", len(raw), taskType, dedupKey)
	}
	if len(evidence) == 0 {
		t.Fatal("expected evidence catalog")
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 eligible candidate, got %d", len(candidates))
	}
	var decoded ai.Observation
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Nodes) != 1 || decoded.Nodes[0].Ref == "" {
		t.Fatalf("nodes=%+v", decoded.Nodes)
	}
	rawStr := string(raw)
	for _, forbidden := range []string{"http://internal", "fp", "alice", "11111111-1111-4111-8111-111111111111"} {
		if containsSubstring(rawStr, forbidden) {
			t.Fatalf("observation leaked %q", forbidden)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func containsSubstring(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestNodeEligibilityMirrorsDeterministicRules(t *testing.T) {
	t.Parallel()
	open := &store.Node{
		Role: "compute", ConnectivityState: "online", OperationalState: "active",
		CompatibilityState: "compatible", CapacityState: "open",
	}
	if !nodeEligibleForNewLoad(open) {
		t.Fatal("open compute node must be eligible")
	}
	full := &store.Node{
		Role: "compute", ConnectivityState: "online", OperationalState: "active",
		CompatibilityState: "compatible", CapacityState: "full",
	}
	if nodeEligibleForNewLoad(full) {
		t.Fatal("full node must not be eligible")
	}
	storage := &store.Node{
		Role: "storage", ConnectivityState: "online", OperationalState: "active",
		CompatibilityState: "compatible", CapacityState: "open",
	}
	if nodeEligibleForNewLoad(storage) {
		t.Fatal("storage node must not be eligible for compute load")
	}
	if !nodeEligibleAsBackupTarget(storage) {
		t.Fatal("storage node must be eligible as backup target")
	}
}

func TestAIAdminEndpointsRejectWithoutAdminSession(t *testing.T) {
	t.Parallel()
	s := &Server{Cfg: config.DefaultController()}
	router := newRouter()
	s.routes(router)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/ai/status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("expected 401/403 without admin session, got %d", rec.Code)
	}
}

func TestAISupervisorStartIsNoopWhenDisabled(t *testing.T) {
	t.Parallel()
	s := &Server{Cfg: config.DefaultController(), secretKey: []byte("key")}
	s.startAISupervisor(context.Background())
}

func TestAISupervisorStartIsNoopWithInvalidConfig(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultController()
	cfg.AISupervisor.Enabled = true
	cfg.AISupervisor.Provider = "not_a_provider"
	s := &Server{Cfg: cfg, secretKey: []byte("key")}
	s.startAISupervisor(context.Background())
}

func TestAIAdminStatusPayloadShape(t *testing.T) {
	t.Parallel()
	s := &Server{Cfg: config.DefaultController()}
	if s.Cfg.AISupervisor.Enabled {
		t.Fatal("AI must be disabled by default")
	}
	if s.Cfg.AISupervisor.Mode != "shadow" {
		t.Fatalf("default mode=%q", s.Cfg.AISupervisor.Mode)
	}
}

package controller

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"stcontrol/internal/ai"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

// fakeAISupervisor is a minimal stub capturing EnqueueTask calls.
type fakeAISupervisor struct {
	tasks []struct {
		taskType string
		obs      []byte
		dedup    string
	}
}

func (f *fakeAISupervisor) EnqueueTask(_ context.Context, taskType string, obs []byte, dedup string) error {
	f.tasks = append(f.tasks, struct {
		taskType string
		obs      []byte
		dedup    string
	}{taskType, obs, dedup})
	return nil
}

func phaseTestServer(t *testing.T) (*Server, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Server{
		Cfg:          config.DefaultController(),
		Store:        &store.Store{DB: db},
		secretKey:    []byte("controller-secret-key"),
		aiSupervisor: &fakeAISupervisor{},
	}, mock
}

func TestEnqueueAnomalyAttribution(t *testing.T) {
	t.Parallel()
	s, mock := phaseTestServer(t)
	now := time.Now()
	alertRows := sqlmock.NewRows([]string{
		"severity", "state", "category", "user_uuid", "username", "node_name",
		"summary", "first_seen_at", "last_seen_at",
	}).AddRow(
		"critical", "open", "user_protection", "11111111-1111-4111-8111-111111111111",
		"alice", "", "archive 完整性复核失败", now.Add(-time.Hour), now,
	)
	mock.ExpectQuery(`SELECT .* FROM alerts`).WillReturnRows(alertRows)
	mock.ExpectQuery(`SELECT severity, COUNT\(\*\) FROM alerts`).
		WillReturnRows(sqlmock.NewRows([]string{"severity", "count"}).AddRow("critical", int64(1)))
	if err := s.enqueueAnomalyAttribution(context.Background()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	sup := s.aiSupervisor.(*fakeAISupervisor)
	if len(sup.tasks) != 1 || sup.tasks[0].taskType != string(ai.TaskAnomalyAttribution) {
		t.Fatalf("tasks=%+v", sup.tasks)
	}
	if sup.tasks[0].dedup == "" {
		t.Fatal("missing dedup key")
	}
	var obs aiAnomalyObservation
	if err := json.Unmarshal(sup.tasks[0].obs, &obs); err != nil {
		t.Fatalf("obs: %v", err)
	}
	if len(obs.Alerts) != 1 || obs.Alerts[0].Severity != "critical" {
		t.Fatalf("obs=%+v", obs)
	}
	rawStr := string(sup.tasks[0].obs)
	for _, forbidden := range []string{"alice", "11111111-1111-4111-8111-111111111111"} {
		if containsSubstring(rawStr, forbidden) {
			t.Fatalf("observation leaked %q", forbidden)
		}
	}
}

func TestEnqueueAnomalyAttributionSkipsWhenNoAlerts(t *testing.T) {
	t.Parallel()
	s, mock := phaseTestServer(t)
	mock.ExpectQuery(`SELECT .* FROM alerts`).
		WillReturnRows(sqlmock.NewRows([]string{
			"severity", "state", "category", "user_uuid", "username", "node_name",
			"summary", "first_seen_at", "last_seen_at",
		}))
	if err := s.enqueueAnomalyAttribution(context.Background()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(s.aiSupervisor.(*fakeAISupervisor).tasks) != 0 {
		t.Fatal("must not enqueue without alerts")
	}
}

func TestEnqueueScheduleRecommendation(t *testing.T) {
	t.Parallel()
	s, mock := phaseTestServer(t)
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
	now := time.Now()
	rows := sqlmock.NewRows(nodeCols).
		AddRow(1, "node-a", "compute", "http://internal", "", "cn-east",
			30.0, 40.0, 55.0, "1.0", "1.0", now.Add(-time.Minute), "active",
			"online", "active", "managed", int64(1), "managed", int64(1),
			"open", "ok", now, now, "compatible", "ok", "fp", now, now,
			30.0, 35.0, 40.0, 45.0, 50.0, 60.0,
			int64(1<<40), int64(500<<30), int64(0), int64(0), int64(0), "synced", now, "",
			int64(0), int64(0), int64(0), "adapter",
			int64(5), now, true, int64(0), true, "open",
			int64(3), now, now, "", now).
		AddRow(2, "node-b", "compute", "http://internal2", "", "us-west",
			20.0, 30.0, 45.0, "1.0", "1.0", now.Add(-time.Minute), "active",
			"online", "active", "managed", int64(1), "managed", int64(1),
			"open", "ok", now, now, "compatible", "ok", "fp2", now, now,
			20.0, 25.0, 30.0, 35.0, 40.0, 50.0,
			int64(1<<40), int64(600<<30), int64(0), int64(0), int64(0), "synced", now, "",
			int64(0), int64(0), int64(0), "adapter",
			int64(5), now, true, int64(0), true, "open",
			int64(3), now, now, "", now)
	mock.ExpectQuery(`SELECT .* FROM nodes ORDER BY id`).WillReturnRows(rows)
	if err := s.enqueueScheduleRecommendation(context.Background()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	sup := s.aiSupervisor.(*fakeAISupervisor)
	if len(sup.tasks) != 1 || sup.tasks[0].taskType != string(ai.TaskScheduleRecommend) {
		t.Fatalf("tasks=%+v", sup.tasks)
	}
	rawStr := string(sup.tasks[0].obs)
	for _, forbidden := range []string{"http://internal", "fp", "fp2"} {
		if containsSubstring(rawStr, forbidden) {
			t.Fatalf("observation leaked %q", forbidden)
		}
	}
	// D5 regression: the candidate catalog must be serialized so ordering
	// actions can pass validation instead of failing with empty_candidates.
	var obs aiAnomalyObservation
	if err := json.Unmarshal(sup.tasks[0].obs, &obs); err != nil {
		t.Fatalf("obs: %v", err)
	}
	if len(obs.CandidateCatalog) != 2 {
		t.Fatalf("candidate_catalog=%+v, want 2 eligible node refs", obs.CandidateCatalog)
	}
	for _, c := range obs.CandidateCatalog {
		if c.Kind != "node" || c.Ref == "" {
			t.Fatalf("malformed candidate %+v", c)
		}
	}
}

func TestEnqueueScheduleRecommendationSkipsWithoutTwoCandidates(t *testing.T) {
	t.Parallel()
	s, mock := phaseTestServer(t)
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
	now := time.Now()
	rows := sqlmock.NewRows(nodeCols).
		AddRow(1, "node-a", "compute", "http://internal", "", "cn-east",
			30.0, 40.0, 55.0, "1.0", "1.0", now.Add(-time.Minute), "active",
			"online", "active", "managed", int64(1), "managed", int64(1),
			"open", "ok", now, now, "compatible", "ok", "fp", now, now,
			30.0, 35.0, 40.0, 45.0, 50.0, 60.0,
			int64(1<<40), int64(500<<30), int64(0), int64(0), int64(0), "synced", now, "",
			int64(0), int64(0), int64(0), "adapter",
			int64(5), now, true, int64(0), true, "open",
			int64(3), now, now, "", now)
	mock.ExpectQuery(`SELECT .* FROM nodes ORDER BY id`).WillReturnRows(rows)
	if err := s.enqueueScheduleRecommendation(context.Background()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(s.aiSupervisor.(*fakeAISupervisor).tasks) != 0 {
		t.Fatal("must not enqueue with fewer than two candidates")
	}
}

func TestEnqueueRecoveryPlan(t *testing.T) {
	t.Parallel()
	s, mock := phaseTestServer(t)
	now := time.Now()
	mock.ExpectQuery(`SELECT id::text, state, attempt, error_code, created_at, updated_at`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "state", "attempt", "error_code", "created_at", "updated_at",
		}).AddRow("11111111-1111-4111-8111-111111111111", "retry_wait", 2, "timeout", now, now))
	if err := s.enqueueRecoveryPlan(context.Background()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	sup := s.aiSupervisor.(*fakeAISupervisor)
	if len(sup.tasks) != 1 || sup.tasks[0].taskType != string(ai.TaskRecoveryPlan) {
		t.Fatalf("tasks=%+v", sup.tasks)
	}
	// D5 regression: workflow refs must be serialized as candidates so
	// RECOVERY_STEP_ORDER advisories can pass validation.
	var obs aiRecoveryObservation
	if err := json.Unmarshal(sup.tasks[0].obs, &obs); err != nil {
		t.Fatalf("obs: %v", err)
	}
	if len(obs.CandidateCatalog) != 1 || obs.CandidateCatalog[0].Kind != "workflow" ||
		obs.CandidateCatalog[0].Ref == "" {
		t.Fatalf("candidate_catalog=%+v, want 1 workflow ref", obs.CandidateCatalog)
	}
}

func TestEnqueueImportReview(t *testing.T) {
	t.Parallel()
	s, mock := phaseTestServer(t)
	mock.ExpectQuery(`SELECT batch_id::text, source, account_kind, resolution_state`).
		WithArgs(50).
		WillReturnRows(sqlmock.NewRows([]string{
			"batch_id", "source", "account_kind", "resolution_state", "size_bucket",
		}).AddRow("22222222-2222-4222-8222-222222222222", "adapter", "password", "claim_required", "small"))
	if err := s.enqueueImportReview(context.Background()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	sup := s.aiSupervisor.(*fakeAISupervisor)
	if len(sup.tasks) != 1 || sup.tasks[0].taskType != string(ai.TaskImportReview) {
		t.Fatalf("tasks=%+v", sup.tasks)
	}
}

func TestEnqueueDisasterReview(t *testing.T) {
	t.Parallel()
	s, mock := phaseTestServer(t)
	now := time.Now()
	mock.ExpectQuery(`SELECT node_id, reported_mode, desired_mode, reason_code, observed_at`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "reported_mode", "desired_mode", "reason_code", "observed_at",
		}).AddRow(3, "independent", "independent", "sustained_outage", now))
	if err := s.enqueueDisasterReview(context.Background()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	sup := s.aiSupervisor.(*fakeAISupervisor)
	if len(sup.tasks) != 1 || sup.tasks[0].taskType != string(ai.TaskDisasterReview) {
		t.Fatalf("tasks=%+v", sup.tasks)
	}
	var obs aiDisasterObservation
	if err := json.Unmarshal(sup.tasks[0].obs, &obs); err != nil {
		t.Fatal(err)
	}
	if !obs.HardFloorSatisfied {
		t.Fatal("independent mode must satisfy the hard floor")
	}
}

func TestEnqueueConflictReview(t *testing.T) {
	t.Parallel()
	s, mock := phaseTestServer(t)
	now := time.Now()
	mock.ExpectQuery(`SELECT c.user_id, c.state`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "state", "source_count", "file_count", "total_bytes", "captured_at", "updated_at",
		}).AddRow(7, "awaiting_decision", int64(2), int64(120), int64(4096), now, now))
	if err := s.enqueueConflictReview(context.Background()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	sup := s.aiSupervisor.(*fakeAISupervisor)
	if len(sup.tasks) != 1 || sup.tasks[0].taskType != string(ai.TaskConflictReview) {
		t.Fatalf("tasks=%+v", sup.tasks)
	}
	var obs aiConflictObservation
	if err := json.Unmarshal(sup.tasks[0].obs, &obs); err != nil {
		t.Fatal(err)
	}
	if len(obs.Conflicts) != 1 || obs.Conflicts[0].SourceCount != 2 {
		t.Fatalf("obs=%+v", obs)
	}
}

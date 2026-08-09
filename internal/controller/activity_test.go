package controller

import (
	"context"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestActivityLeaseTTLUsesExplicitControllerPolicy(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultController()
	cfg.Activity.LeaseTTLSec = 123
	server := New(cfg, nil, nil)
	if got := server.activityLeaseTTL(); got != 123*time.Second {
		t.Fatalf("activity lease TTL=%s", got)
	}
}

func TestValidateActivityObservationRejectsRollbackAndFutureClockEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 4, 0, 0, 0, time.UTC)
	for name, observedAt := range map[string]int64{
		"negative":       -1,
		"too old":        now.Add(-5*time.Minute - time.Millisecond).UnixMilli(),
		"too far future": now.Add(time.Minute + time.Millisecond).UnixMilli(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateActivityObservation(now, observedAt); err == nil {
				t.Fatalf("unsafe observation %d was accepted", observedAt)
			}
		})
	}
	for _, observedAt := range []int64{0, now.Add(-5 * time.Minute).UnixMilli(), now.UnixMilli(), now.Add(time.Minute).UnixMilli()} {
		if err := validateActivityObservation(now, observedAt); err != nil {
			t.Fatalf("valid observation %d rejected: %v", observedAt, err)
		}
	}
}

func TestNonAuthoritativeActivityTelemetryFailsClosed(t *testing.T) {
	t.Parallel()
	server := New(config.DefaultController(), nil, nil)
	server.activity[7] = map[string]protocol.UserStatus{
		"alice": {Handle: "alice", IsOnline: false, LastActivity: 1},
	}
	if _, err := server.trackUserActivity(context.Background(), 7, "directory_fallback", []protocol.UserStatus{{
		Handle: "alice", IsOnline: false, LastActivity: 1,
	}}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, ok := server.activity[7]; ok {
		t.Fatal("directory fallback retained a schedulable offline fact")
	}
}

func TestAuthoritativeEmptyActivitySnapshotReplacesStaleFacts(t *testing.T) {
	t.Parallel()
	server := New(config.DefaultController(), nil, nil)
	server.activity[7] = map[string]protocol.UserStatus{
		"alice": {Handle: "alice", IsOnline: false, LastActivity: 1},
	}
	if _, err := server.trackUserActivity(context.Background(), 7, "adapter", nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got := len(server.activity[7]); got != 0 {
		t.Fatalf("stale adapter facts retained: %d", got)
	}
}

func TestNormalizeUserActivityUsesPageRequestAndInFlightFacts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 4, 0, 0, 0, time.UTC)
	ttl := 15 * time.Minute
	tests := []struct {
		name   string
		status protocol.UserStatus
		online bool
	}{
		{name: "foreground page", online: true, status: protocol.UserStatus{
			Handle: "alice", LastActivity: now.UnixMilli(), LastPageHeartbeat: now.Add(-time.Minute).UnixMilli(),
		}},
		{name: "background page", online: true, status: protocol.UserStatus{
			Handle: "alice", LastActivity: now.UnixMilli(), LastPageHeartbeat: now.Add(-5 * time.Minute).UnixMilli(),
		}},
		{name: "ordinary request", online: true, status: protocol.UserStatus{
			Handle: "alice", LastActivity: now.UnixMilli(), LastRequest: now.Add(-time.Second).UnixMilli(),
		}},
		{name: "in flight write", online: true, status: protocol.UserStatus{
			Handle: "alice", LastActivity: now.Add(-time.Hour).UnixMilli(), InFlightWrites: 1,
		}},
		{name: "idle", online: false, status: protocol.UserStatus{
			Handle: "alice", LastActivity: now.Add(-time.Hour).UnixMilli(),
			LastPageHeartbeat: now.Add(-ttl - time.Second).UnixMilli(),
			LastRequest:       now.Add(-ttl - time.Second).UnixMilli(),
		}},
		{name: "ended overrides in flight", online: false, status: protocol.UserStatus{
			Handle: "alice", Ended: true, LastActivity: now.UnixMilli(), InFlightWrites: 1,
		}},
		{name: "future last activity fails closed", online: true, status: protocol.UserStatus{
			Handle: "alice", LastActivity: now.Add(2 * time.Minute).UnixMilli(),
		}},
		{name: "future page heartbeat fails closed", online: true, status: protocol.UserStatus{
			Handle: "alice", LastActivity: now.Add(-time.Hour).UnixMilli(),
			LastPageHeartbeat: now.Add(2 * time.Minute).UnixMilli(),
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			normalized, _, _, ok := normalizeUserActivityStatus(test.status, now, ttl)
			if !ok || normalized.IsOnline != test.online {
				t.Fatalf("normalized=%+v ok=%v want online=%v", normalized, ok, test.online)
			}
		})
	}
}

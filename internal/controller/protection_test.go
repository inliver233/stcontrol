package controller

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestPublicProtectionStateUsesSafeProductLanguage(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	tests := []struct {
		state string
		label string
	}{
		{state: "protected", label: "已保护"},
		{state: "temporary", label: "临时保护"},
		{state: "unprotected", label: "未保护"},
		{state: "takeover_available", label: "可接管"},
		{state: "restore_required", label: "需要恢复"},
		{state: "conflict", label: "冲突已冻结"},
		{state: "unavailable", label: "暂不可恢复"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.state, func(t *testing.T) {
			t.Parallel()
			response := publicProtectionState(&store.UserProtectionState{
				State: test.state, Version: 3,
				AuthoritativeNodeID: sql.NullInt64{Int64: 8, Valid: true},
				RecoveryNodeID:      sql.NullInt64{Int64: 9, Valid: true},
				ActiveWriterNodeID:  sql.NullInt64{Int64: 8, Valid: true},
				LatestRecoveryAt:    sql.NullTime{Time: now, Valid: true},
			})
			if response.Label != test.label || response.Risk == "" || response.Version != 3 {
				t.Fatalf("response=%+v", response)
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"reason_code", "snapshot_id", "operation_id"} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("public response leaked %q: %s", forbidden, encoded)
				}
			}
		})
	}
}

func TestReplicaTakeoverDigestBindsUserTargetAndAcknowledgement(t *testing.T) {
	t.Parallel()
	server := &Server{secretKey: bytes.Repeat([]byte{1}, 32)}
	recoveryAt := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	first, err := server.replicaTakeoverDigest(70, 9, recoveryAt, true)
	second, err2 := server.replicaTakeoverDigest(70, 9, recoveryAt, true)
	userChanged, _ := server.replicaTakeoverDigest(71, 9, recoveryAt, true)
	targetChanged, _ := server.replicaTakeoverDigest(70, 10, recoveryAt, true)
	recoveryChanged, _ := server.replicaTakeoverDigest(70, 9, recoveryAt.Add(time.Minute), true)
	ackChanged, _ := server.replicaTakeoverDigest(70, 9, recoveryAt, false)
	if err != nil || err2 != nil || !bytes.Equal(first, second) || bytes.Equal(first, userChanged) ||
		bytes.Equal(first, targetChanged) || bytes.Equal(first, recoveryChanged) ||
		bytes.Equal(first, ackChanged) || len(first) != 32 {
		t.Fatalf("digest binding failed err=%v err2=%v", err, err2)
	}
}

func TestConfirmReplicaTakeoverRequiresExplicitRiskAcknowledgement(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: config.DefaultController()}
	req := httptest.NewRequest(http.MethodPost, "/api/users/me/takeover", strings.NewReader(`{
		"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"target_node_id":9,
		"acknowledge_data_loss":false
	}`))
	recorder := httptest.NewRecorder()
	server.handleConfirmReplicaTakeover(recorder, req)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "确认") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestConfirmReplicaTakeoverRejectsMissingRecoveryPointBeforeStoreAccess(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: config.DefaultController()}
	req := httptest.NewRequest(http.MethodPost, "/api/users/me/takeover", strings.NewReader(`{
		"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"target_node_id":9,
		"acknowledge_data_loss":true
	}`))
	recorder := httptest.NewRecorder()
	server.handleConfirmReplicaTakeover(recorder, req)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "恢复时间") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestProtectionAlertGraceFallsBackSafely(t *testing.T) {
	t.Parallel()
	for _, server := range []*Server{{}, {Cfg: &config.ControllerConfig{}}} {
		if got := server.protectionAlertGrace(); got != time.Hour {
			t.Fatalf("grace=%v", got)
		}
	}
}

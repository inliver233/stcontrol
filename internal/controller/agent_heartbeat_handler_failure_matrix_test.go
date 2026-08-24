package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func validControllerHeartbeat() protocol.HeartbeatRequest {
	return protocol.HeartbeatRequest{
		NodeID: 12, AgentVersion: "agent-test", MetricsValid: true,
		CPUPct: 10, MemPct: 20, DiskPct: 30, DiskTotalBytes: 1000,
		DiskAvailableBytes: 500, DiskQuotaBytes: 900, TelemetrySource: "agent",
		ActivityObservedAt: time.Now().UTC().UnixMilli(),
		Compatibility:      protocol.NodeCompatibilityReport{State: "unknown", ErrorCode: "adapter_unavailable"},
		ControlMode: protocol.NodeControlModeReport{
			Mode: protocol.NodeModeManaged, ModeGeneration: 1, ControllerGeneration: 1,
		},
	}
}

func heartbeatHandlerRequest(t *testing.T, body any, node *store.Node, authenticated, active int64) *http.Request {
	t.Helper()
	var encoded string
	if value, ok := body.(string); ok {
		encoded = value
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		encoded = string(data)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", strings.NewReader(encoded))
	ctx := req.Context()
	if node != nil {
		ctx = context.WithValue(ctx, ctxKey("stcontrol-node"), node)
	}
	ctx = context.WithValue(ctx, ctxKey("stcontrol-agent-credential-generation"), authenticated)
	ctx = context.WithValue(ctx, ctxKey("stcontrol-active-controller-generation"), active)
	return req.WithContext(ctx)
}

func TestAgentHeartbeatHandlerRejectsInvalidAndUnreconciledReports(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected heartbeat reconciliation failure")
	for _, tc := range []struct {
		name          string
		body          any
		node          *store.Node
		authenticated int64
		active        int64
		setup         func(sqlmock.Sqlmock)
		status        int
		wantGate      bool
	}{
		{name: "unknown node", body: `{}`, status: http.StatusUnauthorized},
		{name: "malformed JSON", body: `{`, node: &store.Node{ID: 12}, status: http.StatusBadRequest},
		{
			name: "future activity", node: &store.Node{ID: 12}, body: func() protocol.HeartbeatRequest {
				req := validControllerHeartbeat()
				req.ActivityObservedAt = time.Now().Add(2 * time.Minute).UnixMilli()
				return req
			}(), status: http.StatusBadRequest,
		},
		{
			name: "invalid mode", node: &store.Node{ID: 12}, body: func() protocol.HeartbeatRequest {
				req := validControllerHeartbeat()
				req.ControlMode.Mode = "unsafe"
				return req
			}(), status: http.StatusBadRequest,
		},
		{
			name: "invalid transfer URL", node: &store.Node{ID: 12}, authenticated: 1, active: 1,
			body: func() protocol.HeartbeatRequest {
				req := validControllerHeartbeat()
				req.TransferURL = "http://public.example/transfer"
				return req
			}(), status: http.StatusBadRequest,
		},
		{
			name: "recovery generation closes gate before invalid transfer", node: &store.Node{ID: 12}, authenticated: 1, active: 2,
			body: func() protocol.HeartbeatRequest {
				req := validControllerHeartbeat()
				req.TransferURL = "http://public.example/transfer"
				return req
			}(), status: http.StatusBadRequest, wantGate: true,
		},
		{
			name: "durable reconciliation failure", node: &store.Node{ID: 12, RegistrationPolicyVersion: 4}, authenticated: 1, active: 1,
			body: func() protocol.HeartbeatRequest {
				req := validControllerHeartbeat()
				req.RegistrationPolicy = protocol.RegistrationPolicyReport{State: "error", Version: 1}
				return req
			}(),
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectBegin().WillReturnError(injected) },
			status: http.StatusConflict,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			server := &Server{Cfg: config.DefaultController(), Store: &store.Store{DB: db}}
			if tc.setup != nil {
				tc.setup(mock)
			}
			recorder := httptest.NewRecorder()
			server.handleAgentHeartbeat(recorder,
				heartbeatHandlerRequest(t, tc.body, tc.node, tc.authenticated, tc.active))
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			blocked, _ := server.controlPlaneGate()
			if blocked != tc.wantGate {
				t.Fatalf("gate blocked=%v, want %v", blocked, tc.wantGate)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

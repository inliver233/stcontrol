package controller

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/store"
)

func TestWorkflowPublicStateAndErrorMappings(t *testing.T) {
	t.Parallel()
	for internal, want := range map[string]string{
		"scheduled": "preparing", "transferring": "preparing", "publishing": "publishing",
		"retry_wait": "retrying", "cancelled": "failed", "succeeded": "succeeded",
	} {
		got := publicConflictResolution(&store.ConflictResolutionStatus{State: internal})
		if got.State != want {
			t.Errorf("conflict state %q -> %q, want %q", internal, got.State, want)
		}
	}
	for internal, want := range map[string]string{
		"scheduled": "preparing", "quiescing": "preparing", "drained": "preparing",
		"snapshotting": "preparing", "transferring": "transferring",
		"retry_wait": "retrying", "cancelled": "failed", "succeeded": "succeeded",
	} {
		got := publicArchiveRestoreStatus(&store.RestoreOperationStatus{State: internal})
		if got.State != want {
			t.Errorf("restore state %q -> %q, want %q", internal, got.State, want)
		}
	}
}

func TestWorkflowErrorsExposeStableSafeHTTPMessages(t *testing.T) {
	t.Parallel()
	conflictCases := []struct {
		err  error
		code int
	}{
		{store.ErrConflictResolutionState, http.StatusConflict},
		{store.ErrConflictResolutionReplay, http.StatusConflict},
		{store.ErrNoActiveController, http.StatusServiceUnavailable},
		{errors.New("sensitive database detail"), http.StatusInternalServerError},
	}
	server := &Server{}
	for _, test := range conflictCases {
		recorder := httptest.NewRecorder()
		server.writeConflictResolutionError(recorder, test.err)
		if recorder.Code != test.code || strings.Contains(recorder.Body.String(), "sensitive database detail") {
			t.Errorf("conflict err=%v status=%d body=%s", test.err, recorder.Code, recorder.Body.String())
		}
	}
	restoreCases := []struct {
		err  error
		code int
	}{
		{store.ErrUserDataFaultState, http.StatusConflict},
		{store.ErrReplicaTakeoverLeaseActive, http.StatusConflict},
		{store.ErrRestoreUnavailable, http.StatusConflict},
		{store.ErrRestoreConflict, http.StatusConflict},
		{store.ErrNoActiveController, http.StatusServiceUnavailable},
		{errors.New("sensitive database detail"), http.StatusInternalServerError},
	}
	for _, test := range restoreCases {
		recorder := httptest.NewRecorder()
		server.writeArchiveRestoreError(recorder, test.err)
		if recorder.Code != test.code || strings.Contains(recorder.Body.String(), "sensitive database detail") {
			t.Errorf("restore err=%v status=%d body=%s", test.err, recorder.Code, recorder.Body.String())
		}
	}
}

func TestRetryPoliciesAreBoundedAndErrorCodesAllowlisted(t *testing.T) {
	t.Parallel()
	for _, code := range []string{"invalid_command_payload", "replica_cleanup_failed", "replica_identity_unavailable"} {
		if got := safeReplicaCleanupFailureCode(code); got != code {
			t.Errorf("safe code %q mapped to %q", code, got)
		}
	}
	if got := safeReplicaCleanupFailureCode("postgres password=secret"); got != "agent_command_unavailable" {
		t.Fatalf("untrusted code leaked as %q", got)
	}
	previous := time.Duration(0)
	for attempt := -1; attempt <= 32; attempt++ {
		delay := replicaCleanupRetryDelay(attempt)
		if delay < time.Minute || delay > 6*time.Hour || (previous > 0 && delay < previous) {
			t.Fatalf("attempt=%d delay=%s previous=%s", attempt, delay, previous)
		}
		previous = delay
	}
}

func TestAIHelperOrderingAndObservationParsing(t *testing.T) {
	t.Parallel()
	if !sameInt64s([]int64{1, 2, 3}, []int64{1, 2, 3}) ||
		sameInt64s([]int64{1, 2}, []int64{1, 2, 3}) || sameInt64s([]int64{1, 3}, []int64{1, 2}) {
		t.Fatal("sameInt64s comparison is incorrect")
	}
	if got := joinInt64s([]int64{9, 7, 5}); got != "9,7,5" {
		t.Fatalf("joinInt64s=%q", got)
	}
	if got := observationIDFromJSON([]byte(`{"observation_id":"obs_safe"}`)); got != "obs_safe" {
		t.Fatalf("observation id=%q", got)
	}
	if got := observationIDFromJSON([]byte(`{`)); got != "" {
		t.Fatalf("malformed observation id=%q", got)
	}
	recorder := httptest.NewRecorder()
	writeAdminError(recorder, http.StatusTeapot, "safe_code")
	if recorder.Code != http.StatusTeapot || recorder.Header().Get("Content-Type") != "application/json" ||
		!strings.Contains(recorder.Body.String(), "safe_code") {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestRegistrationFailureMessageNeverReflectsRawAgentText(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		"node_unavailable", "node_rejected", "policy_changed", "policy_expired", "command_timeout",
		"command_uncertain", "invalid_command_payload", "unknown-secret=password",
	} {
		message := registrationFailureMessage(code)
		if message == "" || strings.Contains(message, "password") {
			t.Errorf("code=%q message=%q", code, message)
		}
	}
}

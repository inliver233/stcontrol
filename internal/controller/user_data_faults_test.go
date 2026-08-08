package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/store"
)

func TestUserDataFaultRequestDigestBindsScopeAndAcknowledgement(t *testing.T) {
	t.Parallel()
	request := reportUserDataFaultRequest{
		OperationID:        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ExpectedHomeNodeID: 8, ReasonCode: "user_database_corrupt", AcknowledgeRisk: true,
	}
	first, err := userDataFaultRequestDigest("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", request)
	second, err2 := userDataFaultRequestDigest("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", request)
	changedUser, _ := userDataFaultRequestDigest("cccccccc-cccc-4ccc-8ccc-cccccccccccc", request)
	changedNode := request
	changedNode.ExpectedHomeNodeID++
	changedNodeDigest, _ := userDataFaultRequestDigest("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", changedNode)
	changedAck := request
	changedAck.AcknowledgeRisk = false
	changedAckDigest, _ := userDataFaultRequestDigest("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", changedAck)
	if err != nil || err2 != nil || len(first) != 32 || !bytes.Equal(first, second) ||
		bytes.Equal(first, changedUser) || bytes.Equal(first, changedNodeDigest) ||
		bytes.Equal(first, changedAckDigest) {
		t.Fatalf("digest binding failed: err=%v err2=%v", err, err2)
	}
}

func TestAdminUserDataFaultRequiresStrictSingleJSONAndRiskAcknowledgement(t *testing.T) {
	t.Parallel()
	server := &Server{}
	for _, body := range []string{
		`{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","expected_home_node_id":8,"reason_code":"user_database_corrupt","acknowledge_risk":false}`,
		`{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","expected_home_node_id":8,"reason_code":"free_text","acknowledge_risk":true}`,
		`{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","expected_home_node_id":8,"reason_code":"user_database_corrupt","acknowledge_risk":true}{}`,
	} {
		request := httptest.NewRequest(http.MethodPost,
			"/api/admin/users/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/data-faults",
			strings.NewReader(body))
		recorder := httptest.NewRecorder()
		server.handleAdminReportUserDataFault(recorder, request)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "确认") {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestUserDataFreezeNodeEligibilityIsClosed(t *testing.T) {
	t.Parallel()
	base := store.Node{
		Role: "compute", ConnectivityState: "online", OperationalState: "active",
		CompatibilityState: "compatible", ControlMode: "managed",
	}
	if !nodeAcceptsUserDataFreeze(&base) {
		t.Fatal("eligible managed compute node was rejected")
	}
	independent := base
	independent.ControlMode = "independent-draining"
	independent.OperationalState = "draining"
	if !nodeAcceptsUserDataFreeze(&independent) {
		t.Fatal("independent-draining node cannot receive the fixed freeze command")
	}
	for name, mutate := range map[string]func(*store.Node){
		"storage":        func(node *store.Node) { node.Role = "storage" },
		"offline":        func(node *store.Node) { node.ConnectivityState = "offline" },
		"incompatible":   func(node *store.Node) { node.CompatibilityState = "incompatible" },
		"decommissioned": func(node *store.Node) { node.OperationalState = "decommissioned" },
		"unknown mode":   func(node *store.Node) { node.ControlMode = "unknown" },
	} {
		node := base
		mutate(&node)
		if nodeAcceptsUserDataFreeze(&node) {
			t.Errorf("%s node was accepted", name)
		}
	}
}

func TestUserDataFaultRetriesAreBoundedAndErrorsAreMachineSafe(t *testing.T) {
	t.Parallel()
	if safeUserDataFaultFailureCode("user_data_freeze_failed") != "user_data_freeze_failed" ||
		safeUserDataFaultFailureCode("database password leaked") != "agent_command_unavailable" {
		t.Fatal("failure code allowlist is not closed")
	}
	if got := userDataFaultRetryDelay(1); got != 5*time.Second {
		t.Fatalf("first retry=%v", got)
	}
	if got := userDataFaultRetryDelay(100); got != 5*time.Minute {
		t.Fatalf("capped retry=%v", got)
	}
}

func TestUserDataFaultReasonAllowlistIsClosed(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{
		"authoritative_integrity_mismatch", "user_directory_missing",
		"user_directory_unreadable", "user_database_corrupt",
	} {
		if !userDataFaultReasonCode(reason) {
			t.Errorf("documented reason %q was rejected", reason)
		}
	}
	for _, reason := range []string{"", "operator_note", "../../etc/passwd"} {
		if userDataFaultReasonCode(reason) {
			t.Errorf("undocumented reason %q was accepted", reason)
		}
	}
}

func TestUserProtectionActionsRemainClosedUntilNodeFreezeIsConfirmed(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"reported", "freezing", "retry_wait", "recovery_unavailable"} {
		response := userProtectionResponse{
			State: "takeover_available", Label: "可接管",
			TakeoverAvailable: true, StorageRestoreNeeded: true,
		}
		applyUserDataFaultGate(&response, &store.UserDataFaultStatus{
			State: state, ReasonCode: "user_database_corrupt",
		})
		if response.TakeoverAvailable || response.StorageRestoreNeeded ||
			response.DataFaultState != state {
			t.Fatalf("state=%s response=%+v", state, response)
		}
	}
	response := userProtectionResponse{
		State: "takeover_available", TakeoverAvailable: true,
	}
	applyUserDataFaultGate(&response, &store.UserDataFaultStatus{
		State: "recovery_available", ReasonCode: "user_database_corrupt",
	})
	if !response.TakeoverAvailable || response.DataFaultState != "recovery_available" {
		t.Fatalf("confirmed freeze response=%+v", response)
	}
	resolved := userProtectionResponse{TakeoverAvailable: true}
	applyUserDataFaultGate(&resolved, &store.UserDataFaultStatus{State: "resolved"})
	if !resolved.TakeoverAvailable || resolved.DataFaultState != "" {
		t.Fatalf("resolved fault still gates protection=%+v", resolved)
	}
}

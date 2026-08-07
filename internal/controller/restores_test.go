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

func TestArchiveRestoreDigestBindsUserTargetRecoveryPointAndAcknowledgement(t *testing.T) {
	t.Parallel()
	server := &Server{secretKey: bytes.Repeat([]byte{1}, 32)}
	recoveryAt := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	first, err := server.archiveRestoreDigest(70, 9, recoveryAt, true)
	second, err2 := server.archiveRestoreDigest(70, 9, recoveryAt, true)
	userChanged, _ := server.archiveRestoreDigest(71, 9, recoveryAt, true)
	targetChanged, _ := server.archiveRestoreDigest(70, 10, recoveryAt, true)
	recoveryChanged, _ := server.archiveRestoreDigest(70, 9, recoveryAt.Add(time.Minute), true)
	ackChanged, _ := server.archiveRestoreDigest(70, 9, recoveryAt, false)
	if err != nil || err2 != nil || !bytes.Equal(first, second) || len(first) != 32 ||
		bytes.Equal(first, userChanged) || bytes.Equal(first, targetChanged) ||
		bytes.Equal(first, recoveryChanged) || bytes.Equal(first, ackChanged) {
		t.Fatalf("digest binding failed err=%v err2=%v", err, err2)
	}
}

func TestStartArchiveRestoreRequiresExplicitSingleJSONAcknowledgement(t *testing.T) {
	t.Parallel()
	server := &Server{}
	for _, body := range []string{
		`{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","target_node_id":9,"expected_recovery_at":"2026-08-08T09:00:00Z","acknowledge_data_loss":false}`,
		`{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","target_node_id":9,"expected_recovery_at":"2026-08-08T09:00:00Z","acknowledge_data_loss":true}{}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/users/me/restore", strings.NewReader(body))
		recorder := httptest.NewRecorder()
		server.handleStartArchiveRestore(recorder, req)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "确认") {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestPublicArchiveRestoreStatusMapsInternalWorkflowWithoutLeakingIDs(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	status := publicArchiveRestoreStatus(&store.RestoreOperationStatus{
		OperationID: "operation", State: "retry_wait", TargetNodeID: 9,
		TargetNodeName: "compute-b", SourcePublishedAt: now,
		ErrorSummary: "目标节点暂不可用",
	})
	if status.State != "retrying" || status.LatestRecoveryAt != now ||
		status.TargetNodeName != "compute-b" || status.Error == "" {
		t.Fatalf("status=%+v", status)
	}
}

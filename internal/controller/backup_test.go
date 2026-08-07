package controller

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestTransferCapabilityIsDeterministicButScoped(t *testing.T) {
	t.Parallel()
	key := []byte("controller-master-key")
	a := deriveTransferCapability(key, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	b := deriveTransferCapability(key, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if a == "" || a != deriveTransferCapability(key, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") || a == b {
		t.Fatalf("capabilities a=%q b=%q", a, b)
	}
	if len(sha256.Sum256([]byte(a))) != sha256.Size {
		t.Fatal("unexpected capability digest size")
	}
}

func TestWorkflowOperationIDIsStableAndStepScoped(t *testing.T) {
	t.Parallel()
	workflowID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	prepare := deriveWorkflowOperationID(workflowID, "prepare")
	if prepare != deriveWorkflowOperationID(workflowID, "prepare") || prepare == deriveWorkflowOperationID(workflowID, "transfer") || !isUUID(prepare) {
		t.Fatalf("prepare operation=%q", prepare)
	}
}

func TestSnapshotRetryOperationsAreAttemptScoped(t *testing.T) {
	t.Parallel()
	workflowID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	capabilityID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	first := deriveWorkflowOperationID(workflowID, fmt.Sprintf("start-source:%s:%d", capabilityID, 0))
	retry := deriveWorkflowOperationID(workflowID, fmt.Sprintf("start-source:%s:%d", capabilityID, 1))
	if first == retry {
		t.Fatal("snapshot retry reused a completed command operation")
	}
}

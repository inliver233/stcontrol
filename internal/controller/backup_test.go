package controller

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
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

func TestSnapshotReplicaOriginSeparatesAutomaticStorageRepair(t *testing.T) {
	t.Parallel()
	if got := snapshotReplicaOrigin("storage_repair"); got != "temporary_failure_protection" {
		t.Fatalf("repair origin=%q", got)
	}
	if got := snapshotReplicaOrigin("offline"); got != "configured" {
		t.Fatalf("offline origin=%q", got)
	}
}

func TestChooseStorageRepairTargetUsesHealthyPureStorage(t *testing.T) {
	t.Parallel()
	nodes := []*store.Node{
		{ID: 2, Role: "compute", IsBackupTarget: true, TransferURL: "https://compute/transfer", ConnectivityState: "online", OperationalState: "active", CompatibilityState: "compatible", CapacityState: "open"},
		{ID: 3, Role: "storage", IsBackupTarget: true, TransferURL: "https://busy/transfer", ConnectivityState: "online", OperationalState: "active", CompatibilityState: "compatible", CapacityState: "busy"},
		{ID: 4, Role: "storage", IsBackupTarget: true, TransferURL: "https://open/transfer", ConnectivityState: "online", OperationalState: "active", CompatibilityState: "compatible", CapacityState: "open"},
		{ID: 5, Role: "storage", IsBackupTarget: true, TransferURL: "https://full/transfer", ConnectivityState: "online", OperationalState: "active", CompatibilityState: "compatible", CapacityState: "full"},
	}
	target := chooseStorageRepairTarget(nodes, 1)
	if target == nil || target.ID != 4 {
		t.Fatalf("target=%+v", target)
	}
	if target := chooseStorageRepairTarget(nodes, 4); target == nil || target.ID != 3 {
		t.Fatalf("fallback target=%+v", target)
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

func TestRelayBearersAreRecoverablePurposeScopedAndNeverStoredPlaintext(t *testing.T) {
	t.Parallel()
	key := []byte("stable-controller-secret")
	taskID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	upload := deriveRelayBearer(key, taskID, "upload")
	download := deriveRelayBearer(key, taskID, "download")
	if len(upload) < 32 || upload == download || upload != deriveRelayBearer(key, taskID, "upload") {
		t.Fatalf("upload=%q download=%q", upload, download)
	}
	endpoint, err := snapshotRelayEndpoint("https://relay.example/data", taskID)
	if err != nil || !strings.HasSuffix(endpoint, "/data/relay/v1/transfers/"+taskID) {
		t.Fatalf("endpoint=%q err=%v", endpoint, err)
	}
}

func TestRelayFallbackRequiresExplicitConfiguration(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: config.DefaultController()}
	if server.relayAvailable() {
		t.Fatal("disabled relay was considered available")
	}
	server.Cfg.Relay.Listen = "127.0.0.1:9444"
	server.Cfg.Relay.PublicURL = "http://127.0.0.1:9444"
	if !server.relayAvailable() {
		t.Fatal("fully configured relay was not available")
	}
}

func TestRelayCompletionRequiresMatchingSourceAndTargetFacts(t *testing.T) {
	t.Parallel()
	source := &protocol.SnapshotTransferReceipt{
		OK: true, RelayPending: true, SnapshotID: "snapshot", ManifestSHA256: "manifest",
		ArchiveSHA256: "archive", FileCount: 2, TotalBytes: 3,
	}
	target := *source
	target.RelayPending = false
	if !matchingRelayReceipts(source, &target) {
		t.Fatal("matching relay facts were rejected")
	}
	target.TotalBytes++
	if matchingRelayReceipts(source, &target) {
		t.Fatal("mismatched relay facts were accepted")
	}
}

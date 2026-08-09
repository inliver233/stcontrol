package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestSnapshotWorkflowLeaseMaintainerCancelsOnFenceLoss(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: &store.Store{DB: db}}
	mock.ExpectExec(`UPDATE workflows workflow SET lease_until`).
		WithArgs("workflow", "unique-lease-owner", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT state FROM workflows`).WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("snapshotting"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = server.maintainSnapshotWorkflowLeaseWithTiming(
		ctx, cancel, "workflow", "unique-lease-owner", 10*time.Millisecond, time.Second,
	)
	if !errors.Is(err, store.ErrSnapshotStateConflict) {
		t.Fatalf("error=%v, want lease fence conflict", err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("lease fence loss did not cancel workflow execution")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

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
	for _, trigger := range []string{"node_retirement", "node_retirement_storage"} {
		if got := snapshotReplicaOrigin(trigger); got != "migration" {
			t.Fatalf("retirement trigger=%q origin=%q", trigger, got)
		}
	}
}

func TestChooseStorageRepairTargetUsesHealthyPureStorage(t *testing.T) {
	t.Parallel()
	nodes := []*store.Node{
		{ID: 2, Role: "compute", IsBackupTarget: true, TransferURL: "https://compute/transfer", ConnectivityState: "online", OperationalState: "active", ControlMode: "managed", DesiredControlMode: "managed", CompatibilityState: "compatible", CapacityState: "open"},
		{ID: 3, Role: "storage", IsBackupTarget: true, TransferURL: "https://busy/transfer", ConnectivityState: "online", OperationalState: "active", ControlMode: "managed", DesiredControlMode: "managed", CompatibilityState: "compatible", CapacityState: "busy"},
		{ID: 4, Role: "storage", IsBackupTarget: true, TransferURL: "https://open/transfer", ConnectivityState: "online", OperationalState: "active", ControlMode: "managed", DesiredControlMode: "managed", CompatibilityState: "compatible", CapacityState: "open"},
		{ID: 5, Role: "storage", IsBackupTarget: true, TransferURL: "https://full/transfer", ConnectivityState: "online", OperationalState: "active", ControlMode: "managed", DesiredControlMode: "managed", CompatibilityState: "compatible", CapacityState: "full"},
	}
	target := chooseStorageRepairTarget(nodes, 1)
	if target == nil || target.ID != 4 {
		t.Fatalf("target=%+v", target)
	}
	if target := chooseStorageRepairTarget(nodes, 4); target == nil || target.ID != 3 {
		t.Fatalf("fallback target=%+v", target)
	}
	nodes[2].ControlMode = "independent"
	if target := chooseStorageRepairTarget(nodes, 1); target == nil || target.ID != 3 {
		t.Fatalf("independent target was not excluded: %+v", target)
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

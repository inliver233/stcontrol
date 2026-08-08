package controller

import (
	"testing"
	"time"

	"stcontrol/internal/store"
)

func TestOrderedRetirementTargetsFailClosedAndPreferOpenCapacity(t *testing.T) {
	t.Parallel()
	nodes := []*store.Node{
		retirementTestNode(7, "compute", "busy"),
		retirementTestNode(4, "compute", "open"),
		retirementTestNode(3, "compute", "open"),
		retirementTestNode(2, "storage", "open"),
		retirementTestNode(8, "compute", "full"),
		retirementTestNode(9, "compute", "open"),
	}
	nodes[5].CompatibilityState = "incompatible"
	targets := orderedRetirementTargets(nodes, "compute", 4)
	if len(targets) != 2 || targets[0].ID != 3 || targets[1].ID != 7 {
		t.Fatalf("targets=%+v", targets)
	}
}

func TestOrderedRetirementStorageTargetsRequireExplicitBackupRole(t *testing.T) {
	t.Parallel()
	compute := retirementTestNode(1, "compute", "open")
	storage := retirementTestNode(2, "storage", "open")
	storage.IsBackupTarget = true
	notTarget := retirementTestNode(3, "storage", "open")
	targets := orderedRetirementTargets([]*store.Node{compute, notTarget, storage}, "storage", 1)
	if len(targets) != 1 || targets[0].ID != 2 {
		t.Fatalf("targets=%+v", targets)
	}
}

func TestRetiringComputeSourceRemainsCommandEligibleOnlyDuringDrain(t *testing.T) {
	t.Parallel()
	node := retirementTestNode(5, "compute", "busy")
	for _, state := range []string{"draining", "retiring"} {
		node.OperationalState = state
		if !nodeCanServeRetirementSnapshot(node, 5) {
			t.Fatalf("state %q was rejected", state)
		}
	}
	for _, state := range []string{"active", "maintenance", "failed", "decommissioned"} {
		node.OperationalState = state
		if nodeCanServeRetirementSnapshot(node, 5) {
			t.Fatalf("state %q was accepted", state)
		}
	}
	node.OperationalState = "retiring"
	node.ControlMode = "independent"
	if nodeCanServeRetirementSnapshot(node, 5) {
		t.Fatal("independent source was accepted")
	}
}

func TestNodeRetirementRetryDelayIsBounded(t *testing.T) {
	t.Parallel()
	if got := nodeRetirementRetryDelay(0); got != 15*time.Second {
		t.Fatalf("first delay=%v", got)
	}
	if got := nodeRetirementRetryDelay(100); got != 5*time.Minute {
		t.Fatalf("capped delay=%v", got)
	}
}

func retirementTestNode(id int64, role, capacity string) *store.Node {
	return &store.Node{
		ID: id, Role: role, TransferURL: "https://node.example/transfer",
		ConnectivityState: "online", OperationalState: "active",
		ControlMode: "managed", DesiredControlMode: "managed",
		CompatibilityState: "compatible", CapacityState: capacity,
	}
}

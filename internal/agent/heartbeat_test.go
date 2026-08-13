package agent

import (
	"context"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestApplyControllerQuotaPolicyAppliesOnceAndRespectsVersion(t *testing.T) {
	t.Parallel()
	agent, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 9, AgentPSK: "quota-test-secret",
		DataDir: t.TempDir(), BackupDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// No policy echoed: no change.
	if err := agent.applyControllerQuotaPolicy(ctx, protocol.HeartbeatResponse{}); err != nil {
		t.Fatal(err)
	}
	if agent.runtimeDiskQuota() != 0 || agent.appliedQuotaVersion() != 0 {
		t.Fatal("empty policy changed agent quota state")
	}

	// Higher version applies the expected quota.
	if err := agent.applyControllerQuotaPolicy(ctx, protocol.HeartbeatResponse{
		QuotaPolicyVersion: 1, ExpectedDiskQuotaBytes: 200 << 30,
	}); err != nil {
		t.Fatal(err)
	}
	if agent.runtimeDiskQuota() != 200<<30 || agent.appliedQuotaVersion() != 1 {
		t.Fatalf("quota=%d version=%d", agent.runtimeDiskQuota(), agent.appliedQuotaVersion())
	}

	// Same or lower version is ignored (idempotent echo).
	if err := agent.applyControllerQuotaPolicy(ctx, protocol.HeartbeatResponse{
		QuotaPolicyVersion: 1, ExpectedDiskQuotaBytes: 999 << 30,
	}); err != nil {
		t.Fatal(err)
	}
	if agent.runtimeDiskQuota() != 200<<30 {
		t.Fatal("re-echoed version moved the quota")
	}

	// Version 0 (inherit agent.yaml) clears the override.
	if err := agent.applyControllerQuotaPolicy(ctx, protocol.HeartbeatResponse{
		QuotaPolicyVersion: 2, ExpectedDiskQuotaBytes: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if agent.runtimeDiskQuota() != 0 || agent.appliedQuotaVersion() != 2 {
		t.Fatalf("quota=%d version=%d", agent.runtimeDiskQuota(), agent.appliedQuotaVersion())
	}

	// A negative expected quota is treated as "no policy" (no-op, no mutation).
	if err := agent.applyControllerQuotaPolicy(ctx, protocol.HeartbeatResponse{
		QuotaPolicyVersion: 3, ExpectedDiskQuotaBytes: -1,
	}); err != nil {
		t.Fatal(err)
	}
	if agent.runtimeDiskQuota() != 0 || agent.appliedQuotaVersion() != 2 {
		t.Fatal("no-op apply mutated quota state")
	}
}

func TestAgentHeartbeatReportsAppliedQuotaVersion(t *testing.T) {
	t.Parallel()
	agent, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 9, AgentPSK: "quota-test-secret",
		DataDir: t.TempDir(), BackupDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.appliedQuotaVersion() != 0 {
		t.Fatal("fresh agent should report quota version 0")
	}
}
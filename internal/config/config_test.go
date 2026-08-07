package config

import "testing"

func TestDefaultControllerHasSafeCapacityHysteresis(t *testing.T) {
	t.Parallel()
	node := DefaultController().Node
	if node.RegisterCPU != 50 || node.RegisterMem != 50 || node.RegisterDisk != 50 ||
		node.AllocationHardPct != 60 || node.CapacityWindowSec <= 0 ||
		node.CapacitySustainSec <= 0 || node.CapacityRecoverySec <= node.CapacitySustainSec ||
		node.CapacityCooldownSec <= 0 || node.MinDiskFreeBytes <= 0 ||
		node.MaxOnlineUsers < 100 || node.MaxTaskQueueDepth <= 0 {
		t.Fatalf("unsafe default node policy: %+v", node)
	}
}

func TestDefaultAgentUsesFilesystemCapacityUnlessQuotaConfigured(t *testing.T) {
	t.Parallel()
	agent := DefaultAgent()
	if agent.DiskQuotaBytes != 0 || agent.BackupDir == "" || agent.HeartbeatSec <= 0 {
		t.Fatalf("agent defaults=%+v", agent)
	}
}

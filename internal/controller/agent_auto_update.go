package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"stcontrol/internal/protocol"
)

const minimumSelfUpdatingAgentVersion = "0.4.0"

func (s *Server) agentAutoUpdateReconciler(ctx context.Context) {
	if s == nil || s.Cfg == nil || s.Store == nil || !s.Cfg.AgentAutoUpdate.Enabled {
		return
	}
	interval := time.Duration(s.Cfg.AgentAutoUpdate.IntervalSec) * time.Second
	if interval < 30*time.Second {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.updateOneIdleAgent(ctx)
		}
	}
}

func (s *Server) updateOneIdleAgent(ctx context.Context) {
	if s.checkNewOperations() != nil {
		return
	}
	nodes, err := s.Store.ListNodes(ctx)
	if err != nil {
		return
	}
	for _, node := range nodes {
		if !nodeReadyForManagedOperation(node) || node.OnlineUsers != 0 || node.TaskQueueDepth != 0 ||
			!node.AgentVersion.Valid ||
			compareControllerAgentVersions(node.AgentVersion.String, minimumSelfUpdatingAgentVersion) < 0 ||
			compareControllerAgentVersions(node.AgentVersion.String, protocol.CurrentAgentVersion) >= 0 {
			continue
		}
		// A ten-minute attempt bucket retries transport/staging failures without
		// ever creating a command storm. A successful command remains idempotent
		// while the Agent performs its delayed restart.
		attemptBucket := time.Now().UTC().Unix() / 600
		operationID := deriveWorkflowOperationID(
			"agent-auto-update",
			fmt.Sprintf("node-%d-to-%s-attempt-%d", node.ID, protocol.CurrentAgentVersion, attemptBucket),
		)
		result, err := s.runAgentCommandWithOperation(
			ctx, node, "stage_agent_upgrade",
			protocol.AgentUpgradeRequest{TargetVersion: protocol.CurrentAgentVersion},
			operationID, 60*time.Second,
		)
		if err == nil && result.AgentUpgrade != nil && result.AgentUpgrade.Scheduled {
			_ = s.Store.Audit(ctx, "system", "agent-auto-update", node.Name, nil)
		}
		return
	}
}

func compareControllerAgentVersions(left, right string) int {
	l, ok := parseControllerAgentVersion(left)
	if !ok {
		return -1
	}
	r, ok := parseControllerAgentVersion(right)
	if !ok {
		return 1
	}
	for index := range l {
		if l[index] < r[index] {
			return -1
		}
		if l[index] > r[index] {
			return 1
		}
	}
	return 0
}

func parseControllerAgentVersion(value string) ([3]int, bool) {
	var parsed [3]int
	parts := strings.Split(value, ".")
	if len(parts) != len(parsed) || len(value) > 32 {
		return parsed, false
	}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return parsed, false
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || number > 9999 {
			return parsed, false
		}
		parsed[index] = number
	}
	return parsed, true
}

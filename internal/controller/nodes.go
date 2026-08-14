package controller

import (
	"context"
	"net/http"
	"sort"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// aiOrderingHint returns the active adopted node ordering of one hint kind,
// or nil when no live hint exists. Hints are decision-④ adoption effects:
// they only ever reorder nodes that already pass every deterministic gate
// (capacity/compatibility/admin weight) and expire with the advisory that
// produced them; a lookup error is treated as "no hint" so the AI layer can
// never degrade the deterministic path.
func (s *Server) aiOrderingHint(ctx context.Context, kind, target string) []int64 {
	effect, err := s.Store.GetLatestAIAdoptionEffect(ctx, kind, target, time.Now().UTC())
	if err != nil || effect == nil {
		return nil
	}
	hint, ok := store.AIOrderingHintFrom(effect)
	if !ok {
		return nil
	}
	return hint.Order
}

// nodeRegistrable admits new allocations only when every independent health
// dimension is safe. Busy nodes remain selectable but sort below open nodes;
// only durable full/unknown states close allocation.
func (s *Server) nodeRegistrable(n *store.Node) bool {
	if n.Role != "compute" || !nodeReadyForManagedOperation(n) ||
		(n.CapacityState != "open" && n.CapacityState != "busy") || !n.AllowRegister {
		return false
	}
	if (n.RegistrationPolicyState != "open" && n.RegistrationPolicyState != "invitation_required") ||
		n.RegistrationPolicyVersion <= 0 || !n.RegistrationPolicyExpiresAt.Valid ||
		!n.RegistrationPolicyExpiresAt.Time.After(time.Now().UTC()) {
		return false
	}
	return true
}

// nodeStatusLabel 计算节点状态标签（注册页显示用）。
func (s *Server) nodeStatusLabel(n *store.Node) string {
	switch {
	case n.ConnectivityState == "offline" || n.OperationalState == "failed" || n.OperationalState == "degraded":
		return "故障"
	case n.Role == "storage":
		return "备份"
	case !nodeReadyForManagedOperation(n):
		return "维护"
	case !n.AllowRegister:
		return "满载"
	case n.RegistrationPolicyState == "closed":
		return "满载"
	case (n.RegistrationPolicyState != "open" && n.RegistrationPolicyState != "invitation_required") ||
		!n.RegistrationPolicyExpiresAt.Valid || !n.RegistrationPolicyExpiresAt.Time.After(time.Now().UTC()):
		return "维护"
	case n.CapacityState == "full":
		return "满载"
	case n.CapacityState == "busy":
		return "繁忙"
	case n.CapacityState != "open":
		return "维护"
	default:
		return "开放"
	}
}

type availableNode struct {
	ID                   int64  `json:"id"`
	Name                 string `json:"name"`
	Region               string `json:"region"`
	BaseURL              string `json:"base_url"`
	StatusLabel          string `json:"status_label"`
	Registrable          bool   `json:"registrable"`
	Recommended          bool   `json:"recommended"`
	InvitationRequired   bool   `json:"invitation_required"`
	capacityState        string
	recommendationWeight int
	clientLatencyMS      int64
}

// handleAvailableNodes 注册页：列出产品状态，前端再测延迟。
func (s *Server) handleAvailableNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Store.ListNodes(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询节点失败")
		return
	}
	out := make([]availableNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, availableNode{
			ID:                   n.ID,
			Name:                 n.Name,
			Region:               n.Region.String,
			BaseURL:              n.BaseURL,
			StatusLabel:          s.nodeStatusLabel(n),
			Registrable:          s.nodeRegistrable(n),
			InvitationRequired:   n.RegistrationPolicyState == "invitation_required",
			capacityState:        n.CapacityState,
			recommendationWeight: n.RecommendationWeight,
			clientLatencyMS:      n.ClientLatencyMS.Int64,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return availableNodeRank(out[i]) < availableNodeRank(out[j])
	})
	// Decision-④ adopted ordering hint: reorders nodes ONLY within the same
	// deterministic rank tier (registrable + capacity + admin weight + latency
	// tier). Unhinted nodes keep their deterministic position ahead of hinted
	// reshuffles only when the hint does not mention them; the recommended flag
	// below still picks the first registrable node, so the AI can never promote
	// an ineligible node or override the admin weight tiers.
	if order := s.aiOrderingHint(r.Context(), "node_order_hint", "registration"); len(order) > 1 {
		position := make(map[int64]int, len(order))
		for idx, id := range order {
			position[id] = idx
		}
		unhinted := len(order)
		sort.SliceStable(out, func(i, j int) bool {
			ri, rj := availableNodeRank(out[i]), availableNodeRank(out[j])
			if ri != rj {
				return ri < rj
			}
			pi, ok := position[out[i].ID]
			if !ok {
				pi = unhinted
			}
			pj, ok := position[out[j].ID]
			if !ok {
				pj = unhinted
			}
			return pi < pj
		})
	}
	for index := range out {
		if out[index].Registrable {
			out[index].Recommended = true
			break
		}
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

// availableNodeRank orders registrable nodes by capacity, then lets the
// administrator's recommendation weight (Round 20) break ties: higher weight
// sorts earlier among equally eligible nodes.  Non-registrable nodes always
// sort last regardless of weight.
func availableNodeRank(node availableNode) int {
	if !node.Registrable {
		return 1_000_000
	}
	rank := 0
	if node.capacityState != "open" {
		rank = 10_000
	}
	// The administrator's weight (Round 20) dominates; persisted latency (R18)
	// is a secondary tiebreaker only within the same weight tier.
	return rank - node.recommendationWeight*10 + latencyTier(node.clientLatencyMS)
}

func latencyTier(ms int64) int {
	switch {
	case ms <= 0:
		return 0
	case ms < 100:
		return 1
	case ms < 300:
		return 2
	case ms < 800:
		return 3
	default:
		return 4
	}
}

func nodeReadyForManagedOperation(node *store.Node) bool {
	return node != nil && node.ConnectivityState == "online" &&
		node.OperationalState == "active" && node.CompatibilityState == "compatible" &&
		node.ControlMode == "managed" && node.DesiredControlMode == "managed"
}

func nodeAcceptsNewData(node *store.Node) bool {
	return nodeReadyForManagedOperation(node) &&
		(node.CapacityState == "open" || node.CapacityState == "busy")
}

type myNode struct {
	NodeID           int64      `json:"node_id"`
	Name             string     `json:"name"`
	Region           string     `json:"region"`
	BaseURL          string     `json:"base_url"`
	Kind             string     `json:"kind"`       // home|hot_standby
	KindLabel        string     `json:"kind_label"` // 我的服务器|备用服务器
	Ready            bool       `json:"ready"`
	RequiresTakeover bool       `json:"requires_takeover"`
	LastSyncedAt     *time.Time `json:"last_synced_at,omitempty"`
	Version          int64      `json:"data_version"`
}

// handleMyNodes 登录后：列出当前用户可用节点（家节点 + 就绪热备; 存储节点不显示）。
func (s *Server) handleMyNodes(w http.ResponseWriter, r *http.Request) {
	userID, _ := CurrentUser(r)
	user, err := s.Store.GetUserByID(r.Context(), userID)
	if err != nil || user == nil || user.GlobalID <= 0 {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在或不可用")
		return
	}
	replicas, err := s.Store.ListReplicasByUser(r.Context(), userID)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	out := make([]myNode, 0, len(replicas))
	for _, rep := range replicas {
		if rep.Kind == "archive" {
			continue // 存储节点不显示
		}
		node, err := s.Store.GetNodeByID(r.Context(), rep.NodeID)
		if err != nil || node == nil {
			continue
		}
		// 家节点也必须有 ready 副本；热备还必须绑定用户自己的不可变恢复点。
		ready := node.ConnectivityState == "online" && node.OperationalState == "active" &&
			node.CompatibilityState == "compatible" && rep.State == "ready"
		kindLabel := "备用服务器"
		if rep.Kind == "home" {
			kindLabel = "我的服务器"
		}
		var lastSyncedAt *time.Time
		if rep.LastSyncAt.Valid {
			value := rep.LastSyncAt.Time
			lastSyncedAt = &value
		}
		if rep.Kind == "hot_standby" {
			recoveryPoint, err := s.Store.GetImmutableHotStandbyRecoveryPoint(
				r.Context(), user.GlobalID, rep.NodeID,
			)
			if err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, "读取热备恢复点失败")
				return
			}
			ready = ready && recoveryPoint.Valid
			if recoveryPoint.Valid {
				value := recoveryPoint.Time
				lastSyncedAt = &value
			} else {
				lastSyncedAt = nil
			}
		}
		out = append(out, myNode{
			NodeID: node.ID, Name: node.Name, Region: node.Region.String,
			BaseURL: node.BaseURL, Kind: rep.Kind, KindLabel: kindLabel,
			Ready: ready, RequiresTakeover: rep.Kind == "hot_standby",
			LastSyncedAt: lastSyncedAt, Version: rep.DataVersion,
		})
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

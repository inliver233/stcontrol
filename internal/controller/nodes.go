package controller

import (
	"net/http"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// nodeRegistrable 判断节点是否可注册（在线 + 负载全低于阈值 + 允许注册 + 是计算节点）。
func (s *Server) nodeRegistrable(n *store.Node) bool {
	if n.Role != "compute" || n.Status != "online" || !n.AllowRegister {
		return false
	}
	if (n.RegistrationPolicyState != "open" && n.RegistrationPolicyState != "invitation_required") ||
		n.RegistrationPolicyVersion <= 0 || !n.RegistrationPolicyExpiresAt.Valid ||
		!n.RegistrationPolicyExpiresAt.Time.After(time.Now().UTC()) {
		return false
	}
	th := s.Cfg.Node
	if n.CPUPct.Valid && n.CPUPct.Float64 >= th.RegisterCPU {
		return false
	}
	if n.MemPct.Valid && n.MemPct.Float64 >= th.RegisterMem {
		return false
	}
	if n.DiskPct.Valid && n.DiskPct.Float64 >= th.RegisterDisk {
		return false
	}
	return true
}

// nodeStatusLabel 计算节点状态标签（注册页显示用）。
func (s *Server) nodeStatusLabel(n *store.Node) string {
	switch {
	case n.Role == "storage":
		return "备份用"
	case n.Status == "offline":
		return "宕机"
	case n.Status == "pending":
		return "待接入"
	case !n.AllowRegister:
		return "满员"
	case n.RegistrationPolicyState == "closed":
		return "满员"
	case (n.RegistrationPolicyState != "open" && n.RegistrationPolicyState != "invitation_required") ||
		!n.RegistrationPolicyExpiresAt.Valid || !n.RegistrationPolicyExpiresAt.Time.After(time.Now().UTC()):
		return "维护"
	case n.CPUPct.Valid && n.CPUPct.Float64 >= s.Cfg.Node.RegisterCPU:
		return "满员"
	case n.MemPct.Valid && n.MemPct.Float64 >= s.Cfg.Node.RegisterMem:
		return "满员"
	case n.DiskPct.Valid && n.DiskPct.Float64 >= s.Cfg.Node.RegisterDisk:
		return "满员"
	default:
		return "空闲"
	}
}

type availableNode struct {
	ID                 int64   `json:"id"`
	Name               string  `json:"name"`
	Region             string  `json:"region"`
	BaseURL            string  `json:"base_url"`
	Status             string  `json:"status"`       // online|offline|pending
	StatusLabel        string  `json:"status_label"` // 空闲|满员|备份用|宕机|待接入
	Registrable        bool    `json:"registrable"`
	CPUPct             float64 `json:"cpu_pct"`
	MemPct             float64 `json:"mem_pct"`
	DiskPct            float64 `json:"disk_pct"`
	InvitationRequired bool    `json:"invitation_required"`
}

// handleAvailableNodes 注册页：列出所有节点（含状态与负载, 前端再测延迟）。
func (s *Server) handleAvailableNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Store.ListNodes(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询节点失败")
		return
	}
	out := make([]availableNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, availableNode{
			ID:                 n.ID,
			Name:               n.Name,
			Region:             n.Region.String,
			BaseURL:            n.BaseURL,
			Status:             n.Status,
			StatusLabel:        s.nodeStatusLabel(n),
			Registrable:        s.nodeRegistrable(n),
			CPUPct:             n.CPUPct.Float64,
			MemPct:             n.MemPct.Float64,
			DiskPct:            n.DiskPct.Float64,
			InvitationRequired: n.RegistrationPolicyState == "invitation_required",
		})
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

type myNode struct {
	NodeID    int64  `json:"node_id"`
	Name      string `json:"name"`
	Region    string `json:"region"`
	BaseURL   string `json:"base_url"`
	Kind      string `json:"kind"`       // home|hot_standby
	KindLabel string `json:"kind_label"` // 我的服务器|备用服务器
	Ready     bool   `json:"ready"`
	Version   int64  `json:"data_version"`
}

// handleMyNodes 登录后：列出当前用户可用节点（家节点 + 就绪热备; 存储节点不显示）。
func (s *Server) handleMyNodes(w http.ResponseWriter, r *http.Request) {
	userID, _ := CurrentUser(r)
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
		// 可用条件: 节点在线 + (家节点即可 或 热备已同步完成)
		ready := node.Status == "online" && (rep.Kind == "home" || rep.State == "ready")
		kindLabel := "备用服务器"
		if rep.Kind == "home" {
			kindLabel = "我的服务器"
		}
		out = append(out, myNode{
			NodeID: node.ID, Name: node.Name, Region: node.Region.String,
			BaseURL: node.BaseURL, Kind: rep.Kind, KindLabel: kindLabel,
			Ready: ready, Version: rep.DataVersion,
		})
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

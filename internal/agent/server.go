package agent

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"stcontrol/internal/protocol"
)

// Handler exposes only local health and the capability-authenticated snapshot
// data plane. Controller operations are exclusively Agent-initiated commands.
func (a *Agent) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Get("/agent/health", a.handleHealth)
	router.Post("/transfer/v1/snapshots/{snapshotID}", a.handleSnapshotTransfer)
	return router
}

func (a *Agent) handleHealth(w http.ResponseWriter, _ *http.Request) {
	info, _ := ProbeTavern(a.Cfg.TavernDir)
	cpu, mem, disk, _ := CollectMetrics(a.Cfg.TavernDir)
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "agent_version": Version, "tavern_version": info.TavernVersion,
		"cpu_pct": cpu, "mem_pct": mem, "disk_pct": disk,
		"node_id": a.Cfg.NodeID, "role": a.Cfg.Role,
	})
}

func (a *Agent) handleSnapshotTransfer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	snapshotID := chi.URLParam(r, "snapshotID")
	authorization := r.Header.Get("Authorization")
	token, found := strings.CutPrefix(authorization, "Bearer ")
	if !found || token == "" || !validUUID(snapshotID) || r.Header.Get("X-Workflow-Id") == "" ||
		r.Header.Get("X-Archive-Sha256") == "" || r.Header.Get("Content-Type") != "application/zstd" {
		protocol.WriteError(w, http.StatusForbidden, "传输授权无效")
		return
	}
	if r.ContentLength <= 0 || r.ContentLength > maxSnapshotBytes {
		protocol.WriteError(w, http.StatusRequestEntityTooLarge, "快照归档大小无效")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBytes)
	receipt, err := a.ReceiveSnapshot(
		r.Context(), r.Header.Get("X-Workflow-Id"), snapshotID, token,
		r.Header.Get("X-Archive-Sha256"), r.Body,
	)
	if err != nil {
		protocol.WriteError(w, http.StatusUnprocessableEntity, "快照接收或验证失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, receipt)
}

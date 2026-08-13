package controller

import (
	"encoding/json"
	"net/http"
	"time"

	"stcontrol/internal/protocol"
)

// handleReportNodeLatency persists a browser-measured latency sample so node
// selection can use stable, aggregated values across page reloads (R18).  The
// sample is validated and EWMA-smoothed server-side; no per-user history is
// retained.
func (s *Server) handleReportNodeLatency(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID    int64 `json:"node_id"`
		LatencyMS int64 `json:"latency_ms"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.NodeID <= 0 ||
		req.LatencyMS < 0 || req.LatencyMS > 3_600_000 {
		protocol.WriteError(w, http.StatusBadRequest, "延迟样本无效")
		return
	}
	if err := s.Store.RecordNodeClientLatency(r.Context(), req.NodeID, req.LatencyMS, time.Now().UTC()); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "保存延迟样本失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

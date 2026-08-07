package controller

import (
	"bytes"
	"net/http"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type publicReplicaConflict struct {
	ID                   string                              `json:"id"`
	State                string                              `json:"state"`
	ProtectionVersion    int64                               `json:"protection_version"`
	Version              int64                               `json:"version"`
	DetectedAt           time.Time                           `json:"detected_at"`
	UpdatedAt            time.Time                           `json:"updated_at"`
	InspectionState      string                              `json:"inspection_state"`
	SourceCount          int                                 `json:"source_count"`
	ImmutableSourceCount int                                 `json:"immutable_source_count"`
	Sources              []store.PublicReplicaConflictSource `json:"sources"`
}

func (s *Server) handleMyReplicaConflict(w http.ResponseWriter, r *http.Request) {
	sess := currentSession(r)
	if sess == nil || sess.GlobalUserID <= 0 || sess.IsAdmin {
		protocol.WriteError(w, http.StatusUnauthorized, "需要冲突恢复认证")
		return
	}
	conflict, err := s.Store.GetOpenReplicaConflict(r.Context(), sess.GlobalUserID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取冲突事实失败")
		return
	}
	if conflict == nil {
		protocol.WriteError(w, http.StatusNotFound, "没有待处理的副本冲突")
		return
	}
	response := publicReplicaConflict{
		ID: conflict.ID, State: conflict.State,
		ProtectionVersion: conflict.ProtectionVersion, Version: conflict.Version,
		DetectedAt: conflict.DetectedAt, UpdatedAt: conflict.UpdatedAt,
		InspectionState: "capture_required", SourceCount: len(conflict.Sources),
		Sources: make([]store.PublicReplicaConflictSource, 0, len(conflict.Sources)),
	}
	var firstManifest []byte
	manifestScopesDiffer := false
	for _, source := range conflict.Sources {
		response.Sources = append(response.Sources, source.Public())
		if source.SnapshotID.Valid && len(source.ManifestSHA256) == 32 {
			response.ImmutableSourceCount++
			if firstManifest == nil {
				firstManifest = source.ManifestSHA256
			} else if !bytes.Equal(firstManifest, source.ManifestSHA256) {
				manifestScopesDiffer = true
			}
		}
	}
	if response.ImmutableSourceCount >= 2 {
		response.InspectionState = "manifest_inspection_ready"
		if manifestScopesDiffer {
			response.InspectionState = "distinct_manifests"
		}
	}
	protocol.WriteJSON(w, http.StatusOK, response)
}

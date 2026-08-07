package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type publicReplicaConflict struct {
	ID                 string                              `json:"id"`
	State              string                              `json:"state"`
	ProtectionVersion  int64                               `json:"protection_version"`
	Version            int64                               `json:"version"`
	DetectedAt         time.Time                           `json:"detected_at"`
	UpdatedAt          time.Time                           `json:"updated_at"`
	InspectionState    string                              `json:"inspection_state"`
	SourceCount        int                                 `json:"source_count"`
	ReadyEvidenceCount int                                 `json:"ready_evidence_count"`
	Sources            []store.PublicReplicaConflictSource `json:"sources"`
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
	evidenceDiffers := false
	for _, source := range conflict.Sources {
		response.Sources = append(response.Sources, source.Public())
		if source.EvidenceState == "ready" && len(source.EvidenceSHA256) == 32 {
			response.ReadyEvidenceCount++
			if firstManifest == nil {
				firstManifest = source.EvidenceSHA256
			} else if !bytes.Equal(firstManifest, source.EvidenceSHA256) {
				evidenceDiffers = true
			}
		}
	}
	if response.ReadyEvidenceCount == len(conflict.Sources) && len(conflict.Sources) >= 2 {
		response.InspectionState = "identical"
		if evidenceDiffers {
			response.InspectionState = "differences_ready"
		}
	}
	for _, source := range conflict.Sources {
		if source.EvidenceState == "failed" {
			response.InspectionState = "evidence_failed"
			break
		}
	}
	protocol.WriteJSON(w, http.StatusOK, response)
}

type conflictDifferenceSource struct {
	NodeID   int64  `json:"node_id"`
	NodeName string `json:"node_name"`
	Present  bool   `json:"present"`
	Size     int64  `json:"size,omitempty"`
}

type conflictFileDifference struct {
	Path       string                     `json:"path"`
	Category   string                     `json:"category"`
	Difference string                     `json:"difference"`
	Policy     string                     `json:"policy"`
	Sources    []conflictDifferenceSource `json:"sources"`
}

type conflictDifferenceResponse struct {
	ConflictID string                   `json:"conflict_id"`
	Offset     int                      `json:"offset"`
	Limit      int                      `json:"limit"`
	Total      int                      `json:"total"`
	OnlyOnSome int                      `json:"only_on_some_sources"`
	Different  int                      `json:"different_at_same_path"`
	Files      []conflictFileDifference `json:"files"`
}

func (s *Server) handleMyReplicaConflictDifferences(w http.ResponseWriter, r *http.Request) {
	sess := currentSession(r)
	if sess == nil || sess.GlobalUserID <= 0 || sess.IsAdmin {
		protocol.WriteError(w, http.StatusUnauthorized, "需要冲突恢复认证")
		return
	}
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 || limit > 100 {
		limit = 50
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
	if len(conflict.Sources) < 2 {
		protocol.WriteError(w, http.StatusConflict, "冲突来源不足，无法比较")
		return
	}
	entriesByNode := make(map[int64]map[string]protocol.ManifestEntry, len(conflict.Sources))
	for _, source := range conflict.Sources {
		if source.EvidenceState != "ready" {
			protocol.WriteError(w, http.StatusConflict, "冲突证据仍在安全捕获中")
			return
		}
		entries, err := s.loadConflictEvidenceEntries(r.Context(), conflict.ID, source)
		if err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "冲突证据暂不可读")
			return
		}
		byPath := make(map[string]protocol.ManifestEntry, len(entries))
		for _, entry := range entries {
			byPath[entry.Path] = entry
		}
		entriesByNode[source.NodeID] = byPath
	}
	response := buildConflictDifferences(conflict, entriesByNode)
	response.Offset = offset
	response.Limit = limit
	if offset >= len(response.Files) {
		response.Files = []conflictFileDifference{}
	} else {
		end := offset + limit
		if end > len(response.Files) {
			end = len(response.Files)
		}
		response.Files = response.Files[offset:end]
	}
	protocol.WriteJSON(w, http.StatusOK, response)
}

func (s *Server) loadConflictEvidenceEntries(
	ctx context.Context,
	conflictID string,
	source store.ReplicaConflictSource,
) ([]protocol.ManifestEntry, error) {
	pages, err := s.Store.LoadConflictEvidencePages(ctx, conflictID, source.NodeID)
	if err != nil || len(pages) == 0 || source.EvidenceID == "" || len(source.EvidenceSHA256) != 32 ||
		!source.EvidenceFileCount.Valid || !source.EvidenceTotalBytes.Valid {
		return nil, fmt.Errorf("conflict evidence pages unavailable")
	}
	key := s.deriveConflictEvidenceKey("at-rest", source.EvidenceID)
	entries := make([]protocol.ManifestEntry, 0, source.EvidenceFileCount.Int64)
	cursor := 0
	for pageIndex, ciphertext := range pages {
		plaintext, err := controlcrypto.Decrypt(key, ciphertext)
		if err != nil {
			return nil, err
		}
		page, err := decodeConflictEvidencePage(plaintext)
		if err != nil || page.EvidenceID != source.EvidenceID || page.Cursor != cursor ||
			page.NextCursor != cursor+len(page.Entries) ||
			(pageIndex < len(pages)-1 && page.Complete) ||
			(pageIndex == len(pages)-1 && !page.Complete) {
			return nil, fmt.Errorf("invalid persisted conflict evidence page")
		}
		entries = append(entries, page.Entries...)
		cursor = page.NextCursor
	}
	if int64(len(entries)) != source.EvidenceFileCount.Int64 ||
		validateConflictEvidenceEntries(entries, source.EvidenceTotalBytes.Int64) != nil {
		return nil, fmt.Errorf("invalid persisted conflict evidence manifest")
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if !hmac.Equal(digest[:], source.EvidenceSHA256) {
		return nil, fmt.Errorf("persisted conflict evidence digest mismatch")
	}
	var total int64
	for _, entry := range entries {
		total += entry.Size
	}
	if total != source.EvidenceTotalBytes.Int64 {
		return nil, fmt.Errorf("persisted conflict evidence size mismatch")
	}
	return entries, nil
}

func buildConflictDifferences(
	conflict *store.ReplicaConflict,
	entriesByNode map[int64]map[string]protocol.ManifestEntry,
) conflictDifferenceResponse {
	response := conflictDifferenceResponse{ConflictID: conflict.ID}
	allPaths := make(map[string]struct{})
	for _, entries := range entriesByNode {
		for path := range entries {
			allPaths[path] = struct{}{}
		}
	}
	paths := make([]string, 0, len(allPaths))
	for path := range allPaths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		versions := make(map[string]struct{})
		present := 0
		difference := conflictFileDifference{
			Path: path, Category: conflictPathCategory(path),
			Sources: make([]conflictDifferenceSource, 0, len(conflict.Sources)),
		}
		for _, source := range conflict.Sources {
			entry, ok := entriesByNode[source.NodeID][path]
			item := conflictDifferenceSource{NodeID: source.NodeID, NodeName: source.NodeName, Present: ok}
			if ok {
				present++
				item.Size = entry.Size
				versions[entry.SHA256+":"+strconv.FormatInt(entry.Size, 10)] = struct{}{}
			}
			difference.Sources = append(difference.Sources, item)
		}
		if present == len(conflict.Sources) && len(versions) == 1 {
			continue
		}
		if present < len(conflict.Sources) && len(versions) == 1 {
			difference.Difference = "only_on_some_sources"
			difference.Policy = "auto_merge_disjoint_path"
			response.OnlyOnSome++
		} else {
			difference.Difference = "different_at_same_path"
			difference.Policy = "choose_source_or_preserve_both"
			response.Different++
		}
		response.Files = append(response.Files, difference)
	}
	response.Total = len(response.Files)
	return response
}

func conflictPathCategory(value string) string {
	lower := strings.ToLower(value)
	extension := pathpkg.Ext(lower)
	if extension == ".jsonl" || strings.Contains(lower, "/chats/") || strings.HasPrefix(lower, "chats/") {
		return "chat_or_log"
	}
	if extension == ".json" {
		return "structured_json"
	}
	switch extension {
	case ".txt", ".md", ".yaml", ".yml", ".css", ".js", ".ts":
		return "text"
	default:
		return "binary_or_unknown"
	}
}

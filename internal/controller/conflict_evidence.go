package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	pathpkg "path"
	"strings"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	conflictEvidencePageBytes = 384 << 10
	conflictEvidenceMaxFiles  = 100_000
	conflictEvidenceMaxBytes  = int64(1 << 40)
)

func (s *Server) conflictEvidenceReconciler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		s.reconcileConflictEvidence(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) reconcileConflictEvidence(ctx context.Context) {
	if s.workflowWorkerID == "" {
		return
	}
	tasks, err := s.Store.ListConflictEvidenceTasks(ctx, 20, time.Now().UTC())
	if err != nil {
		return
	}
	for _, task := range tasks {
		task := task
		select {
		case s.snapshotSlots <- struct{}{}:
			go func() {
				defer func() { <-s.snapshotSlots }()
				runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 65*time.Minute)
				defer cancel()
				_ = s.executeConflictEvidenceTask(runCtx, task)
			}()
		default:
			return
		}
	}
}

func (s *Server) executeConflictEvidenceTask(ctx context.Context, task store.ConflictEvidenceTask) error {
	attempt, claimed, err := s.Store.ClaimConflictEvidenceTask(
		ctx, task.EvidenceID, s.workflowWorkerID, time.Now().UTC(), time.Hour,
	)
	if err != nil || !claimed {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = s.Store.RetryConflictEvidenceTask(
				context.WithoutCancel(ctx), task.EvidenceID, s.workflowWorkerID,
				"evidence_capture_unavailable", attempt, time.Now().UTC(),
			)
		}
	}()
	node, err := s.Store.GetNodeByID(ctx, task.NodeID)
	if err != nil || node == nil || node.Role != task.NodeRole ||
		(node.Role != "compute" && node.Role != "storage") {
		return fmt.Errorf("conflict evidence node unavailable")
	}
	request := protocol.CaptureConflictEvidenceRequest{
		ConflictID: task.ConflictID, EvidenceID: task.EvidenceID,
		GlobalUserID: task.GlobalUserID, Handle: task.Handle, SourceKind: task.SourceKind,
	}
	if task.SourceSnapshotID.Valid {
		request.SourceSnapshotID = task.SourceSnapshotID.String
	}
	if task.SourceKind == "archive" && len(task.SourceManifestSHA256) > 0 {
		request.SourceManifestSHA256 = hex.EncodeToString(task.SourceManifestSHA256)
	}
	captureResult, err := s.runAgentCommandWithOperation(
		ctx, node, "capture_conflict_evidence", request,
		deriveWorkflowOperationID(task.ConflictID, fmt.Sprintf("capture-evidence:%s:%d", task.EvidenceID, attempt)),
		55*time.Minute,
	)
	if err != nil || captureResult.ConflictEvidence == nil {
		return fmt.Errorf("capture conflict evidence: %w", err)
	}
	receipt := captureResult.ConflictEvidence
	entriesDigest, err := decodeSnapshotDigest(receipt.EntriesSHA256)
	if err != nil || receipt.EvidenceID != task.EvidenceID || receipt.FileCount < 0 ||
		receipt.FileCount > conflictEvidenceMaxFiles || receipt.TotalBytes < 0 ||
		receipt.TotalBytes > conflictEvidenceMaxBytes ||
		(receipt.CaptureBasis != "verified_archive" && receipt.CaptureBasis != "frozen_live") ||
		(task.SourceKind == "archive" && (receipt.CaptureBasis != "verified_archive" ||
			receipt.SourceSnapshotID != task.SourceSnapshotID.String)) {
		return fmt.Errorf("invalid conflict evidence receipt")
	}
	responseKey := s.deriveConflictEvidenceKey("response", task.EvidenceID)
	responseKeyEncoded := base64.StdEncoding.EncodeToString(responseKey)
	atRestKey := s.deriveConflictEvidenceKey("at-rest", task.EvidenceID)
	allEntries := make([]protocol.ManifestEntry, 0, receipt.FileCount)
	pages := make([]store.ConflictEvidencePageRecord, 0)
	pageOperationIDs := make([]string, 0)
	cursor := 0
	for {
		pageOperationID := deriveWorkflowOperationID(task.ConflictID, fmt.Sprintf(
			"read-evidence:%s:%d:%d", task.EvidenceID, attempt, cursor,
		))
		pageResult, err := s.runAgentCommandWithOperation(
			ctx, node, "read_conflict_evidence_page", protocol.ReadConflictEvidencePageRequest{
				ConflictID: task.ConflictID, EvidenceID: task.EvidenceID,
				Cursor: cursor, MaxBytes: conflictEvidencePageBytes, ResponseKey: responseKeyEncoded,
			}, pageOperationID, 45*time.Second,
		)
		if err != nil || pageResult.Ciphertext == "" {
			return fmt.Errorf("read conflict evidence page: %w", err)
		}
		plaintext, err := controlcrypto.Decrypt(responseKey, pageResult.Ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt conflict evidence page: %w", err)
		}
		page, err := decodeConflictEvidencePage(plaintext)
		if err != nil || page.EvidenceID != task.EvidenceID || page.Cursor != cursor ||
			page.NextCursor != cursor+len(page.Entries) || page.NextCursor > int(receipt.FileCount) ||
			(!page.Complete && len(page.Entries) == 0) ||
			(page.Complete && page.NextCursor != int(receipt.FileCount)) {
			return fmt.Errorf("invalid conflict evidence page")
		}
		allEntries = append(allEntries, page.Entries...)
		if err := validateConflictEvidenceEntries(allEntries, receipt.TotalBytes); err != nil {
			return err
		}
		plaintextDigest := sha256.Sum256(plaintext)
		encryptedPage, err := controlcrypto.Encrypt(atRestKey, plaintext)
		if err != nil {
			return err
		}
		pages = append(pages, store.ConflictEvidencePageRecord{
			PageIndex: len(pages), EntryCount: len(page.Entries),
			EncryptedPayload: encryptedPage, PlaintextSHA256: plaintextDigest[:],
		})
		pageOperationIDs = append(pageOperationIDs, pageOperationID)
		cursor = page.NextCursor
		if page.Complete {
			break
		}
	}
	entriesJSON, err := json.Marshal(allEntries)
	if err != nil {
		return err
	}
	gotEntriesDigest := sha256.Sum256(entriesJSON)
	if !hmac.Equal(entriesDigest, gotEntriesDigest[:]) || int64(len(allEntries)) != receipt.FileCount {
		return fmt.Errorf("conflict evidence manifest digest mismatch")
	}
	var totalBytes int64
	for _, entry := range allEntries {
		totalBytes += entry.Size
	}
	if totalBytes != receipt.TotalBytes {
		return fmt.Errorf("conflict evidence size mismatch")
	}
	if err := s.Store.CompleteConflictEvidence(ctx, store.CompleteConflictEvidenceParams{
		ConflictID: task.ConflictID, EvidenceID: task.EvidenceID,
		WorkerID: s.workflowWorkerID, EntriesSHA256: entriesDigest,
		FileCount: receipt.FileCount, TotalBytes: receipt.TotalBytes,
		CaptureBasis: receipt.CaptureBasis, Pages: pages, Now: time.Now().UTC(),
		CommandOperationIDs: pageOperationIDs,
	}); err != nil {
		return err
	}
	succeeded = true
	return nil
}

func (s *Server) deriveConflictEvidenceKey(purpose, evidenceID string) []byte {
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-conflict-evidence:" + purpose + ":v1:" + evidenceID))
	return mac.Sum(nil)
}

func decodeConflictEvidencePage(plaintext []byte) (protocol.ConflictEvidencePage, error) {
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var page protocol.ConflictEvidencePage
	if err := decoder.Decode(&page); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return protocol.ConflictEvidencePage{}, fmt.Errorf("invalid conflict evidence page")
	}
	return page, nil
}

func validateConflictEvidenceEntries(entries []protocol.ManifestEntry, expectedTotal int64) error {
	if len(entries) > conflictEvidenceMaxFiles {
		return fmt.Errorf("conflict evidence file limit exceeded")
	}
	var total int64
	previous := ""
	for _, entry := range entries {
		cleaned := pathpkg.Clean(entry.Path)
		if entry.Path == "" || len(entry.Path) > 4096 || cleaned != entry.Path ||
			strings.HasPrefix(entry.Path, "/") || strings.Contains(entry.Path, "\\") ||
			entry.Path == "." || entry.Path == ".." || strings.HasPrefix(entry.Path, "../") ||
			strings.HasPrefix(entry.Path, ".stcontrol/") || entry.Path == ".stcontrol-archive.json" ||
			entry.Path == ".stcontrol-conflict.json" || entry.Path <= previous ||
			entry.Size < 0 || total > conflictEvidenceMaxBytes-entry.Size {
			return fmt.Errorf("invalid conflict evidence manifest entry")
		}
		digest, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("invalid conflict evidence manifest digest")
		}
		previous = entry.Path
		total += entry.Size
	}
	if total > expectedTotal {
		return fmt.Errorf("conflict evidence manifest exceeds receipt")
	}
	return nil
}

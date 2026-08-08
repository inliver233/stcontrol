package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type scanExistingRequest struct {
	OperationID string `json:"operation_id"`
}

type claimImportedAccountRequest struct {
	OperationID string `json:"operation_id"`
	NodeID      int64  `json:"node_id"`
	Password    string `json:"password"`
}

func (s *Server) handleListMyAccountImportClaims(w http.ResponseWriter, r *http.Request) {
	legacyUserID, ok := CurrentUser(r)
	if !ok {
		protocol.WriteError(w, http.StatusUnauthorized, "未登录")
		return
	}
	user, err := s.Store.GetUserByID(r.Context(), legacyUserID)
	if err != nil || user == nil || user.GlobalID <= 0 {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取待认领节点账号失败")
		return
	}
	targets, err := s.Store.ListAccountImportClaimTargets(r.Context(), user.GlobalID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取待认领节点账号失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"claims": targets})
}

func (s *Server) handleClaimImportedAccount(w http.ResponseWriter, r *http.Request) {
	if !s.requireNewOperations(w) {
		return
	}
	var req claimImportedAccountRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || !isUUID(req.OperationID) || req.NodeID <= 0 ||
		len(req.Password) == 0 || len(req.Password) > 256 {
		protocol.WriteError(w, http.StatusBadRequest, "请输入该节点上的原密码")
		return
	}
	legacyUserID, ok := CurrentUser(r)
	if !ok {
		protocol.WriteError(w, http.StatusUnauthorized, "未登录")
		return
	}
	user, err := s.Store.GetUserByID(r.Context(), legacyUserID)
	if err != nil || user == nil || user.GlobalID <= 0 || user.Status != "active" {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不可用")
		return
	}
	targets, err := s.Store.ListAccountImportClaimTargets(r.Context(), user.GlobalID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "账号认领暂不可用")
		return
	}
	var target *store.AccountImportClaimTarget
	for index := range targets {
		if targets[index].NodeID == req.NodeID {
			target = &targets[index]
			break
		}
	}
	if target == nil || (target.AccountKind != "password" && target.AccountKind != "mixed") {
		protocol.WriteError(w, http.StatusConflict, "该节点账号不能用密码证明认领")
		return
	}
	node, err := s.Store.GetNodeByID(r.Context(), req.NodeID)
	if err != nil || node == nil || !nodeReadyForManagedOperation(node) {
		protocol.WriteError(w, http.StatusConflict, "节点当前不可验证账号")
		return
	}
	commandOperationID := deriveWorkflowOperationID(req.OperationID, "verify-local-account")
	result, err := s.runAgentCommandWithOperation(r.Context(), node, "verify_local_user", protocol.VerifyLocalUserRequest{
		OperationID: commandOperationID, Handle: target.LocalHandle, Password: req.Password,
	}, commandOperationID, 45*time.Second)
	if err != nil || result.LocalUserProof == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "节点账号验证暂不可用")
		return
	}
	proof := result.LocalUserProof
	if !proof.Verified || proof.Handle != target.LocalHandle || proof.LocalUserID == "" {
		protocol.WriteError(w, http.StatusForbidden, "节点账号密码错误")
		return
	}
	if err := s.Store.CompleteAccountImportClaim(r.Context(), store.CompleteAccountImportClaimParams{
		OperationID: req.OperationID, GlobalUserID: user.GlobalID, NodeID: req.NodeID,
		LocalHandle: target.LocalHandle, LocalUserID: proof.LocalUserID, Now: time.Now().UTC(),
	}); err != nil {
		if errors.Is(err, store.ErrAccountImportConflict) {
			protocol.WriteError(w, http.StatusConflict, "重复认领操作与原请求不一致")
			return
		}
		protocol.WriteError(w, http.StatusConflict, "节点账号已变化或已被认领")
		return
	}
	detail, _ := json.Marshal(map[string]any{"node_id": req.NodeID, "handle": target.LocalHandle})
	_ = s.Store.Audit(r.Context(), user.Username, "account-import-claim", node.Name, detail)
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAdminScanExisting(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	nodeID, err := parseID(chi.URLParam(r, "id"))
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "非法节点 ID")
		return
	}
	var req scanExistingRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !isUUID(req.OperationID) {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	node, err := s.Store.GetNodeByID(r.Context(), nodeID)
	if err != nil || node == nil || node.Role != "compute" {
		protocol.WriteError(w, http.StatusNotFound, "计算节点不存在")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusUnauthorized, "管理员会话无效")
		return
	}
	existing, err := s.Store.GetAccountImportBatchByOperation(
		r.Context(), req.OperationID, 0, store.MaxAccountImportPageSize,
	)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取重复导入操作失败")
		return
	}
	if existing != nil {
		if existing.Batch.NodeID != node.ID {
			protocol.WriteError(w, http.StatusConflict, "重复操作已绑定其他节点")
			return
		}
		existing.Batch.Replayed = true
		protocol.WriteJSON(w, http.StatusOK, existing)
		return
	}
	scanAttemptID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "创建扫描尝试失败")
		return
	}
	users, err := s.scanAccountInventory(r.Context(), node, scanAttemptID)
	if err != nil {
		protocol.WriteError(w, http.StatusBadGateway, "扫描结果尚未确认，请使用同一操作重试")
		return
	}
	batchID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "创建导入批次失败")
		return
	}
	params, err := s.buildAccountImportBatch(
		r.Context(), node, batchID, req.OperationID, sess.AdminID, users, time.Now().UTC(),
	)
	if err != nil {
		if errors.Is(err, store.ErrInvalidAccountImport) {
			protocol.WriteError(w, http.StatusConflict, "节点返回的账号库存无效")
			return
		}
		protocol.WriteError(w, http.StatusServiceUnavailable, "账号身份匹配暂不可用")
		return
	}
	imported, err := s.Store.IngestAccountImportBatch(r.Context(), params)
	if err != nil {
		if errors.Is(err, store.ErrAccountImportConflict) {
			protocol.WriteError(w, http.StatusConflict, "重复操作的扫描内容不一致")
			return
		}
		protocol.WriteError(w, http.StatusServiceUnavailable, "保存导入库存失败")
		return
	}
	if imported == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "导入库存暂不可用")
		return
	}
	detail, _ := json.Marshal(map[string]int{
		"candidates":  imported.Batch.CandidateCount,
		"auto_linked": imported.Batch.AutoLinkedCount,
		"unresolved":  imported.Batch.UnresolvedCount,
	})
	_ = s.Store.Audit(r.Context(), sess.Username, "account-import-scan", node.Name, detail)
	protocol.WriteJSON(w, http.StatusOK, imported)
}

func (s *Server) handleAdminLatestAccountImport(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	nodeID, err := parseID(chi.URLParam(r, "id"))
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "非法节点 ID")
		return
	}
	limit, rawOffset, err := parseAdminPage(r, "offset")
	if err != nil || rawOffset > protocol.MaxAccountInventoryUsers {
		protocol.WriteError(w, http.StatusBadRequest, "非法库存分页参数")
		return
	}
	result, err := s.Store.GetLatestAccountImportBatchPage(r.Context(), nodeID, int(rawOffset), limit)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取导入库存失败")
		return
	}
	if result == nil {
		protocol.WriteJSON(w, http.StatusOK, map[string]any{
			"batch": nil, "candidates": []any{}, "candidate_offset": int(rawOffset),
			"candidate_limit": limit, "has_more": false,
		})
		return
	}
	protocol.WriteJSON(w, http.StatusOK, result)
}

type accountInventoryScan struct {
	revision string
	total    int
	source   string
	users    []protocol.ScanExistingUser
}

func (s *Server) scanAccountInventory(
	ctx context.Context,
	node *store.Node,
	attemptID string,
) ([]protocol.ScanExistingUser, error) {
	if node == nil || !isUUID(attemptID) {
		return nil, store.ErrInvalidAccountImport
	}
	state := accountInventoryScan{}
	cursor := 0
	maxPages := (protocol.MaxAccountInventoryUsers + protocol.MaxAccountInventoryPageUsers - 1) /
		protocol.MaxAccountInventoryPageUsers
	for pageIndex := 0; pageIndex < maxPages; pageIndex++ {
		operationID := deriveWorkflowOperationID(
			attemptID, fmt.Sprintf("scan-existing-page-%04d", pageIndex),
		)
		result, err := s.runAgentCommandWithOperation(
			ctx, node, "scan_existing_page", protocol.ScanExistingPageRequest{
				Cursor: cursor, InventoryRevision: state.revision,
				Limit: protocol.MaxAccountInventoryPageUsers,
			}, operationID, 45*time.Second,
		)
		if err != nil || result.InventoryPage == nil {
			return nil, store.ErrInvalidAccountImport
		}
		complete, err := state.appendPage(cursor, *result.InventoryPage)
		if err != nil {
			return nil, err
		}
		if complete {
			return state.users, nil
		}
		cursor = result.InventoryPage.NextCursor
	}
	return nil, store.ErrInvalidAccountImport
}

func (scan *accountInventoryScan) appendPage(
	requestedCursor int,
	page protocol.ScanExistingPageResult,
) (bool, error) {
	if requestedCursor < 0 || page.Cursor != requestedCursor ||
		page.TotalUsers < 0 || page.TotalUsers > protocol.MaxAccountInventoryUsers ||
		!validScannedFingerprint(page.InventoryRevision) ||
		len(page.Users) > protocol.MaxAccountInventoryPageUsers ||
		page.Cursor+len(page.Users) > page.TotalUsers {
		return false, store.ErrInvalidAccountImport
	}
	if scan.revision == "" {
		scan.revision = page.InventoryRevision
		scan.total = page.TotalUsers
		scan.users = make([]protocol.ScanExistingUser, 0, page.TotalUsers)
	} else if scan.revision != page.InventoryRevision || scan.total != page.TotalUsers {
		return false, store.ErrInvalidAccountImport
	}
	for _, user := range page.Users {
		if !validScannedInventoryUser(user) ||
			(len(scan.users) > 0 && scan.users[len(scan.users)-1].LocalUserID >= user.LocalUserID) {
			return false, store.ErrInvalidAccountImport
		}
		if scan.source == "" {
			scan.source = user.Source
		} else if scan.source != user.Source {
			return false, store.ErrInvalidAccountImport
		}
		scan.users = append(scan.users, user)
	}
	end := page.Cursor + len(page.Users)
	if page.HasMore {
		if len(page.Users) != protocol.MaxAccountInventoryPageUsers ||
			page.NextCursor != end || end >= page.TotalUsers {
			return false, store.ErrInvalidAccountImport
		}
		return false, nil
	}
	if page.NextCursor != 0 || end != page.TotalUsers || len(scan.users) != scan.total {
		return false, store.ErrInvalidAccountImport
	}
	return true, nil
}

func (s *Server) buildAccountImportBatch(
	ctx context.Context,
	node *store.Node,
	batchID, operationID string,
	adminID int64,
	users []protocol.ScanExistingUser,
	now time.Time,
) (store.CreateAccountImportBatchParams, error) {
	if node == nil || !isUUID(batchID) || !isUUID(operationID) || adminID <= 0 ||
		len(users) > protocol.MaxAccountInventoryUsers {
		return store.CreateAccountImportBatchParams{}, store.ErrInvalidAccountImport
	}
	psk, err := s.agentPSK(ctx, node)
	if err != nil {
		return store.CreateAccountImportBatchParams{}, err
	}
	if psk == "" {
		return store.CreateAccountImportBatchParams{}, store.ErrInvalidAccountImport
	}
	identitySubjects, err := s.Store.ListActiveOAuthIdentitySubjects(ctx)
	if err != nil {
		return store.CreateAccountImportBatchParams{}, err
	}
	identityMatches := make(map[string][]int64, len(identitySubjects))
	for _, identity := range identitySubjects {
		fingerprint := controlcrypto.AgentInventoryFingerprint(
			psk, "oauth-subject", identity.Provider, identity.Subject,
		)
		key := identity.Provider + "\n" + fingerprint
		identityMatches[key] = append(identityMatches[key], identity.GlobalUserID)
	}

	normalized := append([]protocol.ScanExistingUser(nil), users...)
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].LocalUserID < normalized[j].LocalUserID })
	seen := make(map[string]struct{}, len(normalized))
	candidates := make([]store.AccountImportCandidateInput, 0, len(normalized))
	sources := make(map[string]struct{}, 2)
	for index := range normalized {
		user := &normalized[index]
		sort.Slice(user.Identities, func(i, j int) bool { return user.Identities[i].Provider < user.Identities[j].Provider })
		if !validScannedInventoryUser(*user) {
			return store.CreateAccountImportBatchParams{}, store.ErrInvalidAccountImport
		}
		if _, exists := seen[user.LocalUserID]; exists {
			return store.CreateAccountImportBatchParams{}, store.ErrInvalidAccountImport
		}
		seen[user.LocalUserID] = struct{}{}
		sources[user.Source] = struct{}{}
		candidateID, err := newUUID()
		if err != nil {
			return store.CreateAccountImportBatchParams{}, err
		}
		candidate := store.AccountImportCandidateInput{
			ID: candidateID, LocalUserID: user.LocalUserID, LocalHandle: user.Handle,
			SizeBytes: user.Size, DirectoryFingerprint: user.DirectoryFingerprint,
			Source: user.Source, AccountKind: user.AccountKind, IsAdmin: user.IsAdmin,
		}
		matched := make(map[int64]struct{})
		for _, identity := range user.Identities {
			candidate.Identities = append(candidate.Identities, store.AccountImportIdentityFingerprint{
				Provider: identity.Provider, Fingerprint: identity.Fingerprint,
			})
			for _, globalUserID := range identityMatches[identity.Provider+"\n"+identity.Fingerprint] {
				matched[globalUserID] = struct{}{}
			}
		}
		for globalUserID := range matched {
			candidate.MatchedGlobalUserIDs = append(candidate.MatchedGlobalUserIDs, globalUserID)
		}
		sort.Slice(candidate.MatchedGlobalUserIDs, func(i, j int) bool {
			return candidate.MatchedGlobalUserIDs[i] < candidate.MatchedGlobalUserIDs[j]
		})
		candidates = append(candidates, candidate)
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return store.CreateAccountImportBatchParams{}, err
	}
	digest := sha256.Sum256(encoded)
	source := "mixed"
	if len(sources) == 1 {
		for value := range sources {
			source = value
		}
	}
	if len(normalized) == 0 {
		source = "adapter"
	}
	return store.CreateAccountImportBatchParams{
		ID: batchID, OperationID: operationID, NodeID: node.ID,
		InventoryDigest: digest[:], Source: source, CreatedByAdminID: adminID,
		Candidates: candidates, Now: now,
	}, nil
}

func validScannedInventoryUser(user protocol.ScanExistingUser) bool {
	if !safeScannedInventoryString(user.LocalUserID, 256) ||
		!safeScannedInventoryString(user.Handle, 128) || user.Size < 0 ||
		(user.Source != "adapter" && user.Source != "directory_fallback") ||
		(user.AccountKind != "password" && user.AccountKind != "oauth" &&
			user.AccountKind != "mixed" && user.AccountKind != "unknown") ||
		!validScannedFingerprint(user.DirectoryFingerprint) || len(user.Identities) > 2 {
		return false
	}
	providers := make(map[string]struct{}, len(user.Identities))
	for _, identity := range user.Identities {
		if (identity.Provider != "discord" && identity.Provider != "linuxdo") ||
			!validScannedFingerprint(identity.Fingerprint) {
			return false
		}
		if _, exists := providers[identity.Provider]; exists {
			return false
		}
		providers[identity.Provider] = struct{}{}
	}
	hasOAuth := len(user.Identities) > 0
	if user.Source == "directory_fallback" &&
		(user.AccountKind != "unknown" || hasOAuth || user.IsAdmin) {
		return false
	}
	return (user.AccountKind == "oauth" || user.AccountKind == "mixed") == hasOAuth
}

func safeScannedInventoryString(value string, limit int) bool {
	if value == "" || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func validScannedFingerprint(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

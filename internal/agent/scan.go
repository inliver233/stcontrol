package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

// 酒馆 data 目录下需要排除的非用户目录。
var excludedDirs = map[string]bool{
	"_storage": true, "_uploads": true, "_cache": true, "_exports": true,
	"_webpack": true, "_global": true, "_stcontrol": true,
	"default-user": true, "default-template": true,
	"announcements": true, "forum_data": true, "public_characters": true,
	"system-monitor": true, "backups": true,
}

// isManagedUserDirectory mirrors SillyTavern's canonical handle namespace.
// The explicit list documents known node-global directories, while the handle
// check fails closed for new underscore/space-delimited global directories so
// they cannot silently become user inventory or capacity facts.
func isManagedUserDirectory(name string) bool {
	return validHandle(name) && !excludedDirs[name]
}

var errInvalidAdapterInventory = errors.New("invalid adapter inventory")

type adapterInventoryIdentity struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

type adapterInventoryUser struct {
	LocalUserID          string                     `json:"local_user_id"`
	Handle               string                     `json:"handle"`
	SizeBytes            int64                      `json:"size_bytes"`
	DirectoryFingerprint string                     `json:"directory_fingerprint"`
	HasPassword          bool                       `json:"has_password"`
	OAuthIdentities      []adapterInventoryIdentity `json:"oauth_identities"`
	IsAdmin              bool                       `json:"is_admin"`
}

type adapterInventoryResponse struct {
	OK                bool                   `json:"ok"`
	Users             []adapterInventoryUser `json:"users"`
	Cursor            int                    `json:"cursor"`
	NextCursor        int                    `json:"next_cursor"`
	TotalUsers        int                    `json:"total_users"`
	InventoryRevision string                 `json:"inventory_revision"`
	HasMore           bool                   `json:"has_more"`
}

// ScanExistingUsers prefers the authenticated adapter's exact account facts.
// The directory fallback is intentionally identity-blind and can never cause
// automatic linking at the Controller. This compatibility helper is bounded
// to one page; Controller workflows use ScanExistingUsersPage exclusively.
func (a *Agent) ScanExistingUsers(ctx context.Context) ([]protocol.ScanExistingUser, error) {
	page, err := a.ScanExistingUsersPage(ctx, protocol.ScanExistingPageRequest{
		Limit: protocol.MaxAccountInventoryPageUsers,
	})
	if err != nil {
		return nil, err
	}
	if page.HasMore {
		return nil, fmt.Errorf("inventory requires paged command")
	}
	return page.Users, nil
}

// ScanExistingUsersPage returns a stable, bounded account inventory page. An
// invalid authenticated adapter response fails closed; transport failures may
// use the identity-blind directory fallback.
func (a *Agent) ScanExistingUsersPage(
	ctx context.Context,
	req protocol.ScanExistingPageRequest,
) (protocol.ScanExistingPageResult, error) {
	if !validInventoryPageRequest(req) {
		return protocol.ScanExistingPageResult{}, errInvalidAdapterInventory
	}
	page, err := a.scanExistingUsersFromAdapterPage(ctx, req)
	if err == nil {
		return page, nil
	}
	if errors.Is(err, errInvalidAdapterInventory) {
		return protocol.ScanExistingPageResult{}, err
	}
	return a.scanExistingUsersFromDiskPage(req)
}

func (a *Agent) scanExistingUsersFromAdapterPage(
	ctx context.Context,
	req protocol.ScanExistingPageRequest,
) (protocol.ScanExistingPageResult, error) {
	var response adapterInventoryResponse
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/users/scan", req, &response); err != nil {
		return protocol.ScanExistingPageResult{}, err
	}
	if !validAdapterInventoryPage(req, response) {
		return protocol.ScanExistingPageResult{}, fmt.Errorf("%w: response", errInvalidAdapterInventory)
	}
	seen := make(map[string]struct{}, len(response.Users))
	out := make([]protocol.ScanExistingUser, 0, len(response.Users))
	for _, user := range response.Users {
		if !safeInventoryString(user.LocalUserID, 256) || !safeInventoryString(user.Handle, 128) ||
			user.SizeBytes < 0 || !validInventoryDigest(user.DirectoryFingerprint) {
			return protocol.ScanExistingPageResult{}, fmt.Errorf("%w: user", errInvalidAdapterInventory)
		}
		if _, exists := seen[user.LocalUserID]; exists {
			return protocol.ScanExistingPageResult{}, fmt.Errorf("%w: duplicate user", errInvalidAdapterInventory)
		}
		if len(out) > 0 && out[len(out)-1].LocalUserID >= user.LocalUserID {
			return protocol.ScanExistingPageResult{}, fmt.Errorf("%w: unstable user order", errInvalidAdapterInventory)
		}
		seen[user.LocalUserID] = struct{}{}
		identities := make([]protocol.ScanExistingIdentity, 0, len(user.OAuthIdentities))
		providers := make(map[string]struct{}, len(user.OAuthIdentities))
		for _, identity := range user.OAuthIdentities {
			if (identity.Provider != "discord" && identity.Provider != "linuxdo") ||
				!safeInventoryString(identity.Subject, 512) {
				return protocol.ScanExistingPageResult{}, fmt.Errorf("%w: identity", errInvalidAdapterInventory)
			}
			if _, exists := providers[identity.Provider]; exists {
				return protocol.ScanExistingPageResult{}, fmt.Errorf("%w: duplicate identity", errInvalidAdapterInventory)
			}
			providers[identity.Provider] = struct{}{}
			identities = append(identities, protocol.ScanExistingIdentity{
				Provider: identity.Provider,
				Fingerprint: controlcrypto.AgentInventoryFingerprint(
					a.adapterPSK(), "oauth-subject", identity.Provider, identity.Subject,
				),
			})
		}
		out = append(out, protocol.ScanExistingUser{
			LocalUserID: user.LocalUserID, Handle: user.Handle, Size: user.SizeBytes,
			DirectoryFingerprint: controlcrypto.AgentInventoryFingerprint(
				a.adapterPSK(), "directory", user.DirectoryFingerprint,
			),
			Source: "adapter", AccountKind: inventoryAccountKind(user.HasPassword, len(identities) > 0),
			Identities: identities, IsAdmin: user.IsAdmin,
		})
	}
	return protocol.ScanExistingPageResult{
		Users: out, Cursor: response.Cursor, NextCursor: response.NextCursor,
		TotalUsers: response.TotalUsers, InventoryRevision: response.InventoryRevision,
		HasMore: response.HasMore,
	}, nil
}

func (a *Agent) scanExistingUsersFromDiskPage(
	req protocol.ScanExistingPageRequest,
) (protocol.ScanExistingPageResult, error) {
	dataRoot := a.dataRoot()
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return protocol.ScanExistingPageResult{}, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !isManagedUserDirectory(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > protocol.MaxAccountInventoryUsers || req.Cursor > len(names) {
		return protocol.ScanExistingPageResult{}, fmt.Errorf("inventory exceeds supported bound")
	}
	revision := controlcrypto.AgentInventoryFingerprint(
		a.adapterPSK(), "directory-list", strings.Join(names, "\x00"),
	)
	if req.InventoryRevision != "" && !hmac.Equal([]byte(req.InventoryRevision), []byte(revision)) {
		return protocol.ScanExistingPageResult{}, fmt.Errorf("inventory revision changed")
	}
	end := req.Cursor + req.Limit
	if end > len(names) {
		end = len(names)
	}
	out := make([]protocol.ScanExistingUser, 0, end-req.Cursor)
	for _, name := range names[req.Cursor:end] {
		size, fingerprint, err := directoryInventory(filepath.Join(dataRoot, name), a.Cfg.AgentPSK)
		if err != nil {
			return protocol.ScanExistingPageResult{}, err
		}
		out = append(out, protocol.ScanExistingUser{
			LocalUserID: name, Handle: name, Size: size, DirectoryFingerprint: fingerprint,
			Source: "directory_fallback", AccountKind: "unknown",
		})
	}
	hasMore := end < len(names)
	nextCursor := 0
	if hasMore {
		nextCursor = end
	}
	return protocol.ScanExistingPageResult{
		Users: out, Cursor: req.Cursor, NextCursor: nextCursor, TotalUsers: len(names),
		InventoryRevision: revision, HasMore: hasMore,
	}, nil
}

func validInventoryPageRequest(req protocol.ScanExistingPageRequest) bool {
	return req.Cursor >= 0 && req.Cursor <= protocol.MaxAccountInventoryUsers &&
		req.Limit > 0 && req.Limit <= protocol.MaxAccountInventoryPageUsers &&
		(req.InventoryRevision == "" && req.Cursor == 0 || validInventoryDigest(req.InventoryRevision))
}

func validAdapterInventoryPage(req protocol.ScanExistingPageRequest, response adapterInventoryResponse) bool {
	if !response.OK || response.Cursor != req.Cursor || response.TotalUsers < 0 ||
		response.TotalUsers > protocol.MaxAccountInventoryUsers || response.Cursor > response.TotalUsers ||
		len(response.Users) > req.Limit || !validInventoryDigest(response.InventoryRevision) {
		return false
	}
	if req.InventoryRevision != "" &&
		!hmac.Equal([]byte(req.InventoryRevision), []byte(response.InventoryRevision)) {
		return false
	}
	end := response.Cursor + len(response.Users)
	if end > response.TotalUsers {
		return false
	}
	if response.HasMore {
		return len(response.Users) == req.Limit && response.NextCursor == end && end < response.TotalUsers
	}
	return response.NextCursor == 0 && end == response.TotalUsers
}

func inventoryAccountKind(hasPassword, hasOAuth bool) string {
	switch {
	case hasPassword && hasOAuth:
		return "mixed"
	case hasPassword:
		return "password"
	case hasOAuth:
		return "oauth"
	default:
		return "unknown"
	}
}

func safeInventoryString(value string, limit int) bool {
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

func validInventoryDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

// scanUserActivityFromDisk 用目录修改时间近似用户 lastActivity。
func (a *Agent) scanUserActivityFromDisk() []protocol.UserStatus {
	users, _, _ := a.scanUserActivityAndSize()
	return users
}

func (a *Agent) scanUserActivityAndSize() ([]protocol.UserStatus, int64, error) {
	dataRoot := a.dataRoot()
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return nil, 0, err
	}
	now := time.Now()
	var out []protocol.UserStatus
	var allocatedBytes int64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !isManagedUserDirectory(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		mtime, size, err := latestMtimeAndSize(filepath.Join(dataRoot, name), info.ModTime())
		if err != nil {
			return nil, 0, err
		}
		allocatedBytes += size
		// 近似: 最近 2.5 分钟内有修改视为可能在线(心跳2min)
		isOnline := now.Sub(mtime) < 150*time.Second
		out = append(out, protocol.UserStatus{
			Handle:       name,
			IsOnline:     isOnline,
			LastActivity: mtime.UnixMilli(),
		})
	}
	return out, allocatedBytes, nil
}

// dataRoot 返回酒馆数据目录。
func (a *Agent) dataRoot() string {
	info, err := ProbeTavern(a.Cfg.TavernDir)
	if err == nil && info.DataRoot != "" {
		return info.DataRoot
	}
	return filepath.Join(a.Cfg.TavernDir, "data")
}

func directoryInventory(root, psk string) (int64, string, error) {
	mac := hmac.New(sha256.New, controlcrypto.DeriveAgentInventoryKey(psk))
	_, _ = mac.Write([]byte("stcontrol-directory-inventory:v1\n"))
	var size int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(len(relative)))
		_, _ = mac.Write(encoded[:])
		_, _ = mac.Write([]byte(relative))
		binary.BigEndian.PutUint64(encoded[:], uint64(info.Size()))
		_, _ = mac.Write(encoded[:])
		binary.BigEndian.PutUint64(encoded[:], uint64(info.ModTime().UnixNano()))
		_, _ = mac.Write(encoded[:])
		size += info.Size()
		return nil
	})
	if err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(mac.Sum(nil)), nil
}

// latestMtime 找目录树中最新的文件修改时间。
func latestMtime(root string, seed time.Time) time.Time {
	latest, _, _ := latestMtimeAndSize(root, seed)
	return latest
}

func latestMtimeAndSize(root string, seed time.Time) (time.Time, int64, error) {
	latest := seed
	var size int64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Mode().IsRegular() {
			size += info.Size()
		}
		if !info.IsDir() && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	return latest, size, err
}

func directorySize(root string) (int64, error) {
	if root == "" {
		return 0, fmt.Errorf("managed data root is required")
	}
	var size int64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !info.IsDir() && info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

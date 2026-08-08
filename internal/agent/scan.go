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
	"_webpack": true, "_global": true, "default-user": true,
	"announcements": true, "forum_data": true, "public_characters": true,
	"system-monitor": true, "backups": true,
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
	OK    bool                   `json:"ok"`
	Users []adapterInventoryUser `json:"users"`
}

// ScanExistingUsers prefers the authenticated adapter's exact account facts.
// The directory fallback is intentionally identity-blind and can never cause
// automatic linking at the Controller.
func (a *Agent) ScanExistingUsers(ctx context.Context) ([]protocol.ScanExistingUser, error) {
	users, err := a.scanExistingUsersFromAdapter(ctx)
	if err == nil {
		return users, nil
	}
	if errors.Is(err, errInvalidAdapterInventory) {
		return nil, err
	}
	return a.scanExistingUsersFromDisk()
}

func (a *Agent) scanExistingUsersFromAdapter(ctx context.Context) ([]protocol.ScanExistingUser, error) {
	var response adapterInventoryResponse
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/users/scan", struct{}{}, &response); err != nil {
		return nil, err
	}
	if !response.OK || len(response.Users) > protocol.MaxAccountInventoryUsers {
		return nil, fmt.Errorf("%w: response", errInvalidAdapterInventory)
	}
	seen := make(map[string]struct{}, len(response.Users))
	out := make([]protocol.ScanExistingUser, 0, len(response.Users))
	for _, user := range response.Users {
		if !safeInventoryString(user.LocalUserID, 256) || !safeInventoryString(user.Handle, 128) ||
			user.SizeBytes < 0 || !validInventoryDigest(user.DirectoryFingerprint) {
			return nil, fmt.Errorf("%w: user", errInvalidAdapterInventory)
		}
		if _, exists := seen[user.LocalUserID]; exists {
			return nil, fmt.Errorf("%w: duplicate user", errInvalidAdapterInventory)
		}
		seen[user.LocalUserID] = struct{}{}
		identities := make([]protocol.ScanExistingIdentity, 0, len(user.OAuthIdentities))
		providers := make(map[string]struct{}, len(user.OAuthIdentities))
		for _, identity := range user.OAuthIdentities {
			if (identity.Provider != "discord" && identity.Provider != "linuxdo") ||
				!safeInventoryString(identity.Subject, 512) {
				return nil, fmt.Errorf("%w: identity", errInvalidAdapterInventory)
			}
			if _, exists := providers[identity.Provider]; exists {
				return nil, fmt.Errorf("%w: duplicate identity", errInvalidAdapterInventory)
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
	sort.Slice(out, func(i, j int) bool { return out[i].LocalUserID < out[j].LocalUserID })
	return out, nil
}

func (a *Agent) scanExistingUsersFromDisk() ([]protocol.ScanExistingUser, error) {
	dataRoot := a.dataRoot()
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return nil, err
	}
	var out []protocol.ScanExistingUser
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if excludedDirs[name] || strings.HasPrefix(name, ".") {
			continue
		}
		if len(out) >= protocol.MaxAccountInventoryUsers {
			return nil, fmt.Errorf("inventory requires pagination")
		}
		size, fingerprint, err := directoryInventory(filepath.Join(dataRoot, name), a.Cfg.AgentPSK)
		if err != nil {
			return nil, err
		}
		out = append(out, protocol.ScanExistingUser{
			LocalUserID: name, Handle: name, Size: size, DirectoryFingerprint: fingerprint,
			Source: "directory_fallback", AccountKind: "unknown",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handle < out[j].Handle })
	return out, nil
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
		if excludedDirs[name] || strings.HasPrefix(name, ".") {
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

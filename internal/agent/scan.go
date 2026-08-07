package agent

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"stcontrol/internal/protocol"
)

// 酒馆 data 目录下需要排除的非用户目录。
var excludedDirs = map[string]bool{
	"_storage": true, "_uploads": true, "_cache": true, "_exports": true,
	"_webpack": true, "_global": true, "default-user": true,
	"announcements": true, "forum_data": true, "public_characters": true,
	"system-monitor": true, "backups": true,
}

// ScanExistingUsers 扫描 data/ 下既有用户目录（接管老节点用）。
func (a *Agent) ScanExistingUsers() ([]protocol.ScanExistingUser, error) {
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
		// 计算目录大小
		size := dirSize(filepath.Join(dataRoot, name))
		out = append(out, protocol.ScanExistingUser{Handle: name, Size: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handle < out[j].Handle })
	return out, nil
}

// scanUserActivityFromDisk 用目录修改时间近似用户 lastActivity。
func (a *Agent) scanUserActivityFromDisk() []protocol.UserStatus {
	dataRoot := a.dataRoot()
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return nil
	}
	now := time.Now()
	var out []protocol.UserStatus
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if excludedDirs[name] {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		mtime := latestMtime(filepath.Join(dataRoot, name), info.ModTime())
		// 近似: 最近 2.5 分钟内有修改视为可能在线(心跳2min)
		isOnline := now.Sub(mtime) < 150*time.Second
		out = append(out, protocol.UserStatus{
			Handle:       name,
			IsOnline:     isOnline,
			LastActivity: mtime.UnixMilli(),
		})
	}
	return out
}

// dataRoot 返回酒馆数据目录。
func (a *Agent) dataRoot() string {
	info, err := ProbeTavern(a.Cfg.TavernDir)
	if err == nil && info.DataRoot != "" {
		return info.DataRoot
	}
	return filepath.Join(a.Cfg.TavernDir, "data")
}

// dirSize 递归计算目录大小。
func dirSize(root string) int64 {
	var size int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

// latestMtime 找目录树中最新的文件修改时间。
func latestMtime(root string, seed time.Time) time.Time {
	latest := seed
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	return latest
}

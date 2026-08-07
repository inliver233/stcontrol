package agent

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"stcontrol/internal/protocol"
)

// StartBackup 作为源节点启动一次备份：打包 data/<handle> → tar.zst 流推给目标子控 → 上报结果。
func (a *Agent) StartBackup(parentCtx context.Context, req *protocol.BackupStartRequest) error {
	a.mu.Lock()
	if _, exists := a.backupJobs[req.JobID]; exists {
		a.mu.Unlock()
		return fmt.Errorf("备份任务 %d 已在进行", req.JobID)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.backupJobs[req.JobID] = cancel
	a.mu.Unlock()

	// 异步执行, 不阻塞总控调用
	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.backupJobs, req.JobID)
			a.mu.Unlock()
		}()
		res := a.runBackup(ctx, req)
		a.reportBackupResult(parentCtx, req.JobID, res)
	}()
	return nil
}

// backupResult 备份执行结果。
type backupResult struct {
	status    string
	bytes     int64
	fileCount int
	checksum  string
	err       string
}

// runBackup 执行打包与传输。
func (a *Agent) runBackup(ctx context.Context, req *protocol.BackupStartRequest) backupResult {
	srcDir := filepath.Join(a.dataRoot(), req.Handle)
	if _, err := os.Stat(srcDir); err != nil {
		return backupResult{status: "failed", err: "用户数据目录不存在"}
	}

	// 1. 生成文件清单 + 打包 tar.zst 到临时文件(保证原子性与可重传)
	tmpFile, manifest, fileCount, totalBytes, err := a.packUserDir(ctx, srcDir, req.Handle)
	if err != nil {
		return backupResult{status: "failed", err: "打包失败: " + err.Error()}
	}
	defer os.Remove(tmpFile)

	// 2. 计算清单 SHA256 作为整体校验
	manifestJSON, _ := json.Marshal(manifest)
	manifestSum := sha256.Sum256(manifestJSON)
	checksum := hex.EncodeToString(manifestSum[:])

	// 3. 流式推送给目标子控
	if err := a.streamToTarget(ctx, req, tmpFile, manifestJSON); err != nil {
		if ctx.Err() != nil {
			return backupResult{status: "aborted", err: "备份被中止"}
		}
		return backupResult{status: "failed", err: "传输失败: " + err.Error()}
	}

	return backupResult{
		status: "done", bytes: totalBytes, fileCount: fileCount, checksum: checksum,
	}
}

// packUserDir 把用户目录打包为 tar.zst 临时文件, 返回 (文件路径, 清单, 文件数, 总字节)。
func (a *Agent) packUserDir(ctx context.Context, srcDir, handle string) (string, []protocol.ManifestEntry, int, int64, error) {
	tmp, err := os.CreateTemp("", "stbackup-*.tar.zst")
	if err != nil {
		return "", nil, 0, 0, err
	}
	defer tmp.Close()

	level := zstd.EncoderLevelFromZstd(3)
	zw, err := zstd.NewWriter(tmp, zstd.WithEncoderLevel(level))
	if err != nil {
		os.Remove(tmp.Name())
		return "", nil, 0, 0, err
	}
	tw := tar.NewWriter(zw)

	var manifest []protocol.ManifestEntry
	fileCount := 0
	var totalBytes int64

	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = rel
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil // 跳过软链/设备
		}

		// 写文件内容并同时算 SHA256
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(tw, io.TeeReader(f, h))
		f.Close()
		if err != nil {
			return err
		}
		manifest = append(manifest, protocol.ManifestEntry{
			Path:   rel,
			Size:   info.Size(),
			SHA256: hex.EncodeToString(h.Sum(nil)),
		})
		fileCount++
		totalBytes += n
		return nil
	})
	if err != nil {
		tw.Close()
		zw.Close()
		os.Remove(tmp.Name())
		return "", nil, 0, 0, err
	}

	if err := tw.Close(); err != nil {
		zw.Close()
		os.Remove(tmp.Name())
		return "", nil, 0, 0, err
	}
	if err := zw.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", nil, 0, 0, err
	}
	return tmp.Name(), manifest, fileCount, totalBytes, nil
}

// streamToTarget 把打包好的临时文件流式 POST 给目标子控的 receive 端点。
func (a *Agent) streamToTarget(ctx context.Context, req *protocol.BackupStartRequest, tmpPath string, manifestJSON []byte) error {
	f, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer f.Close()
	stat, _ := f.Stat()

	params := url.Values{
		"job_id": {fmt.Sprint(req.JobID)},
		"handle": {req.Handle},
		"kind":   {req.DstKind},
	}
	targetURL := req.DstAgentURL + "/agent/backup/receive?" + params.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, f)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	httpReq.Header.Set("X-Manifest", url.QueryEscape(string(manifestJSON)))
	if stat != nil {
		httpReq.ContentLength = stat.Size()
	}
	// 用目标节点的 PSK 签名(receive 端单独校验头摘要)
	signBackupReceive(httpReq, req.DstNodeID, req.DstNodePSK)

	client := &http.Client{Timeout: 0} // 大文件, 不超时
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("目标拒绝, 状态 %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// reportBackupResult 向总控上报备份结果。
func (a *Agent) reportBackupResult(ctx context.Context, jobID int64, res backupResult) {
	rep := protocol.BackupStatusResponse{
		JobID:     jobID,
		Status:    res.status,
		Bytes:     res.bytes,
		FileCount: res.fileCount,
		Checksum:  res.checksum,
		Error:     res.err,
	}
	// 用带超时的上下文上报(避免父 ctx 已取消)
	reportCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = a.callController(reportCtx, http.MethodPost, "/api/agent/backup/report", rep, nil)
}

// AbortBackup 中止进行中的备份。
func (a *Agent) AbortBackup(jobID int64) {
	a.mu.Lock()
	cancel, ok := a.backupJobs[jobID]
	a.mu.Unlock()
	if ok {
		cancel()
	}
}

// ReceiveBackup 作为目标节点接收备份流, 解压到目标目录。
// dstKind: archive → 存到 backup_dir/<handle>/; hot_standby → 解压到 data/<handle>/
func (a *Agent) ReceiveBackup(ctx context.Context, jobID int64, handle, dstKind string, body io.Reader) error {
	// 校验 receive 签名(在 query 上)
	// (签名校验在 handler 之前的专用逻辑完成; 这里直接处理流)

	var dstDir string
	switch dstKind {
	case "hot_standby":
		dstDir = filepath.Join(a.dataRoot(), handle)
		// 先备份旧目录
		if _, err := os.Stat(dstDir); err == nil {
			bakDir := dstDir + ".bak-" + time.Now().Format("20060102150405")
			_ = os.Rename(dstDir, bakDir)
		}
	default: // archive
		dstDir = filepath.Join(a.Cfg.BackupDir, handle)
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}

	// 解压 tar.zst 流
	zr, err := zstd.NewReader(body)
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		target := filepath.Join(dstDir, filepath.FromSlash(header.Name))
		// 防路径穿越
		if !isSubPath(dstDir, target) {
			continue
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}

// RestoreBackup 从备份恢复(占位, 完整逻辑后续)。
func (a *Agent) RestoreBackup(ctx context.Context, handle string) error {
	return fmt.Errorf("恢复功能待实现")
}

// isSubPath 判断 target 是否在 base 之下。
func isSubPath(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"stcontrol/internal/protocol"
)

// Handler 子控 HTTP 路由（仅总控可调, HMAC 签名校验）。
func (a *Agent) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	// 健康检查(无需签名, 供本地探活)
	r.Get("/agent/health", a.handleHealth)

	// 以下需总控签名
	r.Group(func(r chi.Router) {
		r.Use(a.hmacMiddleware)
		r.Post("/agent/provision-user", a.handleProvisionUser)
		r.Post("/agent/set-password", a.handleSetPassword)
		r.Get("/agent/scan-existing", a.handleScanExisting)
		r.Post("/agent/user-status", a.handleUserStatus)
		r.Post("/agent/backup/start", a.handleBackupStart)
		r.Post("/agent/backup/receive", a.handleBackupReceive)
		r.Post("/agent/backup/abort", a.handleBackupAbort)
		r.Post("/agent/backup/restore", a.handleBackupRestore)
	})
	return r
}

// hmacMiddleware 校验总控请求的 HMAC 签名（用本节点 PSK）。
func (a *Agent) hmacMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 流式接口(receive)body 太大, 用头里的摘要校验而非整体 body
		if r.URL.Path == "/agent/backup/receive" {
			next.ServeHTTP(w, r) // receive 用单独的校验(见 handler)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			protocol.WriteError(w, http.StatusBadRequest, "读取请求体失败")
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err := protocol.VerifyRequest(r, a.Cfg.AgentPSK, body); err != nil {
			protocol.WriteError(w, http.StatusUnauthorized, "签名校验失败: "+err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleHealth 健康检查 + 负载。
func (a *Agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	info, _ := ProbeTavern(a.Cfg.TavernDir)
	cpu, mem, disk, _ := CollectMetrics(a.Cfg.TavernDir)
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"agent_version":  Version,
		"tavern_version": info.TavernVersion,
		"cpu_pct":        cpu,
		"mem_pct":        mem,
		"disk_pct":       disk,
		"node_id":        a.Cfg.NodeID,
		"role":           a.Cfg.Role,
	})
}

// handleProvisionUser 代注册。
func (a *Agent) handleProvisionUser(w http.ResponseWriter, r *http.Request) {
	var req protocol.ProvisionUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	resp, err := a.provisionUser(r.Context(), &req)
	if err != nil {
		protocol.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !resp.OK {
		protocol.WriteJSON(w, http.StatusBadGateway, resp)
		return
	}
	protocol.WriteJSON(w, http.StatusOK, resp)
}

// handleSetPassword 改密同步。
func (a *Agent) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	var req protocol.SetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := a.setPassword(r.Context(), &req); err != nil {
		protocol.WriteError(w, http.StatusNotImplemented, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleScanExisting 扫描既有用户。
func (a *Agent) handleScanExisting(w http.ResponseWriter, r *http.Request) {
	users, err := a.ScanExistingUsers()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "扫描失败: "+err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"users": users})
}

// handleUserStatus 查询某用户在线状态。
func (a *Agent) handleUserStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Handle string `json:"handle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	statuses := a.scanUserActivityFromDisk()
	for _, st := range statuses {
		if st.Handle == req.Handle {
			protocol.WriteJSON(w, http.StatusOK, st)
			return
		}
	}
	protocol.WriteError(w, http.StatusNotFound, "用户不存在")
}

// ---------- 备份端点(具体引擎见 backup.go) ----------

func (a *Agent) handleBackupStart(w http.ResponseWriter, r *http.Request) {
	var req protocol.BackupStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := a.StartBackup(r.Context(), &req); err != nil {
		protocol.WriteError(w, http.StatusConflict, "启动备份失败: "+err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (a *Agent) handleBackupReceive(w http.ResponseWriter, r *http.Request) {
	// 元信息经查询参数传递, body 为 tar.zst 流
	jobID, _ := strconv.ParseInt(r.URL.Query().Get("job_id"), 10, 64)
	handle := r.URL.Query().Get("handle")
	dstKind := r.URL.Query().Get("kind")
	if handle == "" || jobID == 0 {
		protocol.WriteError(w, http.StatusBadRequest, "缺少 job_id 或 handle")
		return
	}
	if err := a.ReceiveBackup(r.Context(), jobID, handle, dstKind, r.Body); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "接收备份失败: "+err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *Agent) handleBackupAbort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JobID int64 `json:"job_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	a.AbortBackup(req.JobID)
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *Agent) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Handle string `json:"handle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := a.RestoreBackup(r.Context(), req.Handle); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "恢复失败: "+err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

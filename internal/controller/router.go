package controller

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func newRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))
	return r
}

func (s *Server) routes(r *chi.Mux) {
	// 静态前端（React 构建产物, 若存在）
	s.mountStatic(r)

	// 健康检查
	r.Get("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// 一键安装脚本分发(供 curl ... | bash)
	r.Get("/install.sh", s.handleInstallScript)

	// 认证
	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/register", s.handleRegister)
		r.Get("/registration/status", s.handleRegistrationStatus)
		r.Post("/login", s.handleLogin)
		r.Post("/admin/login", s.handleAdminLogin)
		r.Post("/oauth/complete", s.handleOAuthComplete)
		r.Get("/oauth/{provider}", s.handleOAuthBegin)
		r.Get("/oauth/{provider}/callback", s.handleOAuthCallback)
	})

	// 节点公开信息（注册页用）
	r.Get("/api/nodes/available", s.handleAvailableNodes)

	// 票据核销（仅已认证节点可调用；节点身份不接受请求体声明）
	r.Route("/api/tickets", func(r chi.Router) {
		r.Use(s.agentAuthMiddleware)
		r.Post("/redeem", s.handleTicketRedeem)
		r.Post("/redeem-admin", s.handleAdminTicketRedeem)
	})

	// 子控注册（一次性令牌, 无需 PSK）
	r.Post("/api/agent/register", s.handleAgentRegister)

	// 子控心跳/状态（需 PSK 签名）
	r.Route("/api/agent", func(r chi.Router) {
		r.Use(s.agentAuthMiddleware)
		r.Post("/heartbeat", s.handleAgentHeartbeat)
		r.Post("/commands/lease", s.handleAgentLeaseCommand)
		r.Post("/commands/{id}/ack", s.handleAgentAckCommand)
		r.Post("/commands/{id}/result", s.handleAgentFinishCommand)
		r.Post("/snapshots/progress", s.handleSnapshotProgress)
	})

	// 用户区（需登录）
	r.Route("/api", func(r chi.Router) {
		r.Use(s.userAuthMiddleware)
		r.Post("/auth/logout", s.handleLogout)
		r.Get("/users/me", s.handleMe)
		r.Get("/users/me/nodes", s.handleMyNodes)
		r.Get("/users/me/protection", s.handleMyProtection)
		r.Post("/users/me/takeover", s.handleConfirmReplicaTakeover)
		r.Get("/users/me/restore-targets", s.handleRestoreTargets)
		r.Post("/users/me/restore", s.handleStartArchiveRestore)
		r.Get("/users/me/restores/{operationID}", s.handleArchiveRestoreStatus)
		r.Post("/login/redirect", s.handleLoginRedirect)
		r.Post("/users/me/password", s.handleChangePassword)
		r.Get("/users/me/identities", s.handleListIdentities)
		r.Post("/users/me/identities/password", s.handleBindPasswordIdentity)
		r.Post("/users/me/identities/{provider}/bind", s.handleBeginOAuthIdentityBinding)
		r.Delete("/users/me/identities/{provider}", s.handleUnbindIdentity)
		r.Get("/users/me/import-claims", s.handleListMyAccountImportClaims)
		r.Post("/users/me/import-claims", s.handleClaimImportedAccount)
	})

	// 冲突恢复区只接受 conflict-frozen 用户，不继承普通用户权限。
	r.Route("/api/conflicts", func(r chi.Router) {
		r.Use(s.conflictAuthMiddleware)
		r.Get("/me", s.handleMyReplicaConflict)
		r.Get("/me/differences", s.handleMyReplicaConflictDifferences)
		r.Post("/me/resolutions", s.handleStartConflictResolution)
		r.Get("/me/resolutions/{operationID}", s.handleConflictResolutionStatus)
		r.Post("/me/resolutions/{operationID}/retry", s.handleRetryConflictResolution)
		r.Post("/auth/logout", s.handleLogout)
	})

	// 管理后台（需管理员）
	r.Route("/api/admin", func(r chi.Router) {
		r.Use(s.userAuthMiddleware)
		r.Use(s.adminOnly)
		r.Get("/overview", s.handleAdminOverview)
		r.Get("/nodes", s.handleAdminListNodes)
		r.Get("/node-links", s.handleAdminNodeLinks)
		r.Post("/nodes", s.handleAdminCreateNode)
		r.Put("/nodes/{id}", s.handleAdminUpdateNode)
		r.Post("/nodes/{id}/lifecycle", s.handleAdminTransitionNodeLifecycle)
		r.Post("/nodes/{id}/register-token", s.handleAdminNodeRegisterToken)
		r.Post("/nodes/{id}/scan-existing", s.handleAdminScanExisting)
		r.Post("/nodes/{id}/admin-link", s.handleVerifyAdminNodeLink)
		r.Delete("/nodes/{id}/admin-link", s.handleRevokeAdminNodeLink)
		r.Post("/nodes/{id}/admin-handoff", s.handleCreateAdminHandoff)
		r.Get("/nodes/{id}/imports/latest", s.handleAdminLatestAccountImport)
		r.Get("/users", s.handleAdminListUsers)
		r.Post("/users/{uuid}/identity-recovery", s.handleAdminRecoverUserIdentity)
		r.Post("/users/{id}/backup", s.handleAdminTriggerBackup)
		r.Post("/users/{id}/disable", s.handleAdminDisableUser)
		r.Get("/backups", s.handleAdminListBackups)
		r.Post("/backups/{id}/abort", s.handleAdminAbortBackup)
		r.Get("/alerts/protection", s.handleAdminProtectionAlerts)
		r.Get("/admins", s.handleAdminListAdmins)
		r.Post("/admins", s.handleAdminCreateAdmin)
		r.Put("/admins/{id}/status", s.handleAdminSetAdminStatus)
		r.Put("/admins/{id}/password", s.handleAdminResetPassword)
	})
}

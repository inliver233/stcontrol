package controller

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const maxAgentRequestBody = 1 << 20

// userAuthMiddleware 要求用户登录。
func (s *Server) userAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store, max-age=0")
		w.Header().Add("Vary", "Cookie")
		sess, _, err := s.getSession(r)
		if err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "会话服务暂不可用")
			return
		}
		if sess == nil {
			protocol.WriteError(w, http.StatusUnauthorized, "未登录")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !s.validateCSRF(r, sess) {
				protocol.WriteError(w, http.StatusForbidden, "CSRF 校验失败")
				return
			}
		} else {
			s.ensureCSRFCookie(w, r, sess)
		}
		ctx := context.WithValue(r.Context(), ctxUser, sess.UserID)
		ctx = context.WithValue(ctx, ctxKey("stcontrol-isadmin"), sess.IsAdmin)
		ctx = context.WithValue(ctx, ctxKey("stcontrol-session"), sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// conflictAuthMiddleware accepts the same opaque session token only for a
// conflict-frozen user with an open conflict case. It is mounted separately so
// the token cannot reach normal user mutations while the account is frozen.
func (s *Server) conflictAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store, max-age=0")
		w.Header().Add("Vary", "Cookie")
		sess, _, err := s.getConflictSession(r)
		if err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "冲突恢复会话暂不可用")
			return
		}
		if sess == nil {
			protocol.WriteError(w, http.StatusUnauthorized, "需要冲突恢复认证")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !s.validateCSRF(r, sess) {
				protocol.WriteError(w, http.StatusForbidden, "CSRF 校验失败")
				return
			}
		} else {
			s.ensureCSRFCookie(w, r, sess)
		}
		ctx := context.WithValue(r.Context(), ctxUser, sess.UserID)
		ctx = context.WithValue(ctx, ctxKey("stcontrol-session"), sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// adminOnly 要求管理员。
func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAdmin, _ := r.Context().Value(ctxKey("stcontrol-isadmin")).(bool)
		if !isAdmin {
			protocol.WriteError(w, http.StatusForbidden, "需要管理员权限")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// agentAuthMiddleware 校验子控请求的 HMAC 签名。
// 通过 X-Agent-Id 找到节点 PSK，读取请求体后校验签名，再把 body 放回供 handler 读取。
func (s *Server) agentAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentIDStr := r.Header.Get(protocol.HeaderAgentID)
		agentID, err := strconv.ParseInt(agentIDStr, 10, 64)
		if err != nil {
			protocol.WriteError(w, http.StatusUnauthorized, "缺少或非法的 Agent ID")
			return
		}
		node, err := s.Store.GetNodeByID(r.Context(), agentID)
		if err != nil || node == nil {
			protocol.WriteError(w, http.StatusUnauthorized, "未知节点")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAgentRequestBody))
		if err != nil {
			protocol.WriteError(w, http.StatusBadRequest, "读取请求体失败")
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		credentials, err := s.Store.ListAgentAuthenticationCredentials(r.Context(), node.ID, time.Now().UTC())
		if err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "节点认证暂不可用")
			return
		}
		var matched *store.AgentAuthenticationCredential
		var matchedPSK string
		for index := range credentials {
			plaintext, decryptErr := controlcrypto.Decrypt(s.secretKey, string(credentials[index].Ciphertext))
			if decryptErr == nil && protocol.VerifyRequest(r, string(plaintext), body) == nil {
				matched = &credentials[index]
				matchedPSK = string(plaintext)
				break
			}
		}
		if matched == nil || (matched.Pending && r.URL.Path != "/api/agent/credentials/confirm") {
			protocol.WriteError(w, http.StatusUnauthorized, "签名校验失败")
			return
		}
		activeGeneration, err := s.Store.GetActiveControllerGeneration(r.Context())
		if err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "节点认证暂不可用")
			return
		}
		if matched.ControllerGeneration != activeGeneration {
			// A previous-generation active credential is retained only long
			// enough to authenticate the durable recovery heartbeat that wraps
			// its successor. It cannot lease, acknowledge or finish commands.
			if matched.Pending || matched.ControllerGeneration > activeGeneration ||
				r.URL.Path != "/api/agent/heartbeat" {
				protocol.WriteError(w, http.StatusUnauthorized, "节点凭据世代已失效")
				return
			}
		}
		signedUnix, err := strconv.ParseInt(r.Header.Get(protocol.HeaderTimestamp), 10, 64)
		if err != nil {
			protocol.WriteError(w, http.StatusUnauthorized, "签名校验失败")
			return
		}
		signedAt := time.Unix(signedUnix, 0).UTC()
		accepted, err := s.Store.ConsumeAgentNonce(
			r.Context(), node.ID, r.Header.Get(protocol.HeaderNonce),
			signedAt, signedAt.Add(2*protocol.MaxClockSkew),
		)
		if err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "节点认证暂不可用")
			return
		}
		if !accepted {
			protocol.WriteError(w, http.StatusUnauthorized, "请求签名已使用")
			return
		}
		// 把节点放进上下文
		ctx := context.WithValue(r.Context(), ctxKey("stcontrol-node"), node)
		ctx = context.WithValue(ctx, ctxKey("stcontrol-agent-credential-version"), matched.CredentialVersion)
		ctx = context.WithValue(ctx, ctxKey("stcontrol-agent-credential-generation"), matched.ControllerGeneration)
		ctx = context.WithValue(ctx, ctxKey("stcontrol-agent-credential-pending"), matched.Pending)
		ctx = context.WithValue(ctx, ctxKey("stcontrol-agent-psk"), matchedPSK)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func currentAgentCredential(r *http.Request) (int64, bool, string) {
	version, _ := r.Context().Value(ctxKey("stcontrol-agent-credential-version")).(int64)
	pending, _ := r.Context().Value(ctxKey("stcontrol-agent-credential-pending")).(bool)
	psk, _ := r.Context().Value(ctxKey("stcontrol-agent-psk")).(string)
	return version, pending, psk
}

func currentAgentCredentialGeneration(r *http.Request) int64 {
	generation, _ := r.Context().Value(ctxKey("stcontrol-agent-credential-generation")).(int64)
	return generation
}

func (s *Server) agentPSK(ctx context.Context, node *store.Node) (string, error) {
	if node == nil {
		return "", nil
	}
	ciphertext, _, _, err := s.Store.GetActiveAgentCredential(ctx, node.ID)
	if err != nil || len(ciphertext) == 0 {
		return "", err
	}
	plaintext, err := controlcrypto.Decrypt(s.secretKey, string(ciphertext))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// currentNode 从上下文取节点。
func currentNode(r *http.Request) *store.Node {
	v := r.Context().Value(ctxKey("stcontrol-node"))
	if v == nil {
		return nil
	}
	n, _ := v.(*store.Node)
	return n
}

// validMutationOrigin rejects browser cross-site mutations while preserving
// non-browser clients that do not send Origin/Sec-Fetch-Site.
func (s *Server) validMutationOrigin(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	got, err := url.Parse(origin)
	if err != nil || got.Scheme == "" || got.Host == "" {
		return false
	}
	want, err := url.Parse(s.Cfg.PublicURL)
	if err != nil || want.Scheme == "" || want.Host == "" {
		return false
	}
	return strings.EqualFold(got.Scheme, want.Scheme) && strings.EqualFold(got.Host, want.Host)
}

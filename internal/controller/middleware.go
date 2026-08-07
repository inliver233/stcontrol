package controller

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const maxAgentRequestBody = 1 << 20

// userAuthMiddleware 要求用户登录。
func (s *Server) userAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := s.getSession(r)
		if sess == nil {
			protocol.WriteError(w, http.StatusUnauthorized, "未登录")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, sess.UserID)
		ctx = context.WithValue(ctx, ctxKey("stcontrol-isadmin"), sess.IsAdmin)
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

		if err := protocol.VerifyRequest(r, node.AgentPSK, body); err != nil {
			protocol.WriteError(w, http.StatusUnauthorized, "签名校验失败")
			return
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
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

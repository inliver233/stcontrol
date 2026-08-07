package controller

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

const sessionCookie = "stcontrol_session"
const sessionTTL = 7 * 24 * time.Hour

// createSession 建立会话并写 cookie。
func (s *Server) createSession(w http.ResponseWriter, userID int64, username string, isAdmin bool) string {
	token := randToken()
	s.mu.Lock()
	s.sessions[token] = &session{
		UserID:    userID,
		Username:  username,
		IsAdmin:   isAdmin,
		ExpiresAt: time.Now().Add(sessionTTL),
	}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
		// Secure 由部署层(HTTPS)保证; 本地 http 开发不设
	})
	return token
}

// getSession 读取会话。
func (s *Server) getSession(r *http.Request) (*session, string) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, ""
	}
	s.mu.RLock()
	sess, ok := s.sessions[c.Value]
	s.mu.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil, ""
	}
	return sess, c.Value
}

// destroySession 销毁会话。
func (s *Server) destroySession(w http.ResponseWriter, r *http.Request) {
	_, token := s.getSession(r)
	if token != "" {
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

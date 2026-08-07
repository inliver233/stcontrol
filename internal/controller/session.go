package controller

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"stcontrol/internal/store"
)

const (
	sessionCookie        = "stcontrol_session"
	csrfCookie           = "stcontrol_csrf"
	sessionTTL           = 7 * 24 * time.Hour
	adminSessionTTL      = 12 * time.Hour
	sessionTouchInterval = 5 * time.Minute
)

// createUserSession rotates any presented session, persists a new opaque-token
// digest, and writes host-only cookies. The raw session token is never stored.
func (s *Server) createUserSession(w http.ResponseWriter, r *http.Request, user *store.User) error {
	if user == nil || user.ID <= 0 || user.GlobalID <= 0 {
		return store.ErrInvalidControllerSession
	}
	if existing, err := r.Cookie(sessionCookie); err == nil && existing.Value != "" {
		digest := sha256.Sum256([]byte(existing.Value))
		_ = s.Store.RevokeControllerSession(r.Context(), digest[:], time.Now().UTC())
	}

	sessionID, err := newUUID()
	if err != nil {
		return err
	}
	token, err := randomBearerToken()
	if err != nil {
		return err
	}
	csrfToken := s.deriveCSRFToken(sessionID)
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrfToken))
	now := time.Now().UTC()
	globalUserID := user.GlobalID
	_, err = s.Store.CreateControllerSession(r.Context(), store.CreateControllerSessionParams{
		ID:        sessionID,
		UserID:    &globalUserID,
		TokenHash: tokenHash[:],
		CSRFHash:  csrfHash[:],
		ExpiresAt: now.Add(sessionTTL),
		Now:       now,
	})
	if err != nil {
		return err
	}
	s.setSessionCookies(w, r, token, csrfToken, int(sessionTTL.Seconds()))
	return nil
}

func (s *Server) createAdminSession(w http.ResponseWriter, r *http.Request, admin *store.Admin) error {
	if admin == nil || admin.ID <= 0 || admin.Status != "active" {
		return store.ErrInvalidControllerSession
	}
	if existing, err := r.Cookie(sessionCookie); err == nil && existing.Value != "" {
		digest := sha256.Sum256([]byte(existing.Value))
		_ = s.Store.RevokeControllerSession(r.Context(), digest[:], time.Now().UTC())
	}
	sessionID, err := newUUID()
	if err != nil {
		return err
	}
	token, err := randomBearerToken()
	if err != nil {
		return err
	}
	csrfToken := s.deriveCSRFToken(sessionID)
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrfToken))
	now := time.Now().UTC()
	adminID := admin.ID
	_, err = s.Store.CreateControllerSession(r.Context(), store.CreateControllerSessionParams{
		ID:        sessionID,
		AdminID:   &adminID,
		TokenHash: tokenHash[:],
		CSRFHash:  csrfHash[:],
		ExpiresAt: now.Add(adminSessionTTL),
		Now:       now,
	})
	if err != nil {
		return err
	}
	s.setSessionCookies(w, r, token, csrfToken, int(adminSessionTTL.Seconds()))
	return nil
}

// getSession resolves the opaque cookie through the durable store. It performs
// a throttled best-effort last-seen update rather than writing on every request.
func (s *Server) getSession(r *http.Request) (*session, string, error) {
	return s.resolveSession(r, false)
}

func (s *Server) getConflictSession(r *http.Request) (*session, string, error) {
	return s.resolveSession(r, true)
}

func (s *Server) resolveSession(r *http.Request, conflictOnly bool) (*session, string, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return nil, "", nil
	}
	tokenHash := sha256.Sum256([]byte(cookie.Value))
	now := time.Now().UTC()
	var stored *store.ControllerSession
	if conflictOnly {
		stored, err = s.Store.GetConflictControllerSession(r.Context(), tokenHash[:], now)
	} else {
		stored, err = s.Store.GetControllerSession(r.Context(), tokenHash[:], now)
	}
	if err != nil || stored == nil {
		return nil, cookie.Value, err
	}
	if now.Sub(stored.LastSeenAt) >= sessionTouchInterval {
		_ = s.Store.TouchControllerSession(r.Context(), stored.ID, now)
	}
	return &session{
		ID:                   stored.ID,
		UserID:               stored.LegacyUserID,
		GlobalUserID:         stored.GlobalUserID,
		AdminID:              stored.AdminID,
		Username:             stored.Username,
		IsAdmin:              stored.IsAdmin,
		CSRFHash:             stored.CSRFHash,
		ExpiresAt:            stored.ExpiresAt,
		LastSeenAt:           stored.LastSeenAt,
		ControllerGeneration: stored.ControllerGeneration,
	}, cookie.Value, nil
}

func (s *Server) destroySession(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie(sessionCookie)
	if err == nil && cookie.Value != "" {
		digest := sha256.Sum256([]byte(cookie.Value))
		if err := s.Store.RevokeControllerSession(r.Context(), digest[:], time.Now().UTC()); err != nil {
			return err
		}
	}
	s.clearSessionCookies(w, r)
	return nil
}

func (s *Server) validateCSRF(r *http.Request, sess *session) bool {
	if sess == nil || len(sess.CSRFHash) != sha256.Size {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	cookie, err := r.Cookie(csrfCookie)
	if err != nil || header == "" || cookie.Value == "" || !hmac.Equal([]byte(header), []byte(cookie.Value)) {
		return false
	}
	digest := sha256.Sum256([]byte(header))
	return hmac.Equal(digest[:], sess.CSRFHash)
}

func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request, sess *session) {
	want := s.deriveCSRFToken(sess.ID)
	if cookie, err := r.Cookie(csrfCookie); err == nil && hmac.Equal([]byte(cookie.Value), []byte(want)) {
		return
	}
	remaining := int(time.Until(sess.ExpiresAt).Seconds())
	if remaining < 1 {
		remaining = 1
	}
	s.setCSRFCookie(w, r, want, remaining)
}

func (s *Server) deriveCSRFToken(sessionID string) string {
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-csrf:v1:" + sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func randomBearerToken() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomHexToken(byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = 32
	}
	b := make([]byte, byteLength)
	if _, err := cryptorand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) setSessionCookies(w http.ResponseWriter, r *http.Request, token, csrf string, maxAge int) {
	secure := s.secureCookies(r)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
	s.setCSRFCookie(w, r, csrf, maxAge)
}

func (s *Server) setCSRFCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: token, Path: "/", HttpOnly: false,
		Secure: s.secureCookies(r), SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	})
}

func (s *Server) clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	secure := s.secureCookies(r)
	for _, cookie := range []http.Cookie{
		{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1},
		{Name: csrfCookie, Value: "", Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1},
	} {
		current := cookie
		http.SetCookie(w, &current)
	}
}

func (s *Server) secureCookies(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	parsed, err := url.Parse(s.Cfg.PublicURL)
	return err == nil && parsed.Scheme == "https"
}

func (s *Server) sessionJanitor(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		_, _ = s.Store.CleanupControllerSessions(ctx, time.Now().UTC())
		_, _ = s.Store.CleanupOAuthArtifacts(ctx, time.Now().UTC())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

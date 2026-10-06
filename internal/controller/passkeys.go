package controller

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	webauthnprotocol "github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// Passkeys are an additional way to sign in to the Controller. A sign-in
// creates the same Controller session as a password or OAuth login, and the
// user then reaches their tavern through the normal login handoff.

const (
	passkeyCeremonyTTL  = 5 * time.Minute
	passkeyRequestLimit = 64 << 10
)

var errPasskeyUnknown = errors.New("passkey is not registered")

type passkeyRelyingParty struct {
	authn   *webauthn.WebAuthn
	rpID    string
	origins []string
}

// passkeyDomain resolves the domain passkeys belong to and the page origins
// allowed to use them.
func passkeyDomain(cfg *config.ControllerConfig) (string, []string, error) {
	public, err := url.Parse(cfg.PublicURL)
	if err != nil || public.Hostname() == "" {
		return "", nil, fmt.Errorf("invalid public URL")
	}
	rpID := strings.ToLower(strings.TrimSpace(cfg.Passkeys.RPID))
	if rpID == "" {
		rpID = strings.ToLower(public.Hostname())
	}
	if net.ParseIP(rpID) != nil {
		return "", nil, fmt.Errorf("passkeys need a domain name, not an IP address")
	}
	candidates := append([]string{public.Scheme + "://" + public.Host}, cfg.Passkeys.Origins...)
	origins := make([]string, 0, len(candidates))
	seen := map[string]bool{}
	for _, candidate := range candidates {
		parsed, err := url.Parse(strings.TrimSpace(candidate))
		if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") ||
			parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", nil, fmt.Errorf("invalid passkey origin %q", candidate)
		}
		host := strings.ToLower(parsed.Hostname())
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return "", nil, fmt.Errorf("origin %q is not under passkey domain %q", candidate, rpID)
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopbackHost(host)) {
			return "", nil, fmt.Errorf("passkey origin %q must use HTTPS", candidate)
		}
		origin := strings.ToLower(parsed.Scheme + "://" + parsed.Host)
		if !seen[origin] {
			seen[origin] = true
			origins = append(origins, origin)
		}
	}
	return rpID, origins, nil
}

func newPasskeyRelyingParty(cfg *config.ControllerConfig) (*passkeyRelyingParty, error) {
	rpID, origins, err := passkeyDomain(cfg)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(cfg.Passkeys.RPName)
	if name == "" {
		name = "云酒馆"
	}
	authn, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: name,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, err
	}
	return &passkeyRelyingParty{authn: authn, rpID: rpID, origins: origins}, nil
}

// passkeyRP returns the relying party, or why passkeys cannot work with the
// current configuration. The configuration is fixed for the process lifetime.
func (s *Server) passkeyRP() (*passkeyRelyingParty, error) {
	s.passkeyOnce.Do(func() {
		s.passkeyParty, s.passkeyErr = newPasskeyRelyingParty(s.Cfg)
		if s.passkeyErr != nil {
			log.Printf("通行密钥不可用: %v", s.passkeyErr)
		}
	})
	return s.passkeyParty, s.passkeyErr
}

// passkeyUser adapts a Controller user for the WebAuthn library. The user
// handle stored in each passkey is the global user UUID.
type passkeyUser struct {
	user        *store.User
	handle      []byte
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte { return u.handle }

func (u passkeyUser) WebAuthnName() string { return u.user.Username }

func (u passkeyUser) WebAuthnDisplayName() string {
	if strings.TrimSpace(u.user.DisplayName) != "" {
		return u.user.DisplayName
	}
	return u.user.Username
}

func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func passkeyUserHandle(uuidText string) ([]byte, bool) {
	hexText := strings.ReplaceAll(uuidText, "-", "")
	if len(hexText) != 32 {
		return nil, false
	}
	handle, err := hex.DecodeString(hexText)
	return handle, err == nil
}

func decodePasskeyCredentials(passkeys []store.UserPasskey) ([]webauthn.Credential, error) {
	credentials := make([]webauthn.Credential, 0, len(passkeys))
	for _, passkey := range passkeys {
		var credential webauthn.Credential
		if err := json.Unmarshal(passkey.Credential, &credential); err != nil {
			return nil, fmt.Errorf("decode passkey %d: %w", passkey.ID, err)
		}
		credentials = append(credentials, credential)
	}
	return credentials, nil
}

type passkeyCeremony struct {
	CeremonyID string `json:"ceremony_id"`
	Options    any    `json:"options"`
}

type passkeyVerifyRequest struct {
	CeremonyID string          `json:"ceremony_id"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func decodePasskeyVerifyRequest(w http.ResponseWriter, r *http.Request) (passkeyVerifyRequest, bool) {
	var req passkeyVerifyRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, passkeyRequestLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !isUUID(req.CeremonyID) || len(req.Credential) == 0 {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return req, false
	}
	return req, true
}

func (s *Server) storePasskeyCeremony(r *http.Request, purpose string, userID int64, session *webauthn.SessionData) (string, error) {
	ceremonyID, err := newUUID()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	return ceremonyID, s.Store.CreatePasskeyCeremony(r.Context(), ceremonyID, purpose, userID, encoded, now.Add(passkeyCeremonyTTL), now)
}

func (s *Server) takePasskeyCeremony(w http.ResponseWriter, r *http.Request, ceremonyID, purpose string, userID int64) (webauthn.SessionData, bool) {
	var session webauthn.SessionData
	encoded, err := s.Store.ConsumePasskeyCeremony(r.Context(), ceremonyID, purpose, userID, time.Now().UTC())
	if errors.Is(err, store.ErrPasskeyCeremonyFailed) {
		protocol.WriteError(w, http.StatusBadRequest, "验证已过期，请重试")
		return session, false
	}
	if err != nil || json.Unmarshal(encoded, &session) != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return session, false
	}
	return session, true
}

// passkeysReady loads the settings and relying party for a passkey request and
// writes the error response itself when passkeys are switched off.
func (s *Server) passkeysReady(w http.ResponseWriter, r *http.Request) (*passkeyRelyingParty, store.PasskeySettings, bool) {
	settings, err := s.Store.GetPasskeySettings(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return nil, settings, false
	}
	party, err := s.passkeyRP()
	if err != nil || !settings.Enabled {
		protocol.WriteError(w, http.StatusForbidden, "通行密钥未开启")
		return nil, settings, false
	}
	return party, settings, true
}

// handlePasskeyPublicConfig tells the login page whether to offer passkeys.
func (s *Server) handlePasskeyPublicConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	settings, err := s.Store.GetPasskeySettings(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return
	}
	party, rpErr := s.passkeyRP()
	rpID := ""
	if party != nil {
		rpID = party.rpID
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		// enabled also tells managed taverns to link their passkey buttons here.
		"enabled":       rpErr == nil && settings.Enabled,
		"login_enabled": rpErr == nil && settings.Enabled && settings.ShowOnLoginPage,
		"button_text":   settings.LoginButtonText,
		"hint_text":     settings.LoginHintText,
		"rp_id":         rpID,
	})
}

// handlePasskeyLoginOptions starts a username-less passkey sign-in.
func (s *Server) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	if !s.validMutationOrigin(r) {
		protocol.WriteError(w, http.StatusForbidden, "请求来源无效")
		return
	}
	if !s.requireNewOperations(w) {
		return
	}
	party, settings, ok := s.passkeysReady(w, r)
	if !ok {
		return
	}
	assertion, session, err := party.authn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(webauthnprotocol.UserVerificationRequirement(settings.UserVerification)))
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "无法开始通行密钥登录")
		return
	}
	ceremonyID, err := s.storePasskeyCeremony(r, "login", 0, session)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, passkeyCeremony{CeremonyID: ceremonyID, Options: assertion})
}

// handlePasskeyLoginVerify checks a passkey assertion and signs the owner in.
func (s *Server) handlePasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	if !s.validMutationOrigin(r) {
		protocol.WriteError(w, http.StatusForbidden, "请求来源无效")
		return
	}
	if !s.requireNewOperations(w) {
		return
	}
	party, _, ok := s.passkeysReady(w, r)
	if !ok {
		return
	}
	req, ok := decodePasskeyVerifyRequest(w, r)
	if !ok {
		return
	}
	session, ok := s.takePasskeyCeremony(w, r, req.CeremonyID, "login", 0)
	if !ok {
		return
	}
	ctx := r.Context()
	fail := func(status int, reason, message string) {
		if err := s.Store.RecordPasskeyLoginFailure(ctx, reason); err != nil {
			log.Printf("记录通行密钥登录失败: %v", err)
		}
		// The code lets the page tell the browser to stop offering a deleted passkey.
		protocol.WriteJSON(w, status, map[string]string{"error": message, "code": reason})
	}
	parsed, err := webauthnprotocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil {
		fail(http.StatusBadRequest, "malformed_response", "通行密钥响应无效，请重试")
		return
	}
	var owner *store.PasskeyOwner
	var user *store.User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		found, err := s.Store.GetPasskeyOwner(ctx, rawID)
		if err != nil {
			return nil, err
		}
		if found == nil {
			return nil, errPasskeyUnknown
		}
		handle, ok := passkeyUserHandle(found.UserUUID)
		if !ok || !bytes.Equal(handle, userHandle) {
			return nil, errPasskeyUnknown
		}
		account, err := s.Store.GetUserByUUID(ctx, found.UserUUID)
		if err != nil {
			return nil, err
		}
		if account == nil {
			return nil, errPasskeyUnknown
		}
		credentials, err := decodePasskeyCredentials([]store.UserPasskey{found.Passkey})
		if err != nil {
			return nil, err
		}
		owner, user = found, account
		return passkeyUser{user: account, handle: handle, credentials: credentials}, nil
	}
	_, credential, err := party.authn.ValidatePasskeyLogin(handler, session, parsed)
	if err != nil || owner == nil || user == nil || credential == nil {
		if errors.Is(err, errPasskeyUnknown) {
			fail(http.StatusForbidden, "unknown_credential", "这个通行密钥不在本站（可能已被删除），请用其他方式登录")
			return
		}
		fail(http.StatusForbidden, "verification_failed", "通行密钥验证失败，请重试")
		return
	}
	if credential.Authenticator.CloneWarning {
		fail(http.StatusForbidden, "clone_warning", "通行密钥验证失败，请重试")
		return
	}
	if user.Status != "active" && user.Status != "conflict" {
		fail(http.StatusForbidden, "account_disabled", "账号已被禁用")
		return
	}
	updated, err := json.Marshal(credential)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "通行密钥登录失败")
		return
	}
	if err := s.Store.RecordPasskeyLogin(ctx, owner.Passkey.ID, owner.Passkey.UserID, updated, time.Now().UTC()); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return
	}
	if err := s.createUserSession(w, r, user); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "创建会话失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "username": user.Username, "display_name": user.DisplayName,
		"recovery_required": user.Status == "conflict",
	})
}

// currentPasskeyAccount returns the signed-in user and their passkeys.
func (s *Server) currentPasskeyAccount(w http.ResponseWriter, r *http.Request) (*store.User, []store.UserPasskey, bool) {
	sess := currentSession(r)
	if sess == nil || sess.GlobalUserID <= 0 {
		protocol.WriteError(w, http.StatusUnauthorized, "未登录")
		return nil, nil, false
	}
	user, err := s.Store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return nil, nil, false
	}
	if user == nil || user.GlobalID != sess.GlobalUserID {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在或不可用")
		return nil, nil, false
	}
	passkeys, err := s.Store.ListUserPasskeys(r.Context(), user.GlobalID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return nil, nil, false
	}
	return user, passkeys, true
}

// handleListMyPasskeys lists the signed-in user's passkeys.
func (s *Server) handleListMyPasskeys(w http.ResponseWriter, r *http.Request) {
	user, passkeys, ok := s.currentPasskeyAccount(w, r)
	if !ok || user == nil {
		return
	}
	settings, err := s.Store.GetPasskeySettings(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return
	}
	party, rpErr := s.passkeyRP()
	rpID := ""
	if party != nil {
		rpID = party.rpID
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"available":          rpErr == nil && settings.Enabled,
		"allow_registration": settings.AllowRegistration,
		"max_per_user":       settings.MaxPerUser,
		"rp_id":              rpID,
		"passkeys":           passkeys,
	})
}

// handleBeginPasskeyRegistration starts adding a passkey to the signed-in user.
func (s *Server) handleBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	party, settings, ok := s.passkeysReady(w, r)
	if !ok {
		return
	}
	if !settings.AllowRegistration {
		protocol.WriteError(w, http.StatusForbidden, "管理员暂时关闭了添加通行密钥")
		return
	}
	user, passkeys, ok := s.currentPasskeyAccount(w, r)
	if !ok {
		return
	}
	if len(passkeys) >= settings.MaxPerUser {
		protocol.WriteError(w, http.StatusConflict, fmt.Sprintf("最多只能添加 %d 个通行密钥", settings.MaxPerUser))
		return
	}
	handle, valid := passkeyUserHandle(user.UUID)
	credentials, err := decodePasskeyCredentials(passkeys)
	if !valid || err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "无法开始添加通行密钥")
		return
	}
	creation, session, err := party.authn.BeginRegistration(
		passkeyUser{user: user, handle: handle, credentials: credentials},
		webauthn.WithAuthenticatorSelection(webauthnprotocol.AuthenticatorSelection{
			ResidentKey:        webauthnprotocol.ResidentKeyRequirementRequired,
			RequireResidentKey: webauthnprotocol.ResidentKeyRequired(),
			UserVerification:   webauthnprotocol.UserVerificationRequirement(settings.UserVerification),
		}),
		webauthn.WithExclusions(webauthn.Credentials(credentials).CredentialDescriptors()),
		webauthn.WithConveyancePreference(webauthnprotocol.PreferNoAttestation),
	)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "无法开始添加通行密钥")
		return
	}
	ceremonyID, err := s.storePasskeyCeremony(r, "register", user.GlobalID, session)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, passkeyCeremony{CeremonyID: ceremonyID, Options: creation})
}

// handleFinishPasskeyRegistration verifies and stores a new passkey.
func (s *Server) handleFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	party, settings, ok := s.passkeysReady(w, r)
	if !ok {
		return
	}
	if !settings.AllowRegistration {
		protocol.WriteError(w, http.StatusForbidden, "管理员暂时关闭了添加通行密钥")
		return
	}
	req, ok := decodePasskeyVerifyRequest(w, r)
	if !ok {
		return
	}
	user, passkeys, ok := s.currentPasskeyAccount(w, r)
	if !ok {
		return
	}
	session, ok := s.takePasskeyCeremony(w, r, req.CeremonyID, "register", user.GlobalID)
	if !ok {
		return
	}
	parsed, err := webauthnprotocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "通行密钥响应无效，请重试")
		return
	}
	handle, valid := passkeyUserHandle(user.UUID)
	credentials, err := decodePasskeyCredentials(passkeys)
	if !valid || err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "通行密钥添加失败")
		return
	}
	credential, err := party.authn.CreateCredential(passkeyUser{user: user, handle: handle, credentials: credentials}, session, parsed)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "通行密钥验证失败，请重试")
		return
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "通行密钥添加失败")
		return
	}
	passkey, err := s.Store.AddUserPasskey(r.Context(), store.AddUserPasskeyParams{
		UserID: user.GlobalID, CredentialID: credential.ID, Credential: encoded,
		Name: req.Name, MaxPerUser: settings.MaxPerUser, Now: time.Now().UTC(),
	})
	switch {
	case errors.Is(err, store.ErrPasskeyLimit):
		protocol.WriteError(w, http.StatusConflict, fmt.Sprintf("最多只能添加 %d 个通行密钥", settings.MaxPerUser))
		return
	case errors.Is(err, store.ErrPasskeyExists):
		protocol.WriteError(w, http.StatusConflict, "这个通行密钥已经添加过了")
		return
	case err != nil:
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥添加失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "passkey": passkey})
}

func passkeyIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		protocol.WriteError(w, http.StatusBadRequest, "通行密钥 ID 无效")
		return 0, false
	}
	return id, true
}

// handleRenameMyPasskey renames one of the signed-in user's passkeys.
func (s *Server) handleRenameMyPasskey(w http.ResponseWriter, r *http.Request) {
	id, ok := passkeyIDParam(w, r)
	if !ok {
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.GlobalUserID <= 0 {
		protocol.WriteError(w, http.StatusUnauthorized, "未登录")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	passkey, err := s.Store.RenameUserPasskey(r.Context(), sess.GlobalUserID, id, req.Name)
	switch {
	case errors.Is(err, store.ErrPasskeyNotFound):
		protocol.WriteError(w, http.StatusNotFound, "通行密钥不存在")
	case err != nil:
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
	default:
		protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "passkey": passkey})
	}
}

// handleDeleteMyPasskey removes one of the signed-in user's passkeys.
func (s *Server) handleDeleteMyPasskey(w http.ResponseWriter, r *http.Request) {
	id, ok := passkeyIDParam(w, r)
	if !ok {
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.GlobalUserID <= 0 {
		protocol.WriteError(w, http.StatusUnauthorized, "未登录")
		return
	}
	switch err := s.Store.DeletePasskey(r.Context(), id, sess.GlobalUserID, 0); {
	case errors.Is(err, store.ErrPasskeyNotFound):
		protocol.WriteError(w, http.StatusNotFound, "通行密钥不存在")
	case err != nil:
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
	default:
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// handleAdminPasskeys shows settings, configuration and use.
func (s *Server) handleAdminPasskeys(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Store.GetPasskeySettings(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return
	}
	overview, err := s.Store.GetPasskeyOverview(r.Context(), 21, time.Now().UTC())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "通行密钥服务暂不可用")
		return
	}
	party, rpErr := s.passkeyRP()
	response := map[string]any{
		"settings": settings, "overview": overview,
		"configured": rpErr == nil, "rp_id": "", "origins": []string{},
	}
	if party != nil {
		response["rp_id"], response["origins"] = party.rpID, party.origins
	}
	if rpErr != nil {
		response["config_error"] = rpErr.Error()
	}
	protocol.WriteJSON(w, http.StatusOK, response)
}

// handleAdminUpdatePasskeySettings saves the administrator's settings.
func (s *Server) handleAdminUpdatePasskeySettings(w http.ResponseWriter, r *http.Request) {
	var settings store.PasskeySettings
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	if err := decoder.Decode(&settings); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	adminID := int64(0)
	if sess := currentSession(r); sess != nil {
		adminID = sess.AdminID
	}
	saved, err := s.Store.UpdatePasskeySettings(r.Context(), settings, adminID, time.Now().UTC())
	switch {
	case errors.Is(err, store.ErrInvalidPasskeyInput):
		protocol.WriteError(w, http.StatusBadRequest, "设置不合法：数量 1–10，按钮文字 1–24 字，提示最多 80 字")
	case err != nil:
		protocol.WriteError(w, http.StatusServiceUnavailable, "保存失败")
	default:
		protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": saved})
	}
}

// handleAdminDeletePasskey removes any user's passkey.
func (s *Server) handleAdminDeletePasskey(w http.ResponseWriter, r *http.Request) {
	id, ok := passkeyIDParam(w, r)
	if !ok {
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	switch err := s.Store.DeletePasskey(r.Context(), id, 0, sess.AdminID); {
	case errors.Is(err, store.ErrPasskeyNotFound):
		protocol.WriteError(w, http.StatusNotFound, "通行密钥不存在")
	case err != nil:
		protocol.WriteError(w, http.StatusServiceUnavailable, "删除失败")
	default:
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// handleAdminDeleteUserPasskeys removes all passkeys of one user.
func (s *Server) handleAdminDeleteUserPasskeys(w http.ResponseWriter, r *http.Request) {
	userUUID := chi.URLParam(r, "uuid")
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	if !isUUID(userUUID) {
		protocol.WriteError(w, http.StatusBadRequest, "用户 ID 无效")
		return
	}
	removed, err := s.Store.DeleteAllUserPasskeys(r.Context(), userUUID, sess.AdminID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "删除失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
}

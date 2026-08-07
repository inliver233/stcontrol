package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	oauthStateTTL        = 10 * time.Minute
	oauthPendingTTL      = 10 * time.Minute
	oauthPendingClaimTTL = 2 * time.Minute
	oauthPendingCookie   = "stcontrol_oauth_pending"
)

// handleOAuthBegin 发起 OAuth 跳转。query: node_id（注册目标节点，可选）。
func (s *Server) handleOAuthBegin(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	provider := providerOf(r)
	cfg, ok := s.oauthProviderConfig(provider)
	if !ok || !cfg.Enabled {
		protocol.WriteError(w, http.StatusBadRequest, "该登录方式未启用")
		return
	}
	var nodeID *int64
	if v := r.URL.Query().Get("node_id"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil || parsed <= 0 {
			protocol.WriteError(w, http.StatusBadRequest, "节点 ID 无效")
			return
		}
		node, err := s.Store.GetNodeByID(r.Context(), parsed)
		if err != nil || node == nil || !s.nodeRegistrable(node) {
			protocol.WriteError(w, http.StatusConflict, "节点当前不可注册")
			return
		}
		nodeID = &parsed
	}
	state, err := randomBearerToken()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "OAuth 状态生成失败")
		return
	}
	stateHash := sha256.Sum256([]byte(state))
	now := time.Now().UTC()
	if err := s.Store.CreateOAuthState(r.Context(), stateHash[:], provider, nodeID, now.Add(oauthStateTTL), now); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "OAuth 状态保存失败")
		return
	}

	var authURL string
	switch provider {
	case "discord":
		authURL = "https://discord.com/api/oauth2/authorize?" + url.Values{
			"client_id":     {cfg.ClientID},
			"redirect_uri":  {cfg.CallbackURL},
			"response_type": {"code"},
			"scope":         {"identify"},
			"state":         {state},
		}.Encode()
	case "linuxdo":
		base := cfg.AuthURL
		if base == "" {
			base = "https://connect.linux.do/oauth2/authorize"
		}
		authURL = base + "?" + url.Values{
			"client_id":     {cfg.ClientID},
			"redirect_uri":  {cfg.CallbackURL},
			"response_type": {"code"},
			"state":         {state},
		}.Encode()
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOAuthCallback OAuth 回调：换 token → 取用户信息 → 找/建用户 → 登录或引导选节点。
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	provider := providerOf(r)
	cfg, ok := s.oauthProviderConfig(provider)
	if !ok || !cfg.Enabled {
		protocol.WriteError(w, http.StatusBadRequest, "该登录方式未启用")
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		protocol.WriteError(w, http.StatusBadRequest, "OAuth 状态无效")
		return
	}
	stateHash := sha256.Sum256([]byte(state))
	nodeID, consumed, err := s.Store.ConsumeOAuthState(r.Context(), stateHash[:], provider, time.Now().UTC())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "OAuth 状态验证失败")
		return
	}
	if !consumed {
		protocol.WriteError(w, http.StatusBadRequest, "OAuth 状态无效")
		return
	}

	oauthID, displayName, avatarURL, err := s.exchangeOAuthUser(r.Context(), provider, cfg, code)
	if err != nil {
		protocol.WriteError(w, http.StatusBadGateway, "OAuth 验证失败")
		return
	}

	ctx := r.Context()
	user, err := s.Store.GetUserByOAuth(ctx, provider, oauthID)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}

	if user == nil {
		if nodeID == nil {
			pendingToken, err := randomBearerToken()
			if err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, "待注册凭证生成失败")
				return
			}
			pendingID, err := newUUID()
			if err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, "待注册凭证生成失败")
				return
			}
			pendingHash := sha256.Sum256([]byte(pendingToken))
			now := time.Now().UTC()
			if strings.TrimSpace(displayName) == "" {
				displayName = provider + " user"
			}
			if err := s.Store.CreateOAuthPending(ctx, store.CreateOAuthPendingParams{
				ID: pendingID, TokenHash: pendingHash[:], Provider: provider,
				ProviderSubject: oauthID, DisplayName: displayName, AvatarURL: avatarURL,
				ExpiresAt: now.Add(oauthPendingTTL), Now: now,
			}); err != nil {
				protocol.WriteError(w, http.StatusServiceUnavailable, "待注册状态保存失败")
				return
			}
			s.setOAuthPendingCookie(w, r, pendingToken, int(oauthPendingTTL.Seconds()))
			http.Redirect(w, r, "/select-node", http.StatusFound)
			return
		}
		user, err = s.provisionOAuthUser(ctx, provider, oauthID, displayName, avatarURL, *nodeID)
		if err != nil {
			protocol.WriteError(w, http.StatusBadGateway, "创建账号失败")
			return
		}
	}
	if user.Status != "active" {
		protocol.WriteError(w, http.StatusForbidden, "账号已被禁用")
		return
	}

	if err := s.createUserSession(w, r, user); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "创建会话失败")
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

type completeOAuthRequest struct {
	NodeID int64 `json:"node_id"`
}

// handleOAuthComplete finishes a new OAuth enrollment after node selection.
// Identity attributes never transit the browser.
func (s *Server) handleOAuthComplete(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	if !s.validMutationOrigin(r) {
		protocol.WriteError(w, http.StatusForbidden, "请求来源无效")
		return
	}
	var req completeOAuthRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.NodeID <= 0 {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	cookie, err := r.Cookie(oauthPendingCookie)
	if err != nil || cookie.Value == "" {
		protocol.WriteError(w, http.StatusUnauthorized, "OAuth 待注册状态不存在或已过期")
		return
	}
	tokenHash := sha256.Sum256([]byte(cookie.Value))
	claimID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "注册操作创建失败")
		return
	}
	now := time.Now().UTC()
	pending, found, err := s.Store.ClaimOAuthPending(r.Context(), tokenHash[:], claimID, now, oauthPendingClaimTTL)
	if errors.Is(err, store.ErrOAuthPendingBusy) {
		protocol.WriteError(w, http.StatusConflict, "该注册正在处理中，请稍后重试")
		return
	}
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取待注册状态失败")
		return
	}
	if !found {
		s.clearOAuthPendingCookie(w, r)
		protocol.WriteError(w, http.StatusUnauthorized, "OAuth 待注册状态不存在或已过期")
		return
	}

	var user *store.User
	if pending.AlreadyCompleted {
		user, err = s.Store.GetUserByID(r.Context(), pending.ResultUserID)
	} else {
		user, err = s.Store.GetUserByOAuth(r.Context(), pending.Provider, pending.ProviderSubject)
		if err == nil && user == nil {
			user, err = s.provisionOAuthUser(
				r.Context(), pending.Provider, pending.ProviderSubject,
				pending.DisplayName, pending.AvatarURL, req.NodeID,
			)
		}
		if err != nil || user == nil {
			_ = s.Store.ReleaseOAuthPending(r.Context(), pending.ID, pending.ClaimID, time.Now().UTC())
			protocol.WriteError(w, http.StatusBadGateway, "创建账号失败")
			return
		}
		completed, err := s.Store.CompleteOAuthPending(
			r.Context(), pending.ID, pending.ClaimID, user.ID, time.Now().UTC(),
		)
		if err != nil || !completed {
			_ = s.Store.ReleaseOAuthPending(r.Context(), pending.ID, pending.ClaimID, time.Now().UTC())
			protocol.WriteError(w, http.StatusConflict, "注册操作已失效，请重试")
			return
		}
	}
	if err != nil || user == nil || user.Status != "active" {
		protocol.WriteError(w, http.StatusForbidden, "账号不可用")
		return
	}
	if err := s.createUserSession(w, r, user); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "创建会话失败")
		return
	}
	s.clearOAuthPendingCookie(w, r)
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "username": user.Username})
}

func (s *Server) setOAuthPendingCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: oauthPendingCookie, Value: token, Path: "/api/auth/oauth/complete",
		HttpOnly: true, Secure: s.secureCookies(r), SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

func (s *Server) clearOAuthPendingCookie(w http.ResponseWriter, r *http.Request) {
	s.setOAuthPendingCookie(w, r, "", -1)
}

// provisionOAuthUser 为 OAuth 新用户生成 handle、随机占位密码, 代注册到节点并建总控用户。
func (s *Server) provisionOAuthUser(ctx context.Context, provider, oauthID, displayName, avatarURL string, nodeID int64) (*store.User, error) {
	node, err := s.Store.GetNodeByID(ctx, nodeID)
	if err != nil || node == nil {
		return nil, fmt.Errorf("节点不存在")
	}
	if !s.nodeRegistrable(node) {
		return nil, fmt.Errorf("节点当前不可注册")
	}
	// 生成 handle: displayName 规范化, 冲突则加随机后缀
	base := NormalizeHandle(displayName)
	if !isValidHandle(base) {
		suffix, err := randomHexToken(3)
		if err != nil {
			return nil, err
		}
		base = provider + "-" + suffix
	}
	handle := base
	for i := 0; i < 5; i++ {
		existing, _ := s.Store.GetUserByUsername(ctx, handle)
		if existing == nil {
			break
		}
		suffix, err := randomHexToken(2)
		if err != nil {
			return nil, err
		}
		handle = fmt.Sprintf("%s-%s", base, suffix)
	}
	// 随机占位密码(节点侧, 用户用不到)
	randPw, err := crypto.RandomPassword(24)
	if err != nil {
		return nil, err
	}
	provReq := &protocol.ProvisionUserRequest{
		Handle: handle, Name: displayName, Password: randPw,
	}
	if _, err := s.agent.provisionUser(ctx, node.ID, node.AgentPSK, node.AgentURL, provReq); err != nil {
		return nil, err
	}
	user := &store.User{
		Username:     handle,
		DisplayName:  displayName,
		AuthProvider: provider,
		OAuthID:      sql.NullString{String: oauthID, Valid: true},
		AvatarURL:    sql.NullString{String: avatarURL, Valid: avatarURL != ""},
		HomeNodeID:   sql.NullInt64{Int64: node.ID, Valid: true},
		Status:       "active",
	}
	if err := s.Store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	_ = s.Store.UpsertReplica(ctx, &store.UserReplica{
		UserID: user.ID, NodeID: node.ID, Kind: "home", State: "ready",
	})
	_ = s.Store.Audit(ctx, handle, "oauth-register-"+provider, node.Name, nil)
	return user, nil
}

// oauthProviderConfig 返回指定 provider 的配置。
func (s *Server) oauthProviderConfig(provider string) (cfg oauthCfg, ok bool) {
	switch provider {
	case "discord":
		c := s.Cfg.OAuth.Discord
		return oauthCfg{Enabled: c.Enabled, ClientID: c.ClientID, ClientSecret: c.ClientSecret,
			CallbackURL: c.CallbackURL, GuildID: c.GuildID}, c.Enabled
	case "linuxdo":
		c := s.Cfg.OAuth.LinuxDo
		return oauthCfg{Enabled: c.Enabled, ClientID: c.ClientID, ClientSecret: c.ClientSecret,
			CallbackURL: c.CallbackURL, AuthURL: c.AuthURL, TokenURL: c.TokenURL, UserInfoURL: c.UserInfoURL}, c.Enabled
	}
	return oauthCfg{}, false
}

type oauthCfg struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	CallbackURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	GuildID      string
}

// exchangeOAuthUser exchanges a short-lived authorization code using a bounded,
// injectable HTTP client so provider dependencies can be safely tested.
func (s *Server) exchangeOAuthUser(ctx context.Context, provider string, cfg oauthCfg, code string) (string, string, string, error) {
	switch provider {
	case "discord":
		return s.exchangeDiscord(ctx, cfg, code)
	case "linuxdo":
		return s.exchangeLinuxDo(ctx, cfg, code)
	}
	return "", "", "", fmt.Errorf("未知 provider")
}

func (s *Server) exchangeDiscord(ctx context.Context, cfg oauthCfg, code string) (string, string, string, error) {
	resp, err := s.postOAuthForm(ctx, "https://discord.com/api/oauth2/token", url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.CallbackURL},
	})
	if err != nil {
		return "", "", "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeOAuthResponse(resp, &tok); err != nil || tok.AccessToken == "" {
		return "", "", "", fmt.Errorf("获取 access_token 失败")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/users/@me", nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uresp, err := s.oauthClient().Do(req)
	if err != nil {
		return "", "", "", err
	}
	var me struct {
		ID         string `json:"id"`
		Username   string `json:"username"`
		GlobalName string `json:"global_name"`
		Avatar     string `json:"avatar"`
	}
	if err := decodeOAuthResponse(uresp, &me); err != nil || me.ID == "" || me.Username == "" {
		return "", "", "", fmt.Errorf("获取 Discord 用户失败")
	}
	if cfg.GuildID != "" {
		membershipURL := "https://discord.com/api/users/@me/guilds/" + url.PathEscape(cfg.GuildID) + "/member"
		membershipReq, err := http.NewRequestWithContext(ctx, http.MethodGet, membershipURL, nil)
		if err != nil {
			return "", "", "", err
		}
		membershipReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		membershipResp, err := s.oauthClient().Do(membershipReq)
		if err != nil {
			return "", "", "", err
		}
		if err := decodeOAuthResponse(membershipResp, &struct{}{}); err != nil {
			return "", "", "", fmt.Errorf("Discord 公会成员校验失败")
		}
	}
	name := me.GlobalName
	if name == "" {
		name = me.Username
	}
	avatar := ""
	if me.Avatar != "" {
		avatar = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", me.ID, me.Avatar)
	}
	return me.ID, name, avatar, nil
}

func (s *Server) exchangeLinuxDo(ctx context.Context, cfg oauthCfg, code string) (string, string, string, error) {
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://connect.linux.do/oauth2/token"
	}
	resp, err := s.postOAuthForm(ctx, tokenURL, url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.CallbackURL},
	})
	if err != nil {
		return "", "", "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeOAuthResponse(resp, &tok); err != nil || tok.AccessToken == "" {
		return "", "", "", fmt.Errorf("获取 access_token 失败")
	}
	userInfoURL := cfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://connect.linux.do/api/user"
	}
	parsedUserInfo, err := url.Parse(userInfoURL)
	if err != nil || parsedUserInfo.Scheme != "https" || parsedUserInfo.Host == "" {
		return "", "", "", fmt.Errorf("OAuth endpoint must use HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uresp, err := s.oauthClient().Do(req)
	if err != nil {
		return "", "", "", err
	}
	var me struct {
		ID             json.Number `json:"id"`
		Username       string      `json:"username"`
		Name           string      `json:"name"`
		AvatarTemplate string      `json:"avatar_template"`
	}
	if err := decodeOAuthResponse(uresp, &me); err != nil || me.ID.String() == "" || me.Username == "" {
		return "", "", "", fmt.Errorf("获取 LinuxDo 用户失败")
	}
	name := me.Name
	if name == "" {
		name = me.Username
	}
	avatar := me.AvatarTemplate
	if avatar != "" && strings.HasPrefix(avatar, "/") {
		avatar = "https://connect.linux.do" + strings.Replace(avatar, "{size}", "96", 1)
	}
	return me.ID.String(), name, avatar, nil
}

func (s *Server) oauthClient() *http.Client {
	if s.oauthHTTP != nil {
		return s.oauthHTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (s *Server) postOAuthForm(ctx context.Context, endpoint string, values url.Values) (*http.Response, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("OAuth endpoint must use HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return s.oauthClient().Do(req)
}

func decodeOAuthResponse(response *http.Response, out any) error {
	if response == nil {
		return fmt.Errorf("empty OAuth response")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return fmt.Errorf("OAuth provider returned status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.UseNumber()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode OAuth response: %w", err)
	}
	return nil
}

func providerOf(r *http.Request) string {
	return chi.URLParam(r, "provider")
}

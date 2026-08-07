package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// oauthState 临时 state（防 CSRF），存内存。
// 生产可多实例时改 Redis/DB。
type oauthStateEntry struct {
	Provider  string
	NodeID    int64
	ExpiresAt time.Time
}

var oauthStates = struct {
	m map[string]*oauthStateEntry
}{m: make(map[string]*oauthStateEntry)}

// handleOAuthBegin 发起 OAuth 跳转。query: node_id（注册目标节点，可选）。
func (s *Server) handleOAuthBegin(w http.ResponseWriter, r *http.Request) {
	provider := providerOf(r)
	cfg, ok := s.oauthProviderConfig(provider)
	if !ok || !cfg.Enabled {
		protocol.WriteError(w, http.StatusBadRequest, "该登录方式未启用")
		return
	}
	nodeID := int64(0)
	if v := r.URL.Query().Get("node_id"); v != "" {
		fmt.Sscanf(v, "%d", &nodeID)
	}
	state, err := randomBearerToken()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "OAuth 状态生成失败")
		return
	}
	oauthStates.m[state] = &oauthStateEntry{
		Provider: provider, NodeID: nodeID,
		ExpiresAt: time.Now().Add(10 * time.Minute),
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
	provider := providerOf(r)
	cfg, ok := s.oauthProviderConfig(provider)
	if !ok || !cfg.Enabled {
		protocol.WriteError(w, http.StatusBadRequest, "该登录方式未启用")
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	entry := oauthStates.m[state]
	if code == "" || entry == nil || time.Now().After(entry.ExpiresAt) || entry.Provider != provider {
		protocol.WriteError(w, http.StatusBadRequest, "OAuth 状态无效")
		return
	}
	delete(oauthStates.m, state)

	oauthID, displayName, avatarURL, err := s.exchangeOAuthUser(provider, cfg, code)
	if err != nil {
		protocol.WriteError(w, http.StatusBadGateway, "OAuth 验证失败: "+err.Error())
		return
	}

	ctx := r.Context()
	user, err := s.Store.GetUserByOAuth(ctx, provider, oauthID)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}

	if user == nil {
		// 新用户: 需先选节点才能代注册。若无 node_id, 跳前端选节点页(携带临时 pending token)。
		if entry.NodeID == 0 {
			// 前端路由: /select-node?provider=...&oauth_id=...&name=...
			redirect := fmt.Sprintf("/select-node?provider=%s&oauth_id=%s&name=%s&avatar=%s",
				provider, url.QueryEscape(oauthID), url.QueryEscape(displayName), url.QueryEscape(avatarURL))
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		user, err = s.provisionOAuthUser(ctx, provider, oauthID, displayName, avatarURL, entry.NodeID)
		if err != nil {
			protocol.WriteError(w, http.StatusBadGateway, "创建账号失败: "+err.Error())
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

// exchangeOAuthUser 用 code 换 token 并拉取用户信息，返回 (oauthID, displayName, avatarURL)。
func (s *Server) exchangeOAuthUser(provider string, cfg oauthCfg, code string) (string, string, string, error) {
	switch provider {
	case "discord":
		return s.exchangeDiscord(cfg, code)
	case "linuxdo":
		return s.exchangeLinuxDo(cfg, code)
	}
	return "", "", "", fmt.Errorf("未知 provider")
}

func (s *Server) exchangeDiscord(cfg oauthCfg, code string) (string, string, string, error) {
	tokenURL := "https://discord.com/api/oauth2/token"
	resp, err := http.PostForm(tokenURL, url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.CallbackURL},
	})
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", "", "", fmt.Errorf("获取 access_token 失败")
	}
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uresp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer uresp.Body.Close()
	var me struct {
		ID         string `json:"id"`
		Username   string `json:"username"`
		GlobalName string `json:"global_name"`
		Avatar     string `json:"avatar"`
	}
	if err := json.NewDecoder(uresp.Body).Decode(&me); err != nil {
		return "", "", "", err
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

func (s *Server) exchangeLinuxDo(cfg oauthCfg, code string) (string, string, string, error) {
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://connect.linux.do/oauth2/token"
	}
	resp, err := http.PostForm(tokenURL, url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.CallbackURL},
	})
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", "", "", fmt.Errorf("获取 access_token 失败")
	}
	userInfoURL := cfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://connect.linux.do/api/user"
	}
	req, _ := http.NewRequest("GET", userInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uresp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer uresp.Body.Close()
	var me struct {
		ID             json.Number `json:"id"`
		Username       string      `json:"username"`
		Name           string      `json:"name"`
		AvatarTemplate string      `json:"avatar_template"`
	}
	if err := json.NewDecoder(uresp.Body).Decode(&me); err != nil {
		return "", "", "", err
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

func providerOf(r *http.Request) string {
	return chi.URLParam(r, "provider")
}

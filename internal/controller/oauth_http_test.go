package controller

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExchangeLinuxDoUsesBoundedInjectableClient(t *testing.T) {
	t.Parallel()
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Errorf("unexpected token request: %s %s", r.Method, r.Header.Get("Content-Type"))
			}
			_ = r.ParseForm()
			if r.Form.Get("code") != "authorization-code" || r.Form.Get("client_secret") != "client-secret" {
				t.Errorf("unexpected token form: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"provider-token"}`)
		case "/user":
			if r.Header.Get("Authorization") != "Bearer provider-token" {
				t.Errorf("missing bearer authorization: %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":123,"username":"alice","name":"Alice","avatar_template":"/avatar/{size}.png"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	server := &Server{oauthHTTP: provider.Client()}
	id, name, avatar, err := server.exchangeLinuxDo(context.Background(), oauthCfg{
		ClientID: "client-id", ClientSecret: "client-secret", CallbackURL: "https://control.example/callback",
		TokenURL: provider.URL + "/token", UserInfoURL: provider.URL + "/user",
	}, "authorization-code")
	if err != nil {
		t.Fatalf("exchangeLinuxDo: %v", err)
	}
	if id != "123" || name != "Alice" || avatar != "https://connect.linux.do/avatar/96.png" {
		t.Fatalf("unexpected identity: id=%q name=%q avatar=%q", id, name, avatar)
	}
}

func TestExchangeLinuxDoRejectsProviderErrorAndInsecureURL(t *testing.T) {
	t.Parallel()
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "secret provider details", http.StatusBadGateway)
	}))
	defer provider.Close()
	server := &Server{oauthHTTP: provider.Client()}
	_, _, _, err := server.exchangeLinuxDo(context.Background(), oauthCfg{
		TokenURL: provider.URL, UserInfoURL: provider.URL,
	}, "code")
	if err == nil || strings.Contains(err.Error(), "secret provider details") {
		t.Fatalf("provider error was not safely summarized: %v", err)
	}
	_, err = server.postOAuthForm(context.Background(), "http://provider.example/token", nil)
	if err == nil {
		t.Fatal("insecure OAuth endpoint accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestExchangeDiscordChecksConfiguredGuildMembership(t *testing.T) {
	t.Parallel()
	seenMembership := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{}`
		switch request.URL.Path {
		case "/api/oauth2/token":
			body = `{"access_token":"discord-token"}`
		case "/api/users/@me":
			body = `{"id":"42","username":"alice","global_name":"Alice","avatar":"avatar-hash"}`
		case "/api/users/@me/guilds/guild-1/member":
			seenMembership = true
			if request.Header.Get("Authorization") != "Bearer discord-token" {
				t.Fatalf("membership request missing bearer token")
			}
		default:
			t.Fatalf("unexpected Discord URL: %s", request.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})}
	server := &Server{oauthHTTP: client}
	id, name, avatar, err := server.exchangeDiscord(context.Background(), oauthCfg{
		ClientID: "client", ClientSecret: "secret", CallbackURL: "https://control.example/callback", GuildID: "guild-1",
	}, "code")
	if err != nil {
		t.Fatalf("exchangeDiscord: %v", err)
	}
	if !seenMembership || id != "42" || name != "Alice" || avatar == "" {
		t.Fatalf("unexpected Discord result: membership=%v id=%q name=%q avatar=%q", seenMembership, id, name, avatar)
	}
}

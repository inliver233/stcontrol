package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseProviderKindAndConfiguration(t *testing.T) {
	t.Parallel()
	for _, value := range []string{" OPENAI ", "openai_responses", "Anthropic", "GEMINI", "openai_compatible"} {
		if _, err := ParseProviderKind(value); err != nil {
			t.Errorf("ParseProviderKind(%q): %v", value, err)
		}
	}
	if _, err := ParseProviderKind("unknown"); err == nil {
		t.Fatal("unknown provider accepted")
	}
	for _, cfg := range []ProviderConfig{
		{},
		{Kind: ProviderOpenAI, BaseURL: "https://example.test"},
		{Kind: ProviderOpenAI, Model: "model"},
		{Kind: ProviderKind("unknown"), Model: "model"},
	} {
		if _, err := NewProvider(cfg); err == nil {
			t.Fatalf("invalid configuration accepted: %+v", cfg)
		}
	}
	for _, cfg := range []ProviderConfig{
		{Kind: ProviderOpenAI, BaseURL: "https://example.test/", Model: "model"},
		{Kind: ProviderOpenAIResponses, BaseURL: "https://example.test", Model: "model"},
		{Kind: ProviderAnthropic, Model: "model"},
		{Kind: ProviderGemini, Model: "model"},
		{Kind: ProviderOpenAICompat, BaseURL: "https://example.test", Model: "model"},
	} {
		if provider, err := NewProvider(cfg); err != nil || provider == nil {
			t.Fatalf("valid configuration rejected: %+v provider=%T err=%v", cfg, provider, err)
		}
	}
}

func TestProvidersSendAuthenticatedStructuredRequests(t *testing.T) {
	t.Parallel()
	type observedRequest struct {
		Path          string
		Authorization string
		AnthropicKey  string
		GeminiKey     string
		RawQuery      string
		Body          map[string]any
	}
	var mu sync.Mutex
	var observed []observedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		observed = append(observed, observedRequest{
			Path: r.URL.Path, Authorization: r.Header.Get("Authorization"),
			AnthropicKey: r.Header.Get("x-api-key"), GeminiKey: r.Header.Get("x-goog-api-key"),
			RawQuery: r.URL.RawQuery, Body: body,
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"chat-result"}}]}`)
		case strings.HasSuffix(r.URL.Path, "/responses"):
			_, _ = io.WriteString(w, `{"output_text":"responses-result"}`)
		case strings.HasSuffix(r.URL.Path, "/v1/messages"):
			_, _ = io.WriteString(w, `{"content":[{"type":"tool","text":"ignored"},{"type":"text","text":"anthropic-result"}]}`)
		case strings.Contains(r.URL.Path, ":generateContent"):
			_, _ = io.WriteString(w, `{"candidates":[{"content":{"parts":[{"text":"gemini-result"}]}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		kind ProviderKind
		want string
	}{
		{ProviderOpenAI, "chat-result"},
		{ProviderOpenAIResponses, "responses-result"},
		{ProviderAnthropic, "anthropic-result"},
		{ProviderGemini, "gemini-result"},
	}
	for _, test := range tests {
		provider, err := NewProvider(ProviderConfig{
			Kind: test.kind, BaseURL: server.URL + "/", APIKey: "secret-api-key", Model: "configured-model",
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := provider.Complete(context.Background(), CallParams{
			Model: "request-model", SystemPrompt: "system", TaskPrompt: "task",
			Observation: []byte(`{"node":"redacted"}`), Timeout: time.Second,
		})
		if err != nil || got != test.want {
			t.Errorf("kind=%s result=%q err=%v", test.kind, got, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(observed) != len(tests) {
		t.Fatalf("observed requests=%d, want %d", len(observed), len(tests))
	}
	for _, request := range observed {
		if request.RawQuery != "" || !strings.Contains(mustJSON(t, request.Body), "observed_data") {
			t.Errorf("unsafe or incomplete provider request: %+v", request)
		}
		switch {
		case strings.HasSuffix(request.Path, "/chat/completions"), strings.HasSuffix(request.Path, "/responses"):
			if request.Authorization != "Bearer secret-api-key" {
				t.Errorf("authorization=%q", request.Authorization)
			}
		case strings.HasSuffix(request.Path, "/v1/messages"):
			if request.AnthropicKey != "secret-api-key" {
				t.Errorf("anthropic key=%q", request.AnthropicKey)
			}
		case strings.Contains(request.Path, ":generateContent"):
			if request.GeminiKey != "secret-api-key" || strings.Contains(request.RawQuery, "secret") {
				t.Errorf("gemini credentials leaked or missing: %+v", request)
			}
		}
	}
}

func TestProvidersRejectMalformedEmptyAndFailedResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		kind     ProviderKind
		response string
		want     string
	}{
		{"openai malformed", ProviderOpenAI, `{`, "decode chat completion"},
		{"openai empty", ProviderOpenAI, `{"choices":[]}`, "no choices"},
		{"responses malformed", ProviderOpenAIResponses, `{`, "decode responses"},
		{"responses empty", ProviderOpenAIResponses, `{"output_text":""}`, "empty output_text"},
		{"anthropic malformed", ProviderAnthropic, `{`, "decode anthropic messages"},
		{"anthropic empty", ProviderAnthropic, `{"content":[{"type":"tool","text":"ignored"}]}`, "no text block"},
		{"gemini malformed", ProviderGemini, `{`, "decode gemini response"},
		{"gemini empty", ProviderGemini, `{"candidates":[]}`, "no candidates"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, test.response)
			}))
			defer server.Close()
			provider, err := NewProvider(ProviderConfig{Kind: test.kind, BaseURL: server.URL, Model: "model"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Complete(context.Background(), CallParams{Model: "model"}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestProviderHTTPFailuresAreBoundedAndTimeoutsPropagate(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "timeout") {
			time.Sleep(100 * time.Millisecond)
			_, _ = io.WriteString(w, `{\"choices\":[{\"message\":{\"content\":\"late\"}}]}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, strings.Repeat("sensitive-upstream-detail", 1000))
	}))
	defer server.Close()

	provider, err := NewProvider(ProviderConfig{Kind: ProviderOpenAI, BaseURL: server.URL, Model: "model"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Complete(context.Background(), CallParams{Model: "model"})
	if err == nil || !strings.Contains(err.Error(), "429 Too Many Requests") || len(err.Error()) > 4200 {
		t.Fatalf("bounded HTTP error=%v length=%d", err, len(err.Error()))
	}

	timeoutProvider, err := NewProvider(ProviderConfig{
		Kind: ProviderOpenAI, BaseURL: server.URL + "/timeout", Model: "model", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = timeoutProvider.Complete(context.Background(), CallParams{Model: "model", Timeout: 10 * time.Millisecond})
	if err == nil || (!errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline exceeded")) {
		t.Fatalf("timeout error=%v", err)
	}

	badProvider, err := NewProvider(ProviderConfig{Kind: ProviderOpenAI, BaseURL: "://bad-url", Model: "model"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badProvider.Complete(context.Background(), CallParams{Model: "model"}); err == nil {
		t.Fatal("malformed request URL was accepted")
	}
	if _, err := postJSON(context.Background(), http.DefaultClient, server.URL, nil, make(chan int)); err == nil {
		t.Fatal("unencodable request body was accepted")
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

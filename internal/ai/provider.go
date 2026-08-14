// Package ai implements the AI 监管层 (read-only advisory layer).
//
// Design invariants (ai接入优化方案详细.md §3/§4):
//   - AI is never on any request critical path; a background worker drives it.
//   - AI consumes only redacted observation snapshots and emits structured
//     JSON advisories; it has no write capability anywhere.
//   - Every advisory passes local schema/allowlist/evidence/hard-gate
//     validation before it may be shown or auto-adopted.
//   - AI off (default) == zero behavior difference.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProviderKind enumerates the supported provider wire formats. Models and
// endpoints are fully user-defined (Cherry Studio style); the system only
// implements request construction and response parsing per provider format.
type ProviderKind string

const (
	ProviderOpenAI          ProviderKind = "openai"            // Chat Completions
	ProviderOpenAIResponses ProviderKind = "openai_responses"  // Responses API
	ProviderAnthropic       ProviderKind = "anthropic"         // Messages API
	ProviderGemini          ProviderKind = "gemini"            // generateContent
	ProviderOpenAICompat    ProviderKind = "openai_compatible" // any OpenAI-compatible endpoint
)

// ParseProviderKind validates a configured provider name.
func ParseProviderKind(value string) (ProviderKind, error) {
	switch ProviderKind(strings.ToLower(strings.TrimSpace(value))) {
	case ProviderOpenAI, ProviderOpenAIResponses, ProviderAnthropic,
		ProviderGemini, ProviderOpenAICompat:
		return ProviderKind(strings.ToLower(strings.TrimSpace(value))), nil
	default:
		return "", fmt.Errorf("unsupported ai provider %q", value)
	}
}

// CallParams is the normalized request the supervisor passes to a provider.
// SystemPrompt and TaskPrompt are the fixed versioned prompt pair; the
// observation is always embedded as data (observed_data), never as an
// instruction.
type CallParams struct {
	Model        string
	SystemPrompt string
	TaskPrompt   string
	Observation  []byte // redacted observation JSON (observed_data)
	Timeout      time.Duration
}

// Provider is the supplier-agnostic chat interface.
type Provider interface {
	// Complete sends one request and returns the raw text payload. The
	// implementation must enforce the deadline and cap the response size.
	Complete(ctx context.Context, params CallParams) (string, error)
}

// ProviderConfig carries the user-defined endpoint and credentials.
type ProviderConfig struct {
	Kind    ProviderKind
	BaseURL string // scheme://host[:port] (user-defined; may be any endpoint)
	APIKey  string // from env only
	Model   string
	Timeout time.Duration
}

// NewProvider builds a provider for the configured kind. Unknown kinds are
// rejected at configuration time, so callers may treat the error as fatal.
func NewProvider(cfg ProviderConfig) (Provider, error) {
	if cfg.Kind == "" {
		return nil, fmt.Errorf("empty ai provider kind")
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("ai provider model must be configured")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	client := &http.Client{Timeout: cfg.Timeout}
	switch cfg.Kind {
	case ProviderOpenAI, ProviderOpenAICompat:
		if base == "" {
			return nil, fmt.Errorf("ai provider base_url must be configured")
		}
		return &openAICompletionsProvider{client: client, cfg: cfg, base: base}, nil
	case ProviderOpenAIResponses:
		if base == "" {
			return nil, fmt.Errorf("ai provider base_url must be configured")
		}
		return &openAIResponsesProvider{client: client, cfg: cfg, base: base}, nil
	case ProviderAnthropic:
		if base == "" {
			base = "https://api.anthropic.com"
		}
		return &anthropicProvider{client: client, cfg: cfg, base: base}, nil
	case ProviderGemini:
		if base == "" {
			base = "https://generativelanguage.googleapis.com"
		}
		return &geminiProvider{client: client, cfg: cfg, base: base}, nil
	default:
		return nil, fmt.Errorf("unsupported ai provider %q", cfg.Kind)
	}
}

const maxAIResponseBytes = 256 << 10 // 256 KiB hard cap

func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("ai provider returned %s: %s", resp.Status, strings.TrimSpace(string(limited)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxAIResponseBytes))
}

// ---------- OpenAI Chat Completions ----------

type openAICompletionsProvider struct {
	client *http.Client
	cfg    ProviderConfig
	base   string
}

func (p *openAICompletionsProvider) Complete(ctx context.Context, params CallParams) (string, error) {
	body := map[string]any{
		"model": params.Model,
		"messages": []map[string]string{
			{"role": "system", "content": params.SystemPrompt},
			{"role": "user", "content": params.TaskPrompt + "\n\nobserved_data:\n" + string(params.Observation)},
		},
		"temperature": 0.0,
	}
	if params.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, params.Timeout)
		defer cancel()
	}
	raw, err := postJSON(ctx, p.client, p.base+"/chat/completions", map[string]string{
		"Authorization": "Bearer " + p.cfg.APIKey,
	}, body)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode chat completion: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("chat completion returned no choices")
	}
	return parsed.Choices[0].Message.Content, nil
}

// ---------- OpenAI Responses ----------

type openAIResponsesProvider struct {
	client *http.Client
	cfg    ProviderConfig
	base   string
}

func (p *openAIResponsesProvider) Complete(ctx context.Context, params CallParams) (string, error) {
	body := map[string]any{
		"model": params.Model,
		"input": []map[string]string{
			{"role": "system", "content": params.SystemPrompt},
			{"role": "user", "content": params.TaskPrompt + "\n\nobserved_data:\n" + string(params.Observation)},
		},
		"temperature": 0.0,
	}
	if params.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, params.Timeout)
		defer cancel()
	}
	raw, err := postJSON(ctx, p.client, p.base+"/responses", map[string]string{
		"Authorization": "Bearer " + p.cfg.APIKey,
	}, body)
	if err != nil {
		return "", err
	}
	var parsed struct {
		OutputText string `json:"output_text"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode responses: %w", err)
	}
	if parsed.OutputText == "" {
		return "", fmt.Errorf("responses returned empty output_text")
	}
	return parsed.OutputText, nil
}

// ---------- Anthropic Messages ----------

type anthropicProvider struct {
	client *http.Client
	cfg    ProviderConfig
	base   string
}

func (p *anthropicProvider) Complete(ctx context.Context, params CallParams) (string, error) {
	body := map[string]any{
		"model":      params.Model,
		"max_tokens": 2048,
		"system":     params.SystemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": params.TaskPrompt + "\n\nobserved_data:\n" + string(params.Observation)},
		},
	}
	if params.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, params.Timeout)
		defer cancel()
	}
	raw, err := postJSON(ctx, p.client, p.base+"/v1/messages", map[string]string{
		"x-api-key":         p.cfg.APIKey,
		"anthropic-version": "2023-06-01",
	}, body)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode anthropic messages: %w", err)
	}
	for _, block := range parsed.Content {
		if block.Type == "text" && block.Text != "" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("anthropic messages returned no text block")
}

// ---------- Gemini generateContent ----------

type geminiProvider struct {
	client *http.Client
	cfg    ProviderConfig
	base   string
}

func (p *geminiProvider) Complete(ctx context.Context, params CallParams) (string, error) {
	body := map[string]any{
		"contents": []map[string]any{
			{
				"role": "user",
				"parts": []map[string]string{
					{"text": params.SystemPrompt + "\n\n" + params.TaskPrompt + "\n\nobserved_data:\n" + string(params.Observation)},
				},
			},
		},
		"generationConfig": map[string]any{"temperature": 0.0},
	}
	if params.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, params.Timeout)
		defer cancel()
	}
	endpoint := p.base + "/v1beta/models/" + params.Model + ":generateContent"
	headers := map[string]string{}
	if p.cfg.APIKey != "" {
		// The API key belongs in the x-goog-api-key header, never in the URL
		// query string where it leaks into proxies and access logs.
		headers["x-goog-api-key"] = p.cfg.APIKey
	}
	raw, err := postJSON(ctx, p.client, endpoint, headers, body)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode gemini response: %w", err)
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini returned no candidates")
	}
	return parsed.Candidates[0].Content.Parts[0].Text, nil
}

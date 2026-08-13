package ai

import (
	"context"
	"fmt"
	"sync"
)

// mockProvider is the Phase 0 test double: it returns a canned raw response
// and records calls. It is used by unit tests and by the controller's test
// wiring when no real provider is configured.
type mockProvider struct {
	mu        sync.Mutex
	responses []string // consumed round-robin; last one repeats
	errs      []error  // consumed round-robin; last one repeats
	calls     []CallParams
}

// MockProvider builds a provider whose Complete returns the given responses
// in order (the final one repeats). A nil response string means the provider
// returns the matching err instead.
func MockProvider(responses []string, errs []error) *mockProvider {
	if len(responses) == 0 {
		responses = []string{`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_test","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"一切正常","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`}
	}
	return &mockProvider{responses: responses, errs: errs}
}

// Calls returns the recorded request params (for assertions).
func (m *mockProvider) Calls() []CallParams {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]CallParams(nil), m.calls...)
}

func (m *mockProvider) Complete(_ context.Context, params CallParams) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, params)
	if len(m.errs) > 0 {
		err := m.errs[0]
		if len(m.errs) > 1 {
			m.errs = m.errs[1:]
		}
		if err != nil {
			return "", err
		}
	}
	if len(m.responses) == 0 {
		return "", fmt.Errorf("mock provider exhausted")
	}
	resp := m.responses[0]
	if len(m.responses) > 1 {
		m.responses = m.responses[1:]
	}
	return resp, nil
}

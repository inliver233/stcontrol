package ai

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEveryTaskHasVersionedPromptAndUnknownTasksFailClosed(t *testing.T) {
	t.Parallel()
	if strings.TrimSpace(SystemPrompt()) == "" || !strings.Contains(SystemPrompt(), "observed_data") {
		t.Fatal("system prompt is empty or does not isolate observed_data")
	}
	for _, required := range []string{`"schema_version":"1.0"`, `"observation_id"`, `"requested_observations"`, "PROMPT_INJECTION_SUSPECTED", "REGISTRATION_POLICY_STATUS"} {
		if !strings.Contains(SystemPrompt(), required) {
			t.Fatalf("system prompt missing output contract field %s", required)
		}
	}
	for task := range taskPrompts {
		prompt, err := TaskPrompt(task)
		if err != nil || prompt == "" || !strings.Contains(prompt, "允许 action") {
			t.Errorf("task=%q prompt=%q err=%v", task, prompt, err)
		}
		rendered, err := RenderTaskPrompt(task, []byte(`{"safe":true}`))
		if err != nil || rendered == "" {
			t.Errorf("render task=%q result=%q err=%v", task, rendered, err)
		}
	}
	unknown := TaskType("unknown_task")
	if _, err := TaskPrompt(unknown); err == nil {
		t.Fatal("unknown task prompt accepted")
	}
	if _, err := RenderTaskPrompt(unknown, nil); err == nil {
		t.Fatal("unknown rendered task accepted")
	}
	err := errUnknownTask("unsafe")
	var taskErr *TaskError
	if !errors.As(err, &taskErr) || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("task error=%T %v", err, err)
	}
}

func TestSupervisorEnqueuePersistsDigestAndDeadline(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	sup := NewSupervisor(st, MockProvider(nil, nil), NewRedactor([]byte("key")), ModeShadow, "model-a", time.Second)
	before := time.Now().UTC()
	observation := []byte(`{"observation_id":"obs_enqueue"}`)
	if err := sup.EnqueueTask(context.Background(), string(TaskMonitoringInspect), observation, "dedup-a"); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.requests) != 1 {
		t.Fatalf("requests=%+v", st.requests)
	}
	req := st.requests[0]
	if req.ModelID != "model-a" || req.State != "queued" || req.DedupKey != "dedup-a" ||
		!bytes.Equal(req.ObservationJSON, observation) || len(req.ObservationDigest) != 32 ||
		req.DeadlineAt.Before(before.Add(119*time.Second)) || req.DeadlineAt.After(before.Add(121*time.Second)) {
		t.Fatalf("request=%+v", req)
	}
}

func TestSupervisorRunTicksAndStopsOnCancellation(t *testing.T) {
	st := &fakeStore{}
	sup := NewSupervisor(st, MockProvider(nil, nil), NewRedactor([]byte("key")), ModeShadow, "model-a", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	built := make(chan struct{}, 1)
	done := make(chan struct{})
	var buildCount atomic.Int32
	go func() {
		defer close(done)
		sup.Run(ctx, time.Millisecond, func(context.Context) ([]byte, map[string]bool, map[string]bool, string, string, error) {
			if buildCount.Add(1) > 1 {
				<-ctx.Done()
				return nil, nil, nil, "", "", ctx.Err()
			}
			select {
			case built <- struct{}{}:
			default:
			}
			return []byte(`{"observation_id":"obs_tick"}`), nil, nil, "tick", string(TaskMonitoringInspect), nil
		})
	}()
	select {
	case <-built:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("monitoring ticker did not build an observation")
	}
	for deadline := time.Now().Add(time.Second); ; {
		st.mu.Lock()
		persisted := len(st.requests) == 1 && st.requests[0].DedupKey == "tick"
		st.mu.Unlock()
		if persisted {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("monitoring request was not persisted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("Supervisor.Run did not stop after cancellation")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.requests) != 1 || st.requests[0].DedupKey != "tick" {
		t.Fatalf("requests=%+v", st.requests)
	}
}

func TestSupervisorMonitoringAndCatalogErrorBoundaries(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	sup := NewSupervisor(st, MockProvider(nil, nil), nil, ModeShadow, "model", time.Second)
	if err := sup.enqueueMonitoring(context.Background(), nil); err != nil {
		t.Fatalf("nil builder error=%v", err)
	}
	wantErr := errors.New("observation unavailable")
	err := sup.enqueueMonitoring(context.Background(), func(context.Context) ([]byte, map[string]bool, map[string]bool, string, string, error) {
		return nil, nil, nil, "", "", wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("builder error=%v", err)
	}
	evidence, candidates := catalogsFromObservation([]byte(`{`))
	if len(evidence) != 0 || len(candidates) != 0 {
		t.Fatalf("malformed catalogs evidence=%v candidates=%v", evidence, candidates)
	}
	evidence, candidates = catalogsFromObservation([]byte(`{"evidence_catalog":[{"ref":"ev_a"}],"candidate_catalog":[{"ref":"ref_b"}]}`))
	if !evidence["ev_a"] || !candidates["ref_b"] {
		t.Fatalf("catalogs evidence=%v candidates=%v", evidence, candidates)
	}
	if len(hexDigest([]byte("stable"))) != 64 {
		t.Fatal("hex digest is not SHA-256 sized")
	}
}

func TestBreakerHalfOpenAllowsOneProbeAndResets(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	b := &breaker{}
	for range 5 {
		b.record(false, now)
	}
	if b.allow(now.Add(9 * time.Minute)) {
		t.Fatal("open breaker allowed an early request")
	}
	if !b.allow(now.Add(10*time.Minute)) || b.allow(now.Add(11*time.Minute)) {
		t.Fatal("half-open breaker did not allow exactly one probe")
	}
	b.record(true, now.Add(10*time.Minute))
	if !b.allow(now.Add(10 * time.Minute)) {
		t.Fatal("successful probe did not reset breaker")
	}
}

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func disasterTestAgent(t *testing.T, dataDir string) *Agent {
	t.Helper()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "node-secret", DataDir: dataDir,
		ControllerGeneration: 3,
		Disaster: config.AgentDisasterPolicy{
			UnreachableAfterSec: 10, IndependentAfterSec: 60, MinFailedHeartbeats: 3,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestControllerJitterNeverOpensIndependentLogin(t *testing.T) {
	t.Parallel()
	a := disasterTestAgent(t, t.TempDir())
	started := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, 31 * time.Second, 2 * time.Minute} {
		// The signed heartbeat is failing, but a separately observed healthy
		// controller proves this is not a confirmed controller loss.
		if err := a.recordControllerFailure(started.Add(offset), false, false); err != nil {
			t.Fatal(err)
		}
	}
	report := a.controlModeReport()
	if report.Mode != protocol.NodeModeControllerUnreachable || report.ConsecutiveHealthProbeFails != 0 {
		t.Fatalf("report=%+v", report)
	}
}

func TestSustainedMultiSignalLossPersistsIndependentModeAcrossRestart(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	a := disasterTestAgent(t, dataDir)
	started := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, 11 * time.Second, 61 * time.Second} {
		if err := a.recordControllerFailure(started.Add(offset), true, true); err != nil {
			t.Fatal(err)
		}
	}
	report := a.controlModeReport()
	if report.Mode != protocol.NodeModeIndependent || report.ModeGeneration != 3 ||
		report.IndependentSince.IsZero() || report.ConsecutiveHeartbeatFails != 3 ||
		report.ConsecutiveHealthProbeFails != 3 ||
		report.ConsecutivePeerWitnessFails != 3 ||
		!report.ConfirmedOutageStartedAt.Equal(started) {
		t.Fatalf("report=%+v", report)
	}
	reloaded := disasterTestAgent(t, dataDir)
	reloadedReport := reloaded.controlModeReport()
	if reloadedReport.Mode != protocol.NodeModeIndependent ||
		!reloadedReport.IndependentSince.Equal(report.IndependentSince) {
		t.Fatalf("reloaded=%+v", reloadedReport)
	}
}

func TestPeerWitnessDisagreementResetsConfirmedOutageFloor(t *testing.T) {
	t.Parallel()
	a := disasterTestAgent(t, t.TempDir())
	started := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	if err := a.recordControllerFailure(started, true, true); err != nil {
		t.Fatal(err)
	}
	if err := a.recordControllerFailure(started.Add(2*time.Minute), true, false); err != nil {
		t.Fatal(err)
	}
	if got := a.controlModeReport(); got.Mode != protocol.NodeModeControllerUnreachable ||
		!got.ConfirmedOutageStartedAt.IsZero() || got.ConsecutivePeerWitnessFails != 0 ||
		got.ConsecutiveHealthProbeFails != 2 {
		t.Fatalf("peer disagreement did not fail closed: %+v", got)
	}
	confirmedAgain := started.Add(3 * time.Minute)
	for _, offset := range []time.Duration{0, time.Second, 61 * time.Second} {
		if err := a.recordControllerFailure(confirmedAgain.Add(offset), true, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := a.controlModeReport(); got.Mode != protocol.NodeModeIndependent ||
		!got.ConfirmedOutageStartedAt.Equal(confirmedAgain) || got.ConsecutivePeerWitnessFails != 3 {
		t.Fatalf("new uninterrupted quorum window was not used: %+v", got)
	}
}

func TestPeerWitnessDisagreementClosesExistingIndependentLogin(t *testing.T) {
	t.Parallel()
	a := disasterTestAgent(t, t.TempDir())
	started := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, time.Second, 61 * time.Second} {
		if err := a.recordControllerFailure(started.Add(offset), true, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := a.controlModeReport(); got.Mode != protocol.NodeModeIndependent {
		t.Fatalf("precondition mode=%+v", got)
	}
	if err := a.recordControllerFailure(started.Add(62*time.Second), true, false); err != nil {
		t.Fatal(err)
	}
	if got := a.controlModeReport(); got.Mode != protocol.NodeModeIndependentDraining ||
		got.ReasonCode != "controller_loss_evidence_disputed" ||
		!got.ConfirmedOutageStartedAt.IsZero() || got.ConsecutivePeerWitnessFails != 0 {
		t.Fatalf("disputed independent evidence remained open: %+v", got)
	}
}

func TestLegacyIndependentStateWithoutPeerEvidenceUpgradesToDraining(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	a := disasterTestAgent(t, dataDir)
	a.stateMu.Lock()
	a.state.ControlMode.Mode = protocol.NodeModeIndependent
	a.state.ControlMode.ModeGeneration = 7
	a.state.ControlMode.IndependentSince = time.Now().UTC().Add(-time.Minute)
	a.state.ControlMode.ConsecutivePeerWitnessFails = 0
	if err := a.saveRuntimeStateLocked(); err != nil {
		a.stateMu.Unlock()
		t.Fatal(err)
	}
	a.stateMu.Unlock()

	reloaded := disasterTestAgent(t, dataDir)
	report := reloaded.controlModeReport()
	if report.Mode != protocol.NodeModeIndependentDraining || report.ModeGeneration != 8 ||
		report.ReasonCode != "legacy_independent_without_peer_witness" {
		t.Fatalf("legacy state was not closed safely: %+v", report)
	}
}

func TestHealthyPublicProbeResetsIndependentOutageDuration(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	a := disasterTestAgent(t, dataDir)
	started := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)

	// A signed heartbeat/authentication path may fail for hours while the
	// independent public health probe still proves the Controller network is
	// reachable. That time must never be credited to the dual-signal floor.
	for _, offset := range []time.Duration{0, 30 * time.Second, 2 * time.Minute} {
		if err := a.recordControllerFailure(started.Add(offset), false, false); err != nil {
			t.Fatal(err)
		}
	}
	confirmedAt := started.Add(2*time.Minute + time.Second)
	for _, offset := range []time.Duration{0, time.Second, 2 * time.Second} {
		if err := a.recordControllerFailure(confirmedAt.Add(offset), true, true); err != nil {
			t.Fatal(err)
		}
	}
	report := a.controlModeReport()
	if report.Mode != protocol.NodeModeControllerUnreachable ||
		!report.ConfirmedOutageStartedAt.Equal(confirmedAt) ||
		report.ConsecutiveHealthProbeFails != 3 {
		t.Fatalf("short confirmed outage incorrectly opened independent mode: %+v", report)
	}

	// The confirmed floor is security state and must survive a process restart.
	reloaded := disasterTestAgent(t, dataDir)
	if got := reloaded.controlModeReport(); !got.ConfirmedOutageStartedAt.Equal(confirmedAt) ||
		got.Mode != protocol.NodeModeControllerUnreachable {
		t.Fatalf("confirmed outage floor was not durable: %+v", got)
	}
	if err := reloaded.recordControllerFailure(confirmedAt.Add(61*time.Second), true, true); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.controlModeReport(); got.Mode != protocol.NodeModeIndependent {
		t.Fatalf("sustained confirmed outage did not open independent mode: %+v", got)
	}
}

func TestControllerRecoveryMustDrainAndRejectsOldGeneration(t *testing.T) {
	t.Parallel()
	a := disasterTestAgent(t, t.TempDir())
	started := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, 11 * time.Second, 61 * time.Second} {
		if err := a.recordControllerFailure(started.Add(offset), true, true); err != nil {
			t.Fatal(err)
		}
	}
	report := a.controlModeReport()
	if err := a.recordControllerSuccess(started.Add(62*time.Second), protocol.HeartbeatResponse{
		OK: true, ControllerGeneration: 4,
		DesiredMode: protocol.NodeModeIndependentDraining, ModeGeneration: report.ModeGeneration + 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := a.controlModeReport().Mode; got != protocol.NodeModeIndependentDraining {
		t.Fatalf("mode=%q", got)
	}
	if err := a.recordControllerSuccess(started.Add(63*time.Second), protocol.HeartbeatResponse{
		OK: true, ControllerGeneration: 3,
		DesiredMode: protocol.NodeModeManaged, ModeGeneration: report.ModeGeneration + 2,
	}); err == nil {
		t.Fatal("old controller generation was accepted")
	}
}

func TestIndependentDrainingWaitsForAdapterSessionsAndSyncs(t *testing.T) {
	t.Parallel()
	var received protocol.ApplyNodeControlModeRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stcontrol/internal/control-mode" {
			t.Errorf("path=%q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(protocol.ApplyNodeControlModeResponse{
			OK: true, AppliedMode: received.Mode, ModeGeneration: received.ModeGeneration,
			ActiveIndependentSessions: 1, PendingUserSyncs: 2,
		})
	}))
	defer server.Close()
	a := disasterTestAgent(t, t.TempDir())
	a.Cfg.TavernURL = server.URL
	a.stateMu.Lock()
	a.state.ControlMode.Mode = protocol.NodeModeIndependentDraining
	a.state.ControlMode.ModeGeneration = 4
	a.state.ControlMode.AdapterMode = ""
	a.stateMu.Unlock()
	if err := a.syncTavernControlMode(context.Background()); err != nil {
		t.Fatal(err)
	}
	if received.Mode != protocol.NodeModeIndependentDraining {
		t.Fatalf("received=%+v", received)
	}
	if err := a.recordControllerSuccess(time.Now().UTC(), protocol.HeartbeatResponse{
		OK: true, ControllerGeneration: 4,
		DesiredMode: protocol.NodeModeManaged, ModeGeneration: 5,
	}); err == nil {
		t.Fatal("managed mode skipped active independent sessions and pending syncs")
	}
}

func TestNonManagedModePausesManagedCommands(t *testing.T) {
	t.Parallel()
	a := disasterTestAgent(t, t.TempDir())
	a.stateMu.Lock()
	a.state.ControlMode.Mode = protocol.NodeModeControllerUnreachable
	a.stateMu.Unlock()
	if a.managedCommandsAllowed() {
		t.Fatal("managed commands remained enabled")
	}
	if err := a.pollAndRunCommand(context.Background()); err == nil {
		t.Fatal("command polling was not paused")
	}
}

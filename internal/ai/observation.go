package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// observation.go builds redacted, versioned observation snapshots
// (ai接入优化方案详细.md §3.2/§4.1/§4.4). The controller gathers typed store
// facts and hands them here; this package never touches the database directly,
// so it cannot accidentally leak a field the builder was not given.

// Observation is the redacted snapshot sent to the provider (observed_data).
type Observation struct {
	ObservationID    string                `json:"observation_id"`
	GeneratedAt      string                `json:"generated_at"`
	ExpiresAt        string                `json:"expires_at"`
	FactVersion      int64                 `json:"fact_version"`
	EvidenceCatalog  []Evidence            `json:"evidence_catalog"`
	CandidateCatalog []Candidate           `json:"candidate_catalog,omitempty"`
	Nodes            []NodeObservation     `json:"nodes"`
	Alerts           []AlertObservation    `json:"alerts"`
	Workflows        []WorkflowObservation `json:"workflows"`
	Protection       ProtectionObservation `json:"protection"`
}

// Evidence is one immutable fact the model may cite. Only these refs may
// appear in the advisory's evidence_refs.
type Evidence struct {
	Ref   string `json:"ref"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Candidate is one eligible candidate the model may order. Only these refs may
// appear in the advisory's candidate_refs for ordering actions.
type Candidate struct {
	Ref  string `json:"ref"`
	Kind string `json:"kind"`
}

// NodeObservation is the redacted projection of one node (§4.1). No IDs, URLs,
// fingerprints, paths, or raw metrics; only enum states and buckets.
type NodeObservation struct {
	Ref              string `json:"ref"`
	Role             string `json:"role"`
	RegionBucket     string `json:"region_bucket,omitempty"`
	Connectivity     string `json:"connectivity"`
	Operational      string `json:"operational"`
	Capacity         string `json:"capacity"`
	Compatibility    string `json:"compatibility"`
	CapacityReason   string `json:"capacity_reason_code,omitempty"`
	CompatReason     string `json:"compat_reason_code,omitempty"`
	CPUWindowAvg     int64  `json:"cpu_window_avg_bucket"`
	MemWindowAvg     int64  `json:"mem_window_avg_bucket"`
	DiskPct          int64  `json:"disk_pct_bucket"`
	DiskFreeBucket   string `json:"disk_free_bucket,omitempty"`
	TelemetryAgeSec  int64  `json:"telemetry_age_sec"`
	TelemetrySource  string `json:"telemetry_source,omitempty"`
	EligibleForNew   bool   `json:"eligible_for_new"`
	EligibleAsBackup bool   `json:"eligible_as_backup_target"`
}

// AlertObservation is the redacted projection of one alert.
type AlertObservation struct {
	Ref      string `json:"ref"`
	Severity string `json:"severity"`
	State    string `json:"state"`
	Category string `json:"category"`
	AgeSec   int64  `json:"age_sec"`
	Count    int64  `json:"count"`
	Summary  string `json:"summary"` // already SanitizeText'd
}

// WorkflowObservation is the redacted projection of one workflow.
type WorkflowObservation struct {
	Ref       string `json:"ref"`
	Type      string `json:"type"`
	State     string `json:"state"`
	Attempt   int    `json:"attempt"`
	AgeSec    int64  `json:"age_sec"`
	ErrorCode string `json:"error_code,omitempty"`
}

// ProtectionObservation aggregates anonymous user protection states.
type ProtectionObservation struct {
	TotalUsers       int64 `json:"total_users"`
	ProtectedCount   int64 `json:"protected"`
	UnprotectedCount int64 `json:"unprotected"`
	ConflictCount    int64 `json:"conflict"`
	CorruptCount     int64 `json:"corrupt"`
	AvgReplicaAgeSec int64 `json:"avg_replica_age_sec"`
}

// BuildObservation assembles the JSON observation and returns it plus the
// evidence/candidate catalogs and digest. salt must be fresh per observation
// (use the observation ID) so refs are not correlatable across tasks.
func BuildObservation(
	redactor *Redactor,
	obsID string,
	now time.Time,
	nodes []NodeObservation,
	alerts []AlertObservation,
	workflows []WorkflowObservation,
	protection ProtectionObservation,
) ([]byte, map[string]bool, map[string]bool, string, error) {
	expires := now.Add(15 * time.Minute)
	evidence := make([]Evidence, 0, len(nodes)+len(alerts)+len(workflows))
	evidenceCatalog := make(map[string]bool)
	seen := make(map[string]bool)
	addEvidence := func(kind, value string) {
		ref := "ev_" + shortHash(redactor, obsID, kind, value)
		if seen[ref] {
			return
		}
		seen[ref] = true
		evidence = append(evidence, Evidence{Ref: ref, Kind: kind, Value: value})
		evidenceCatalog[ref] = true
	}
	for _, n := range nodes {
		addEvidence("node_connectivity", n.Ref+"/"+n.Connectivity)
		addEvidence("node_capacity", n.Ref+"/"+n.Capacity)
		addEvidence("node_compat", n.Ref+"/"+n.Compatibility)
	}
	for _, a := range alerts {
		addEvidence("alert", a.Ref+"/"+a.Severity+"/"+a.Category)
	}
	for _, w := range workflows {
		addEvidence("workflow", w.Ref+"/"+w.Type+"/"+w.State)
	}
	candidateCatalog := make(map[string]bool)
	for _, n := range nodes {
		if n.EligibleForNew || n.EligibleAsBackup {
			candidateCatalog[n.Ref] = true
		}
	}
	obs := Observation{
		ObservationID:    obsID,
		GeneratedAt:      now.UTC().Format(time.RFC3339),
		ExpiresAt:        expires.UTC().Format(time.RFC3339),
		FactVersion:      now.Unix(),
		EvidenceCatalog:  evidence,
		CandidateCatalog: make([]Candidate, 0, len(candidateCatalog)),
		Nodes:            nodes,
		Alerts:           alerts,
		Workflows:        workflows,
		Protection:       protection,
	}
	for ref := range candidateCatalog {
		obs.CandidateCatalog = append(obs.CandidateCatalog, Candidate{Ref: ref, Kind: "node"})
	}
	raw, err := json.Marshal(obs)
	if err != nil {
		return nil, nil, nil, "", err
	}
	digest := sha256.Sum256(raw)
	return raw, evidenceCatalog, candidateCatalog, hex.EncodeToString(digest[:]), nil
}

func shortHash(redactor *Redactor, salt, kind, value string) string {
	return EvidenceShortHash(redactor, salt, kind, value)
}

// EvidenceShortHash derives the short stable suffix used for evidence refs of
// the standard observation catalog ("ev_" + this). Exported so the adoption
// executor can map an advisory's evidence refs back to current deterministic
// facts without storing a reverse mapping.
func EvidenceShortHash(redactor *Redactor, salt, kind, value string) string {
	full := redactor.Ref(kind, salt, value)
	if len(full) > 24 {
		return full[len(full)-20:]
	}
	return full
}

// BucketDiskFree converts available bytes into a coarse bucket.
func BucketDiskFree(available, total int64) string {
	if total <= 0 {
		return "unknown"
	}
	pct := float64(available) / float64(total) * 100
	switch {
	case pct >= 30:
		return ">=30%"
	case pct >= 15:
		return "15-30%"
	case pct >= 8:
		return "8-15%"
	default:
		return "<8%"
	}
}

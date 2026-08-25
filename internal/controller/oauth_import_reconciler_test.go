package controller

import (
	"testing"

	"stcontrol/internal/store"
)

func TestDecideOAuthImportReconciliationHandlesEquivalentAndSplitIdentities(t *testing.T) {
	t.Parallel()
	candidates := []store.OAuthUnmatchedCandidateFingerprints{
		{CandidateID: "single", NodeID: 22, Identities: map[string]string{"discord": "fp-a"}},
		{CandidateID: "same-user", NodeID: 22, Identities: map[string]string{
			"discord": "fp-a", "linuxdo": "fp-b",
		}},
		{CandidateID: "split", NodeID: 22, Identities: map[string]string{
			"discord": "fp-a", "linuxdo": "fp-c",
		}},
		{CandidateID: "partial", NodeID: 22, Identities: map[string]string{
			"discord": "fp-a", "linuxdo": "fp-unknown",
		}},
		{CandidateID: "unknown", NodeID: 24, Identities: map[string]string{"discord": "fp-a"}},
	}
	matches := map[oauthImportFingerprintKey][]oauthImportIdentityMatch{
		{nodeID: 22, provider: "discord", fingerprint: "fp-a"}: {
			{globalUserID: 70, subject: "discord-subject"},
		},
		{nodeID: 22, provider: "linuxdo", fingerprint: "fp-b"}: {
			{globalUserID: 70, subject: "linuxdo-subject"},
		},
		{nodeID: 22, provider: "linuxdo", fingerprint: "fp-c"}: {
			{globalUserID: 80, subject: "other-linuxdo-subject"},
		},
	}
	decisions := decideOAuthImportReconciliation(candidates, matches)
	if len(decisions) != 3 || decisions[0].candidateID != "single" || decisions[0].globalUserID != 70 ||
		decisions[0].conflict || len(decisions[0].identityProofs) != 1 ||
		decisions[1].candidateID != "same-user" ||
		decisions[1].globalUserID != 70 || decisions[1].conflict ||
		len(decisions[1].identityProofs) != 2 ||
		decisions[2].candidateID != "split" || !decisions[2].conflict ||
		decisions[2].globalUserID != 0 {
		t.Fatalf("decisions=%+v", decisions)
	}
}

package controller

import (
	"context"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const oauthImportReconcileEvery = 2 * time.Minute

type oauthImportFingerprintKey struct {
	nodeID      int64
	provider    string
	fingerprint string
}

type oauthImportReconcileDecision struct {
	candidateID    string
	globalUserID   int64
	identityProofs []store.OAuthIdentityMatchProof
	conflict       bool
}

type oauthImportIdentityMatch struct {
	globalUserID int64
	subject      string
}

// oauthImportReconciler repairs durable batches produced during rolling
// upgrades. It compares only node-scoped HMACs and never copies raw OAuth
// subjects into scan records, logs, or Agent commands.
func (s *Server) oauthImportReconciler(ctx context.Context) {
	if s == nil || s.Store == nil {
		return
	}
	ticker := time.NewTicker(oauthImportReconcileEvery)
	defer ticker.Stop()
	for {
		s.reconcileOAuthImportsOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) reconcileOAuthImportsOnce(ctx context.Context) {
	if ctx.Err() != nil || s.checkNewOperations() != nil {
		return
	}
	candidates, err := s.Store.ListOAuthUnmatchedCandidateFingerprints(ctx, 10_000)
	if err != nil || len(candidates) == 0 {
		return
	}
	identities, err := s.Store.ListActiveOAuthIdentitySubjects(ctx)
	if err != nil || len(identities) == 0 {
		return
	}
	nodes, err := s.Store.ListNodes(ctx)
	if err != nil {
		return
	}
	wantedNodes := make(map[int64]struct{}, len(candidates))
	for _, candidate := range candidates {
		wantedNodes[candidate.NodeID] = struct{}{}
	}
	matches := make(map[oauthImportFingerprintKey][]oauthImportIdentityMatch)
	for _, node := range nodes {
		if node == nil || node.Role != "compute" {
			continue
		}
		if _, wanted := wantedNodes[node.ID]; !wanted {
			continue
		}
		psk, err := s.agentPSK(ctx, node)
		if err != nil || psk == "" {
			continue
		}
		for _, identity := range identities {
			fingerprint := controlcrypto.AgentInventoryFingerprint(
				psk, "oauth-subject", identity.Provider,
				protocol.CanonicalOAuthSubject(identity.Provider, identity.Subject),
			)
			key := oauthImportFingerprintKey{
				nodeID: node.ID, provider: identity.Provider, fingerprint: fingerprint,
			}
			matches[key] = append(matches[key], oauthImportIdentityMatch{
				globalUserID: identity.GlobalUserID, subject: identity.Subject,
			})
		}
	}
	for _, decision := range decideOAuthImportReconciliation(candidates, matches) {
		if ctx.Err() != nil || s.checkNewOperations() != nil {
			return
		}
		if decision.conflict {
			_ = s.Store.MarkOAuthUnmatchedCandidateIdentityConflict(
				ctx, decision.candidateID, "oauth_subjects_split", time.Now().UTC(),
			)
			continue
		}
		_, _ = s.Store.ResolveOAuthUnmatchedCandidate(
			ctx, decision.candidateID, decision.globalUserID,
			decision.identityProofs, time.Now().UTC(),
		)
	}
}

func decideOAuthImportReconciliation(
	candidates []store.OAuthUnmatchedCandidateFingerprints,
	matches map[oauthImportFingerprintKey][]oauthImportIdentityMatch,
) []oauthImportReconcileDecision {
	decisions := make([]oauthImportReconcileDecision, 0)
	for _, candidate := range candidates {
		matchedUsers := make(map[int64]struct{})
		proofSubjects := make(map[string]map[int64]string, len(candidate.Identities))
		complete := true
		for provider, fingerprint := range candidate.Identities {
			key := oauthImportFingerprintKey{
				nodeID: candidate.NodeID, provider: provider, fingerprint: fingerprint,
			}
			identityMatches := matches[key]
			if len(identityMatches) == 0 {
				complete = false
				break
			}
			proofSubjects[provider] = make(map[int64]string, len(identityMatches))
			for _, match := range identityMatches {
				if match.globalUserID > 0 && match.subject != "" {
					matchedUsers[match.globalUserID] = struct{}{}
					if _, exists := proofSubjects[provider][match.globalUserID]; !exists {
						proofSubjects[provider][match.globalUserID] = match.subject
					}
				}
			}
		}
		if !complete {
			continue
		}
		decision := oauthImportReconcileDecision{candidateID: candidate.CandidateID}
		switch len(matchedUsers) {
		case 0:
			continue
		case 1:
			for globalUserID := range matchedUsers {
				decision.globalUserID = globalUserID
			}
			for provider := range candidate.Identities {
				decision.identityProofs = append(decision.identityProofs, store.OAuthIdentityMatchProof{
					Provider: provider, Subject: proofSubjects[provider][decision.globalUserID],
				})
			}
		default:
			decision.conflict = true
		}
		decisions = append(decisions, decision)
	}
	return decisions
}

package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"stcontrol/internal/protocol"
)

const (
	peerOwnershipQueryRoute       = "/agent/activity-ownership/v1/query"
	peerOwnershipObserveRoute     = "/agent/activity-ownership/v1/observe"
	adapterOwnershipResolveRoute  = "/agent/activity-ownership/v1/resolve"
	adapterOwnershipTakeoverRoute = "/agent/activity-ownership/v1/takeover"
	maxOwnershipRequestBytes      = 8 << 10
	maxOwnershipResponseBytes     = 16 << 10
	maxOwnershipTakeovers         = 1000
	peerOwnershipResponseSig      = "X-Ownership-Signature"
	peerOwnershipResponseTime     = "X-Ownership-Timestamp"
)

type activityOwnershipClaim struct {
	ClaimID              string `json:"claim_id"`
	Handle               string `json:"handle"`
	OwnerNodeID          int64  `json:"owner_node_id"`
	ControllerGeneration int64  `json:"controller_generation"`
	ActivityEpoch        int64  `json:"activity_epoch"`
	TakeoverSequence     int64  `json:"takeover_sequence"`
	Kind                 string `json:"kind"`
	ParentClaimID        string `json:"parent_claim_id,omitempty"`
	OperationID          string `json:"operation_id,omitempty"`
	ObservedAt           int64  `json:"observed_at"`
}

type ownershipTakeoverOperation struct {
	OperationID   string                 `json:"operation_id"`
	ParentClaimID string                 `json:"parent_claim_id"`
	Claim         activityOwnershipClaim `json:"claim"`
	Succeeded     bool                   `json:"succeeded"`
	Audited       bool                   `json:"audited"`
	UpdatedAt     int64                  `json:"updated_at"`
}

type ownershipPeerRequest struct {
	ControllerFingerprint string                  `json:"controller_fingerprint"`
	Handle                string                  `json:"handle,omitempty"`
	Claim                 *activityOwnershipClaim `json:"claim,omitempty"`
}

type ownershipPeerResponse struct {
	OK               bool                    `json:"ok"`
	WitnessNodeID    int64                   `json:"witness_node_id"`
	Found            bool                    `json:"found"`
	Claim            *activityOwnershipClaim `json:"claim,omitempty"`
	AdapterAvailable bool                    `json:"adapter_available"`
	Accepted         bool                    `json:"accepted,omitempty"`
	ObservedAt       int64                   `json:"observed_at"`
}

type ownershipResolveRequest struct {
	Handle string `json:"handle"`
}

type ownershipResolveResponse struct {
	OK         bool   `json:"ok"`
	Decision   string `json:"decision"`
	ClaimID    string `json:"claim_id,omitempty"`
	ReasonCode string `json:"reason_code"`
}

type ownershipTakeoverRequest struct {
	Handle        string `json:"handle"`
	ParentClaimID string `json:"parent_claim_id"`
	OperationID   string `json:"operation_id"`
}

func makeActivityOwnershipClaim(
	handle string,
	ownerNodeID, controllerGeneration, activityEpoch, takeoverSequence int64,
	kind, parentClaimID, operationID string,
	now time.Time,
) (activityOwnershipClaim, error) {
	claim := activityOwnershipClaim{
		Handle: handle, OwnerNodeID: ownerNodeID,
		ControllerGeneration: controllerGeneration, ActivityEpoch: activityEpoch,
		TakeoverSequence: takeoverSequence, Kind: kind,
		ParentClaimID: parentClaimID, OperationID: operationID,
		ObservedAt: now.UTC().UnixMilli(),
	}
	claim.ClaimID = activityOwnershipClaimID(claim)
	if err := validateActivityOwnershipClaim(claim); err != nil {
		return activityOwnershipClaim{}, err
	}
	return claim, nil
}

func activityOwnershipClaimID(claim activityOwnershipClaim) string {
	canonical := fmt.Sprintf("stcontrol-activity-owner:v1\n%s\n%d\n%d\n%d\n%d\n%s\n%s\n%s",
		claim.Handle, claim.OwnerNodeID, claim.ControllerGeneration, claim.ActivityEpoch,
		claim.TakeoverSequence, claim.Kind, claim.ParentClaimID, claim.OperationID)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

func validateActivityOwnershipClaim(claim activityOwnershipClaim) error {
	if !safeInventoryString(claim.Handle, 128) || strings.ToLower(claim.Handle) != claim.Handle ||
		claim.OwnerNodeID <= 0 || claim.ControllerGeneration <= 0 || claim.ActivityEpoch <= 0 ||
		claim.TakeoverSequence < 0 || claim.ObservedAt <= 0 ||
		claim.ClaimID != activityOwnershipClaimID(claim) {
		return fmt.Errorf("invalid activity ownership claim")
	}
	switch claim.Kind {
	case "controller_grant":
		if claim.TakeoverSequence != 0 || claim.ParentClaimID != "" || claim.OperationID != "" {
			return fmt.Errorf("invalid controller ownership grant")
		}
	case "user_confirmed_takeover":
		if claim.TakeoverSequence <= 0 || !validOwnershipDigest(claim.ParentClaimID) ||
			!validUUID(claim.OperationID) {
			return fmt.Errorf("invalid user-confirmed ownership takeover")
		}
	default:
		return fmt.Errorf("invalid activity ownership kind")
	}
	return nil
}

func validOwnershipDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func compareActivityOwnership(left, right activityOwnershipClaim) int {
	values := [][2]int64{
		{left.ControllerGeneration, right.ControllerGeneration},
		{left.ActivityEpoch, right.ActivityEpoch},
		{left.TakeoverSequence, right.TakeoverSequence},
	}
	for _, pair := range values {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if left.ClaimID == right.ClaimID {
		return 0
	}
	// Same generation/epoch/sequence with different immutable facts is a
	// conflict, not a deterministic tie-break. Callers fail closed.
	return 2
}

func (a *Agent) recordControllerOwnershipGrant(
	ctx context.Context,
	handle string,
	controllerGeneration, activityEpoch int64,
) error {
	claim, err := makeActivityOwnershipClaim(
		strings.ToLower(handle), a.Cfg.NodeID, controllerGeneration, activityEpoch,
		0, "controller_grant", "", "", time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	if _, err := a.applyActivityOwnershipClaim(claim, false); err != nil {
		return err
	}
	// Replication is best effort while managed: absence of a quorum never
	// weakens ordinary Controller login, but later disaster login fails closed
	// unless a majority really retained this exact grant.
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = a.broadcastOwnershipClaim(probeCtx, claim)
	return nil
}

func (a *Agent) applyActivityOwnershipClaim(claim activityOwnershipClaim, requireParent bool) (bool, error) {
	if err := validateActivityOwnershipClaim(claim); err != nil {
		return false, err
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.state.ActivityOwnership == nil {
		a.state.ActivityOwnership = make(map[string]activityOwnershipClaim)
	}
	current, exists := a.state.ActivityOwnership[claim.Handle]
	if exists {
		if current.ClaimID == claim.ClaimID {
			return true, nil
		}
		if requireParent && current.ClaimID != claim.ParentClaimID {
			return false, nil
		}
		comparison := compareActivityOwnership(claim, current)
		if comparison <= 0 || comparison == 2 {
			return false, nil
		}
	} else if requireParent {
		return false, nil
	}
	a.state.ActivityOwnership[claim.Handle] = claim
	return true, a.saveRuntimeStateLocked()
}

func (a *Agent) currentActivityOwnership(handle string) (activityOwnershipClaim, bool) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	claim, exists := a.state.ActivityOwnership[handle]
	return claim, exists
}

func (a *Agent) handlePeerOwnershipQuery(w http.ResponseWriter, r *http.Request) {
	request, requesterNodeID, ok := a.authenticatePeerOwnershipRequest(w, r)
	if !ok {
		return
	}
	_ = requesterNodeID
	if request.Claim != nil || !validOwnershipHandle(request.Handle) {
		writeOwnershipError(w, http.StatusBadRequest, "invalid_ownership_query")
		return
	}
	claim, found := a.currentActivityOwnership(request.Handle)
	response := ownershipPeerResponse{
		OK: true, WitnessNodeID: a.Cfg.NodeID, Found: found,
		AdapterAvailable: a.localAdapterAvailable(r.Context()), ObservedAt: time.Now().UTC().UnixMilli(),
	}
	if found {
		response.Claim = &claim
	}
	a.writeSignedOwnershipResponse(w, r, peerOwnershipQueryRoute, response)
}

func (a *Agent) handlePeerOwnershipObserve(w http.ResponseWriter, r *http.Request) {
	request, _, ok := a.authenticatePeerOwnershipRequest(w, r)
	if !ok {
		return
	}
	if request.Claim == nil || request.Handle != "" ||
		request.Claim.Handle == "" || validateActivityOwnershipClaim(*request.Claim) != nil {
		writeOwnershipError(w, http.StatusBadRequest, "invalid_ownership_observation")
		return
	}
	requireParent := request.Claim.Kind == "user_confirmed_takeover"
	accepted, err := a.applyActivityOwnershipClaim(*request.Claim, requireParent)
	if err != nil {
		writeOwnershipError(w, http.StatusInternalServerError, "ownership_persistence_failed")
		return
	}
	current, found := a.currentActivityOwnership(request.Claim.Handle)
	response := ownershipPeerResponse{
		OK: true, WitnessNodeID: a.Cfg.NodeID, Found: found, Accepted: accepted,
		ObservedAt: time.Now().UTC().UnixMilli(),
	}
	if found {
		response.Claim = &current
	}
	a.writeSignedOwnershipResponse(w, r, peerOwnershipObserveRoute, response)
}

func (a *Agent) authenticatePeerOwnershipRequest(
	w http.ResponseWriter,
	r *http.Request,
) (ownershipPeerRequest, int64, bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if a == nil || a.Cfg == nil || len(a.peerWitnessSecret) < minimumPeerWitnessSecretBytes ||
		r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" ||
		r.ContentLength <= 0 || r.ContentLength > maxOwnershipRequestBytes {
		writeOwnershipError(w, http.StatusBadRequest, "invalid_ownership_request")
		return ownershipPeerRequest{}, 0, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOwnershipRequestBytes))
	requesterNodeID, nodeErr := strconv.ParseInt(r.Header.Get(protocol.HeaderAgentID), 10, 64)
	if err != nil || nodeErr != nil || requesterNodeID <= 0 || requesterNodeID == a.Cfg.NodeID ||
		protocol.VerifyRequest(r, string(a.peerWitnessSecret), body) != nil ||
		!a.consumeWitnessNonce(r.Header.Get(protocol.HeaderNonce), time.Now().UTC()) {
		writeOwnershipError(w, http.StatusUnauthorized, "ownership_authentication_failed")
		return ownershipPeerRequest{}, 0, false
	}
	var request ownershipPeerRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	fingerprint, fingerprintErr := a.controllerFingerprint()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		fingerprintErr != nil || !hmac.Equal([]byte(request.ControllerFingerprint), []byte(fingerprint)) {
		writeOwnershipError(w, http.StatusBadRequest, "invalid_ownership_request")
		return ownershipPeerRequest{}, 0, false
	}
	return request, requesterNodeID, true
}

func (a *Agent) writeSignedOwnershipResponse(
	w http.ResponseWriter,
	r *http.Request,
	route string,
	response ownershipPeerResponse,
) {
	body, err := json.Marshal(response)
	if err != nil {
		writeOwnershipError(w, http.StatusInternalServerError, "ownership_response_failed")
		return
	}
	timestamp := strconv.FormatInt(response.ObservedAt/1000, 10)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(peerOwnershipResponseTime, timestamp)
	w.Header().Set(peerOwnershipResponseSig, protocol.Sign(
		string(a.peerWitnessSecret), "RESPONSE", route, timestamp,
		r.Header.Get(protocol.HeaderNonce), body,
	))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (a *Agent) localAdapterAvailable(ctx context.Context) bool {
	if a.Cfg.Role != "compute" {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var response struct {
		OK bool `json:"ok"`
	}
	return a.callTavernAdapter(probeCtx, "/api/stcontrol/internal/health", struct{}{}, &response) == nil && response.OK
}

func (a *Agent) queryOwnershipQuorum(ctx context.Context, handle string) ownershipResolveResponse {
	if !validOwnershipHandle(handle) || len(a.Cfg.Disaster.PeerWitnessURLs) == 0 ||
		len(a.peerWitnessSecret) < minimumPeerWitnessSecretBytes {
		return ownershipResolveResponse{OK: false, Decision: "unavailable", ReasonCode: "ownership_quorum_unavailable"}
	}
	fingerprint, err := a.controllerFingerprint()
	if err != nil {
		return ownershipResolveResponse{OK: false, Decision: "unavailable", ReasonCode: "ownership_quorum_unavailable"}
	}
	type queryResult struct {
		response ownershipPeerResponse
		valid    bool
	}
	results := make(chan queryResult, len(a.Cfg.Disaster.PeerWitnessURLs))
	probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	for _, raw := range a.Cfg.Disaster.PeerWitnessURLs {
		endpoint, _ := peerWitnessEndpointForRoute(raw, peerOwnershipQueryRoute)
		go func(endpoint string) {
			response, valid := a.callOwnershipPeer(probeCtx, endpoint, peerOwnershipQueryRoute,
				ownershipPeerRequest{ControllerFingerprint: fingerprint, Handle: handle})
			results <- queryResult{response: response, valid: valid}
		}(endpoint)
	}
	claims := make(map[int64]activityOwnershipClaim)
	availability := make(map[int64]bool)
	if local, found := a.currentActivityOwnership(handle); found {
		claims[a.Cfg.NodeID] = local
		availability[a.Cfg.NodeID] = true
	}
	for range a.Cfg.Disaster.PeerWitnessURLs {
		select {
		case <-probeCtx.Done():
			return ownershipResolveResponse{OK: false, Decision: "unavailable", ReasonCode: "ownership_quorum_unavailable"}
		case result := <-results:
			if !result.valid {
				continue
			}
			availability[result.response.WitnessNodeID] = result.response.AdapterAvailable
			if result.response.Found && result.response.Claim != nil {
				claims[result.response.WitnessNodeID] = *result.response.Claim
			}
		}
	}
	var maximal activityOwnershipClaim
	haveMaximal := false
	conflict := false
	for _, claim := range claims {
		if !haveMaximal {
			maximal, haveMaximal = claim, true
			continue
		}
		switch comparison := compareActivityOwnership(claim, maximal); comparison {
		case 1:
			maximal = claim
			conflict = false
		case 2:
			conflict = true
		}
	}
	if !haveMaximal || conflict {
		return ownershipResolveResponse{OK: false, Decision: "unavailable", ReasonCode: "ownership_fact_conflict"}
	}
	accepted, _ := a.applyActivityOwnershipClaim(maximal, false)
	if !accepted {
		return ownershipResolveResponse{OK: false, Decision: "unavailable", ReasonCode: "ownership_fact_conflict"}
	}
	matchingNodes := make(map[int64]struct{})
	matchingNodes[a.Cfg.NodeID] = struct{}{}
	for nodeID, claim := range claims {
		if claim.ClaimID == maximal.ClaimID {
			matchingNodes[nodeID] = struct{}{}
		}
	}
	required := (len(a.Cfg.Disaster.PeerWitnessURLs)+1)/2 + 1
	if len(matchingNodes) < required {
		return ownershipResolveResponse{OK: false, Decision: "unavailable", ReasonCode: "ownership_quorum_unavailable"}
	}
	if maximal.OwnerNodeID == a.Cfg.NodeID {
		return ownershipResolveResponse{OK: true, Decision: "automatic", ClaimID: maximal.ClaimID, ReasonCode: "last_active_owner"}
	}
	if availability[maximal.OwnerNodeID] {
		return ownershipResolveResponse{OK: true, Decision: "owner_available", ClaimID: maximal.ClaimID, ReasonCode: "last_active_owner_available"}
	}
	return ownershipResolveResponse{OK: true, Decision: "takeover_required", ClaimID: maximal.ClaimID, ReasonCode: "last_active_owner_unavailable"}
}

func (a *Agent) callOwnershipPeer(
	ctx context.Context,
	endpoint, route string,
	input ownershipPeerRequest,
) (ownershipPeerResponse, bool) {
	payload, err := json.Marshal(input)
	if err != nil {
		return ownershipPeerResponse{}, false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return ownershipPeerResponse{}, false
	}
	request.Header.Set("Content-Type", "application/json")
	protocol.SignRequest(request, a.Cfg.NodeID, string(a.peerWitnessSecret), payload)
	nonce := request.Header.Get(protocol.HeaderNonce)
	response, err := a.httpClient.Do(request)
	if err != nil {
		return ownershipPeerResponse{}, false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxOwnershipResponseBytes+1))
	if err != nil || len(body) > maxOwnershipResponseBytes || response.StatusCode != http.StatusOK {
		return ownershipPeerResponse{}, false
	}
	timestamp := response.Header.Get(peerOwnershipResponseTime)
	parsedTime, err := strconv.ParseInt(timestamp, 10, 64)
	expected := protocol.Sign(string(a.peerWitnessSecret), "RESPONSE", route, timestamp, nonce, body)
	if err != nil || absDuration(time.Since(time.Unix(parsedTime, 0))) > protocol.MaxClockSkew ||
		!hmac.Equal([]byte(expected), []byte(response.Header.Get(peerOwnershipResponseSig))) {
		return ownershipPeerResponse{}, false
	}
	var result ownershipPeerResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || !result.OK ||
		result.WitnessNodeID <= 0 || result.WitnessNodeID == a.Cfg.NodeID ||
		result.ObservedAt/1000 != parsedTime ||
		absDuration(time.Since(time.UnixMilli(result.ObservedAt))) > protocol.MaxClockSkew ||
		(result.Found && (result.Claim == nil || validateActivityOwnershipClaim(*result.Claim) != nil)) ||
		(!result.Found && result.Claim != nil) {
		return ownershipPeerResponse{}, false
	}
	return result, true
}

func (a *Agent) broadcastOwnershipClaim(ctx context.Context, claim activityOwnershipClaim) (int, error) {
	if len(a.Cfg.Disaster.PeerWitnessURLs) == 0 || len(a.peerWitnessSecret) < minimumPeerWitnessSecretBytes {
		return 1, nil
	}
	fingerprint, err := a.controllerFingerprint()
	if err != nil {
		return 1, err
	}
	type result struct {
		nodeID   int64
		accepted bool
	}
	results := make(chan result, len(a.Cfg.Disaster.PeerWitnessURLs))
	for _, raw := range a.Cfg.Disaster.PeerWitnessURLs {
		endpoint, _ := peerWitnessEndpointForRoute(raw, peerOwnershipObserveRoute)
		go func(endpoint string) {
			response, valid := a.callOwnershipPeer(ctx, endpoint, peerOwnershipObserveRoute,
				ownershipPeerRequest{ControllerFingerprint: fingerprint, Claim: &claim})
			accepted := valid && response.Found && response.Claim != nil &&
				response.Claim.ClaimID == claim.ClaimID && response.Accepted
			results <- result{nodeID: response.WitnessNodeID, accepted: accepted}
		}(endpoint)
	}
	nodes := map[int64]struct{}{a.Cfg.NodeID: {}}
	for range a.Cfg.Disaster.PeerWitnessURLs {
		select {
		case <-ctx.Done():
			return len(nodes), ctx.Err()
		case result := <-results:
			if result.accepted {
				nodes[result.nodeID] = struct{}{}
			}
		}
	}
	return len(nodes), nil
}

func peerWitnessEndpointForRoute(raw, route string) (string, error) {
	endpoint, err := peerWitnessEndpoint(raw)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(endpoint, peerWitnessRoute) + route, nil
}

func (a *Agent) handleAdapterOwnershipResolve(w http.ResponseWriter, r *http.Request) {
	var request ownershipResolveRequest
	if !a.authenticateAdapterOwnershipRequest(w, r, &request) {
		return
	}
	if !validOwnershipHandle(request.Handle) {
		writeOwnershipError(w, http.StatusBadRequest, "invalid_adapter_ownership_request")
		return
	}
	if !a.independentModeActive() {
		protocol.WriteJSON(w, http.StatusConflict, ownershipResolveResponse{
			OK: false, Decision: "unavailable", ReasonCode: "independent_mode_required",
		})
		return
	}
	protocol.WriteJSON(w, http.StatusOK, a.queryOwnershipQuorum(r.Context(), request.Handle))
}

func (a *Agent) handleAdapterOwnershipTakeover(w http.ResponseWriter, r *http.Request) {
	var request ownershipTakeoverRequest
	if !a.authenticateAdapterOwnershipRequest(w, r, &request) {
		return
	}
	if !validOwnershipHandle(request.Handle) || !validOwnershipDigest(request.ParentClaimID) ||
		!validUUID(request.OperationID) {
		writeOwnershipError(w, http.StatusBadRequest, "invalid_adapter_ownership_request")
		return
	}
	if !a.independentModeActive() {
		writeOwnershipError(w, http.StatusConflict, "independent_mode_required")
		return
	}
	result, err := a.performUserConfirmedTakeover(r.Context(), request)
	if err != nil {
		writeOwnershipError(w, http.StatusConflict, "ownership_takeover_not_committed")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, result)
}

func (a *Agent) authenticateAdapterOwnershipRequest(w http.ResponseWriter, r *http.Request, out any) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if a == nil || a.Cfg == nil || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" ||
		r.ContentLength <= 0 || r.ContentLength > maxOwnershipRequestBytes {
		writeOwnershipError(w, http.StatusBadRequest, "invalid_adapter_ownership_request")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOwnershipRequestBytes))
	nodeID, nodeErr := strconv.ParseInt(r.Header.Get(protocol.HeaderAgentID), 10, 64)
	if err != nil || nodeErr != nil || nodeID != a.Cfg.NodeID ||
		protocol.VerifyRequest(r, a.adapterPSK(), body) != nil ||
		!a.consumeAdapterNonce(r.Header.Get(protocol.HeaderNonce), time.Now().UTC()) {
		writeOwnershipError(w, http.StatusUnauthorized, "adapter_ownership_authentication_failed")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeOwnershipError(w, http.StatusBadRequest, "invalid_adapter_ownership_request")
		return false
	}
	return true
}

func (a *Agent) independentModeActive() bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.state.ControlMode.Mode == protocol.NodeModeIndependent
}

func (a *Agent) performUserConfirmedTakeover(
	ctx context.Context,
	request ownershipTakeoverRequest,
) (ownershipResolveResponse, error) {
	// Serialize the durable compare-and-set journal and its exactly-once local
	// audit. Takeovers are rare; an Agent-wide lock avoids duplicate audit
	// records when the adapter retries the same operation concurrently.
	a.ownershipTakeoverMu.Lock()
	defer a.ownershipTakeoverMu.Unlock()
	a.stateMu.Lock()
	operation, exists := a.state.OwnershipTakeovers[request.OperationID]
	a.stateMu.Unlock()
	if exists {
		if operation.Claim.Handle != request.Handle || operation.ParentClaimID != request.ParentClaimID {
			return ownershipResolveResponse{}, fmt.Errorf("ownership takeover operation conflict")
		}
	} else {
		decision := a.queryOwnershipQuorum(ctx, request.Handle)
		if !decision.OK || decision.Decision != "takeover_required" || decision.ClaimID != request.ParentClaimID {
			return ownershipResolveResponse{}, fmt.Errorf("ownership takeover precondition changed")
		}
		parent, found := a.currentActivityOwnership(request.Handle)
		if !found || parent.ClaimID != request.ParentClaimID {
			return ownershipResolveResponse{}, fmt.Errorf("ownership takeover parent unavailable")
		}
		claim, err := makeActivityOwnershipClaim(
			request.Handle, a.Cfg.NodeID, parent.ControllerGeneration, parent.ActivityEpoch,
			parent.TakeoverSequence+1, "user_confirmed_takeover", parent.ClaimID,
			request.OperationID, time.Now().UTC(),
		)
		if err != nil {
			return ownershipResolveResponse{}, err
		}
		accepted, err := a.applyActivityOwnershipClaim(claim, true)
		if err != nil || !accepted {
			return ownershipResolveResponse{}, fmt.Errorf("ownership takeover local CAS failed")
		}
		operation = ownershipTakeoverOperation{
			OperationID: request.OperationID, ParentClaimID: parent.ClaimID,
			Claim: claim, UpdatedAt: time.Now().UTC().UnixMilli(),
		}
		a.stateMu.Lock()
		if len(a.state.OwnershipTakeovers) >= maxOwnershipTakeovers {
			a.stateMu.Unlock()
			return ownershipResolveResponse{}, fmt.Errorf("ownership takeover journal full")
		}
		a.state.OwnershipTakeovers[request.OperationID] = operation
		err = a.saveRuntimeStateLocked()
		a.stateMu.Unlock()
		if err != nil {
			return ownershipResolveResponse{}, err
		}
	}
	if operation.Succeeded {
		if err := a.ensureOwnershipTakeoverAudit(operation); err != nil {
			return ownershipResolveResponse{}, err
		}
		return ownershipResolveResponse{
			OK: true, Decision: "takeover_committed", ClaimID: operation.Claim.ClaimID,
			ReasonCode: "user_confirmed_last_owner_failure",
		}, nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	acknowledged, _ := a.broadcastOwnershipClaim(probeCtx, operation.Claim)
	required := (len(a.Cfg.Disaster.PeerWitnessURLs)+1)/2 + 1
	if acknowledged < required {
		return ownershipResolveResponse{}, fmt.Errorf("ownership takeover quorum unavailable")
	}
	a.stateMu.Lock()
	current := a.state.OwnershipTakeovers[request.OperationID]
	current.Succeeded = true
	current.UpdatedAt = time.Now().UTC().UnixMilli()
	a.state.OwnershipTakeovers[request.OperationID] = current
	err := a.saveRuntimeStateLocked()
	a.stateMu.Unlock()
	if err != nil {
		return ownershipResolveResponse{}, err
	}
	operation = current
	if err := a.ensureOwnershipTakeoverAudit(operation); err != nil {
		return ownershipResolveResponse{}, err
	}
	return ownershipResolveResponse{
		OK: true, Decision: "takeover_committed", ClaimID: operation.Claim.ClaimID,
		ReasonCode: "user_confirmed_last_owner_failure",
	}, nil
}

func (a *Agent) ensureOwnershipTakeoverAudit(operation ownershipTakeoverOperation) error {
	if operation.Audited {
		return nil
	}
	succeeded := true
	if err := a.appendLocalAudit(localAuditEvent{
		Event: "user_confirmed_activity_takeover", OperationID: operation.OperationID,
		ControllerGeneration: operation.Claim.ControllerGeneration, Succeeded: &succeeded,
	}); err != nil {
		return fmt.Errorf("persist activity takeover audit: %w", err)
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	current, exists := a.state.OwnershipTakeovers[operation.OperationID]
	if !exists || current.Claim.ClaimID != operation.Claim.ClaimID || !current.Succeeded {
		return fmt.Errorf("activity takeover audit state changed")
	}
	current.Audited = true
	current.UpdatedAt = time.Now().UTC().UnixMilli()
	a.state.OwnershipTakeovers[operation.OperationID] = current
	return a.saveRuntimeStateLocked()
}

func validOwnershipHandle(handle string) bool {
	return safeInventoryString(handle, 128) && strings.ToLower(handle) == handle
}

func writeOwnershipError(w http.ResponseWriter, status int, code string) {
	protocol.WriteJSON(w, status, protocol.APIError{Error: "activity ownership request rejected", Code: code})
}

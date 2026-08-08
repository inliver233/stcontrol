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
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

const (
	peerWitnessRoute              = "/agent/disaster-witness/v1"
	peerWitnessSignatureHeader    = "X-Witness-Signature"
	peerWitnessTimestampHeader    = "X-Witness-Timestamp"
	maxPeerWitnessRequestBytes    = 4 << 10
	maxPeerWitnessResponseBytes   = 4 << 10
	maxPeerWitnesses              = 8
	minimumPeerWitnessSecretBytes = 32
)

type peerWitnessRequest struct {
	ControllerFingerprint string `json:"controller_fingerprint"`
}

type peerWitnessResponse struct {
	OK                    bool   `json:"ok"`
	WitnessNodeID         int64  `json:"witness_node_id"`
	ControllerFingerprint string `json:"controller_fingerprint"`
	ControllerAvailable   bool   `json:"controller_available"`
	ObservedAt            int64  `json:"observed_at"`
}

type peerWitnessResult struct {
	valid               bool
	controllerAvailable bool
	witnessNodeID       int64
}

func (a *Agent) loadPeerWitnessSecret() error {
	if a == nil || a.Cfg == nil {
		return fmt.Errorf("agent config is required")
	}
	if err := validatePeerWitnessPolicy(a.Cfg.Disaster); err != nil {
		return err
	}
	envName := strings.TrimSpace(a.Cfg.Disaster.PeerWitnessSecretEnv)
	if envName == "" {
		if len(a.Cfg.Disaster.PeerWitnessURLs) > 0 {
			return fmt.Errorf("peer witness secret environment variable is required")
		}
		return nil
	}
	secret, exists := os.LookupEnv(envName)
	if !exists || secret == "" {
		if len(a.Cfg.Disaster.PeerWitnessURLs) > 0 {
			return fmt.Errorf("peer witness secret is unavailable")
		}
		return nil
	}
	if len(secret) < minimumPeerWitnessSecretBytes {
		return fmt.Errorf("peer witness secret must contain at least %d bytes", minimumPeerWitnessSecretBytes)
	}
	a.peerWitnessSecret = []byte(secret)
	return nil
}

func validatePeerWitnessPolicy(policy config.AgentDisasterPolicy) error {
	if len(policy.PeerWitnessURLs) > maxPeerWitnesses {
		return fmt.Errorf("at most %d peer witnesses are allowed", maxPeerWitnesses)
	}
	seen := make(map[string]struct{}, len(policy.PeerWitnessURLs))
	for _, raw := range policy.PeerWitnessURLs {
		endpoint, err := peerWitnessEndpoint(raw)
		if err != nil {
			return err
		}
		if _, exists := seen[endpoint]; exists {
			return fmt.Errorf("duplicate peer witness URL")
		}
		seen[endpoint] = struct{}{}
	}
	if strings.ContainsAny(policy.PeerWitnessSecretEnv, "\r\n\x00") ||
		strings.TrimSpace(policy.PeerWitnessSecretEnv) != policy.PeerWitnessSecretEnv {
		return fmt.Errorf("invalid peer witness secret environment variable")
	}
	return nil
}

func peerWitnessEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("invalid peer witness URL")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return "", fmt.Errorf("peer witness URL must use HTTPS")
	}
	parsed.Path = peerWitnessRoute
	return parsed.String(), nil
}

func (a *Agent) controllerFingerprint() (string, error) {
	endpoint, err := a.controllerEndpoint("/api/health")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid controller health endpoint")
	}
	canonical := strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host) + parsed.EscapedPath()
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:]), nil
}

func (a *Agent) handlePeerWitness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if a == nil || a.Cfg == nil || len(a.peerWitnessSecret) < minimumPeerWitnessSecretBytes {
		protocol.WriteJSON(w, http.StatusServiceUnavailable, protocol.APIError{
			Error: "peer witness unavailable", Code: "peer_witness_unavailable",
		})
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" ||
		r.ContentLength <= 0 || r.ContentLength > maxPeerWitnessRequestBytes {
		protocol.WriteJSON(w, http.StatusBadRequest, protocol.APIError{
			Error: "peer witness request invalid", Code: "invalid_peer_witness_request",
		})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPeerWitnessRequestBytes))
	requesterNodeID, nodeErr := strconv.ParseInt(r.Header.Get(protocol.HeaderAgentID), 10, 64)
	if err != nil || nodeErr != nil || requesterNodeID <= 0 || requesterNodeID == a.Cfg.NodeID ||
		protocol.VerifyRequest(r, string(a.peerWitnessSecret), body) != nil ||
		!a.consumeWitnessNonce(r.Header.Get(protocol.HeaderNonce), time.Now().UTC()) {
		protocol.WriteJSON(w, http.StatusUnauthorized, protocol.APIError{
			Error: "peer witness authentication failed", Code: "peer_witness_authentication_failed",
		})
		return
	}
	var request peerWitnessRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	localFingerprint, fingerprintErr := a.controllerFingerprint()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		fingerprintErr != nil || len(request.ControllerFingerprint) != sha256.Size*2 ||
		!hmac.Equal([]byte(request.ControllerFingerprint), []byte(localFingerprint)) {
		protocol.WriteJSON(w, http.StatusBadRequest, protocol.APIError{
			Error: "peer witness request invalid", Code: "invalid_peer_witness_request",
		})
		return
	}
	select {
	case a.witnessSlots <- struct{}{}:
		defer func() { <-a.witnessSlots }()
	default:
		w.Header().Set("Retry-After", "5")
		protocol.WriteJSON(w, http.StatusTooManyRequests, protocol.APIError{
			Error: "peer witness busy", Code: "peer_witness_busy",
		})
		return
	}
	observedAt := time.Now().UTC().UnixMilli()
	response := peerWitnessResponse{
		OK: true, WitnessNodeID: a.Cfg.NodeID,
		ControllerFingerprint: localFingerprint,
		ControllerAvailable:   a.controllerHealthAvailable(r.Context()), ObservedAt: observedAt,
	}
	responseBody, err := json.Marshal(response)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "peer witness unavailable")
		return
	}
	timestamp := strconv.FormatInt(observedAt/1000, 10)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(peerWitnessTimestampHeader, timestamp)
	w.Header().Set(peerWitnessSignatureHeader, protocol.Sign(
		string(a.peerWitnessSecret), "RESPONSE", peerWitnessRoute, timestamp,
		r.Header.Get(protocol.HeaderNonce), responseBody,
	))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseBody)
}

func (a *Agent) consumeWitnessNonce(nonce string, now time.Time) bool {
	a.witnessNonceMu.Lock()
	defer a.witnessNonceMu.Unlock()
	if a.witnessNonces == nil {
		a.witnessNonces = make(map[string]time.Time)
	}
	for value, expiresAt := range a.witnessNonces {
		if !expiresAt.After(now) {
			delete(a.witnessNonces, value)
		}
	}
	if _, exists := a.witnessNonces[nonce]; exists || len(a.witnessNonces) >= 4096 {
		return false
	}
	a.witnessNonces[nonce] = now.Add(2 * protocol.MaxClockSkew)
	return true
}

func (a *Agent) peerWitnessQuorumConfirmsLoss(ctx context.Context) bool {
	if a.peerWitnessProbe != nil {
		return a.peerWitnessProbe(ctx)
	}
	if a == nil || a.Cfg == nil || len(a.peerWitnessSecret) < minimumPeerWitnessSecretBytes ||
		len(a.Cfg.Disaster.PeerWitnessURLs) == 0 ||
		validatePeerWitnessPolicy(a.Cfg.Disaster) != nil {
		return false
	}
	fingerprint, err := a.controllerFingerprint()
	if err != nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	results := make(chan peerWitnessResult, len(a.Cfg.Disaster.PeerWitnessURLs))
	for _, raw := range a.Cfg.Disaster.PeerWitnessURLs {
		endpoint, _ := peerWitnessEndpoint(raw)
		go func(endpoint string) {
			results <- a.probePeerWitness(probeCtx, endpoint, fingerprint)
		}(endpoint)
	}
	requiredPeerConfirmations := (len(a.Cfg.Disaster.PeerWitnessURLs) + 1) / 2
	confirmedNodes := make(map[int64]struct{}, requiredPeerConfirmations)
	for range a.Cfg.Disaster.PeerWitnessURLs {
		select {
		case <-probeCtx.Done():
			return false
		case result := <-results:
			if !result.valid {
				continue
			}
			if result.controllerAvailable {
				return false
			}
			confirmedNodes[result.witnessNodeID] = struct{}{}
		}
	}
	return len(confirmedNodes) >= requiredPeerConfirmations
}

func (a *Agent) probePeerWitness(ctx context.Context, endpoint, fingerprint string) peerWitnessResult {
	payload, err := json.Marshal(peerWitnessRequest{ControllerFingerprint: fingerprint})
	if err != nil {
		return peerWitnessResult{}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return peerWitnessResult{}
	}
	request.Header.Set("Content-Type", "application/json")
	protocol.SignRequest(request, a.Cfg.NodeID, string(a.peerWitnessSecret), payload)
	nonce := request.Header.Get(protocol.HeaderNonce)
	response, err := a.httpClient.Do(request)
	if err != nil {
		return peerWitnessResult{}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPeerWitnessResponseBytes+1))
	if err != nil || len(body) > maxPeerWitnessResponseBytes || response.StatusCode != http.StatusOK {
		return peerWitnessResult{}
	}
	timestamp := response.Header.Get(peerWitnessTimestampHeader)
	parsedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || absDuration(time.Since(time.Unix(parsedTimestamp, 0))) > protocol.MaxClockSkew {
		return peerWitnessResult{}
	}
	expected := protocol.Sign(string(a.peerWitnessSecret), "RESPONSE", peerWitnessRoute, timestamp, nonce, body)
	if !hmac.Equal([]byte(expected), []byte(response.Header.Get(peerWitnessSignatureHeader))) {
		return peerWitnessResult{}
	}
	var result peerWitnessResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || !result.OK ||
		result.WitnessNodeID <= 0 || result.WitnessNodeID == a.Cfg.NodeID ||
		result.ControllerFingerprint != fingerprint || result.ObservedAt/1000 != parsedTimestamp ||
		absDuration(time.Since(time.UnixMilli(result.ObservedAt))) > protocol.MaxClockSkew {
		return peerWitnessResult{}
	}
	return peerWitnessResult{
		valid: true, controllerAvailable: result.ControllerAvailable,
		witnessNodeID: result.WitnessNodeID,
	}
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

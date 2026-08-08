package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"stcontrol/internal/protocol"
)

const (
	maxAdapterTicketRequestBytes  = 16 << 10
	maxAdapterTicketResponseBytes = 64 << 10
)

type adapterTicketRedeemRequest struct {
	Code string `json:"code"`
}

type adapterTicketRedeemResponse struct {
	Handle               string `json:"handle"`
	ActivityEpoch        int64  `json:"activity_epoch"`
	ControllerGeneration int64  `json:"controller_generation"`
}

// handleAdapterTicketRedeem is the only browser-adapter bridge exposed by the
// Agent. SillyTavern authenticates with its stable, node-local adapter key;
// the Agent then forwards one fixed request using the independently rotated
// Controller credential. The adapter never receives that Controller key.
func (a *Agent) handleAdapterTicketRedeem(admin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if a == nil || a.Cfg == nil || r.URL.RawQuery != "" ||
			r.Header.Get("Content-Type") != "application/json" {
			protocol.WriteError(w, http.StatusBadRequest, "adapter ticket request invalid")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAdapterTicketRequestBytes))
		if err != nil || len(body) == 0 {
			protocol.WriteError(w, http.StatusBadRequest, "adapter ticket request invalid")
			return
		}
		nodeID, err := strconv.ParseInt(r.Header.Get(protocol.HeaderAgentID), 10, 64)
		if err != nil || nodeID != a.Cfg.NodeID || protocol.VerifyRequest(r, a.adapterPSK(), body) != nil ||
			!a.consumeAdapterNonce(r.Header.Get(protocol.HeaderNonce), time.Now().UTC()) {
			protocol.WriteError(w, http.StatusUnauthorized, "adapter authentication failed")
			return
		}
		var request adapterTicketRedeemRequest
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || request.Code == "" || len(request.Code) > 1024 ||
			decoder.Decode(&struct{}{}) != io.EOF {
			protocol.WriteError(w, http.StatusBadRequest, "adapter ticket request invalid")
			return
		}
		controllerPath := "/api/tickets/redeem"
		if admin {
			controllerPath = "/api/tickets/redeem-admin"
		}
		status, headers, response, err := a.doControllerRequest(
			r.Context(), http.MethodPost, controllerPath, request,
		)
		if err != nil || len(response) > maxAdapterTicketResponseBytes {
			protocol.WriteError(w, http.StatusServiceUnavailable, "ticket redemption unavailable")
			return
		}
		if !admin && status >= 200 && status < 300 {
			var redemption adapterTicketRedeemResponse
			if json.Unmarshal(response, &redemption) != nil ||
				!validOwnershipHandle(redemption.Handle) || redemption.ActivityEpoch <= 0 ||
				redemption.ControllerGeneration <= 0 {
				protocol.WriteError(w, http.StatusBadGateway, "ticket redemption response invalid")
				return
			}
			if err := a.recordControllerOwnershipGrant(
				r.Context(), redemption.Handle, redemption.ControllerGeneration, redemption.ActivityEpoch,
			); err != nil {
				// Managed login remains available. Disaster-native login will later
				// fail closed unless a peer quorum retained this exact grant.
				log.Printf("持久化活动归属见证失败: %v", err)
			}
		}
		if contentType := headers.Get("Content-Type"); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		} else {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		}
		w.WriteHeader(status)
		_, _ = w.Write(response)
	}
}

func (a *Agent) consumeAdapterNonce(nonce string, now time.Time) bool {
	a.adapterNonceMu.Lock()
	defer a.adapterNonceMu.Unlock()
	if a.adapterNonces == nil {
		a.adapterNonces = make(map[string]time.Time)
	}
	for value, expiresAt := range a.adapterNonces {
		if !expiresAt.After(now) {
			delete(a.adapterNonces, value)
		}
	}
	if _, exists := a.adapterNonces[nonce]; exists || len(a.adapterNonces) >= 4096 {
		return false
	}
	a.adapterNonces[nonce] = now.Add(2 * protocol.MaxClockSkew)
	return true
}

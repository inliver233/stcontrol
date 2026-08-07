package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// DeriveAgentInventoryKey keeps account-inventory fingerprints unlinkable
// between nodes and separate from command encryption/authentication keys.
func DeriveAgentInventoryKey(psk string) []byte {
	return sha256Of([]byte("stcontrol-agent-inventory:v1:" + psk))
}

// AgentInventoryFingerprint produces a stable node-scoped HMAC without
// exposing low-entropy handles or OAuth subjects to durable command results.
func AgentInventoryFingerprint(psk, purpose string, parts ...string) string {
	mac := hmac.New(sha256.New, DeriveAgentInventoryKey(psk))
	_, _ = mac.Write([]byte("stcontrol-agent-inventory-fingerprint:v1\n"))
	_, _ = mac.Write([]byte(purpose))
	for _, part := range parts {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

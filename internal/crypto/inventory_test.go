package crypto

import "testing"

func TestAgentInventoryFingerprintIsNodeAndPurposeScoped(t *testing.T) {
	t.Parallel()
	first := AgentInventoryFingerprint("node-one", "oauth-subject", "discord", "stable-subject")
	replay := AgentInventoryFingerprint("node-one", "oauth-subject", "discord", "stable-subject")
	otherNode := AgentInventoryFingerprint("node-two", "oauth-subject", "discord", "stable-subject")
	otherPurpose := AgentInventoryFingerprint("node-one", "directory", "discord", "stable-subject")
	otherSubject := AgentInventoryFingerprint("node-one", "oauth-subject", "discord", "other-subject")
	if len(first) != 64 || first != replay || first == otherNode || first == otherPurpose || first == otherSubject {
		t.Fatalf("first=%q replay=%q otherNode=%q otherPurpose=%q otherSubject=%q",
			first, replay, otherNode, otherPurpose, otherSubject)
	}
}

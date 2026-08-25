package controller

import "testing"

func TestControllerAgentVersionOrdering(t *testing.T) {
	t.Parallel()
	if compareControllerAgentVersions("0.4.0", "0.3.9") != 1 ||
		compareControllerAgentVersions("0.4.0", "0.4.0") != 0 ||
		compareControllerAgentVersions("0.3.9", "0.4.0") != -1 {
		t.Fatal("unexpected Controller Agent version ordering")
	}
	for _, invalid := range []string{"", "v0.4.0", "0.4", "00.4.0", "0.4.x"} {
		if _, ok := parseControllerAgentVersion(invalid); ok {
			t.Fatalf("invalid Agent version accepted: %q", invalid)
		}
	}
}

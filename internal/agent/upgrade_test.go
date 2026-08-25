package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAgentUpgradeVersionOrdering(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		left, right string
		want        int
	}{
		{"0.4.0", "0.4.0", 0},
		{"0.4.1", "0.4.0", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.3.9", "0.4.0", -1},
	} {
		if got := compareAgentVersions(test.left, test.right); got != test.want {
			t.Fatalf("compareAgentVersions(%q,%q)=%d want %d", test.left, test.right, got, test.want)
		}
	}
	for _, invalid := range []string{"", "v1.0.0", "1.0", "01.0.0", "1.0.-1", "1.0.x"} {
		if validAgentVersion(invalid) {
			t.Fatalf("invalid Agent version accepted: %q", invalid)
		}
	}
}

func TestTrustedControllerArtifactURLRejectsRemotePlaintextAndURLInjection(t *testing.T) {
	t.Parallel()
	got, err := trustedControllerArtifactURL("https://controller.example/base", "amd64")
	if err != nil || got != "https://controller.example/base/dist/agent-linux-amd64" {
		t.Fatalf("trusted artifact URL=%q err=%v", got, err)
	}
	if _, err := trustedControllerArtifactURL("http://controller.example", "amd64"); err == nil {
		t.Fatal("remote plaintext Controller artifact URL accepted")
	}
	if _, err := trustedControllerArtifactURL("https://user:pass@controller.example", "amd64"); err == nil {
		t.Fatal("credential-bearing Controller artifact URL accepted")
	}
	if _, err := trustedControllerArtifactURL("https://controller.example?artifact=evil", "amd64"); err == nil {
		t.Fatal("query-bearing Controller artifact URL accepted")
	}
}

func TestVerifyAgentBinaryVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable fixture uses a POSIX shell")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent-fixture")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n[ \"$1\" = --version ] && printf '0.4.0\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyAgentBinaryVersion(path, "0.4.0"); err != nil {
		t.Fatalf("verify matching Agent binary: %v", err)
	}
	if err := verifyAgentBinaryVersion(path, "0.5.0"); err == nil || !strings.Contains(err.Error(), "version mismatch") {
		t.Fatalf("mismatched Agent binary error=%v", err)
	}
}

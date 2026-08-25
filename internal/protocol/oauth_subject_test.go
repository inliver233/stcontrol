package protocol

import "testing"

func TestCanonicalOAuthSubjectAcceptsRawAndLegacyForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		provider string
		subject  string
		want     string
	}{
		{provider: "discord", subject: "123", want: "discord_123"},
		{provider: "discord", subject: "discord_123", want: "discord_123"},
		{provider: "linuxdo", subject: "42", want: "linuxdo_42"},
		{provider: "linuxdo", subject: "linuxdo_42", want: "linuxdo_42"},
		{provider: "github", subject: "7", want: "github_7"},
		{provider: "unknown", subject: "opaque", want: "opaque"},
		{provider: "discord", subject: "", want: ""},
	}
	for _, test := range tests {
		test := test
		t.Run(test.provider+"/"+test.subject, func(t *testing.T) {
			t.Parallel()
			if got := CanonicalOAuthSubject(test.provider, test.subject); got != test.want {
				t.Fatalf("CanonicalOAuthSubject(%q,%q)=%q, want %q", test.provider, test.subject, got, test.want)
			}
		})
	}
}

package protocol

import "strings"

// CanonicalOAuthSubject normalizes the historical SillyTavern representation
// (for example "discord_123") and the Controller representation ("123") to
// one provider-qualified value. Keeping the provider prefix in the canonical
// form avoids cross-provider collisions while accepting both rolling-upgrade
// formats without exposing the subject itself.
func CanonicalOAuthSubject(provider, subject string) string {
	if subject == "" {
		return ""
	}
	switch provider {
	case "discord", "linuxdo", "github":
		prefix := provider + "_"
		if strings.HasPrefix(subject, prefix) {
			return subject
		}
		return prefix + subject
	default:
		return subject
	}
}

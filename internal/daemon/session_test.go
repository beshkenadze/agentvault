package daemon

import (
	"testing"
	"time"
)

func TestSessionIssueAndRedactor(t *testing.T) {
	s := NewSession(15 * time.Minute)
	s.Issue("GITHUB_TOKEN", "ghp_secret")
	s.Issue("STRIPE", "sk_live_x")

	r := s.Redactor() // *redact.Redactor over all issued values
	got := r.Redact("token=ghp_secret and sk_live_x")
	if got == "token=ghp_secret and sk_live_x" {
		t.Fatalf("issued values not masked: %q", got)
	}
}

func TestSessionExpiryClears(t *testing.T) {
	s := NewSession(0) // already-expired TTL
	s.Issue("X", "v")
	if !s.Expired() {
		t.Fatal("zero TTL should be expired immediately")
	}
	// After expiry, the redactor must not mask the old value.
	if r := s.Redactor(); r.Redact("v") != "v" {
		t.Fatal("expired session must not mask old values")
	}
}

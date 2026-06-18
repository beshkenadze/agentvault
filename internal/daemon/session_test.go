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

// A value issued in an expired window must NOT resurface after a re-issue: once the
// TTL lapses, Issue clears the stale set before recording the new value, so the old
// secret is dropped (not merely hidden). Uses an injected clock — no wall-clock sleep.
func TestSessionReissueAfterExpiryDropsOldValue(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	s := NewSession(10 * time.Minute)
	s.now = func() time.Time { return cur }

	s.Issue("OLD", "oldval") // first Issue rebases the deadline onto the fake clock
	if s.Expired() {
		t.Fatal("must not be expired immediately after issue")
	}

	cur = base.Add(11 * time.Minute) // advance past the deadline
	if !s.Expired() {
		t.Fatal("must be expired once the TTL elapses")
	}

	s.Issue("NEW", "newval") // expired path must clear OLD before recording NEW
	r := s.Redactor()
	if got := r.Redact("oldval"); got != "oldval" {
		t.Fatalf("stale value from an expired window resurfaced: %q", got)
	}
	if got := r.Redact("newval"); got == "newval" {
		t.Fatalf("new value not masked after re-issue: %q", got)
	}
}

package daemon

import (
	"errors"
	"os"
)

// ErrLocked means the daemon cannot authorize a secret issuance (no presence
// available, or session locked). Maps to ipc.CodeLocked.
var ErrLocked = errors.New("vault locked: authorization not available")

// ErrDenied means a presence check ran but the user denied it (cancel/failure).
// Maps to ipc.CodeDenied. Distinct from ErrLocked (no auth available at all).
var ErrDenied = errors.New("access denied")

// Presence is one native presence check: Prompt asks the user to confirm
// (Touch ID in production) and returns nil on success. Phase 5 provides the
// Touch ID implementation; the test stub is env-gated. The resolver/session —
// not the Presence object — enforce which tier needs what.
type Presence interface {
	Prompt(reason string) error
}

// stubPresence approves iff AV_TEST_AUTH=allow is set in the daemon's
// environment. It exists so the pipeline stays end-to-end testable without a
// biometric prompt (CI/e2e).
type stubPresence struct{}

func NewStubPresence() Presence { return stubPresence{} }

func (stubPresence) Prompt(_ string) error {
	if os.Getenv("AV_TEST_AUTH") == "allow" {
		return nil
	}
	return ErrLocked
}

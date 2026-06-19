package daemon

import (
	"errors"
	"testing"
	"time"

	"filippo.io/age"
)

// stubUnwrapper returns the given identity's bytes, mimicking enclave.Unwrap returning
// the raw age identity bytes (id.String()+"\n") after a successful Touch ID. This is the
// presence proof: one biometric covers session-open AND key material.
func stubUnwrapper(id *age.X25519Identity) func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(id.String() + "\n"), nil }
}

// TestUnlockWithUnwrapperYieldsIdentity: a session WithUnwrapper unlocked via
// unlockWithUnwrapper exposes a usable, non-nil age.Identity (the unwrapped key).
func TestUnlockWithUnwrapperYieldsIdentity(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	sess := NewSession(15 * time.Minute).WithUnwrapper(stubUnwrapper(id))
	if !sess.HasUnwrapper() {
		t.Fatal("HasUnwrapper must be true after WithUnwrapper")
	}
	if err := sess.unlockWithUnwrapper(15 * time.Minute); err != nil {
		t.Fatalf("unlockWithUnwrapper: %v", err)
	}
	got, err := sess.Identity()
	if err != nil {
		t.Fatalf("Identity after unlock: %v", err)
	}
	if got == nil {
		t.Fatal("Identity must be non-nil after unlock")
	}
	// The parsed identity must round-trip to the same recipient as the original key,
	// proving it is the very identity the unwrapper handed back (not some empty stub).
	parsed, ok := got.(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected *age.X25519Identity, got %T", got)
	}
	if parsed.Recipient().String() != id.Recipient().String() {
		t.Fatal("Identity() did not round-trip to the unwrapped key")
	}
}

// TestIdentityZeroizedOnLock: the key material the session holds is OVERWRITTEN (not
// merely dropped) when the session locks — daemon compromise after lock cannot recover
// it — and Identity() then reports ErrLocked.
func TestIdentityZeroizedOnLock(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	sess := NewSession(15 * time.Minute).WithUnwrapper(stubUnwrapper(id))
	if err := sess.unlockWithUnwrapper(15 * time.Minute); err != nil {
		t.Fatalf("unlockWithUnwrapper: %v", err)
	}
	// Capture the backing buffer BEFORE locking; Lock's destroyIssuedLocked zeroizes it.
	buf := sess.identity.bytesForTest()
	if len(buf) == 0 {
		t.Fatal("identity buffer must be non-empty before lock")
	}
	sess.Lock()
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("identity buffer not zeroized at byte %d: %d", i, b)
		}
	}
	if _, err := sess.Identity(); !errors.Is(err, ErrLocked) {
		t.Fatalf("Identity after lock must be ErrLocked, got %v", err)
	}
}

// TestUnlockWithUnwrapperDeniedStaysLocked: a failing unwrapper (the user denied Touch
// ID) propagates its error and leaves the session LOCKED with no key — unwrap is the
// presence proof, so a denied unwrap is a denied unlock.
func TestUnlockWithUnwrapperDeniedStaysLocked(t *testing.T) {
	sess := NewSession(15 * time.Minute).WithUnwrapper(func() ([]byte, error) {
		return nil, ErrDenied
	})
	err := sess.unlockWithUnwrapper(15 * time.Minute)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("unlockWithUnwrapper must return ErrDenied, got %v", err)
	}
	if !sess.Locked() {
		t.Fatal("session must remain locked after denied unwrap")
	}
	if _, err := sess.Identity(); !errors.Is(err, ErrLocked) {
		t.Fatalf("Identity after denied unwrap must be ErrLocked, got %v", err)
	}
}

// TestIdentityLockedWithoutUnwrapper: a plain locked session (no unwrapper wired) has no
// identity and reports ErrLocked; HasUnwrapper is false.
func TestIdentityLockedWithoutUnwrapper(t *testing.T) {
	sess := NewSession(15 * time.Minute)
	if sess.HasUnwrapper() {
		t.Fatal("HasUnwrapper must be false on a session with no unwrapper")
	}
	if _, err := sess.Identity(); !errors.Is(err, ErrLocked) {
		t.Fatalf("Identity on locked session must be ErrLocked, got %v", err)
	}
}

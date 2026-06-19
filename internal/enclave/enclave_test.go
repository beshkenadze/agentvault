package enclave

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// cgoEnabled reports whether this binary was built with cgo. The darwin
// implementation requires darwin && cgo; everything else is the stub. We detect
// cgo via the build-tagged constant below so the test branches the same way the
// implementation files do.

// TestErrorIsValueFree asserts no exported function ever embeds plaintext in an
// error: passing obvious "plaintext" through Wrap/Unwrap and checking the error
// string never contains it. This holds on EVERY build (stub or real): the stub
// returns a fixed phrase; the real path fails closed with an OSStatus-only error
// when the Enclave is unreachable. SECURITY regression guard.
func TestErrorIsValueFree(t *testing.T) {
	secret := "AGE-SECRET-KEY-PLAINTEXTMUSTNOTLEAK0000000000000000000000000000"

	if _, err := Wrap([]byte(secret)); err != nil {
		if strings.Contains(err.Error(), "PLAINTEXTMUSTNOTLEAK") {
			t.Fatalf("Wrap error leaked plaintext: %q", err)
		}
	}
	if _, err := Unwrap([]byte(secret)); err != nil {
		if strings.Contains(err.Error(), "PLAINTEXTMUSTNOTLEAK") {
			t.Fatalf("Unwrap error leaked plaintext: %q", err)
		}
	}
}

// TestEmptyInputRejected asserts the Go-side guards reject empty input on every
// build BEFORE any native call, so a zero-length blob can never be mistaken for a
// successful wrap/unwrap (fail-closed).
func TestEmptyInputRejected(t *testing.T) {
	if _, err := Wrap(nil); err == nil {
		t.Fatal("Wrap(nil) must error")
	}
	if _, err := Unwrap(nil); err == nil {
		t.Fatal("Unwrap(nil) must error")
	}
}

// TestStubUnavailableWhenNoCgo asserts that on builds WITHOUT darwin+cgo every
// operation reports the stable "unavailable" phrase, so cmd/avd's fallback to the
// env-path identity engages. On darwin+cgo this assertion is skipped (the real
// path is exercised by TestEnclaveLinkedAndCallable instead).
func TestStubUnavailableWhenNoCgo(t *testing.T) {
	if cgoEnabled && runtime.GOOS == "darwin" {
		t.Skip("darwin+cgo build: real enclave path, not the stub")
	}
	const want = "secure enclave unavailable on this build"
	if err := EnsureKey(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("EnsureKey stub: got %v, want %q", err, want)
	}
	if _, err := Wrap([]byte("x")); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Wrap stub: got %v, want %q", err, want)
	}
	if _, err := Unwrap([]byte("x")); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Unwrap stub: got %v, want %q", err, want)
	}
}

// TestEnclaveLinkedAndCallable verifies (on darwin+cgo) that the Security.framework
// bridge is LINKED and the functions are CALLABLE — it does NOT assert success.
//
// COMPILE-VERIFIED ONLY: CI/subagents have no Secure Enclave + entitlements, so
// EnsureKey is EXPECTED to fail there; we skip gracefully on failure rather than
// fail the test. A real hardware run is a separate MANUAL step. Crucially we never
// call Unwrap here (it would block on a Touch ID prompt) and we never assert a
// functional round trip — that is precisely what cannot run in CI.
func TestEnclaveLinkedAndCallable(t *testing.T) {
	if !cgoEnabled || runtime.GOOS != "darwin" {
		t.Skip("not a darwin+cgo build: enclave is the stub")
	}
	// The only thing we can safely assert in an automated context: the call links
	// and returns without panicking. Key creation needs the keychain-access-group
	// entitlement + Enclave hardware, absent in CI, so a non-nil error is fine and
	// we skip. A nil error means a real key now exists (a hardware run); also OK.
	if err := EnsureKey(); err != nil {
		t.Skipf("enclave unreachable in this environment (expected in CI): %v", err)
	}
	t.Log("EnsureKey succeeded: a Secure Enclave key exists (likely real hardware)")
}

// TestIsUserCanceledFalseForNonCancel asserts the build-agnostic NEGATIVE cases: a nil
// error, a plain error, and the "unavailable" error every stub returns must all report
// false, so cmd/avd maps them to CodeLocked (not CodeDenied). The POSITIVE case
// (errSecUserCanceled / errSecAuthFailed) references the darwin-only *StatusError and is
// covered in enclave_cancel_darwin_test.go.
func TestIsUserCanceledFalseForNonCancel(t *testing.T) {
	if IsUserCanceled(nil) {
		t.Fatal("IsUserCanceled(nil) must be false")
	}
	if IsUserCanceled(errors.New("some other failure")) {
		t.Fatal("IsUserCanceled(plain error) must be false")
	}
	// errUnavailable is what every non-cgo stub returns and what the real path returns
	// when the Enclave is unreachable — neither is a user cancel.
	if IsUserCanceled(errUnavailable) {
		t.Fatal("IsUserCanceled(errUnavailable) must be false")
	}
}

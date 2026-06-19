//go:build darwin && cgo

package enclave

import (
	"errors"
	"fmt"
	"testing"
)

// TestIsUserCanceledTrueForCancelCodes is the POSITIVE side of the user-cancel
// classification (darwin+cgo only — *StatusError exists only on the real path). It
// proves IsUserCanceled inspects the structured OSStatus Code (via errors.As) rather
// than the error string: a *StatusError carrying errSecUserCanceled / errSecAuthFailed
// reports true (so cmd/avd maps it to daemon.ErrDenied → CodeDenied), while another
// OSStatus reports false (→ CodeLocked). A wrapped *StatusError still matches.
func TestIsUserCanceledTrueForCancelCodes(t *testing.T) {
	cancel := []int{errSecUserCanceled, errSecAuthFailed}
	for _, code := range cancel {
		err := statusError("enclave unwrap", code)
		if !IsUserCanceled(err) {
			t.Fatalf("IsUserCanceled(StatusError{%d}) = false, want true", code)
		}
		// Wrapped through fmt.Errorf %w must still be detected (errors.As unwraps).
		if !IsUserCanceled(fmt.Errorf("unlock: %w", err)) {
			t.Fatalf("IsUserCanceled(wrapped StatusError{%d}) = false, want true", code)
		}
	}
	// A hardware/entitlement failure (some other OSStatus) is NOT a user cancel.
	if IsUserCanceled(statusError("enclave unwrap", -25300)) {
		t.Fatal("IsUserCanceled(non-cancel OSStatus) must be false")
	}
	// A plain (non-StatusError) error never matches.
	if IsUserCanceled(errors.New("nope")) {
		t.Fatal("IsUserCanceled(plain error) must be false")
	}
}

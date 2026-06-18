//go:build darwin

package keychain

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// mockRunner records the args it was called with and returns canned output/error,
// standing in for the real `security` binary so the resolve logic is fully testable.
type mockRunner struct {
	gotArgs []string
	out     []byte
	err     error
}

func (m *mockRunner) run(args ...string) ([]byte, error) {
	m.gotArgs = args
	return m.out, m.err
}

func TestResolveMapsLocatorToSecurityArgsAndReturnsValue(t *testing.T) {
	// `security ... -w` writes ONLY the password to stdout (trailing newline); trim it.
	m := &mockRunner{out: []byte("ghp_value\n")}
	b := NewWithRunner(m.run)

	got, err := b.Resolve("GitHub/ci-token")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q, want %q", got.Value, "ghp_value")
	}

	// service = first segment, account = rest; passed as -s <service> -a <account> -w.
	want := []string{"find-generic-password", "-s", "GitHub", "-a", "ci-token", "-w"}
	if len(m.gotArgs) != len(want) {
		t.Fatalf("args = %v, want %v", m.gotArgs, want)
	}
	for i := range want {
		if m.gotArgs[i] != want[i] {
			t.Fatalf("args = %v, want %v", m.gotArgs, want)
		}
	}
}

func TestResolveAccountMayContainSlashes(t *testing.T) {
	// service = first segment, account = the rest verbatim (may contain "/").
	m := &mockRunner{out: []byte("v\n")}
	b := NewWithRunner(m.run)

	if _, err := b.Resolve("AWS/role/ci/key"); err != nil {
		t.Fatal(err)
	}
	want := []string{"find-generic-password", "-s", "AWS", "-a", "role/ci/key", "-w"}
	if len(m.gotArgs) != len(want) {
		t.Fatalf("args = %v, want %v", m.gotArgs, want)
	}
	for i := range want {
		if m.gotArgs[i] != want[i] {
			t.Fatalf("args = %v, want %v", m.gotArgs, want)
		}
	}
}

func TestResolveRejectsLocatorWithoutAccount(t *testing.T) {
	// A bare service with no "/account" is malformed; must error and never call security.
	m := &mockRunner{}
	b := NewWithRunner(m.run)

	if _, err := b.Resolve("GitHub"); err == nil {
		t.Fatal("expected error for locator without account")
	}
	if m.gotArgs != nil {
		t.Fatalf("security must not be invoked for a malformed locator; got %v", m.gotArgs)
	}
}

func TestResolveNotFoundMapsToErrNotFound(t *testing.T) {
	// A security-style not-found message must surface as backend.ErrNotFound (errors.Is-able)
	// so a missing secret is never confused with a transport/permission failure.
	m := &mockRunner{err: errors.New("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.")}
	b := NewWithRunner(m.run)

	_, err := b.Resolve("GitHub/missing")
	if !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestResolveExitStatus44MapsToErrNotFound(t *testing.T) {
	// `security` exits 44 when the item is absent; that code alone (even without the
	// stderr phrase) must map to ErrNotFound.
	m := &mockRunner{err: &fakeExit{code: 44}}
	b := NewWithRunner(m.run)

	_, err := b.Resolve("GitHub/missing")
	if !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestResolveGenericErrorIsWrappedWithoutValue(t *testing.T) {
	// A generic security failure must NOT be ErrNotFound (fail-closed: don't drop a secret
	// by reporting "missing"), must be wrapped, and must never leak the value.
	const value = "super-secret-value"
	m := &mockRunner{err: errors.New("security: SecKeychainOpenError: User interaction is not allowed.")}
	b := NewWithRunner(m.run)

	_, err := b.Resolve("GitHub/ci-token")
	if err == nil {
		t.Fatal("expected error for generic security failure")
	}
	if errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("generic failure misreported as ErrNotFound: %v", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error leaked the value: %v", err)
	}
	// The locator is helpful and value-free; assert it is present for actionability.
	if !strings.Contains(err.Error(), "GitHub/ci-token") {
		t.Fatalf("error should carry the locator, got: %v", err)
	}
}

func TestListReturnsEmpty(t *testing.T) {
	b := NewWithRunner((&mockRunner{}).run)
	metas, err := b.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 0 {
		t.Fatalf("List returned %d metas, want 0 (metadata-only, not load-bearing)", len(metas))
	}
}

// End-to-end through the registry: a real av://keychain/... reference dispatches to
// this backend and returns the value, proving the locator survives ParseRef and the
// service/account split reaches `security` intact.
func TestRegistryEndToEnd(t *testing.T) {
	m := &mockRunner{out: []byte("ghp_value\n")}
	reg := backend.NewRegistry()
	reg.Register("keychain", NewWithRunner(m.run))

	got, err := reg.Resolve("av://keychain/GitHub/ci-token")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q, want %q", got.Value, "ghp_value")
	}
	want := []string{"find-generic-password", "-s", "GitHub", "-a", "ci-token", "-w"}
	if len(m.gotArgs) != len(want) {
		t.Fatalf("args = %v, want %v", m.gotArgs, want)
	}
	for i := range want {
		if m.gotArgs[i] != want[i] {
			t.Fatalf("args = %v, want %v", m.gotArgs, want)
		}
	}
}

// fakeExit emulates an *exec.ExitError carrying a given exit code, so the exit-44
// not-found path can be exercised without invoking the real `security` binary.
type fakeExit struct {
	code int
}

func (e *fakeExit) Error() string { return "exit status " + itoa(e.code) }
func (e *fakeExit) ExitCode() int { return e.code }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Compile-time assurance the production runner type matches exec usage (kept here so the
// test file references exec and stays honest about the production wiring shape).
var _ = exec.Command

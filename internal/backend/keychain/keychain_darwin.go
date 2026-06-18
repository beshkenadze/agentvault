//go:build darwin

// Package keychain implements a Backend backed by the macOS keychain via the
// `security` CLI. It shells out to `security find-generic-password -s <service>
// -a <account> -w` to resolve a generic-password item; the `-w` flag prints ONLY the
// password to stdout. The exec runner is INJECTED (type runner) so the resolve LOGIC is
// fully unit-testable with a mock; production wires the real `security` binary. Isolated
// package (like onepassword/agefile) so the os/exec dependency never reaches the thin av
// — only avd links it.
//
// SECURITY: a resolved value is returned only in Secret.Value. No error path ever embeds
// the value: `security` errors carry the locator and security's own (value-free) message.
//
// MANUAL: on macOS, avd registers this backend under "keychain" and
// `av://keychain/<service>/<account>` resolves for real against the user's keychain
// (which may prompt for keychain access on first use). CI/subagents have no populated
// keychain, so only the injected-runner logic is covered by tests; the live path is
// verified by hand.
package keychain

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// runner runs the `security` CLI with args and returns its stdout (or an error). It is
// injected so tests can mock `security` without the binary; production uses securityExec.
type runner func(args ...string) ([]byte, error)

// Backend resolves secrets through the injected `security` runner.
type Backend struct {
	run runner
}

// New returns a Backend that shells out to the real `security` binary.
func New() *Backend {
	return &Backend{run: securityExec}
}

// NewWithRunner returns a Backend driven by the injected runner (for tests).
func NewWithRunner(run runner) *Backend {
	return &Backend{run: run}
}

// securityExec is the production runner: it runs `security <args...>` via os/exec and
// returns stdout with the trailing newline trimmed. exec.Command(...).Output() captures
// stderr in *exec.ExitError.Stderr, which Resolve inspects to classify not-found.
func securityExec(args ...string) ([]byte, error) {
	out, err := exec.Command("security", args...).Output()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

// Resolve maps the av:// locator (everything after "av://keychain/") to a generic-password
// lookup. The locator is "<service>/<account>": the FIRST "/" separates the service from
// the account, and the account is the verbatim remainder (so an account name may itself
// contain "/", e.g. "AWS/role/ci/key" → service "AWS", account "role/ci/key"). A locator
// with no "/" (a bare service, no account) is malformed and errors without invoking
// `security`.
//
// It runs `security find-generic-password -s <service> -a <account> -w`; `-w` prints only
// the password to stdout. On success it returns the trimmed output as the value.
//
// `security` exits non-zero when the item is missing; not-found is distinguished from a
// generic failure by security's stderr ("could not be found", "SecKeychainSearchCopyNext")
// or exit status 44, so a missing secret maps to backend.ErrNotFound and any other failure
// is a wrapped error that NEVER contains the value.
func (b *Backend) Resolve(locator string) (backend.Secret, error) {
	service, account, ok := strings.Cut(locator, "/")
	if !ok || service == "" || account == "" {
		return backend.Secret{}, fmt.Errorf("keychain: malformed locator %q (want <service>/<account>)", locator)
	}

	out, err := b.run("find-generic-password", "-s", service, "-a", account, "-w")
	if err != nil {
		if isNotFound(err) {
			return backend.Secret{}, fmt.Errorf("keychain %s: %w", locator, backend.ErrNotFound)
		}
		// Wrap with the locator and security's (value-free) error. The value never
		// appears here because on error security writes only diagnostics to stderr.
		return backend.Secret{}, fmt.Errorf("keychain %s: %w", locator, redactExec(err))
	}
	return backend.Secret{Value: strings.TrimRight(string(out), "\n")}, nil
}

// List is best-effort metadata only. The macOS keychain has no cheap, scriptable
// per-service enumeration that is load-bearing for resolve (the design treats List as
// metadata-only), so v1 returns an empty list — resolution does not depend on it.
func (b *Backend) List(prefix string) ([]backend.Meta, error) {
	return nil, nil
}

// exitCoder is satisfied by *exec.ExitError; isNotFound uses it to detect security's
// "item not found" exit status 44.
type exitCoder interface {
	ExitCode() int
}

// isNotFound reports whether a `security` failure means "no such item" (→ ErrNotFound)
// rather than a permission/transport/other error. It checks the exit code (44 == item
// not found) and security's stderr (captured in *exec.ExitError.Stderr by Output()).
func isNotFound(err error) bool {
	// Exit status 44 is security's canonical "item could not be found".
	var ec exitCoder
	if errors.As(err, &ec) && ec.ExitCode() == 44 {
		return true
	}

	msg := strings.ToLower(err.Error())
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		msg += " " + strings.ToLower(string(ee.Stderr))
	}
	// Match only security's RESOURCE-specific not-found phrasings. Deliberately
	// fail-closed: broad substrings ("not found", "no such") are NOT matched because a
	// permission/transport error ("no such host") would then be misreported as
	// ErrNotFound — masking a real failure as "no secret". A genuine not-found we miss
	// just stays a hard error (safe); a transport error we wrongly call "not found" would
	// silently drop a secret (unsafe).
	for _, phrase := range []string{
		"could not be found in the keychain",
		"seckeychainsearchcopynext",
		"the specified item could not be found",
	} {
		if strings.Contains(msg, phrase) {
			return true
		}
	}
	return false
}

// redactExec returns an error safe to wrap: for an *exec.ExitError it surfaces security's
// stderr (diagnostics, never the value) instead of the bare "exit status N" so the wrapped
// error is actionable while staying value-free.
func redactExec(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}

// compile-time check that Backend satisfies the interface.
var _ backend.Backend = (*Backend)(nil)

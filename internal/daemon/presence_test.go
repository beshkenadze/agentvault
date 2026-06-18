package daemon

import (
	"errors"
	"testing"
)

func TestStubPresenceRequiresEnv(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "")
	p := NewStubPresence()
	err := p.Prompt("X")
	if err == nil {
		t.Fatal("without AV_TEST_AUTH=allow, prompt must fail")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("deny must be ErrLocked (maps to CodeLocked), got %v", err)
	}
}

// The secure default must be exact-match on "allow" — no truthy/case/whitespace
// parsing. Any other value denies. Guards against a future loose-parse refactor.
func TestStubPresenceExactMatchOnly(t *testing.T) {
	p := NewStubPresence()
	for _, v := range []string{"", "1", "true", "yes", "ALLOW", "Allow", " allow ", "allow\n", "allowed"} {
		t.Setenv("AV_TEST_AUTH", v)
		if err := p.Prompt("X"); !errors.Is(err, ErrLocked) {
			t.Errorf("AV_TEST_AUTH=%q must deny with ErrLocked, got %v", v, err)
		}
	}
}

func TestStubPresenceAllows(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	p := NewStubPresence()
	if err := p.Prompt("X"); err != nil {
		t.Fatalf("with AV_TEST_AUTH=allow, prompt must pass: %v", err)
	}
}

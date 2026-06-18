package daemon

import (
	"errors"
	"testing"

	"github.com/beshkenadze/agentvault/internal/manifest"
)

func TestStubAuthorizerRequiresEnv(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "")
	a := NewStubAuthorizer()
	err := a.Authorize(manifest.TierNormal, "X")
	if err == nil {
		t.Fatal("without AV_TEST_AUTH=allow, authorize must fail")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("deny must be ErrLocked (maps to CodeLocked), got %v", err)
	}
}

// The secure default must be exact-match on "allow" — no truthy/case/whitespace
// parsing. Any other value denies. Guards against a future loose-parse refactor.
func TestStubAuthorizerExactMatchOnly(t *testing.T) {
	a := NewStubAuthorizer()
	for _, v := range []string{"", "1", "true", "yes", "ALLOW", "Allow", " allow ", "allow\n", "allowed"} {
		t.Setenv("AV_TEST_AUTH", v)
		if err := a.Authorize(manifest.TierNormal, "X"); !errors.Is(err, ErrLocked) {
			t.Errorf("AV_TEST_AUTH=%q must deny with ErrLocked, got %v", v, err)
		}
	}
}

func TestStubAuthorizerAllows(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	a := NewStubAuthorizer()
	if err := a.Authorize(manifest.TierNormal, "X"); err != nil {
		t.Fatalf("with AV_TEST_AUTH=allow, authorize must pass: %v", err)
	}
	if err := a.Authorize(manifest.TierDangerous, "Y"); err != nil {
		t.Fatalf("stub authorizes dangerous too (real prompt is Phase 5): %v", err)
	}
}

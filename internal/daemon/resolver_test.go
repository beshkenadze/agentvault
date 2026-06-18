package daemon

import (
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
)

type mockBE struct{ data map[string]string }

func (m mockBE) Resolve(loc string) (backend.Secret, error) {
	v, ok := m.data[loc]
	if !ok {
		return backend.Secret{}, backend.ErrNotFound
	}
	return backend.Secret{Value: v}, nil
}
func (m mockBE) List(string) ([]backend.Meta, error) { return nil, nil }

const manifestYAML = `profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://mock/GH
      tier: normal
`

func TestResolveProfile(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}})
	sess := NewSession(15 * time.Minute)
	rv := NewResolver(reg, NewStubPresence(), sess)

	vals, err := rv.Resolve("smoke", []byte(manifestYAML))
	if err != nil {
		t.Fatal(err)
	}
	if vals["GITHUB_TOKEN"] != "ghp_xyz" {
		t.Fatalf("values = %+v", vals)
	}
	// the issued value must now be in the session redactor
	if sess.Redactor().Redact("ghp_xyz") == "ghp_xyz" {
		t.Fatal("resolved value not recorded in session")
	}
}

func TestResolveDeniedWhenLocked(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "") // not allowed
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "x"}})
	rv := NewResolver(reg, NewStubPresence(), NewSession(time.Minute))
	if _, err := rv.Resolve("smoke", []byte(manifestYAML)); err == nil {
		t.Fatal("locked presence must fail resolve")
	}
}

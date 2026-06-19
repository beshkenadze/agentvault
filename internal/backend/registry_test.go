package backend

import (
	"testing"
)

// mockBackend is an in-memory backend for tests.
type mockBackend struct{ data map[string]string }

func (m *mockBackend) Resolve(loc string) (Secret, error) {
	v, ok := m.data[loc]
	if !ok {
		return Secret{}, ErrNotFound
	}
	return Secret{Value: v}, nil
}
func (m *mockBackend) List(prefix string) ([]Meta, error) {
	var out []Meta
	for k := range m.data {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			out = append(out, Meta{Locator: k})
		}
	}
	return out, nil
}

func TestRegistryResolve(t *testing.T) {
	r := NewRegistry()
	r.Register("mock", &mockBackend{data: map[string]string{"TOKEN": "s3cr3t"}})

	got, err := r.Resolve("av://mock/TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "s3cr3t" {
		t.Fatalf("value = %q, want s3cr3t", got.Value)
	}
}

func TestRegistryUnknownBackend(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Resolve("av://nope/X"); err == nil {
		t.Fatal("expected error for unregistered backend")
	}
}

// TestRegistryReRegisterOverwrites guards the live-setup re-wire path: registering a
// second backend under an existing id REPLACES the first (map semantics), so `av setup`
// can swap "file" for the freshly provisioned store without a daemon restart.
func TestRegistryReRegisterOverwrites(t *testing.T) {
	r := NewRegistry()
	r.Register("file", &mockBackend{data: map[string]string{"K": "old"}})
	r.Register("file", &mockBackend{data: map[string]string{"K": "new"}})

	got, err := r.Resolve("av://file/K")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "new" {
		t.Fatalf("value = %q, want new (re-register must overwrite)", got.Value)
	}
}

func TestRegistryListNoValues(t *testing.T) {
	r := NewRegistry()
	r.Register("mock", &mockBackend{data: map[string]string{"A": "1", "B": "2"}})
	metas, err := r.List("mock", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("got %d metas, want 2", len(metas))
	}
	// Meta has no value field — compile-time guarantee values aren't leaked by List.
}

package manifest

import (
	"path/filepath"
	"testing"
)

func TestLoadProfile(t *testing.T) {
	m, err := Load(filepath.Join("testdata", "agentvault.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := m.Profile("smoke")
	if !ok {
		t.Fatal("smoke profile missing")
	}
	gh, ok := p["GITHUB_TOKEN"]
	if !ok {
		t.Fatal("GITHUB_TOKEN missing")
	}
	if gh.Ref != "av://file/GITHUB_TOKEN" || gh.Tier != TierNormal {
		t.Fatalf("bad entry: %+v", gh)
	}
	if p["STRIPE_SECRET"].Tier != TierDangerous {
		t.Fatalf("STRIPE tier = %v, want dangerous", p["STRIPE_SECRET"].Tier)
	}
}

func TestRejectsUnknownTier(t *testing.T) {
	const bad = "profiles:\n  p:\n    X:\n      ref: av://file/X\n      tier: bogus\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected error for unknown tier")
	}
}

func TestRejectsMissingRef(t *testing.T) {
	const bad = "profiles:\n  p:\n    X:\n      tier: normal\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected error for missing ref")
	}
}

func TestRejectsMalformedRef(t *testing.T) {
	const bad = "profiles:\n  p:\n    X:\n      ref: not-a-ref\n      tier: normal\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected error for malformed ref")
	}
}

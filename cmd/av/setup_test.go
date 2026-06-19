package main

import (
	"strings"
	"testing"
)

// TestParseSetupArgsDefault: `av setup` with no flags leaves both booleans false.
func TestParseSetupArgsDefault(t *testing.T) {
	p, err := parseSetupArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rotate || p.Plaintext {
		t.Fatalf("got rotate=%v plaintext=%v, want both false", p.Rotate, p.Plaintext)
	}
}

// TestParseSetupArgsFlags: --rotate and --plaintext set their respective booleans, in
// any order.
func TestParseSetupArgsFlags(t *testing.T) {
	p, err := parseSetupArgs([]string{"--rotate", "--plaintext"})
	if err != nil || !p.Rotate || !p.Plaintext {
		t.Fatalf("got rotate=%v plaintext=%v err=%v, want both true", p.Rotate, p.Plaintext, err)
	}
	p, err = parseSetupArgs([]string{"--plaintext"})
	if err != nil || p.Rotate || !p.Plaintext {
		t.Fatalf("got rotate=%v plaintext=%v err=%v, want plaintext only", p.Rotate, p.Plaintext, err)
	}
}

// TestParseSetupArgsRejectsUnexpected: any non-flag argument is a usage error (setup
// takes no values/positionals).
func TestParseSetupArgsRejectsUnexpected(t *testing.T) {
	if _, err := parseSetupArgs([]string{"--rotate=true"}); err == nil {
		t.Fatal("expected refusal of --rotate=true (flags take no value)")
	}
	_, err := parseSetupArgs([]string{"extra"})
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("err = %v, want an unexpected-argument error", err)
	}
}

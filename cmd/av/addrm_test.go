package main

import (
	"strings"
	"testing"
)

// TestParseAddArgsBackendDefault: `av add NAME` defaults the backend to "file" (the
// only writable backend) and takes NAME as the locator.
func TestParseAddArgsBackendDefault(t *testing.T) {
	backend := "file"
	name, err := parseAddArgs([]string{"GITHUB_TOKEN"}, &backend)
	if err != nil {
		t.Fatal(err)
	}
	if name != "GITHUB_TOKEN" {
		t.Fatalf("name = %q, want GITHUB_TOKEN", name)
	}
	if backend != "file" {
		t.Fatalf("backend = %q, want file", backend)
	}
}

// TestParseAddArgsBackendFlag: --backend overrides the default.
func TestParseAddArgsBackendFlag(t *testing.T) {
	backend := "file"
	name, err := parseAddArgs([]string{"--backend", "file", "K"}, &backend)
	if err != nil || name != "K" || backend != "file" {
		t.Fatalf("got name=%q backend=%q err=%v", name, backend, err)
	}
	backend = "file"
	name, err = parseAddArgs([]string{"--backend=file", "K2"}, &backend)
	if err != nil || name != "K2" || backend != "file" {
		t.Fatalf("got name=%q backend=%q err=%v", name, backend, err)
	}
}

// TestParseAddArgsRefusesValueArg: a SECOND positional (a would-be value on the command
// line) must be REFUSED — a value on argv would leak into shell history / ps. `av add`
// takes exactly one NAME; the value comes from stdin/TTY only.
func TestParseAddArgsRefusesValueArg(t *testing.T) {
	backend := "file"
	_, err := parseAddArgs([]string{"NAME", "the-secret-value"}, &backend)
	if err == nil {
		t.Fatal("expected refusal of a value passed as an argument")
	}
	if !strings.Contains(err.Error(), "value") && !strings.Contains(err.Error(), "one NAME") {
		t.Fatalf("error %q should explain the value cannot be an argument", err)
	}
}

// TestParseAddArgsNeedsName: no positional NAME is a usage error.
func TestParseAddArgsNeedsName(t *testing.T) {
	backend := "file"
	if _, err := parseAddArgs(nil, &backend); err == nil {
		t.Fatal("expected error when no NAME is given")
	}
}

// TestReadSecretFromStdinPiped: when stdin is piped (not a TTY), the value is read from
// stdin and the trailing newline is stripped (a here-string / echo adds one).
func TestReadSecretFromStdinPiped(t *testing.T) {
	got, err := readSecretValue(strings.NewReader("ghp_piped_secret\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ghp_piped_secret" {
		t.Fatalf("value = %q, want ghp_piped_secret (newline stripped)", got)
	}
}

// TestReadSecretFromStdinPreservesInterior: only the trailing newline is stripped; an
// interior newline (a multi-line secret, e.g. a PEM) is preserved.
func TestReadSecretFromStdinPreservesInterior(t *testing.T) {
	got, err := readSecretValue(strings.NewReader("line1\nline2\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "line1\nline2" {
		t.Fatalf("value = %q, want line1\\nline2", got)
	}
}

// TestReadSecretEmptyStdinRejected: an empty piped value is refused (an empty secret is
// almost certainly a mistake; writing it would silently store nothing useful).
func TestReadSecretEmptyStdinRejected(t *testing.T) {
	if _, err := readSecretValue(strings.NewReader(""), false); err == nil {
		t.Fatal("expected an empty piped value to be refused")
	}
}

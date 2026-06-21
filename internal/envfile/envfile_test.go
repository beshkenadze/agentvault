package envfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestParse reads KEY=VALUE pairs (comments and quotes handled by godotenv).
func TestParse(t *testing.T) {
	p := writeEnv(t, "# comment\nOPENAI_API_KEY=av://file/OPENAI_API_KEY\nMSSQL_PORT=1433\n")
	kv, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if kv["OPENAI_API_KEY"] != "av://file/OPENAI_API_KEY" {
		t.Errorf("OPENAI_API_KEY = %q", kv["OPENAI_API_KEY"])
	}
	if kv["MSSQL_PORT"] != "1433" {
		t.Errorf("MSSQL_PORT = %q", kv["MSSQL_PORT"])
	}
}

// TestParseMissing returns an OS error for a missing file (caller decides fallback).
func TestParseMissing(t *testing.T) {
	if _, err := Parse(filepath.Join(t.TempDir(), "nope.env")); err == nil {
		t.Fatal("expected an error for a missing .env")
	}
}

// TestSplit routes av:// values to refs and everything else to literals; a value that
// LOOKS like a ref but is malformed is a hard error (fail-closed — never inject the
// literal string "av://…" as if it were a value).
func TestSplit(t *testing.T) {
	refs, literals, err := Split(map[string]string{
		"OPENAI_API_KEY": "av://file/OPENAI_API_KEY",
		"MSSQL_PORT":     "1433",
		"CHAT_MODEL":     "openai/gpt-4.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if refs["OPENAI_API_KEY"] != "av://file/OPENAI_API_KEY" {
		t.Errorf("refs = %v", refs)
	}
	if literals["MSSQL_PORT"] != "1433" || literals["CHAT_MODEL"] != "openai/gpt-4.1" {
		t.Errorf("literals = %v", literals)
	}
	if _, ok := refs["MSSQL_PORT"]; ok {
		t.Error("MSSQL_PORT must be a literal, not a ref")
	}
}

func TestSplitMalformedRefErrors(t *testing.T) {
	_, _, err := Split(map[string]string{"BAD": "av://file"}) // no locator
	if err == nil {
		t.Fatal("a malformed av:// value must be a hard error, not a literal")
	}
	if !strings.Contains(err.Error(), "BAD") {
		t.Errorf("error %q should name the offending key", err)
	}
}

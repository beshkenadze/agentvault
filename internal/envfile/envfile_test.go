package envfile

import (
	"os"
	"path/filepath"
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

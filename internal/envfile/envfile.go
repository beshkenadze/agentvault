// Package envfile parses a .env into KEY=VALUE pairs and splits AgentVault av://
// references from plain literals. It holds no secret values — references are
// locators, literals are non-secret config. Used by `av env`.
package envfile

import "github.com/joho/godotenv"

// Parse reads a .env at path into a flat KEY=VALUE map (godotenv handles comments,
// quotes, multiline, and the `export ` prefix). A missing/unreadable file is an error
// the caller maps (av env falls back to agentvault.yaml when .env is absent).
func Parse(path string) (map[string]string, error) {
	return godotenv.Read(path)
}

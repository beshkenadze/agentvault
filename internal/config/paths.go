// Package config resolves AgentVault's default on-disk locations (vault + identity).
// SSOT for the zero-config store paths the daemon auto-discovers and `av setup` writes.
package config

import (
	"os"
	"path/filepath"
)

// DefaultConfigDir is $XDG_CONFIG_HOME/agentvault, else ~/.config/agentvault.
func DefaultConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "agentvault")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agentvault")
}

func DefaultVaultPath() string             { return filepath.Join(DefaultConfigDir(), "vault.age") }
func DefaultEnclaveIdentityPath() string   { return filepath.Join(DefaultConfigDir(), "identity.enc") }
func DefaultPlaintextIdentityPath() string { return filepath.Join(DefaultConfigDir(), "identity.txt") }

//go:build darwin

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// autostart launches avd detached so it outlives the short-lived av process. It
// locates the avd binary via AV_AVD_PATH (test/override), else as a sibling of the
// running av binary, else "avd" on PATH. The child gets its own session
// (Setsid) and nil stdio so it is fully decoupled from the agent; we Start without
// Wait. The socketPath argument is unused for now (avd resolves its own default
// path) but kept for a future explicit handoff.
func autostart(socketPath string) error {
	_ = socketPath
	bin := os.Getenv("AV_AVD_PATH")
	if bin == "" {
		if self, err := os.Executable(); err == nil {
			cand := filepath.Join(filepath.Dir(self), "avd")
			if _, err := os.Stat(cand); err == nil {
				bin = cand
			}
		}
	}
	if bin == "" {
		bin = "avd" // PATH
	}
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd.Start() // detached: do not Wait
}

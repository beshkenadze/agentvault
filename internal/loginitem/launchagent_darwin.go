//go:build darwin

package loginitem

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// launchAgent is the build-from-source backend: it writes a per-user plist into
// ~/Library/LaunchAgents and (un)loads it with launchctl. The launchctl call is an
// INJECTED runner (production = launchctlExec) so Enable/Disable/Status logic is
// unit-testable with no real launchd (the internal/backend/keychain pattern).
type launchAgent struct {
	avdPath  string
	plistDir string // ~/Library/LaunchAgents
	logDir   string
	label    string
	uid      int
	run      func(args ...string) error
}

func newLaunchAgent(avdPath string) *launchAgent {
	home, _ := os.UserHomeDir()
	return &launchAgent{
		avdPath:  avdPath,
		plistDir: filepath.Join(home, "Library", "LaunchAgents"),
		logDir:   filepath.Join(home, "Library", "Logs", "agentvault"),
		label:    labelAvd,
		uid:      os.Getuid(),
		run:      launchctlExec,
	}
}

func launchctlExec(args ...string) error { return exec.Command("launchctl", args...).Run() }

func (l *launchAgent) Backend() Backend { return BackendLaunchAgent }

func (l *launchAgent) plistPath() string { return filepath.Join(l.plistDir, l.label+".plist") }

func (l *launchAgent) Enable() error {
	body, err := renderLaunchAgentPlist(launchAgentVars{Label: l.label, AvdPath: l.avdPath, LogDir: l.logDir})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(l.plistDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(l.logDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(l.plistPath(), []byte(body), 0o644); err != nil {
		return err
	}
	// Re-bootstrap is idempotent enough: bootout any prior instance, ignore its error.
	_ = l.run("bootout", fmt.Sprintf("gui/%d/%s", l.uid, l.label))
	return l.run("bootstrap", fmt.Sprintf("gui/%d", l.uid), l.plistPath())
}

func (l *launchAgent) Disable() error {
	_ = l.run("bootout", fmt.Sprintf("gui/%d/%s", l.uid, l.label)) // ignore "not loaded"
	if err := os.Remove(l.plistPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (l *launchAgent) Status() (State, error) {
	if _, err := os.Stat(l.plistPath()); err != nil {
		return StateDisabled, nil
	}
	return StateEnabled, nil
}

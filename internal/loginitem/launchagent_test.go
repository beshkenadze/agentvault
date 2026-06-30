//go:build darwin

package loginitem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderLaunchAgentPlist(t *testing.T) {
	out, err := renderLaunchAgentPlist(launchAgentVars{
		Label:   "app.bshk.agentvault.avd",
		AvdPath: "/usr/local/bin/avd",
		LogDir:  "/Users/x/Library/Logs/agentvault",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<string>app.bshk.agentvault.avd</string>",
		"<string>/usr/local/bin/avd</string>",
		"<string>/Users/x/Library/Logs/agentvault/avd.out.log</string>",
		"<key>RunAtLoad</key>", "<key>KeepAlive</key>", "Interactive",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered plist missing %q\n%s", want, out)
		}
	}
}

// Enable renders+writes the plist and bootstraps it; the injected runner captures
// the launchctl invocation so no real launchd is touched.
func TestLaunchAgentEnable(t *testing.T) {
	dir := t.TempDir()
	var gotArgs []string
	la := &launchAgent{
		avdPath:  "/usr/local/bin/avd",
		plistDir: dir,
		logDir:   dir,
		label:    "app.bshk.agentvault.avd",
		uid:      501,
		run: func(args ...string) error {
			gotArgs = args
			return nil
		},
	}
	if err := la.Enable(); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(dir, "app.bshk.agentvault.avd.plist")
	if _, err := os.Stat(plist); err != nil {
		t.Fatalf("plist not written: %v", err)
	}
	want := []string{"bootstrap", "gui/501", plist}
	if strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Fatalf("launchctl args = %v, want %v", gotArgs, want)
	}
}

// Disable boots out then removes the plist; a "not loaded" bootout error is ignored.
func TestLaunchAgentDisable(t *testing.T) {
	dir := t.TempDir()
	plist := filepath.Join(dir, "app.bshk.agentvault.avd.plist")
	if err := os.WriteFile(plist, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var gotArgs []string
	la := &launchAgent{
		plistDir: dir, label: "app.bshk.agentvault.avd", uid: 501,
		run: func(args ...string) error { gotArgs = args; return nil },
	}
	if err := la.Disable(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Fatalf("plist should be removed, stat err=%v", err)
	}
	want := []string{"bootout", "gui/501/app.bshk.agentvault.avd"}
	if strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Fatalf("launchctl args = %v, want %v", gotArgs, want)
	}
}

// Status: plist present + launchctl print succeeds -> Enabled; absent -> Disabled.
func TestLaunchAgentStatus(t *testing.T) {
	dir := t.TempDir()
	la := &launchAgent{
		plistDir: dir, label: "app.bshk.agentvault.avd", uid: 501,
		run: func(args ...string) error { return nil },
	}
	if st, _ := la.Status(); st != StateDisabled {
		t.Fatalf("no plist: got %v, want disabled", st)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.bshk.agentvault.avd.plist"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st, _ := la.Status(); st != StateEnabled {
		t.Fatalf("plist present: got %v, want enabled", st)
	}
}

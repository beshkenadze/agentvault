# avd Login Item Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `avd` start at login with zero manual steps — `SMAppService` for the signed `.app` (macOS 13+), a `~/Library/LaunchAgents` fallback for build-from-source — and replace the broken `brew services start agentvault` story.

**Architecture:** Registration is an **avd-side** operation (SMAppService resolves the plist relative to the *daemon's* bundle, which `av` is not in). A new `internal/loginitem` package exposes one `Manager` interface with two runtime-selected backends. `av service on/off/status` is a thin RPC to avd; `av setup` calls enable best-effort. Triggered only by the deliberate setup/enable action — never on every avd start — so it never fights the user's System Settings → Login Items toggle.

**Tech Stack:** Go, cgo (ObjC `SMAppService` shim, like `internal/enclave/enclave_darwin.m`), newline-delimited JSON-RPC over a peer-cred-gated unix socket, `launchctl` via an injected runner (the `internal/backend/keychain` pattern).

**Design doc:** `docs/plans/2026-06-30-avd-login-item-design.md` (read it first).

**Conventions for every task:** RED→GREEN→REFACTOR (superpowers:test-driven-development). Run `go build ./... && go vet ./...` before each commit. Tests run on macOS (cgo). Do NOT sign-disable commits unless 1Password is locked. Module path is `github.com/beshkenadze/agentvault` (unchanged despite the repo move to bshk-app).

---

## Task 1: Cask-layout avd lookup in autostart

**Why first:** `av setup` must be able to cold-start avd in the cask layout (`av` at `bin/av`, avd at `AgentVault.app/Contents/MacOS/avd`) before anything can register. Pure refactor of the existing lookup into a testable helper + one new candidate.

**Files:**
- Modify: `internal/client/autostart_darwin.go`
- Test: `internal/client/autostart_darwin_test.go` (create)

**Step 1: Write the failing test**

```go
//go:build darwin

package client

import (
	"os"
	"path/filepath"
	"testing"
)

// resolveAvdPath prefers a sibling `avd`, then the cask bundle layout
// (<dir>/AgentVault.app/Contents/MacOS/avd), then falls back to PATH ("avd").
func TestResolveAvdPath_SiblingWins(t *testing.T) {
	dir := t.TempDir()
	sib := filepath.Join(dir, "avd")
	if err := os.WriteFile(sib, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveAvdPath(dir); got != sib {
		t.Fatalf("got %q, want sibling %q", got, sib)
	}
}

func TestResolveAvdPath_CaskBundle(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "AgentVault.app", "Contents", "MacOS", "avd")
	if err := os.MkdirAll(filepath.Dir(bundled), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundled, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveAvdPath(dir); got != bundled {
		t.Fatalf("got %q, want bundled %q", got, bundled)
	}
}

func TestResolveAvdPath_FallsBackToPATH(t *testing.T) {
	if got := resolveAvdPath(t.TempDir()); got != "avd" {
		t.Fatalf("got %q, want \"avd\"", got)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go -C . test ./internal/client/ -run TestResolveAvdPath -v`
Expected: FAIL — `undefined: resolveAvdPath`.

**Step 3: Write minimal implementation**

Replace the body of `autostart` to delegate to a new `resolveAvdPath` that takes the directory of the running `av` and tries each candidate in order:

```go
// resolveAvdPath finds the avd binary next to the running av. Order: a sibling
// `avd` (dev / formula layout), then the cask bundle layout
// `<dir>/AgentVault.app/Contents/MacOS/avd`, else "avd" on PATH. Pure (takes the
// dir) so the candidate order is unit-testable.
func resolveAvdPath(selfDir string) string {
	for _, cand := range []string{
		filepath.Join(selfDir, "avd"),
		filepath.Join(selfDir, "AgentVault.app", "Contents", "MacOS", "avd"),
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "avd" // PATH
}
```

Rewire `autostart` to use it (keep the `AV_AVD_PATH` override first):

```go
func autostart(socketPath string) error {
	_ = socketPath
	bin := os.Getenv("AV_AVD_PATH")
	if bin == "" {
		if self, err := os.Executable(); err == nil {
			bin = resolveAvdPath(filepath.Dir(self))
		} else {
			bin = "avd"
		}
	}
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd.Start() // detached: do not Wait
}
```

**Step 4: Run tests**

Run: `go -C . test ./internal/client/ -run TestResolveAvdPath -v`
Expected: PASS (3 tests).
Then: `go -C . build ./... && go -C . vet ./...`

**Step 5: Commit**

```bash
git add internal/client/autostart_darwin.go internal/client/autostart_darwin_test.go
git commit -S -m "fix(autostart): locate avd in the cask bundle layout (AgentVault.app/Contents/MacOS/avd)"
```

---

## Task 2: loginitem interface, State, and the backend selector

**Files:**
- Create: `internal/loginitem/loginitem.go` (no build tag — pure, testable everywhere)
- Test: `internal/loginitem/loginitem_test.go`

**Step 1: Write the failing test**

```go
package loginitem

import "testing"

func TestStateString(t *testing.T) {
	cases := map[State]string{
		StateDisabled:         "disabled",
		StateEnabled:          "enabled",
		StateRequiresApproval: "requires-approval",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestSelectBackend(t *testing.T) {
	cases := []struct {
		name  string
		exe   string
		major int
		want  Backend
	}{
		{"bundle on ventura", "/Applications/AgentVault.app/Contents/MacOS/avd", 13, BackendSMAppService},
		{"bundle on sonoma", "/Applications/AgentVault.app/Contents/MacOS/avd", 14, BackendSMAppService},
		{"bundle on monterey -> fallback", "/Applications/AgentVault.app/Contents/MacOS/avd", 12, BackendLaunchAgent},
		{"bare binary on ventura -> fallback", "/usr/local/bin/avd", 13, BackendLaunchAgent},
		{"dev binary -> fallback", "/tmp/go-build/avd", 14, BackendLaunchAgent},
	}
	for _, c := range cases {
		if got := selectBackend(c.exe, c.major); got != c.want {
			t.Errorf("%s: selectBackend(%q, %d) = %q, want %q", c.name, c.exe, c.major, got, c.want)
		}
	}
}
```

**Step 2: Verify it fails**

Run: `go -C . test ./internal/loginitem/ -v`
Expected: FAIL — package/symbols undefined.

**Step 3: Minimal implementation**

```go
// Package loginitem registers avd to start at login. Two backends:
// SMAppService (the signed .app, macOS 13+) and a ~/Library/LaunchAgents plist
// (build-from-source). The pure pieces here — State and selectBackend — carry no
// OS calls so they are testable on any platform; the OS work lives in *_darwin.go.
package loginitem

import "strings"

// State is the login-item registration state. SMAppService adds RequiresApproval
// (registered, but the user must flip it on in System Settings); the LaunchAgent
// backend only ever reports Disabled/Enabled.
type State int

const (
	StateDisabled State = iota
	StateEnabled
	StateRequiresApproval
)

func (s State) String() string {
	switch s {
	case StateEnabled:
		return "enabled"
	case StateRequiresApproval:
		return "requires-approval"
	default:
		return "disabled"
	}
}

// Backend names the mechanism a Manager uses (also the wire value in ServiceResult).
type Backend string

const (
	BackendSMAppService Backend = "smappservice"
	BackendLaunchAgent  Backend = "launchagent"
)

// Manager registers/unregisters avd as a login item. Implemented per-backend in
// *_darwin.go; a non-darwin stub returns ErrUnsupported.
type Manager interface {
	Enable() error
	Disable() error
	Status() (State, error)
	Backend() Backend
}

// selectBackend picks the backend from the avd executable path and the macOS major
// version. SMAppService requires BOTH the signed-app bundle layout (the plist is
// sealed in Contents/Library/LaunchAgents) AND macOS >= 13; everything else uses the
// LaunchAgent fallback. Pure so the gate is unit-tested without a real bundle.
func selectBackend(exe string, macOSMajor int) Backend {
	if macOSMajor >= 13 && strings.HasSuffix(exe, ".app/Contents/MacOS/avd") {
		return BackendSMAppService
	}
	return BackendLaunchAgent
}
```

**Step 4: Run tests** — `go -C . test ./internal/loginitem/ -v` → PASS. Then `go -C . build ./... && go -C . vet ./...`.

**Step 5: Commit**

```bash
git add internal/loginitem/
git commit -S -m "feat(loginitem): Manager interface, State, and the SMAppService/LaunchAgent selector"
```

---

## Task 3: LaunchAgent backend (pure Go, injected launchctl runner)

**Files:**
- Create: `internal/loginitem/launchagent.go` (no tag — plist template + render are pure)
- Create: `internal/loginitem/launchagent_darwin.go` (darwin — the Manager using launchctl)
- Test: `internal/loginitem/launchagent_test.go`

**Step 1: Write the failing test**

```go
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
```

**Step 2: Verify it fails** — `go -C . test ./internal/loginitem/ -run LaunchAgent -v` → undefined symbols.

**Step 3: Minimal implementation**

`internal/loginitem/launchagent.go` (pure — template + render; no build tag):

```go
package loginitem

import (
	"strings"
	"text/template"
)

const labelAvd = "app.bshk.agentvault.avd"

type launchAgentVars struct {
	Label   string
	AvdPath string
	LogDir  string
}

// launchAgentPlistTmpl is the fallback (build-from-source) LaunchAgent. Unlike the
// bundled SMAppService plist it uses an ABSOLUTE ProgramArguments path (avd knows it
// at render time via os.Executable) and Interactive ProcessType so LocalAuthentication
// can present Touch ID in the GUI session. No secret values ever appear here.
var launchAgentPlistTmpl = template.Must(template.New("la").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.AvdPath}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/avd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/avd.err.log</string>
</dict>
</plist>
`))

func renderLaunchAgentPlist(v launchAgentVars) (string, error) {
	var b strings.Builder
	if err := launchAgentPlistTmpl.Execute(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}
```

`internal/loginitem/launchagent_darwin.go` (darwin — Manager + real runner):

```go
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
```

> NOTE on the `Enable` test: it asserts the LAST `run` call is `bootstrap …`. The
> `bootout` warmup in `Enable` also calls `run`; capture only the last invocation
> (the test's `gotArgs = args` does this naturally since it overwrites). Keep it.

**Step 4: Run tests** — `go -C . test ./internal/loginitem/ -v` → PASS. `go -C . build ./... && go -C . vet ./...`.

**Step 5: Commit**

```bash
git add internal/loginitem/launchagent.go internal/loginitem/launchagent_darwin.go internal/loginitem/launchagent_test.go
git commit -S -m "feat(loginitem): LaunchAgent fallback backend (rendered plist + injected launchctl)"
```

---

## Task 4: SMAppService backend (cgo) + New() detector wiring

**No unit test** — cgo + `SMAppService` need a signed bundle and a GUI session (the same boundary as Touch ID / enclave). Verify by **compile** here; the live path is in the manual checklist (Task 11 / `launchagent.md`). Model the shim on `internal/enclave/enclave_darwin.m`.

**Files:**
- Create: `internal/loginitem/smappservice_darwin.go`
- Create: `internal/loginitem/smappservice_darwin.m`
- Create: `internal/loginitem/loginitem_darwin.go` (the `New()` detector + macOS major)
- Create: `internal/loginitem/loginitem_other.go` (non-darwin stub)

**Step 1: `smappservice_darwin.m`**

```objc
//go:build darwin
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

// Register/unregister/status for the bundled LaunchAgent plist via SMAppService
// (macOS 13+). plistName is the file name under Contents/Library/LaunchAgents in
// avd's own .app bundle. On error we copy NSError.localizedDescription into *err
// (caller frees with free()); status returns the raw SMAppServiceStatus.

int av_loginitem_register(const char *plistName, char **err) {
    @autoreleasepool {
        SMAppService *svc = [SMAppService agentServiceWithPlistName:@(plistName)];
        NSError *e = nil;
        if (![svc registerAndReturnError:&e]) {
            if (err && e) *err = strdup([[e localizedDescription] UTF8String]);
            return 1;
        }
        return 0;
    }
}

int av_loginitem_unregister(const char *plistName, char **err) {
    @autoreleasepool {
        SMAppService *svc = [SMAppService agentServiceWithPlistName:@(plistName)];
        NSError *e = nil;
        if (![svc unregisterAndReturnError:&e]) {
            if (err && e) *err = strdup([[e localizedDescription] UTF8String]);
            return 1;
        }
        return 0;
    }
}

// Returns SMAppServiceStatus: 0 NotRegistered, 1 Enabled, 2 RequiresApproval, 3 NotFound.
int av_loginitem_status(const char *plistName) {
    @autoreleasepool {
        SMAppService *svc = [SMAppService agentServiceWithPlistName:@(plistName)];
        return (int)svc.status;
    }
}
```

**Step 2: `smappservice_darwin.go`**

```go
//go:build darwin

package loginitem

/*
#cgo LDFLAGS: -framework Foundation -framework ServiceManagement
#include <stdlib.h>
int av_loginitem_register(const char *plistName, char **err);
int av_loginitem_unregister(const char *plistName, char **err);
int av_loginitem_status(const char *plistName);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// plistNameAvd is the bundled LaunchAgent plist sealed at
// AgentVault.app/Contents/Library/LaunchAgents/<this> (see scripts/release-signed.sh).
const plistNameAvd = "app.bshk.agentvault.avd.plist"

type smAppService struct{ plistName string }

func newSMAppService() *smAppService { return &smAppService{plistName: plistNameAvd} }

func (s *smAppService) Backend() Backend { return BackendSMAppService }

func (s *smAppService) Enable() error  { return s.call(C.av_loginitem_register) }
func (s *smAppService) Disable() error { return s.call(C.av_loginitem_unregister) }

func (s *smAppService) call(fn func(*C.char, **C.char) C.int) error {
	cName := C.CString(s.plistName)
	defer C.free(unsafe.Pointer(cName))
	var cErr *C.char
	if fn(cName, &cErr) != 0 {
		msg := "SMAppService failed"
		if cErr != nil {
			msg = C.GoString(cErr)
			C.free(unsafe.Pointer(cErr))
		}
		return fmt.Errorf("loginitem: %s", msg)
	}
	return nil
}

func (s *smAppService) Status() (State, error) {
	cName := C.CString(s.plistName)
	defer C.free(unsafe.Pointer(cName))
	switch int(C.av_loginitem_status(cName)) {
	case 1: // SMAppServiceStatusEnabled
		return StateEnabled, nil
	case 2: // SMAppServiceStatusRequiresApproval
		return StateRequiresApproval, nil
	default: // 0 NotRegistered, 3 NotFound
		return StateDisabled, nil
	}
}
```

> cgo can't take a Go-typed function value for a C function directly; if `call(fn …)`
> does not compile, inline the two calls instead (call `C.av_loginitem_register` in
> `Enable`, `C.av_loginitem_unregister` in `Disable`, duplicating the CString/err
> handling). Prefer whichever compiles cleanly — correctness over DRY here.

**Step 3: `loginitem_darwin.go`** — the detector that picks a backend:

```go
//go:build darwin

package loginitem

import "os"

/*
#include <sys/utsname.h>
*/
import "C"
import (
	"strconv"
	"strings"
)

// New returns the login-item Manager for this install: SMAppService when avd runs
// from a signed .app on macOS 13+, else the ~/Library/LaunchAgents fallback.
func New() Manager {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	switch selectBackend(exe, macOSMajor()) {
	case BackendSMAppService:
		return newSMAppService()
	default:
		return newLaunchAgent(exe)
	}
}

// macOSMajor returns the Darwin-to-macOS major version (Darwin 22 == macOS 13).
// uname release "22.x.x" -> 13. Returns 0 if it can't parse (forces the fallback).
func macOSMajor() int {
	var u C.struct_utsname
	if C.uname(&u) != 0 {
		return 0
	}
	rel := C.GoString(&u.release[0])
	darwin, err := strconv.Atoi(strings.SplitN(rel, ".", 2)[0])
	if err != nil || darwin < 9 {
		return 0
	}
	return darwin - 9 // Darwin 22 -> macOS 13
}
```

**Step 4: `loginitem_other.go`** — non-darwin stub (mirrors `autostart_other.go`):

```go
//go:build !darwin

package loginitem

import "errors"

// ErrUnsupported reports that login-item registration is macOS-only.
var ErrUnsupported = errors.New("loginitem: unsupported on this platform")

type unsupported struct{}

func New() Manager                      { return unsupported{} }
func (unsupported) Enable() error       { return ErrUnsupported }
func (unsupported) Disable() error      { return ErrUnsupported }
func (unsupported) Status() (State, error) { return StateDisabled, ErrUnsupported }
func (unsupported) Backend() Backend    { return "" }
```

**Step 5: Verify build (both tags)**

Run:
```
go -C . build ./internal/loginitem/
GOOS=linux go -C . build ./internal/loginitem/    # stub compiles
go -C . vet ./internal/loginitem/
```
Expected: clean (the `-lobjc` duplicate-library warning is benign).

**Step 6: Commit**

```bash
git add internal/loginitem/smappservice_darwin.go internal/loginitem/smappservice_darwin.m internal/loginitem/loginitem_darwin.go internal/loginitem/loginitem_other.go
git commit -S -m "feat(loginitem): Secure SMAppService backend (cgo) + runtime backend selector"
```

---

## Task 5: IPC params/result for the service RPC

**Files:**
- Modify: `internal/ipc/proto.go`
- Test: `internal/ipc/proto_test.go` (append a round-trip case)

**Step 1: Failing test** — append to `proto_test.go`:

```go
func TestServiceParamsResultRoundTrip(t *testing.T) {
	p := ServiceParams{Action: "enable"}
	b, _ := json.Marshal(p)
	var got ServiceParams
	if err := json.Unmarshal(b, &got); err != nil || got.Action != "enable" {
		t.Fatalf("ServiceParams round-trip: got %+v err %v", got, err)
	}
	r := ServiceResult{Backend: "smappservice", State: "requires-approval"}
	b, _ = json.Marshal(r)
	var gr ServiceResult
	if err := json.Unmarshal(b, &gr); err != nil || gr != r {
		t.Fatalf("ServiceResult round-trip: got %+v err %v", gr, err)
	}
}
```

(Ensure `encoding/json` and `testing` are imported in the test file.)

**Step 2: Verify fail** — `go -C . test ./internal/ipc/ -run TestServiceParamsResultRoundTrip` → undefined.

**Step 3: Implementation** — append to `proto.go`:

```go
// ServiceParams is the client request for the "service" RPC: manage avd's login-item
// registration. Action is "enable" | "disable" | "status". SECURITY: it carries NO
// secret — only a verb — so nothing sensitive crosses the wire.
type ServiceParams struct {
	Action string `json:"action"`
}

// ServiceResult is the daemon reply for "service": the active backend
// ("smappservice" | "launchagent" | "") and the resulting registration State
// ("enabled" | "disabled" | "requires-approval"). Pure metadata — never a secret.
type ServiceResult struct {
	Backend string `json:"backend"`
	State   string `json:"state"`
}
```

**Step 4: Run** — test PASS; `go -C . build ./... && go -C . vet ./...`.

**Step 5: Commit**

```bash
git add internal/ipc/proto.go internal/ipc/proto_test.go
git commit -S -m "feat(ipc): ServiceParams/ServiceResult for the login-item RPC"
```

---

## Task 6: daemon — inject the Manager + the "service" dispatch case

**Files:**
- Modify: `internal/daemon/server.go` (a `loginitem` field + `SetLoginItem` + `case "service"`)
- Test: `internal/daemon/service_rpc_test.go` (create — mirror `setup_rpc_test.go`)

**Step 1: Failing test**

```go
package daemon

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/loginitem"
)

type fakeLoginItem struct {
	state    loginitem.State
	backend  loginitem.Backend
	enableErr error
	lastCall string
}

func (f *fakeLoginItem) Enable() error  { f.lastCall = "enable"; return f.enableErr }
func (f *fakeLoginItem) Disable() error { f.lastCall = "disable"; f.state = loginitem.StateDisabled; return nil }
func (f *fakeLoginItem) Status() (loginitem.State, error) { return f.state, nil }
func (f *fakeLoginItem) Backend() loginitem.Backend       { return f.backend }

func serviceServer(t *testing.T, m loginitem.Manager) string {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		srv.SetLoginItem(m)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

func TestServiceStatusRoundTrips(t *testing.T) {
	f := &fakeLoginItem{state: loginitem.StateEnabled, backend: loginitem.BackendSMAppService}
	path := serviceServer(t, f)
	resp := rpcParams(t, path, "service", ipc.ServiceParams{Action: "status"})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	var r ipc.ServiceResult
	json.Unmarshal(resp.Result, &r)
	if r.Backend != "smappservice" || r.State != "enabled" {
		t.Fatalf("got %+v, want smappservice/enabled", r)
	}
}

func TestServiceEnableInvokesManager(t *testing.T) {
	f := &fakeLoginItem{state: loginitem.StateRequiresApproval, backend: loginitem.BackendSMAppService}
	path := serviceServer(t, f)
	resp := rpcParams(t, path, "service", ipc.ServiceParams{Action: "enable"})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	if f.lastCall != "enable" {
		t.Fatalf("manager.Enable not called (lastCall=%q)", f.lastCall)
	}
	var r ipc.ServiceResult
	json.Unmarshal(resp.Result, &r)
	if r.State != "requires-approval" {
		t.Fatalf("state = %q, want requires-approval", r.State)
	}
}

func TestServiceBadActionIsBadRequest(t *testing.T) {
	path := serviceServer(t, &fakeLoginItem{})
	resp := rpcParams(t, path, "service", ipc.ServiceParams{Action: "bogus"})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("want CodeBadRequest, got %+v", resp.Error)
	}
}

func TestServiceNilManagerIsInternal(t *testing.T) {
	path := serviceServer(t, nil)
	resp := rpcParams(t, path, "service", ipc.ServiceParams{Action: "status"})
	if resp.Error == nil || resp.Error.Code != ipc.CodeInternal {
		t.Fatalf("want CodeInternal, got %+v", resp.Error)
	}
	_ = errors.New
}
```

**Step 2: Verify fail** — `go -C . test ./internal/daemon/ -run TestService` → `SetLoginItem` undefined.

**Step 3: Implementation in `server.go`**

Add the field near `provision` (around line 81):

```go
	// loginitem serves the "service" RPC: register/unregister avd as a login item.
	// INJECTED via SetLoginItem (avd wires loginitem.New() after New); nil in tests
	// that don't exercise it. Registration MUST run in avd because SMAppService
	// resolves the plist relative to avd's own bundle (av is not in it).
	loginitem loginitem.Manager
```

Add the import `"github.com/beshkenadze/agentvault/internal/loginitem"`.

Add the setter near `SetProvisioner` (around line 142):

```go
// SetLoginItem injects the login-item Manager that serves the "service" RPC.
func (s *Server) SetLoginItem(m loginitem.Manager) { s.loginitem = m }
```

Add the dispatch case (after the `"setup"` case, before `"status"`):

```go
	case "service":
		var p ipc.ServiceParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, ipc.CodeBadRequest, err.Error())
		}
		if s.loginitem == nil {
			return errResp(req.ID, ipc.CodeInternal, "login item not configured")
		}
		// enable/disable mutate the user-owned login item; status only reads. A bad
		// verb is a client bug (CodeBadRequest). SECURITY: ServiceResult is metadata
		// only — backend name + State string — so no secret can reach this reply.
		switch p.Action {
		case "enable":
			if err := s.loginitem.Enable(); err != nil {
				return errResp(req.ID, ipc.CodeInternal, err.Error())
			}
		case "disable":
			if err := s.loginitem.Disable(); err != nil {
				return errResp(req.ID, ipc.CodeInternal, err.Error())
			}
		case "status":
			// read-only
		default:
			return errResp(req.ID, ipc.CodeBadRequest, "unknown service action: "+p.Action)
		}
		st, err := s.loginitem.Status()
		if err != nil {
			return errResp(req.ID, ipc.CodeInternal, err.Error())
		}
		out, _ := json.Marshal(ipc.ServiceResult{Backend: string(s.loginitem.Backend()), State: st.String()})
		return ipc.Response{ID: req.ID, Result: out}
```

Update the package doc comment at the top of `server.go` (line ~1) to mention `"service"` in the dispatch list (one-line edit — keep the comment accurate).

**Step 4: Run** — `go -C . test ./internal/daemon/ -run TestService -v` → PASS. Then full `go -C . test ./internal/daemon/`, `go -C . build ./... && go -C . vet ./...`.

**Step 5: Commit**

```bash
git add internal/daemon/server.go internal/daemon/service_rpc_test.go
git commit -S -m "feat(daemon): service RPC — register/unregister/status via injected loginitem.Manager"
```

---

## Task 7: client — the Service(action) method

**Files:**
- Modify: `internal/client/client.go` (add `Service`)
- Test: covered by Task 6's daemon round-trip; add a thin client test if a stub server harness exists in `internal/client` (optional — do not invent one).

**Step 1 (if adding a test):** otherwise rely on Task 6. The method mirrors `Setup`:

**Step 2: Implementation** — append near `Setup` in `client.go`:

```go
// Service issues the "service" RPC (action: "enable" | "disable" | "status") to
// manage avd's login-item registration, returning the active backend + resulting
// State. SECURITY: ServiceParams/ServiceResult carry no secret. enable/disable are
// the only mutating actions; status is read-only.
func (c *Client) Service(action string) (ipc.ServiceResult, error) {
	pb, _ := json.Marshal(ipc.ServiceParams{Action: action})
	resp, err := c.call(ipc.Request{ID: 1, Method: "service", Params: pb})
	if err != nil {
		return ipc.ServiceResult{}, err
	}
	if resp.Error != nil {
		return ipc.ServiceResult{}, resp.Error
	}
	var r ipc.ServiceResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return ipc.ServiceResult{}, err
	}
	return r, nil
}
```

> No `ensureFresh()` here: `av service` manages the *currently running* daemon's
> registration; a version-skew self-heal is irrelevant to enabling a login item.

**Step 3: Run** — `go -C . build ./... && go -C . vet ./... && go -C . test ./internal/...`.

**Step 4: Commit**

```bash
git add internal/client/client.go
git commit -S -m "feat(client): Service RPC method (enable/disable/status)"
```

---

## Task 8: cmd/av — `av service on|off|status` + parse + output

**Files:**
- Modify: `cmd/av/main.go` (dispatch `case "service"`, `runService`, `parseServiceAction`, usage line)
- Test: `cmd/av/service_test.go` (create — arg parsing, like other cmd/av unit tests)

**Step 1: Failing test**

```go
package main

import "testing"

func TestParseServiceAction(t *testing.T) {
	cases := map[string]string{"on": "enable", "off": "disable", "status": "status"}
	for in, want := range cases {
		got, err := parseServiceAction([]string{in})
		if err != nil || got != want {
			t.Errorf("parseServiceAction(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestParseServiceActionErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"on", "extra"}} {
		if _, err := parseServiceAction(args); err == nil {
			t.Errorf("parseServiceAction(%v) expected error", args)
		}
	}
}
```

**Step 2: Verify fail** — `go -C . test ./cmd/av/ -run TestParseServiceAction` → undefined.

**Step 3: Implementation**

Add to the dispatch switch (after `case "setup"`):

```go
	case "service":
		runService(os.Args[2:])
```

Add the usage line (extend the existing `usage()` string with):
```
  av service on|off|status  (start avd at login; manage in System Settings → Login Items)
```

Implement:

```go
// parseServiceAction maps the user-facing verb to the RPC action. on->enable,
// off->disable, status->status. Exactly one arg; anything else is a usage error.
func parseServiceAction(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("usage: av service on|off|status")
	}
	switch args[0] {
	case "on":
		return "enable", nil
	case "off":
		return "disable", nil
	case "status":
		return "status", nil
	default:
		return "", fmt.Errorf("unknown service command %q (want on|off|status)", args[0])
	}
}

// runService implements `av service on|off|status`: a thin RPC to avd, which owns
// the registration (SMAppService resolves the plist relative to avd's bundle). It
// prints the backend + resulting state and, on requires-approval, points the user to
// System Settings → Login Items.
func runService(args []string) {
	action, err := parseServiceAction(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		usage()
		os.Exit(exitBadRequest)
	}
	res, err := dialClient().Service(action)
	if err != nil {
		os.Exit(exitForError(err))
	}
	fmt.Printf("login item (%s): %s\n", res.Backend, res.State)
	if res.State == "requires-approval" {
		fmt.Println("approve it in System Settings → General → Login Items (Allow in the Background).")
	}
}
```

(Confirm `exitBadRequest`, `exitForError`, `dialClient` exist — they are used by the sibling `runSetup`/`runRm`.)

**Step 4: Run** — `go -C . test ./cmd/av/ -run TestParseServiceAction -v` → PASS. `go -C . build ./... && go -C . vet ./...`.

**Step 5: Commit**

```bash
git add cmd/av/main.go cmd/av/service_test.go
git commit -S -m "feat(av): av service on|off|status — manage the login item"
```

---

## Task 9: wire avd main + `av setup` best-effort enable

**Files:**
- Modify: `cmd/avd/main.go` (construct `loginitem.New()`, `srv.SetLoginItem(...)`)
- Modify: `cmd/av/main.go` (`runSetup` → best-effort `Service("enable")` + hint on `Created`)

**Step 1: avd wiring** — in `cmd/avd/main.go`, after the server is built and the other `Set*` injections, add:

```go
	srv.SetLoginItem(loginitem.New())
```

Add the import `"github.com/beshkenadze/agentvault/internal/loginitem"`. (Find the block where `SetProvisioner`/`SetResolver`/`SetVersion` are called and place it alongside.) This does NOT register anything — it only makes the "service" RPC available. avd never calls Enable on its own (the standard: registration is a user action).

**Step 2: setup glue** — in `runSetup` (`cmd/av/main.go`), after a successful create, attempt enable best-effort:

```go
	if res.Created {
		fmt.Printf("created vault %s\n  identity %s\n", res.VaultPath, res.IdentityPath)
		enableLoginItemBestEffort()
		return
	}
	fmt.Printf("already provisioned: %s\n", res.VaultPath)
```

```go
// enableLoginItemBestEffort registers avd to start at login as part of the deliberate
// `av setup` action (the standards-correct trigger). Best-effort: a failure (e.g.
// SMAppService requires-approval, or an older daemon without the RPC) must NOT fail
// setup — the vault is already provisioned. It prints how to manage/undo it.
func enableLoginItemBestEffort() {
	res, err := dialClient().Service("enable")
	if err != nil {
		fmt.Println("note: could not enable start-at-login automatically; run `av service on`.")
		return
	}
	switch res.State {
	case "requires-approval":
		fmt.Println("avd added to Login Items — approve it in System Settings → General → Login Items.")
	default:
		fmt.Println("avd will start at login. Manage it in System Settings → General → Login Items, or `av service off`.")
	}
}
```

**Step 3: Verify** — `go -C . build ./... && go -C . vet ./... && go -C . test ./...` (full suite green). The setup→enable glue is covered end-to-end by the manual checklist (Task 11); the RPC itself is covered by Task 6.

**Step 4: Commit**

```bash
git add cmd/avd/main.go cmd/av/main.go
git commit -S -m "feat(av): wire loginitem into avd + av setup enables start-at-login (best-effort)"
```

---

## Task 10: packaging — bundled plist, release script, minMacOS, cask

**No automated tests** — verify with `plutil -lint` and a dry `release-signed.sh` read-through.

**Files:**
- Rewrite: `packaging/app.bshk.agentvault.avd.plist` → the bundled SMAppService plist
- Modify: `scripts/release-signed.sh` (copy the plist into the bundle before signing)
- Modify: `packaging/avd.app.Info.plist.template` (`LSMinimumSystemVersion` 11.0 → 13.0)
- Modify: `packaging/agentvault-cask.json` (`dependsOnMacOS` → version; update caveats)

**Step 1: Rewrite `packaging/app.bshk.agentvault.avd.plist`** — bundled, `BundleProgram` relative, no placeholders:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  Bundled LaunchAgent for SMAppService (macOS 13+). It is sealed inside the signed
  app at AgentVault.app/Contents/Library/LaunchAgents/ and registered by avd itself
  via SMAppService.agent(plistName:) (internal/loginitem/smappservice_darwin.m).

  BundleProgram is RELATIVE to the bundle root, so the signature stays valid wherever
  the .app is installed. Interactive ProcessType keeps avd in the user's GUI session
  so LocalAuthentication can present Touch ID. The build-from-source fallback uses a
  DIFFERENT plist with an absolute path — see internal/loginitem/launchagent.go.
-->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>app.bshk.agentvault.avd</string>
    <key>BundleProgram</key>
    <string>Contents/MacOS/avd</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
```

Verify: `plutil -lint packaging/app.bshk.agentvault.avd.plist` → OK.

**Step 2: `scripts/release-signed.sh`** — after the bundle's `Contents/MacOS` is built and Info.plist is written (around line 58), copy the bundled plist into the bundle BEFORE zamokctl signs (the signature seals it):

```bash
# Bundled LaunchAgent for SMAppService (avd registers it at `av setup` time). MUST be
# in place before signing so the signature seals it (Contents/Library/LaunchAgents).
mkdir -p "$APP/Contents/Library/LaunchAgents"
cp "$ROOT/packaging/app.bshk.agentvault.avd.plist" \
   "$APP/Contents/Library/LaunchAgents/app.bshk.agentvault.avd.plist"
```

**Step 3: `packaging/avd.app.Info.plist.template`** — bump the floor (SMAppService needs Ventura):

```
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
```

(Update the comment in the template's header if it references 11.0.)

**Step 4: `packaging/agentvault-cask.json`** — depend on Ventura and fix the caveats (kill `brew services`):

- Change `"dependsOnMacOS": true` → `"dependsOnMacOS": ">= :ventura"` **IF** zamokctl's CaskMetadata accepts a version string there; otherwise leave `true` and add `"minMacOS": "13"` per zamokctl's schema. VERIFY against the schema before changing — do not guess. If unsure, leave `dependsOnMacOS` and only fix caveats in this task, noting the dependency bump for the user.
- Replace `caveats` with:

```
"caveats": "AgentVault runs a per-user background daemon (avd), gated by Touch ID. Provision once:\n\n  av setup\n\nThat creates your vault and registers avd to start at login (you'll see a macOS \"added background item\" notice). Manage it any time in System Settings → General → Login Items, or with `av service on` / `av service off`."
```

- Drop the stale `~/Library/LaunchAgents/...` line from `zapTrash` only if SMAppService is the sole cask mechanism (it is — the cask is the signed .app). Keep it: harmless and covers a user who fell back. Leave `zapTrash` as-is.

**Step 5: Verify** — `plutil -lint` on both plists; `bash -n scripts/release-signed.sh`; re-read the diff.

**Step 6: Commit**

```bash
git add packaging/app.bshk.agentvault.avd.plist packaging/avd.app.Info.plist.template packaging/agentvault-cask.json scripts/release-signed.sh
git commit -S -m "build(packaging): SMAppService bundled plist + macOS 13 floor + cask caveats (drop brew services)"
```

---

## Task 11: docs + manual verification

**Files:**
- Modify: `docs/getting-started.md` (§2 "Start the daemon")
- Modify: `docs/launchagent.md` (the resident-at-login story + the SMAppService manual check)
- Modify: `README.md` (any `brew services start agentvault` mention)
- Verify: `grep -rn "brew services" docs README.md packaging` returns nothing load-bearing

**Step 1: `getting-started.md` §2** — replace the broken `brew services start agentvault` block with:

```markdown
## 2. Provision + start at login

```sh
av setup
```

`av setup` creates your local vault **and** registers `avd` to start at login —
SMAppService on the signed cask, a per-user LaunchAgent on a build-from-source
install. macOS shows a one-time "AgentVault added items that can run in the
background" notice; you can toggle it any time in **System Settings → General →
Login Items**, or with `av service on` / `av service off`.

Verify:

```sh
av service status      # login item (smappservice): enabled
av version             # av/avd versions + active key tier
```
```

Renumber the following sections if needed, and remove the now-duplicated standalone
"Provision the vault" step (setup is now §2).

**Step 2: `launchagent.md`** — reframe from "manual launchctl" to "what `av service` does", and keep the **manual Touch ID + login-item verification** (this is the only coverage for the cgo path):

```markdown
## Manual verification — login item (cannot be unit-tested)

cgo + SMAppService need a signed bundle and a GUI session, so CI can't cover them.
Verify the real path by hand on a signed install:

```sh
av setup                 # registers the login item; expect the macOS background-item notice
av service status        # -> login item (smappservice): enabled   (or requires-approval)
# System Settings → General → Login Items → AgentVault is listed under "Allow in the Background"
# log out and back in    # avd is running without any manual launchctl step
av service off           # -> login item (smappservice): disabled; the entry disappears
```

On a build-from-source install the backend reads `launchagent` and the plist lands at
`~/Library/LaunchAgents/app.bshk.agentvault.avd.plist`.
```

Keep the "Why not a LaunchDaemon" section. Delete the obsolete manual `sed`/`launchctl bootstrap` install steps (superseded by `av service on`), or move them under a short "Manual fallback" note.

**Step 3: `README.md`** — replace any `brew services start agentvault` with `av setup` (which now also enables start-at-login). Mention `av service on|off|status` in the command list.

**Step 4: Verify** — `grep -rn "brew services" docs README.md packaging` → no load-bearing hits. `grep -rn "av service" docs README.md` → present.

**Step 5: Commit**

```bash
git add docs/getting-started.md docs/launchagent.md README.md
git commit -S -m "docs: av setup starts avd at login (av service on/off/status); drop the broken brew services story"
```

---

## Final verification (after all tasks)

```sh
go -C . build ./... && go -C . vet ./... && go -C . test ./...
gofmt -l internal cmd | grep . && echo "FORMAT DRIFT" || echo "format ok"
```

Then **manual** (signed install only — the cgo boundary): the `launchagent.md`
checklist above (setup → notice → Login Items entry → survives logout → `av service
off`).

## Done criteria

- `av setup` provisions the vault and registers avd at login (best-effort), printing the Login Items hint.
- `av service on|off|status` works; `status` distinguishes enabled / requires-approval / disabled.
- avd never auto-registers on a plain start (no dev surprise; honors the Settings toggle).
- Build/vet/test green; `internal/loginitem` covered (selector, plist render, LaunchAgent Enable/Disable/Status, daemon RPC) minus the documented cgo/manual boundary.
- `brew services start agentvault` is gone from docs/cask; replaced by the `av setup` → Login Items story.

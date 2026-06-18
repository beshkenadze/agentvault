package client

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// realSecret is the value the e2e proves NEVER reaches av's stdout/stderr. The
// REAL avd binary (not an in-process Server) decrypts the vault and brokers it;
// av masks it at the source. If this string appears anywhere the agent can see,
// the redaction pipeline — or the production avd resolver wiring (I-1) — is broken.
const realSecret = "ghp_REAL_e2e"

// dangerSecret is the value brokered for the dangerous-tier entry. The
// dangerous-never-cached e2e proves it is masked at layer-1 during `av run` but,
// because dangerous-tier values are NEVER written into the session, is NOT masked
// by the layer-2 scrub stream (no exact-match in the session matcher).
const dangerSecret = "AKIA_DANGER_e2e"

// e2eVault age-encrypts {GITHUB_TOKEN: realSecret} to <dir>/vault.age, writes the
// identity string to <dir>/id.txt (the standard age identity-file format that
// avd's age.ParseIdentities reads), and writes an agentvault.yaml with profile
// "smoke". It returns the identity-file path, vault path, and manifest path.
func e2eVault(t *testing.T, dir string) (idPath, vaultPath, manifestPath string) {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	idPath = filepath.Join(dir, "id.txt")
	if err := os.WriteFile(idPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	vaultPath = filepath.Join(dir, "vault.age")
	vf, err := os.Create(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := agefile.EncryptVault(vf, id.Recipient(), map[string]string{"GITHUB_TOKEN": realSecret}); err != nil {
		vf.Close()
		t.Fatal(err)
	}
	if err := vf.Close(); err != nil {
		t.Fatal(err)
	}

	manifestPath = filepath.Join(dir, "agentvault.yaml")
	manifest := "profiles:\n" +
		"  smoke:\n" +
		"    GITHUB_TOKEN:\n" +
		"      ref: av://file/GITHUB_TOKEN\n" +
		"      tier: normal\n"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return idPath, vaultPath, manifestPath
}

// e2eMixedVault is e2eVault for the dangerous-never-cached e2e: it re-encrypts the
// vault to {GITHUB_TOKEN: realSecret (normal), AWS_KEY: dangerSecret (dangerous)} and
// rewrites the manifest with a "mixed" profile mapping each ref to its tier. The two
// tiers in one profile let one run prove normal IS cached (scrub masks it) while
// dangerous is NOT (scrub passes it through unchanged). It reuses the SAME id/vault/
// manifest paths e2eVault wrote under dir, so the autostarted avd env is unchanged.
func e2eMixedVault(t *testing.T, dir string) (manifestPath string) {
	t.Helper()

	idPath := filepath.Join(dir, "id.txt")
	vaultPath := filepath.Join(dir, "vault.age")
	manifestPath = filepath.Join(dir, "agentvault.yaml")

	ids, err := readIdentityRecipient(idPath)
	if err != nil {
		t.Fatal(err)
	}

	vf, err := os.Create(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := agefile.EncryptVault(vf, ids, map[string]string{
		"GITHUB_TOKEN": realSecret,
		"AWS_KEY":      dangerSecret,
	}); err != nil {
		vf.Close()
		t.Fatal(err)
	}
	if err := vf.Close(); err != nil {
		t.Fatal(err)
	}

	manifest := "profiles:\n" +
		"  mixed:\n" +
		"    GITHUB_TOKEN:\n" +
		"      ref: av://file/GITHUB_TOKEN\n" +
		"      tier: normal\n" +
		"    AWS_KEY:\n" +
		"      ref: av://file/AWS_KEY\n" +
		"      tier: dangerous\n"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath
}

// readIdentityRecipient parses the identity file e2eVault wrote and returns its
// recipient, so e2eMixedVault can re-encrypt a new vault to the SAME identity the
// autostarted avd already loads (AV_AGE_IDENTITY is unchanged).
func readIdentityRecipient(idPath string) (age.Recipient, error) {
	f, err := os.Open(idPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, err
	}
	x, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, errors.New("e2e: identity is not X25519")
	}
	return x.Recipient(), nil
}

// buildAndAutostartEnv builds the REAL avd into a short /tmp dir and points the env
// at it so client.dial autostarts that binary (the spawned avd inherits the parent
// env — autostart uses exec.Command without a custom Env). It sets AV_AGE_IDENTITY /
// AV_AGE_VAULT so the spawned avd wires the agefile backend, and (unless auth is
// "") AV_TEST_AUTH so the stub authorizer allows issuance. It returns the dir, the
// socket path the autostarted daemon will bind, and the manifest path.
//
// Cleanup is mandatory: it kills the spawned avd by its unique binary path and
// removes the socket + lockfile so nothing leaks past the test.
func buildAndAutostartEnv(t *testing.T, auth string) (dir, sockPath, manifestPath string) {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "ave")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	avd := filepath.Join(dir, "avd")
	build := exec.Command("go", "build", "-o", avd, "github.com/beshkenadze/agentvault/cmd/avd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build avd: %v\n%s", err, out)
	}

	idPath, vaultPath, manifestPath := e2eVault(t, dir)

	t.Setenv("AV_AVD_PATH", avd)
	t.Setenv("XDG_RUNTIME_DIR", dir) // socket resolves under this short dir
	t.Setenv("AV_AGE_IDENTITY", idPath)
	t.Setenv("AV_AGE_VAULT", vaultPath)
	if auth != "" {
		t.Setenv("AV_TEST_AUTH", auth)
	} else {
		t.Setenv("AV_TEST_AUTH", "") // explicitly locked: no auth configured
	}

	sockPath = filepath.Join(dir, "agentvault", "avd.sock")
	t.Cleanup(func() {
		_ = exec.Command("pkill", "-f", avd).Run()
		_ = os.Remove(sockPath)
		_ = os.Remove(sockPath + ".lock")
	})
	return dir, sockPath, manifestPath
}

// assertNoSecret fails if the real secret appears anywhere in the given buffers.
func assertNoSecret(t *testing.T, where string, bufs ...*bytes.Buffer) {
	t.Helper()
	for _, b := range bufs {
		if strings.Contains(b.String(), realSecret) {
			t.Fatalf("%s: real secret leaked: %q", where, b.String())
		}
	}
}

// TestE2ERunMasksRealSecret is the I-1 guard: it autostarts the REAL avd binary,
// which must wire the resolver (production path), decrypt the age vault, broker
// GITHUB_TOKEN, and have av mask it at the source. The child echoes the env var;
// av's stdout must show the placeholder and the real value must appear NOWHERE.
//
// PHASE 5 / TASK 8: normal-tier resolve requires an UNLOCKED session, and a fresh avd
// session is LOCKED (Task 2). cmd/avd now wires the stub presence under AV_TEST_AUTH=allow
// (Task 8), so `av unlock` succeeds without a biometric prompt; this e2e calls cl.Unlock()
// before `av run`. Do NOT weaken the resolver's normal-needs-unlocked guard.
func TestE2ERunMasksRealSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds and spawns the real avd")
	}
	_, sockPath, manifestPath := buildAndAutostartEnv(t, "allow")

	cl := New(sockPath)
	// Open the session first: normal-tier resolve refuses a locked session. The stub
	// presence (AV_TEST_AUTH=allow) authorizes unlock without a real Touch ID prompt.
	if err := cl.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	var out, errBuf bytes.Buffer
	code, err := Run(cl, RunOptions{
		Profile:      "smoke",
		ManifestPath: manifestPath,
		Command:      []string{"sh", "-c", "echo got=$GITHUB_TOKEN"},
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr=%q)", err, errBuf.String())
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != "got={{AV:GITHUB_TOKEN}}" {
		t.Fatalf("stdout = %q, want got={{AV:GITHUB_TOKEN}}", got)
	}
	// The whole point: the REAL secret must be nowhere the agent can see it.
	assertNoSecret(t, "run", &out, &errBuf)
}

// TestE2EScrubMasksRealSecret proves layer-2: piping a string containing the real
// secret through the real avd's scrub stream masks it. The session must already
// hold the value, so this reuses the SAME daemon by resolving first (Run), then
// scrubbing over a fresh connection to the same socket.
//
// PHASE 5 / TASK 8: a fresh avd session is LOCKED, so scrub (which reads from the
// session) masks nothing until the session is unlocked. cmd/avd wires the stub presence
// under AV_TEST_AUTH=allow (Task 8), so cl.Unlock() opens the session without a biometric
// prompt before the priming Run caches GITHUB_TOKEN. Do NOT hack the resolver to pass.
func TestE2EScrubMasksRealSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds and spawns the real avd")
	}
	_, sockPath, manifestPath := buildAndAutostartEnv(t, "allow")
	cl := New(sockPath)

	// Open the session so the priming Run can cache GITHUB_TOKEN for scrub to mask.
	if err := cl.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Resolve once so the daemon's session holds GITHUB_TOKEN for scrub to mask.
	var out, errBuf bytes.Buffer
	if _, err := Run(cl, RunOptions{
		Profile:      "smoke",
		ManifestPath: manifestPath,
		Command:      []string{"true"},
	}, &out, &errBuf); err != nil {
		t.Fatalf("priming run: %v", err)
	}

	var scrubbed bytes.Buffer
	in := strings.NewReader("leak " + realSecret + " here")
	if err := cl.Scrub(in, &scrubbed); err != nil {
		t.Fatalf("scrub: %v", err)
	}
	if !strings.Contains(scrubbed.String(), "{{AV:GITHUB_TOKEN}}") {
		t.Fatalf("scrub output not masked: %q", scrubbed.String())
	}
	assertNoSecret(t, "scrub", &scrubbed)
}

// TestE2ELockedRunFails proves the auth seam end-to-end: a real avd started WITHOUT
// AV_TEST_AUTH refuses resolve with CodeLocked, and the value is never issued. The
// run returns a *ipc.RPCError whose Code is CodeLocked (cmd/av maps it to exit 69).
func TestE2ELockedRunFails(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds and spawns the real avd")
	}
	_, sockPath, manifestPath := buildAndAutostartEnv(t, "") // no AV_TEST_AUTH

	var out, errBuf bytes.Buffer
	code, err := Run(New(sockPath), RunOptions{
		Profile:      "smoke",
		ManifestPath: manifestPath,
		Command:      []string{"sh", "-c", "echo got=$GITHUB_TOKEN"},
	}, &out, &errBuf)
	if err == nil {
		t.Fatalf("locked daemon must fail resolve; got code=%d out=%q", code, out.String())
	}
	var rpc *ipc.RPCError
	if !errors.As(err, &rpc) {
		t.Fatalf("want *ipc.RPCError, got %T: %v", err, err)
	}
	if rpc.Code != ipc.CodeLocked {
		t.Fatalf("want CodeLocked, got code=%d msg=%q", rpc.Code, rpc.Message)
	}
	assertNoSecret(t, "locked", &out, &errBuf)
	if strings.Contains(rpc.Message, realSecret) {
		t.Fatalf("locked error leaked secret: %q", rpc.Message)
	}
}

// TestE2EDangerousNotCachedInScrub is the dangerous-never-cached property proven
// end-to-end through the REAL avd. A "mixed" profile holds a NORMAL secret
// (GITHUB_TOKEN) and a DANGEROUS one (AWS_KEY). After cl.Unlock + a run that uses both:
//
//   - layer 1 (`av run` output): BOTH are masked at the source — av redacts the
//     child's stdout against the values it injected for that single run, so neither
//     value leaks regardless of tier.
//   - layer 2 (`av scrub` of the same values): the NORMAL value is masked (it was
//     cached into the session on resolve), but the DANGEROUS value is NOT — dangerous
//     values are never written to the session, so the session matcher has no
//     exact-match for it and it passes through unchanged.
//
// This is the security heart of Phase 5: the dangerous value being absent from the
// scrub matcher is the observable consequence of never-caching it. The stub presence
// (AV_TEST_AUTH=allow) authorizes both unlock and the dangerous-tier prompt.
func TestE2EDangerousNotCachedInScrub(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds and spawns the real avd")
	}
	dir, sockPath, _ := buildAndAutostartEnv(t, "allow")
	manifestPath := e2eMixedVault(t, dir)
	cl := New(sockPath)

	if err := cl.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Run a command that echoes both secrets. Layer-1 masking must hide BOTH values
	// (normal and dangerous) at the source — neither may reach the caller's stdout.
	var out, errBuf bytes.Buffer
	code, err := Run(cl, RunOptions{
		Profile:      "mixed",
		ManifestPath: manifestPath,
		Command:      []string{"sh", "-c", "echo n=$GITHUB_TOKEN d=$AWS_KEY"},
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr=%q)", err, errBuf.String())
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != "n={{AV:GITHUB_TOKEN}} d={{AV:AWS_KEY}}" {
		t.Fatalf("stdout = %q, want both masked", got)
	}
	// Layer 1: neither the normal nor the dangerous value may appear in run output.
	assertNoSecret(t, "run", &out, &errBuf)
	if strings.Contains(out.String(), dangerSecret) || strings.Contains(errBuf.String(), dangerSecret) {
		t.Fatalf("dangerous value leaked in run output: %q", out.String())
	}

	// Layer 2: scrub a string carrying BOTH values. The NORMAL value is cached, so the
	// session matcher masks it; the DANGEROUS value is never cached, so it is NOT masked.
	var scrubbed bytes.Buffer
	in := strings.NewReader("normal=" + realSecret + " danger=" + dangerSecret)
	if err := cl.Scrub(in, &scrubbed); err != nil {
		t.Fatalf("scrub: %v", err)
	}
	got := scrubbed.String()
	if !strings.Contains(got, "{{AV:GITHUB_TOKEN}}") {
		t.Fatalf("normal value should be masked by scrub (cached): %q", got)
	}
	if strings.Contains(got, realSecret) {
		t.Fatalf("normal value leaked through scrub: %q", got)
	}
	// The load-bearing assertion: dangerous value passes through UNCHANGED (never cached
	// -> not in the session matcher -> layer-2 has no exact-match for it).
	if !strings.Contains(got, dangerSecret) {
		t.Fatalf("dangerous value should NOT be masked by scrub (never cached), but was: %q", got)
	}
	if strings.Contains(got, "{{AV:AWS_KEY}}") {
		t.Fatalf("dangerous value was masked by scrub — it must never be cached: %q", got)
	}
}

// Package adapter generates the per-agent integration files for `av init`.
//
// The AgentVault core is agent-agnostic: it knows how to run, scrub, and read
// secrets, but nothing about any particular agent's hook schema. Per-agent
// specifics — the hook script that pipes context-ingress channels through
// `av scrub`, the settings snippet that wires it, and the skill/doc that teaches
// the agent the {{AV:NAME}}-is-opaque contract — live ENTIRELY here, as templates.
// Adding a new agent is a new entry in the registry below plus its template files;
// no new logic. The files are static strings (embedded), so `av` stays thin: no
// backend/age/gitleaks dependency is pulled in.
//
// SECURITY: nothing generated here ever handles a secret value. The hook only pipes
// bytes through `av scrub` (which forwards to avd for layer-2 redaction); the skill
// doc only documents the contract. No secret is embedded, logged, or templated.
package adapter

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed templates
var templates embed.FS

// File is one generated adapter file: a path relative to the target project root,
// the file mode to write it with, and its full content.
type File struct {
	Path    string      // relative to the init target dir (e.g. ".claude/hooks/av-scrub.sh")
	Mode    os.FileMode // 0755 for hook scripts, 0644 for docs/snippets
	Content string
}

// agentFile declares one file of an agent's adapter: where it lands in the target
// project, the mode to write it, and which embedded template produces its content.
type agentFile struct {
	path     string
	mode     os.FileMode
	template string // path under templates/ (the SSOT for the file's bytes)
}

// registry is the SSOT for which agents `av init` supports and which files each one
// generates. Adding an agent = one entry here + its template file(s). The core logic
// (Files/Write) never changes.
var registry = map[string][]agentFile{
	"claude-code": {
		{path: ".claude/hooks/av-scrub.sh", mode: 0o755, template: "templates/claude-code/av-scrub.sh"},
		{path: ".claude/agentvault.hooks.json", mode: 0o644, template: "templates/claude-code/agentvault.hooks.json"},
		{path: ".claude/skills/agentvault/SKILL.md", mode: 0o644, template: "templates/claude-code/SKILL.md"},
	},
	"generic": {
		{path: "agentvault/av-scrub.sh", mode: 0o755, template: "templates/generic/av-scrub.sh"},
		{path: "agentvault/AGENTVAULT.md", mode: 0o644, template: "templates/generic/AGENTVAULT.md"},
	},
}

// KnownAgents returns the supported agent names, sorted for a stable usage message.
func KnownAgents() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Files returns the adapter files for the named agent, resolving each file's content
// from its embedded template. An unknown agent is a clear error that lists the known
// agents so the caller can map it to a non-zero exit and the user can correct it.
func Files(agent string) ([]File, error) {
	specs, ok := registry[agent]
	if !ok {
		return nil, fmt.Errorf("unknown agent %q (known agents: %s)", agent, strings.Join(KnownAgents(), ", "))
	}
	out := make([]File, 0, len(specs))
	for _, s := range specs {
		content, err := templates.ReadFile(s.template)
		if err != nil {
			// A missing embedded template is a build/packaging bug, not user error.
			return nil, fmt.Errorf("adapter template %s: %w", s.template, err)
		}
		out = append(out, File{Path: s.path, Mode: s.mode, Content: string(content)})
	}
	return out, nil
}

// Write materializes files under dir, creating parent directories as needed. Unless
// force is set it REFUSES to overwrite an existing file (so a user's customized hook is
// never destroyed) and reports the conflict before writing anything else. Conflicts are
// detected up front so a partial write never clobbers one file and then aborts.
func Write(dir string, files []File, force bool) error {
	if !force {
		for _, f := range files {
			target := filepath.Join(dir, f.Path)
			if _, err := os.Stat(target); err == nil {
				return fmt.Errorf("refusing to overwrite existing file %s (use --force to replace)", f.Path)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("stat %s: %w", f.Path, err)
			}
		}
	}
	for _, f := range files {
		target := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir for %s: %w", f.Path, err)
		}
		if err := os.WriteFile(target, []byte(f.Content), f.Mode); err != nil {
			return fmt.Errorf("write %s: %w", f.Path, err)
		}
		// WriteFile respects the mode only on creation; chmod to be sure the hook is
		// executable even if the file pre-existed with a different mode (force path).
		if err := os.Chmod(target, f.Mode); err != nil {
			return fmt.Errorf("chmod %s: %w", f.Path, err)
		}
	}
	return nil
}

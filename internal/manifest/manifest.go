// Package manifest parses agentvault.yaml: profiles mapping logical names to a
// backend reference and an access tier. It holds no secret values.
package manifest

import (
	"fmt"
	"os"

	"github.com/beshkenadze/agentvault/internal/backend"
	"gopkg.in/yaml.v3"
)

// Tier is the access tier of an entry.
type Tier string

const (
	TierNormal    Tier = "normal"
	TierDangerous Tier = "dangerous"
)

// Entry maps a logical env name to a backend reference and a tier.
type Entry struct {
	Ref  string `yaml:"ref"`
	Tier Tier   `yaml:"tier"`
}

// Profile is the set of entries activated together (logical name -> entry).
type Profile map[string]Entry

// Manifest is the parsed agentvault.yaml.
type Manifest struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	for pname, p := range m.Profiles {
		for name, e := range p {
			if e.Ref == "" {
				return fmt.Errorf("profile %q entry %q: missing ref", pname, name)
			}
			if e.Tier != TierNormal && e.Tier != TierDangerous {
				return fmt.Errorf("profile %q entry %q: invalid tier %q (want normal|dangerous)", pname, name, e.Tier)
			}
			if _, err := backend.ParseRef(e.Ref); err != nil {
				return fmt.Errorf("profile %q entry %q: %w", pname, name, err)
			}
		}
	}
	return nil
}

func (m *Manifest) Profile(name string) (Profile, bool) {
	p, ok := m.Profiles[name]
	return p, ok
}

// Synthetic builds an in-memory manifest holding one profile with a single entry,
// serialized to the YAML bytes Parse accepts. Direct-addressing paths that resolve a
// ref without an on-disk agentvault.yaml use it — `av read --backend NAME` (and `av
// env`) construct av://<backend>/<NAME> and resolve it through the same path as a real
// profile. Serialization stays here so the schema has a single owner (SSOT).
func Synthetic(profile, name, ref string, tier Tier) ([]byte, error) {
	m := Manifest{Profiles: map[string]Profile{profile: {name: {Ref: ref, Tier: tier}}}}
	return yaml.Marshal(m)
}

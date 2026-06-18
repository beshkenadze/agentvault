package daemon

import (
	"fmt"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/manifest"
)

// Resolver turns a (profile, manifest bytes) request into resolved name->value pairs,
// authorizing each by tier and recording issued values in the session.
type Resolver struct {
	reg  *backend.Registry
	auth Authorizer
	sess *Session
}

func NewResolver(reg *backend.Registry, auth Authorizer, sess *Session) *Resolver {
	return &Resolver{reg: reg, auth: auth, sess: sess}
}

// Resolve parses the manifest, selects the profile, authorizes + resolves each entry,
// records issued values in the session, and returns name->value. On any authorize
// failure it returns ErrLocked (so the daemon maps it to CodeLocked) and issues nothing.
func (r *Resolver) Resolve(profile string, manifestBytes []byte) (map[string]string, error) {
	m, err := manifest.Parse(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	p, ok := m.Profile(profile)
	if !ok {
		return nil, fmt.Errorf("profile %q not found", profile)
	}
	out := make(map[string]string, len(p))
	for name, e := range p {
		if err := r.auth.Authorize(e.Tier, name); err != nil {
			return nil, err // ErrLocked / denied — issue nothing
		}
		sec, err := r.reg.Resolve(e.Ref)
		if err != nil {
			return nil, fmt.Errorf("resolve %s (%s): %w", name, e.Ref, err)
		}
		out[name] = sec.Value
		r.sess.Issue(name, sec.Value)
	}
	return out, nil
}

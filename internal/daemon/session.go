package daemon

import (
	"sync"
	"time"

	"github.com/beshkenadze/agentvault/internal/redact"
)

// Session holds the secret values issued since unlock. It builds the redactor used by
// the scrub service and expires after a TTL. Safe for concurrent use.
type Session struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	deadline time.Time
	issued   map[string]string // logical name -> value (for redaction + {{AV:NAME}})
	det      redact.Detector   // optional gitleaks detector for layer 2
}

// NewSession returns a session with the given TTL. A zero TTL is immediately expired.
func NewSession(ttl time.Duration) *Session {
	s := &Session{ttl: ttl, now: time.Now, issued: map[string]string{}}
	s.deadline = s.now().Add(ttl)
	return s
}

// WithDetector sets the gitleaks detector used by the scrub redactor.
func (s *Session) WithDetector(d redact.Detector) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.det = d
	return s
}

// Issue records a name->value pair. If the session has expired, it first clears the
// old values, then records the new one and refreshes the deadline.
func (s *Session) Issue(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiredLocked() {
		s.issued = map[string]string{}
	}
	s.issued[name] = value
	s.deadline = s.now().Add(s.ttl)
}

// Expired reports whether the session's TTL has elapsed.
func (s *Session) Expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiredLocked()
}

func (s *Session) expiredLocked() bool { return !s.now().Before(s.deadline) }

// Redactor returns a redactor over the currently-valid issued values (empty if expired).
func (s *Session) Redactor() *redact.Redactor {
	s.mu.Lock()
	defer s.mu.Unlock()
	var secrets []redact.Secret
	if !s.expiredLocked() {
		for name, val := range s.issued {
			secrets = append(secrets, redact.Secret{Name: name, Value: val})
		}
	}
	return redact.NewRedactor(secrets, redact.Options{Detector: s.det})
}

// Lock clears all issued values (used by av lock / TTL expiry / Phase 5 auto-lock).
func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.issued {
		delete(s.issued, k)
	}
}

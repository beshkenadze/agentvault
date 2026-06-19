package daemon

import (
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/redact"
)

// Session holds the secret values issued since unlock. It builds the redactor used by
// the scrub service and expires after a TTL. Safe for concurrent use.
//
// Phase 5: a session has an explicit unlock state. A fresh NewSession is LOCKED until
// Unlock is called; while locked (or once the unlock TTL elapses) the redactor/matcher
// mask nothing and the session is treated as closed. Unlock opens it for a TTL; Lock
// (av lock / auto-lock) and TTL expiry both re-lock and clear issued values.
//
// Phase 6 (memguard-style at-rest protection): issued values are held in lockedValue
// buffers — the bytes are mlocked (no swap) on Issue and ZEROIZED (overwritten with
// zeros, then munlocked) on Lock / expiry-driven clear / re-issue. This protects the
// canonical AT-REST stored value.
//
// DOCUMENTED LIMITATION (scope honesty): the redactor's Matcher needs CLEARTEXT to
// build its masking forms, so Redactor()/Matcher() read each buffer's String() into a
// transient normal-Go-memory copy while building redact.Secret. Those transient
// cleartext FORMS (and the derived encodings the matcher generates) are NOT protected —
// protecting every transient copy is out of scope because the masker fundamentally
// needs cleartext to match. memguard here protects the at-rest session values, not the
// matcher's transient working set.
//
// Phase 7 (Enclave-coupled vault key): the session can also hold the UNWRAPPED age
// identity that the file backend decrypts/encrypts the vault with. The unwrapper is the
// Secure-Enclave Unwrap (a Touch ID), so a single unlock prompt covers BOTH opening the
// session AND unwrapping the key — unwrap IS the presence proof. The identity lives as
// RAW BYTES in a lockedValue (mlock + zeroize), parsed to an age.Identity ON DEMAND, so
// the vault key gets the SAME at-rest protection as issued values. It is overwritten
// (not merely dropped) on every lock path via destroyIssuedLocked, so a daemon
// compromise AFTER lock cannot decrypt the vault: the key only exists in memory inside
// the unlocked window.
type Session struct {
	ttl time.Duration
	now func() time.Time

	mu        sync.Mutex
	unlocked  bool // fresh sessions are locked until Unlock
	deadline  time.Time
	issued    map[string]*lockedValue // logical name -> protected value (mlock + zeroize)
	det       redact.Detector         // optional gitleaks detector for layer 2
	unwrapper func() ([]byte, error)  // optional Enclave Unwrap (Touch ID) yielding raw identity bytes
	identity  *lockedValue            // unwrapped age identity bytes (mlock + zeroize); nil while locked
}

// NewSession returns a LOCKED session with the given default TTL. The session must be
// opened with Unlock before issued values are honored.
func NewSession(ttl time.Duration) *Session {
	return &Session{ttl: ttl, now: time.Now, issued: map[string]*lockedValue{}}
}

// WithDetector sets the gitleaks detector used by the scrub redactor.
func (s *Session) WithDetector(d redact.Detector) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.det = d
	return s
}

// WithUnwrapper sets the Secure-Enclave Unwrap (a Touch ID) that yields the raw age
// identity bytes on unlock. Wiring an unwrapper makes unlock UNWRAP the vault key as its
// presence proof (see unlockWithUnwrapper); leaving it unset keeps the plain
// presence-prompt unlock. Mirrors WithDetector's lock + return-self style.
func (s *Session) WithUnwrapper(f func() ([]byte, error)) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unwrapper = f
	return s
}

// HasUnwrapper reports whether an Enclave unwrapper is wired, so the server can choose
// the unwrap-as-presence unlock path over the plain presence prompt.
func (s *Session) HasUnwrapper() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unwrapper != nil
}

// destroyIssuedLocked zeroizes (and munlocks) every protected buffer, then resets the
// map. SSOT for every clear path (Unlock / Issue-into-closed / Lock): a value is never
// merely dropped, it is overwritten. Caller must hold s.mu.
//
// The unwrapped vault identity is cleared here too, so it rides the SAME SSOT as issued
// values: Lock, the Unlock stale-clear, and Issue-into-closed all ZEROIZE the key — it
// is overwritten, never merely dropped — so a daemon compromise after lock cannot
// decrypt the vault. (unlockWithUnwrapper repopulates it right after Unlock's clear.)
func (s *Session) destroyIssuedLocked() {
	for _, lv := range s.issued {
		lv.Destroy()
	}
	s.issued = map[string]*lockedValue{}
	if s.identity != nil {
		s.identity.Destroy()
		s.identity = nil
	}
}

// Unlock opens the session for the given TTL: it marks the session unlocked, sets the
// deadline to now+ttl, and clears (zeroizing) any stale values left from a
// previously-expired window so they cannot resurface.
func (s *Session) Unlock(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.destroyIssuedLocked()
	s.unlocked = true
	s.deadline = s.now().Add(ttl)
}

// Locked reports whether the session is closed: never unlocked, explicitly locked, or
// past its unlock deadline (expiry re-locks).
func (s *Session) Locked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lockedLocked()
}

func (s *Session) lockedLocked() bool { return !s.unlocked || s.expiredLocked() }

// Status reports whether the session is locked and, if unlocked and not expired, the
// time remaining until it re-locks. It NEVER returns issued values.
func (s *Session) Status() (locked bool, remaining time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockedLocked() {
		return true, 0
	}
	return false, s.deadline.Sub(s.now())
}

// Issue records a name->value pair into an open session, refreshing the deadline.
//
// Defense-in-depth: a value is NEVER written into a locked or expired session, even if
// a caller forgets the Locked() guard. If the session is closed Issue is a no-op (and
// it clears any stale values from a just-expired window so they cannot resurface). This
// self-defense backstops the resolver's normal-tier guard and guarantees a locked
// session can hold no maskable secret.
func (s *Session) Issue(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockedLocked() {
		s.destroyIssuedLocked() // zeroize+drop stale values; do not record into a closed session
		return
	}
	if prior := s.issued[name]; prior != nil {
		prior.Destroy() // zeroize the buffer being replaced — never leak it
	}
	s.issued[name] = newLockedValue(value)
	s.deadline = s.now().Add(s.ttl)
}

// Expired reports whether the session's TTL has elapsed.
func (s *Session) Expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiredLocked()
}

func (s *Session) expiredLocked() bool { return !s.now().Before(s.deadline) }

// Redactor returns a redactor over the currently-valid issued values (empty if the
// session is locked or expired, so a closed session masks nothing).
func (s *Session) Redactor() *redact.Redactor {
	s.mu.Lock()
	defer s.mu.Unlock()
	var secrets []redact.Secret
	if !s.lockedLocked() {
		for name, lv := range s.issued {
			// Transient cleartext: lv.String() copies into normal Go memory only for the
			// span of building the redact.Secret (the documented matcher-forms limitation).
			secrets = append(secrets, redact.Secret{Name: name, Value: lv.String()})
		}
	}
	return redact.NewRedactor(secrets, redact.Options{Detector: s.det})
}

// Matcher returns the exact-match matcher over the currently-valid issued values
// (empty if the session is locked or expired). It mirrors Redactor but returns the
// layer-2 streaming matcher for use with redact.NewStreamRedactor, so a secret split
// across scrub chunks is still masked. NOTE: the STREAMING tier masks by EXACT-MATCH
// over session values only (split-safe); the gitleaks Detector tier is layered on top
// per flushed region in the scrub handler (see Session.Detector + server.go).
func (s *Session) Matcher() *redact.Matcher {
	s.mu.Lock()
	defer s.mu.Unlock()
	var secrets []redact.Secret
	if !s.lockedLocked() {
		for name, lv := range s.issued {
			// Transient cleartext (documented matcher-forms limitation): see Redactor.
			secrets = append(secrets, redact.Secret{Name: name, Value: lv.String()})
		}
	}
	return redact.NewMatcher(secrets)
}

// Detector returns the session's layer-2 gitleaks detector for the scrub net, or nil
// when the session is locked/expired or no detector was wired. A nil return means the
// scrub path masks nothing via the detector tier — so a locked session masks nothing
// (neither exact-match issued values nor gitleaks findings).
func (s *Session) Detector() redact.Detector {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockedLocked() {
		return nil
	}
	return s.det
}

// Lock re-locks the session and ZEROIZES + clears all issued values (used by av lock /
// TTL expiry / Phase 5 auto-lock / rate-limit force-relock). Each protected buffer is
// overwritten with zeros and munlocked — the secret is destroyed, not merely dropped.
// destroyIssuedLocked also zeroizes the unwrapped vault identity on this path.
func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unlocked = false
	s.destroyIssuedLocked()
}

// Identity parses and returns the unwrapped age identity the file backend decrypts and
// encrypts the vault with. Structurally this satisfies agefile.IdentitySource (fetched
// per operation), so the key can live HERE and be zeroized on lock rather than held by
// the backend — we intentionally do NOT import agefile to keep the dependency one-way.
//
// It returns ErrLocked when the session is closed or holds no key, so a locked session
// cannot decrypt the vault. The identity is held as RAW BYTES and parsed ON DEMAND (not
// cached as a parsed age.Identity) so the key material gets the same mlock+zeroize
// at-rest protection as issued values; the parsed form is transient working memory.
func (s *Session) Identity() (age.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockedLocked() || s.identity == nil {
		return nil, ErrLocked
	}
	ids, err := age.ParseIdentities(strings.NewReader(s.identity.String()))
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, ErrLocked
	}
	return ids[0], nil
}

// setIdentityLocked stores the unwrapped identity bytes in a fresh protected buffer
// (mlock + zeroize), destroying any prior buffer first so a replaced key is overwritten,
// never leaked. Caller must hold s.mu.
func (s *Session) setIdentityLocked(b []byte) {
	if s.identity != nil {
		s.identity.Destroy()
	}
	s.identity = newLockedValue(string(b))
}

// unlockWithUnwrapper opens the session by UNWRAPPING the vault key — the unwrap (a
// Touch ID via the Secure Enclave) IS the presence proof, so one biometric covers both
// session-open and key material. The unwrap runs FIRST: if it errors (e.g. the user
// denied the prompt), the session stays LOCKED and we surface the error unchanged, so a
// denied unwrap is a denied unlock.
//
// Locking discipline: Unlock takes s.mu itself, so we must not hold s.mu across it. We
// fetch the bytes with no lock held, call Unlock (whose destroyIssuedLocked nils any
// stale identity), then take s.mu only to store the new identity. That ordering is
// deliberate — Unlock clears, then we populate — so the freshly-unwrapped key lands in a
// clean session.
func (s *Session) unlockWithUnwrapper(ttl time.Duration) error {
	b, err := s.unwrapper()
	if err != nil {
		return err
	}
	s.Unlock(ttl)
	s.mu.Lock()
	s.setIdentityLocked(b)
	s.mu.Unlock()
	return nil
}

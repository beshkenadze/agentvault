package daemon

import (
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

// TestUnlockLockNoStrandedKey is the regression guard for the unlock TOCTOU: under the
// OLD code, unlockWithUnwrapper released s.mu between opening the session (Unlock) and
// storing the key (setIdentityLocked). A concurrent Lock() in that window could set
// unlocked=false and nil the identity, after which setIdentityLocked stored a LIVE
// mlock'd key buffer into a session that reports LOCKED — a stranded, never-zeroized
// key. This test hammers unlock and lock from many goroutines and asserts the invariant:
//
//	if Locked() is true, then s.identity == nil (no live key in a locked session).
//
// Run under -race: it catches both the logical strand (invariant violation) and any data
// race on the s.identity field. With the one-lock unlock+store fix the invariant holds.
func TestUnlockLockNoStrandedKey(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	const ttl = 15 * time.Minute
	sess := NewSession(ttl).WithUnwrapper(stubUnwrapper(id))

	const (
		goroutines = 50
		iterations = 200
	)
	var wg sync.WaitGroup

	// Unlockers: repeatedly unwrap+unlock (the operation that stores the key).
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = sess.unlockWithUnwrapper(ttl)
			}
		}()
	}
	// Lockers: repeatedly re-lock (the operation that nils + zeroizes the key).
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sess.Lock()
			}
		}()
	}
	// Invariant checkers: under one lock, observe (locked, identity) atomically and assert
	// a locked session never holds a live key. Checking inside s.mu makes the observation
	// consistent — the fix guarantees the state pair is never torn.
	var violations int32
	var vmu sync.Mutex
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sess.mu.Lock()
				strandedKey := sess.lockedLocked() && sess.identity != nil
				sess.mu.Unlock()
				if strandedKey {
					vmu.Lock()
					violations++
					vmu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if violations != 0 {
		t.Fatalf("invariant violated: a locked session held a live identity (%d times) — unlock TOCTOU stranded a key", violations)
	}
}

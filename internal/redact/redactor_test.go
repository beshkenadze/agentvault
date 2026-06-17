package redact

import (
	"strings"
	"testing"
)

// fakeDetector is an in-test Detector that returns a fixed set of findings,
// proving Redactor's composition without importing gitleaks into this package.
type fakeDetector struct {
	findings []Finding
}

func (f fakeDetector) Detect(string) []Finding { return f.findings }

func TestRedactorExactTier(t *testing.T) {
	r := NewRedactor([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}}, Options{})
	got := r.Redact("see ghp_ABCDEFG")
	if want := "see {{AV:T}}"; got != want {
		t.Errorf("Redact() = %q, want %q", got, want)
	}
}

func TestRedactorDetectorTier(t *testing.T) {
	det := fakeDetector{findings: []Finding{{Secret: "leakedXYZ", Rule: "fake-rule"}}}
	r := NewRedactor(nil, Options{Detector: det})
	got := r.Redact("a leakedXYZ b")
	if !strings.Contains(got, "{{AV:REDACTED:fake-rule}}") {
		t.Errorf("Redact() = %q, want it to contain the detector placeholder", got)
	}
	if strings.Contains(got, "leakedXYZ") {
		t.Errorf("Redact() = %q, raw secret leaked through detector tier", got)
	}
}

func TestRedactorFindingsLongestFirst(t *testing.T) {
	// Two overlapping findings where the short Secret is a substring of the long one.
	// If masking ran in this (shorter-first) order, "abc123" would be replaced first,
	// leaving the trailing "def" exposed and never masking the longer secret whole.
	// Redact must sort findings longest-first so the longer secret is masked as a unit.
	det := fakeDetector{findings: []Finding{
		{Secret: "abc123", Rule: "short"},
		{Secret: "abc123def", Rule: "long"},
	}}
	r := NewRedactor(nil, Options{Detector: det})
	got := r.Redact("token abc123def end")

	if want := "token {{AV:REDACTED:long}} end"; got != want {
		t.Errorf("Redact() = %q, want %q (longer finding must be masked whole)", got, want)
	}
	if strings.Contains(got, "abc123") {
		t.Errorf("Redact() = %q, raw secret survived", got)
	}
	if strings.Contains(got, "def") {
		t.Errorf("Redact() = %q, leftover %q exposed after short-first masking", got, "def")
	}
}

func TestRedactorExactBeforeDetector(t *testing.T) {
	// "secretval" is both an issued secret (exact tier) and a detector finding.
	// Exact runs first, so it must win with {{AV:NAME}}, never the detector mask.
	det := fakeDetector{findings: []Finding{{Secret: "secretval", Rule: "fake-rule"}}}
	r := NewRedactor([]Secret{{Name: "K", Value: "secretval"}}, Options{Detector: det})
	got := r.Redact("x secretval y")
	if want := "x {{AV:K}} y"; got != want {
		t.Errorf("Redact() = %q, want %q (exact tier must win over detector)", got, want)
	}
	if strings.Contains(got, "REDACTED") {
		t.Errorf("Redact() = %q, detector masked a value the exact tier already handled", got)
	}
}

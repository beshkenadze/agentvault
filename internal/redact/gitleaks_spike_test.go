package redact

import (
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/detect"
)

// TestGitleaksDetectsString probes whether gitleaks (v8) can scan an in-memory
// string — no git, no filesystem — and return findings WITH offsets usable for
// masking. This is the exact API redaction layer 2 needs.
//
// SPIKE result (Task 6): GO. The real API is simpler than the plan guessed:
//   - detect.NewDetectorDefaultConfig() (*Detector, error) builds a detector with
//     the embedded default rule set in one call (no ViperConfig.Translate dance).
//   - (*Detector).DetectString(s) []report.Finding scans a bare string.
//   - report.Finding carries StartColumn/EndColumn (1-based, per StartLine) plus
//     the raw Match and captured Secret substrings — enough to mask spans.
func TestGitleaksDetectsString(t *testing.T) {
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		t.Fatalf("NewDetectorDefaultConfig failed (record exact API): %v", err)
	}

	cases := []struct {
		name string
		in   string
	}{
		{"github-pat", "token github ghp_0123456789abcdefABCDEF0123456789abcd"},
		// gitleaks allowlists AWS keys ending in EXAMPLE and requires the body to
		// match [A-Z2-7]{16} with entropy >= 3, so use gitleaks' own valid sample
		// key (AKIALALEMEL33243OLIB) which its aws-access-token rule treats as a
		// true positive.
		{"aws-access-key", "aws_access_key_id = AKIALALEMEL33243OLIB extra"},
	}

	for _, tc := range cases {
		findings := d.DetectString(tc.in)
		if len(findings) == 0 {
			t.Errorf("%s: gitleaks found nothing on an obvious secret; API or rules unusable for layer 2 (input=%q)", tc.name, tc.in)
			continue
		}
		for _, f := range findings {
			t.Logf("%s: rule=%q startLine=%d endLine=%d startCol=%d endCol=%d match=%q secret=%q",
				tc.name, f.RuleID, f.StartLine, f.EndLine, f.StartColumn, f.EndColumn, f.Match, f.Secret)

			// For a single-line input the columns must address the matched span.
			// gitleaks columns are 1-based and inclusive; verify the substring at
			// [StartColumn-1:EndColumn] contains the secret so masking can use it.
			if f.StartColumn >= 1 && f.EndColumn <= len(tc.in) && f.EndColumn >= f.StartColumn {
				span := tc.in[f.StartColumn-1 : f.EndColumn]
				if !strings.Contains(span, f.Secret) && !strings.Contains(f.Match, f.Secret) {
					t.Errorf("%s: span %q (cols %d..%d) does not contain secret %q and Match %q does not either",
						tc.name, span, f.StartColumn, f.EndColumn, f.Secret, f.Match)
				}
			} else {
				t.Logf("%s: columns out of single-line range (start=%d end=%d len=%d); masking should rely on Match/Secret substring search instead",
					tc.name, f.StartColumn, f.EndColumn, len(tc.in))
			}
		}
	}
}

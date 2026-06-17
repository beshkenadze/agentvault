package redact

import (
	"sort"
	"strings"
)

// Secret is one named value to redact.
type Secret struct {
	Name  string
	Value string
}

// Matcher masks known secret values, replacing each with {{AV:NAME}}.
type Matcher struct {
	forms   map[string]string // exact form -> placeholder
	ordered []string          // forms, longest first
	maxLen  int
}

// NewMatcher builds a matcher over the raw values only (encodings added in Task 3).
func NewMatcher(secrets []Secret) *Matcher {
	m := &Matcher{forms: map[string]string{}}
	for _, s := range secrets {
		if s.Value == "" {
			continue
		}
		placeholder := "{{AV:" + s.Name + "}}"
		for _, form := range allForms(s.Value) {
			if form == "" {
				continue
			}
			if _, ok := m.forms[form]; !ok {
				m.forms[form] = placeholder
			}
		}
	}
	for f := range m.forms {
		m.ordered = append(m.ordered, f)
		if len(f) > m.maxLen {
			m.maxLen = len(f)
		}
	}
	sort.Slice(m.ordered, func(i, j int) bool { return len(m.ordered[i]) > len(m.ordered[j]) })
	return m
}

// MaxFormLen is the longest masked form. Stream buffers overlap by at least this-1.
func (m *Matcher) MaxFormLen() int { return m.maxLen }

// Mask replaces every known form in s with its placeholder, preferring the longest
// form at each position (greedy, non-overlapping, left to right). It is exactly
// maskFrom with atEOF=true, so masking a whole string is byte-identical to streaming
// the same string through StreamRedactor.
func (m *Matcher) Mask(s string) string {
	out, _ := m.maskFrom(s, true)
	return out
}

// maskFrom scans s left to right. At each position it masks the LONGEST registered
// form that matches there (longest-first, consistent with Mask). When atEOF is false
// and it reaches a position pos where s[pos:] is a proper prefix of some form (a
// partial that could still complete with future bytes), it stops and returns pos as
// the retain index. Otherwise the loop runs to the end and retainIndex == len(s).
//
// This is the single greedy segmentation shared by whole-string masking and the
// streaming redactor (SSOT). Each position does at most MaxFormLen work, so the whole
// scan is O(len(s) * numForms * MaxFormLen) — linear in the input.
//
// Returns (maskedPrefix, retainIndex).
func (m *Matcher) maskFrom(s string, atEOF bool) (string, int) {
	var b strings.Builder
	pos := 0
	for pos < len(s) {
		// If more bytes may still arrive and the remaining suffix is a proper prefix
		// of some form, retain it: a future byte could complete that form (possibly a
		// longer one that greedy-longest matching would prefer over any shorter form
		// already matching here). This check is only ever true within MaxFormLen of
		// the end, so it does not cause quadratic behavior.
		if !atEOF && m.hasFormWithPrefix(s[pos:]) {
			return b.String(), pos
		}
		if form, ok := m.longestFormAt(s, pos); ok {
			b.WriteString(m.forms[form])
			pos += len(form)
			continue
		}
		b.WriteByte(s[pos])
		pos++
	}
	return b.String(), len(s)
}

// longestFormAt returns the longest registered form that occurs exactly at s[pos:],
// or ("", false) if none does. m.ordered is longest-first, so the first match is the
// longest. The comparison is bounded by MaxFormLen.
func (m *Matcher) longestFormAt(s string, pos int) (string, bool) {
	rest := s[pos:]
	for _, form := range m.ordered {
		if len(form) <= len(rest) && rest[:len(form)] == form {
			return form, true
		}
	}
	return "", false
}

// hasFormWithPrefix reports whether some known form is strictly longer than s and
// begins with s. Used by maskFrom to decide what to retain for the next write.
func (m *Matcher) hasFormWithPrefix(s string) bool {
	for _, form := range m.ordered {
		if len(form) > len(s) && strings.HasPrefix(form, s) {
			return true
		}
	}
	return false
}

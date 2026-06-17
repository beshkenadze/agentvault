package redact

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

func TestMaskEncodings(t *testing.T) {
	val := "AKIA-secret/key+v1"
	m := NewMatcher([]Secret{{Name: "K", Value: val}})

	cases := map[string]string{
		"raw":       val,
		"b64std":    base64.StdEncoding.EncodeToString([]byte(val)),
		"b64url":    base64.URLEncoding.EncodeToString([]byte(val)),
		"b64rawstd": base64.RawStdEncoding.EncodeToString([]byte(val)),
		"hex":       hex.EncodeToString([]byte(val)),
		"urlquery":  url.QueryEscape(val),
	}
	for name, enc := range cases {
		in := "prefix " + enc + " suffix"
		if got := m.Mask(in); got == in {
			t.Errorf("%s: form %q was not masked", name, enc)
		}
	}
}

func TestMaskUpperHex(t *testing.T) {
	val := "AKIA-secret/key+v1"
	m := NewMatcher([]Secret{{Name: "K", Value: val}})

	enc := strings.ToUpper(hex.EncodeToString([]byte(val)))
	in := "prefix " + enc + " suffix"
	if got := m.Mask(in); got == in {
		t.Errorf("uppercase hex form %q was not masked", enc)
	}
}

func TestMaskPathEscaped(t *testing.T) {
	// Contains both '/' and '+': PathEscape leaves '+' literal while
	// QueryEscape encodes it, so the two escaped forms genuinely diverge.
	val := "AKIA-secret/key+v1"
	if url.PathEscape(val) == url.QueryEscape(val) {
		t.Fatalf("test value not meaningful: PathEscape == QueryEscape (%q)", url.PathEscape(val))
	}
	m := NewMatcher([]Secret{{Name: "K", Value: val}})

	enc := url.PathEscape(val)
	in := "prefix " + enc + " suffix"
	if got := m.Mask(in); got == in {
		t.Errorf("path-escaped form %q was not masked", enc)
	}
}

func TestMaskBase64Variants(t *testing.T) {
	// Bytes 0xFB,0xFF force the alphabets apart: Std/RawStd emit '+'/'/',
	// URL/RawURL emit '-'/'_'; padding presence distinguishes raw vs padded.
	val := string([]byte{0xFB, 0xFF, 0x10, 0x20})
	m := NewMatcher([]Secret{{Name: "B", Value: val}})

	cases := map[string]string{
		"b64std":    base64.StdEncoding.EncodeToString([]byte(val)),
		"b64rawstd": base64.RawStdEncoding.EncodeToString([]byte(val)),
		"b64url":    base64.URLEncoding.EncodeToString([]byte(val)),
		"b64rawurl": base64.RawURLEncoding.EncodeToString([]byte(val)),
	}
	// Guard: the four forms must be distinct, otherwise the coverage is hollow.
	seen := map[string]bool{}
	for _, enc := range cases {
		seen[enc] = true
	}
	if len(seen) != 4 {
		t.Fatalf("base64 variants not distinct: %v", cases)
	}
	for name, enc := range cases {
		in := "prefix " + enc + " suffix"
		if got := m.Mask(in); got == in {
			t.Errorf("%s: form %q was not masked", name, enc)
		}
	}
}

func TestMaskJSONEscaped(t *testing.T) {
	val := `line"with\slash`
	m := NewMatcher([]Secret{{Name: "J", Value: val}})
	// how the value appears inside a JSON string literal
	in := `{"k":"line\"with\\slash"}`
	if got := m.Mask(in); got == in {
		t.Fatalf("json-escaped form not masked: %q", got)
	}
}

package redact

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
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

func TestMaskJSONEscaped(t *testing.T) {
	val := `line"with\slash`
	m := NewMatcher([]Secret{{Name: "J", Value: val}})
	// how the value appears inside a JSON string literal
	in := `{"k":"line\"with\\slash"}`
	if got := m.Mask(in); got == in {
		t.Fatalf("json-escaped form not masked: %q", got)
	}
}

package redact

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
)

// allForms returns the raw value plus every encoding we mask.
func allForms(v string) []string {
	b := []byte(v)
	return []string{
		v,
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		strings.ToUpper(hex.EncodeToString(b)),
		url.QueryEscape(v),
		url.PathEscape(v),
		jsonInner(v),
	}
}

// jsonInner returns the value as it appears inside a JSON string, without the quotes.
func jsonInner(v string) string {
	enc, err := json.Marshal(v)
	if err != nil || len(enc) < 2 {
		return ""
	}
	return string(enc[1 : len(enc)-1])
}

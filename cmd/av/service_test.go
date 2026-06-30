package main

import "testing"

func TestParseServiceAction(t *testing.T) {
	cases := map[string]string{"on": "enable", "off": "disable", "status": "status"}
	for in, want := range cases {
		got, err := parseServiceAction([]string{in})
		if err != nil || got != want {
			t.Errorf("parseServiceAction(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestParseServiceActionErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"on", "extra"}} {
		if _, err := parseServiceAction(args); err == nil {
			t.Errorf("parseServiceAction(%v) expected error", args)
		}
	}
}

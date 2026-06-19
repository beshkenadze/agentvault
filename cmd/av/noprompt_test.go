package main

import (
	"os"
	"testing"
)

// TestNoPromptReadsEnv: noPrompt() is truthy for ANY non-empty AV_NO_PROMPT (the agent
// adapter exports AV_NO_PROMPT=1) and false when unset or empty (a human at a TTY).
func TestNoPromptReadsEnv(t *testing.T) {
	cases := []struct {
		name  string
		unset bool
		val   string
		want  bool
	}{
		{name: "unset", unset: true, want: false}, // interactive — auto-unlock allowed
		{name: "empty", val: "", want: false},     // explicitly empty: not truthy
		{name: "one", val: "1", want: true},       // the value the adapter exports
		{name: "true", val: "true", want: true},
		{name: "zero", val: "0", want: true}, // any non-empty value opts out (documented)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AV_NO_PROMPT", c.val) // registers restore-after-test
			if c.unset {
				os.Unsetenv("AV_NO_PROMPT") // model the variable being absent
			}
			if got := noPrompt(); got != c.want {
				t.Errorf("noPrompt() = %v, want %v", got, c.want)
			}
		})
	}
}

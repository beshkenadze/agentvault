package ipc

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc.Encode(Request{ID: 7, Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	// each message is exactly one line
	if bytes.Count(buf.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("expected newline-delimited single line, got %q", buf.String())
	}
	dec := NewDecoder(&buf)
	var got Request
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 7 || got.Method != "ping" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestResponseError(t *testing.T) {
	r := Response{ID: 1, Error: &RPCError{Code: CodeLocked, Message: "vault locked"}}
	b, _ := json.Marshal(r)
	var got Response
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Error == nil || got.Error.Code != CodeLocked {
		t.Fatalf("error not preserved: %+v", got)
	}
}

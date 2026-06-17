package redact

import (
	"bytes"
	"os"
	"testing"
)

func TestGoldenAllChunkSizes(t *testing.T) {
	in, err := os.ReadFile("testdata/golden_input.txt")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/golden_want.txt")
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher([]Secret{{Name: "S", Value: "SECRET_VALUE_123"}})

	for size := 1; size <= len(in); size++ {
		var out bytes.Buffer
		r := NewStreamRedactor(m, &out)
		for i := 0; i < len(in); i += size {
			end := i + size
			if end > len(in) {
				end = len(in)
			}
			if _, err := r.Write(in[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("chunk size %d: leak or mismatch\n got: %q\nwant: %q", size, out.String(), want)
		}
	}
}

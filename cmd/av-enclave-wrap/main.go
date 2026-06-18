// Command av-enclave-wrap creates a Secure-Enclave-wrapped age identity blob.
//
// It is a SEPARATE binary (not a subcommand of the thin `av`) so the Enclave/cgo
// dependency never reaches `av` (see TestAvStaysThin). It is the manual setup step
// for the hardened file-backend identity:
//
//	# 1. Generate an age identity (plaintext, transient):
//	age-keygen -o identity.txt
//	# 2. Wrap it to the Secure Enclave (creates the Enclave key on first run):
//	av-enclave-wrap -in identity.txt -out identity.enc
//	# 3. Point avd at the wrapped blob and shred the plaintext:
//	export AV_AGE_IDENTITY_ENCLAVE=identity.enc
//	rm -P identity.txt
//
// On a non-darwin/non-cgo build, or off Secure Enclave hardware, enclave.Wrap
// returns the "unavailable" error and this command exits nonzero without writing.
//
// SECURITY: the plaintext identity is read into memory only to wrap it; it is never
// logged. The output file is written 0600. Errors carry paths/OSStatus, never key
// material. COMPILE-VERIFIED ONLY: the real wrap needs Enclave hardware.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/beshkenadze/agentvault/internal/enclave"
)

func main() {
	inPath := flag.String("in", "", "path to the plaintext age identity file (AGE-SECRET-KEY-...)")
	outPath := flag.String("out", "", "path to write the Secure-Enclave-wrapped identity blob")
	flag.Parse()

	if *inPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: av-enclave-wrap -in <identity.txt> -out <identity.enc>")
		os.Exit(2)
	}

	plaintext, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "av-enclave-wrap: read identity: %v\n", err)
		os.Exit(1)
	}

	blob, err := enclave.Wrap(plaintext)
	if err != nil {
		// Value-free: enclave.Wrap errors carry only an OSStatus / "unavailable".
		fmt.Fprintf(os.Stderr, "av-enclave-wrap: wrap: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outPath, blob, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "av-enclave-wrap: write blob: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "av-enclave-wrap: wrote wrapped identity to %s; shred the plaintext %s (e.g. rm -P)\n", *outPath, *inPath)
}

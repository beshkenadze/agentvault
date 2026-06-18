//go:build darwin && cgo

package enclave

// cgoEnabled is true only on the darwin+cgo build, where the real Secure Enclave
// implementation (enclave_darwin.go + enclave_darwin.m) is compiled in. The test
// uses it to branch between the real-path and stub-path assertions.
const cgoEnabled = true

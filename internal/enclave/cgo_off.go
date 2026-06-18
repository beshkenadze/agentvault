//go:build !darwin || !cgo

package enclave

// cgoEnabled is false on every build without darwin+cgo, where the stubs
// (enclave_other.go) are compiled in. The test uses it to branch between the
// real-path and stub-path assertions.
const cgoEnabled = false

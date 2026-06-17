// Package redact masks known secret values, and values derived/leaked at runtime,
// in whole strings and in byte streams. It is the single redaction implementation
// shared by both enforcement layers (av run source masking and avd scrub service).
package redact

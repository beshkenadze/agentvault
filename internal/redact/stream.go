package redact

import "io"

// StreamRedactor masks secrets in a byte stream and forwards masked output to w.
// It retains the trailing bytes that could still grow into a known form, so a value
// split across writes is caught. Always call Close to flush the final tail.
//
// Both Write and Close run the single greedy segmentation (Matcher.maskFrom), so the
// emitted output is byte-identical to masking the fully concatenated stream with
// Mask. The retained tail is bounded by MaxFormLen-1, so memory is bounded and the
// total work is linear in the number of bytes written.
//
// StreamRedactor is fully buffering: it accepts and processes every byte of each
// Write before emitting any masked output. Write therefore reports len(p) as the
// number of bytes consumed in all cases. A downstream write error is sticky: once a
// write to w fails, the error is stored and returned by every subsequent Write and by
// Close, and no further output is emitted. Callers MUST check the error returned by
// Write and Close to detect a downstream failure.
type StreamRedactor struct {
	m    *Matcher
	w    io.Writer
	tail []byte
	err  error // sticky downstream write error
}

func NewStreamRedactor(m *Matcher, w io.Writer) *StreamRedactor {
	return &StreamRedactor{m: m, w: w}
}

func (r *StreamRedactor) Write(p []byte) (int, error) {
	if r.err != nil {
		return len(p), r.err
	}
	buf := append(r.tail, p...)
	out, keep := r.m.maskFrom(string(buf), false)
	if out != "" {
		if _, err := io.WriteString(r.w, out); err != nil {
			r.err = err
			r.tail = append(r.tail[:0], buf[keep:]...)
			return len(p), err
		}
	}
	r.tail = append(r.tail[:0], buf[keep:]...)
	return len(p), nil
}

// Close flushes the retained tail, masking it fully (no more data can arrive).
// It returns any sticky downstream error.
func (r *StreamRedactor) Close() error {
	if r.err != nil {
		return r.err
	}
	if len(r.tail) == 0 {
		return nil
	}
	out, _ := r.m.maskFrom(string(r.tail), true)
	r.tail = nil
	if out == "" {
		return nil
	}
	if _, err := io.WriteString(r.w, out); err != nil {
		r.err = err
		return err
	}
	return nil
}

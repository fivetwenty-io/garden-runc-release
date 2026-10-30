package rundmc

import "io"

// OOMLinePrefix is the prefix of the stderr line vm-launch writes after a
// guest OOM, which cmd/vm-launch pins separately.
const OOMLinePrefix = vmOOMLinePrefix

// OOMLineScanner exposes the stderr scanner to the black-box specs.
type OOMLineScanner interface {
	io.Writer
	Seen() bool
}

func NewOOMLineScanner(next io.Writer) OOMLineScanner {
	return newOOMLineScanner(next)
}

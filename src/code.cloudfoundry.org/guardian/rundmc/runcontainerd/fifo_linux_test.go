package runcontainerd_test

import (
	"syscall"

	. "github.com/onsi/gomega"
)

// makeFifo creates a named pipe at path. Named pipes are what a malicious
// image would put at /etc/passwd to hang a lookup that opens the file.
func makeFifo(path string) {
	Expect(syscall.Mkfifo(path, 0644)).To(Succeed())
}

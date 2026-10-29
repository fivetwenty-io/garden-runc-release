//go:build !linux

package runcontainerd_test

import (
	. "github.com/onsi/ginkgo/v2"
)

// makeFifo skips the spec: syscall.Mkfifo exists only on Unix, and the
// gVisor image lookup it exercises only runs on Linux.
func makeFifo(path string) {
	Skip("named pipes need Linux")
}

package seccompvsock

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSeccompvsock(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Seccompvsock Suite")
}

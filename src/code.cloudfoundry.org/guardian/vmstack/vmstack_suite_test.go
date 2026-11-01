package vmstack

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestVMStack(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VMStack Suite")
}

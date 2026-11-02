package vmimage

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestVMImage(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VMImage Suite")
}

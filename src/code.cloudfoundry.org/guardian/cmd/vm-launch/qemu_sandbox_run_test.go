//go:build linux

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the QEMU sandbox option of a run", func() {
	var (
		art    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		GinkgoT().Setenv("TMPDIR", GinkgoT().TempDir())
		logBuf = &bytes.Buffer{}
	})

	// hypervisorArgs runs vm-launch on the fake QEMU with flags and returns
	// the arguments the fake received.
	hypervisorArgs := func(flags ...string) []string {
		GinkgoHelper()
		loader := filepath.Join(art, "qemu/ld-linux-x86-64.so.2")
		writeFakeHypervisor(loader, "")
		argv := append([]string{"--backend", string(backend.VMQemu), "--artifacts", art}, flags...)
		argv = append(argv, "--", "/tmp/lifecycle/launcher", "app", "true", "")
		Expect(run(argv, log.New(logBuf, "", 0))).To(Equal(0), logBuf.String())
		raw, err := os.ReadFile(loader + ".argv")
		Expect(err).NotTo(HaveOccurred())
		return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	}

	It("starts QEMU with the default sandbox and logs nothing about it", func() {
		args := hypervisorArgs()
		Expect(optionAfter(args, "-sandbox", "")).To(Equal(qemuSandbox))
		Expect(logBuf.String()).NotTo(ContainSubstring("sandbox is off"))
	})

	It("passes a custom value through unchanged", func() {
		args := hypervisorArgs("--qemu-sandbox=on,spawn=allow,anything=goes")
		Expect(optionAfter(args, "-sandbox", "")).To(Equal("on,spawn=allow,anything=goes"))
		Expect(logBuf.String()).NotTo(ContainSubstring("sandbox is off"))
	})

	It("leaves -sandbox out and logs that the sandbox is off for an empty value", func() {
		args := hypervisorArgs("--qemu-sandbox=")
		Expect(args).NotTo(ContainElement("-sandbox"))
		Expect(args).NotTo(ContainElement(qemuSandbox))
		Expect(logBuf.String()).To(ContainSubstring("the QEMU sandbox is off"))
	})
})

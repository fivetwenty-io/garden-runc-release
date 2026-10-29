//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("guest memory", func() {
	var (
		logBuf *bytes.Buffer
		logger *log.Logger
	)

	BeforeEach(func() {
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
	})

	DescribeTable("sizes the guest from MEMORY_LIMIT less the reserve",
		func(limit string, want int) {
			Expect(guestMemory(envMap(map[string]string{"MEMORY_LIMIT": limit}), logger)).To(Equal(want))
			Expect(logBuf.String()).To(BeEmpty())
		},
		Entry("the floor plus the reserve", "320m", 128),
		Entry("a 512M app", "512m", 320),
		Entry("a 1G app", "1024m", 832),
		Entry("the ceiling plus the reserve", "16576m", 16384),
	)

	It("keeps the floor for a container too small for it and the reserve, and names both numbers", func() {
		for _, limit := range []string{"319m", "256m", "1m"} {
			logBuf.Reset()
			Expect(guestMemory(envMap(map[string]string{"MEMORY_LIMIT": limit}), logger)).To(Equal(128), limit)
			Expect(logBuf.String()).To(ContainSubstring("MEMORY_LIMIT "+limit+" is below the 320m a guest of 128 MiB needs"), limit)
			Expect(logBuf.String()).To(ContainSubstring("give the app at least 320M"), limit)
			Expect(strings.Count(logBuf.String(), "\n")).To(Equal(1), limit)
		}
	})

	It("caps the guest at the ceiling and says so", func() {
		Expect(guestMemory(envMap(map[string]string{"MEMORY_LIMIT": "9999999m"}), logger)).To(Equal(16384))
		Expect(logBuf.String()).To(Equal("MEMORY_LIMIT 9999999m leaves more than the 16384 MiB a guest may have; the guest gets 16384 MiB\n"))
	})

	It("gives the floor and logs one line when MEMORY_LIMIT is missing", func() {
		Expect(guestMemory(envMap(map[string]string{}), logger)).To(Equal(128))
		Expect(logBuf.String()).To(Equal("MEMORY_LIMIT is not set; the guest gets 128 MiB\n"))
	})

	DescribeTable("gives the floor, and logs one line without the value, when MEMORY_LIMIT is malformed",
		func(limit string) {
			Expect(guestMemory(envMap(map[string]string{"MEMORY_LIMIT": limit}), logger)).To(Equal(128))
			Expect(logBuf.String()).To(Equal("MEMORY_LIMIT is not a whole number of megabytes such as 512m; the guest gets 128 MiB\n"))
		},
		Entry("letters", "abc"),
		Entry("zero", "0m"),
		Entry("no unit", "512"),
		Entry("eight digits", "99999999m"),
		Entry("upper-case unit", "512M"),
		Entry("gigabytes", "1g"),
		Entry("leading zero", "0512m"),
		Entry("signed", "+512m"),
		Entry("spaces", " 512m"),
		Entry("empty", ""),
		Entry("a value that is not a size at all", secretSentinel),
	)

	It("gives the size to QEMU's -m and Firecracker's mem_size_mib", func() {
		nw := &network{port: 8080}
		Expect(optionAfter(qemuArgv(goldenArt, goldenInitrd, 320, nw, ""), "-m", "")).To(Equal("320"))

		raw, err := firecrackerConfigJSON(goldenArt, goldenInitrd, 832, nw, "")
		Expect(err).NotTo(HaveOccurred())
		var cfg firecrackerConfig
		Expect(json.Unmarshal(raw, &cfg)).To(Succeed())
		Expect(cfg.MachineConfig).To(Equal(firecrackerMachineConfig{VCPUCount: 1, MemSizeMiB: 832}))
	})
})

var _ = Describe("run with MEMORY_LIMIT", func() {
	var (
		art    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		GinkgoT().Setenv("TMPDIR", GinkgoT().TempDir())
		logBuf = &bytes.Buffer{}
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	It("boots QEMU with the guest size", func() {
		GinkgoT().Setenv("MEMORY_LIMIT", "512m")
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).To(ContainSubstring("\n-m\n320\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("MEMORY_LIMIT"))
	})

	It("boots Firecracker with the guest size", func() {
		GinkgoT().Setenv("MEMORY_LIMIT", "1024m")
		fcCopy := filepath.Join(GinkgoT().TempDir(), "fc.json")
		writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"),
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`)
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())
		raw, err := os.ReadFile(fcCopy)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(`"machine-config":{"vcpu_count":1,"mem_size_mib":832}`))
	})

	It("boots a guest of 128 MiB and warns when MEMORY_LIMIT is below 320m", func() {
		GinkgoT().Setenv("MEMORY_LIMIT", "256m")
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).To(ContainSubstring("\n-m\n128\n"))
		Expect(logBuf.String()).To(ContainSubstring("MEMORY_LIMIT 256m is below the 320m"))
	})
})

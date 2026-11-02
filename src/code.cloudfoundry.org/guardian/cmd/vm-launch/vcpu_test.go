//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("guest vCPUs", func() {
	var (
		logBuf *bytes.Buffer
		logger *log.Logger
	)

	BeforeEach(func() {
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
	})

	cpus := func(n int) func() (int, error) {
		return func() (int, error) { return n, nil }
	}

	DescribeTable("gives the guest one vCPU for each CPU the container may run on",
		func(kind backend.Kind, available, max, want int) {
			Expect(guestVCPUCount(kind, cpus(available), max, logger)).To(Equal(want))
			Expect(logBuf.String()).To(BeEmpty())
		},
		Entry("one CPU on QEMU", backend.VMQemu, 1, 0, 1),
		Entry("two CPUs on QEMU", backend.VMQemu, 2, 0, 2),
		Entry("three CPUs on QEMU", backend.VMQemu, 3, 0, 3),
		Entry("two CPUs on Firecracker", backend.VMFirecracker, 2, 0, 2),
		Entry("one CPU on Firecracker", backend.VMFirecracker, 1, 0, 1),
		Entry("an operator maximum above the CPUs", backend.VMQemu, 2, 8, 2),
		Entry("an operator maximum equal to the CPUs", backend.VMFirecracker, 4, 4, 4),
		Entry("thirty-two CPUs, the most a guest has", backend.VMFirecracker, 32, 0, 32),
	)

	It("lowers the count to the operator maximum and says so", func() {
		Expect(guestVCPUCount(backend.VMQemu, cpus(8), 2, logger)).To(Equal(2))
		Expect(logBuf.String()).To(Equal("the container can run on 8 CPUs and the operator maximum is 2; the guest gets 2 vCPUs\n"))
	})

	It("caps the count at 32 and says so", func() {
		Expect(guestVCPUCount(backend.VMQemu, cpus(96), 0, logger)).To(Equal(32))
		Expect(logBuf.String()).To(Equal("the container can run on 96 CPUs and a guest has at most 32 vCPUs; the guest gets 32\n"))
	})

	It("gives Firecracker an even count above one, and QEMU the count as it is", func() {
		Expect(guestVCPUCount(backend.VMFirecracker, cpus(5), 0, logger)).To(Equal(4))
		Expect(guestVCPUCount(backend.VMFirecracker, cpus(3), 0, logger)).To(Equal(2))
		Expect(guestVCPUCount(backend.VMFirecracker, cpus(6), 5, logger)).To(Equal(4))
		Expect(guestVCPUCount(backend.VMQemu, cpus(5), 0, logger)).To(Equal(5))
	})

	It("falls back to one vCPU and says why when the CPUs cannot be counted", func() {
		Expect(guestVCPUCount(backend.VMQemu, func() (int, error) { return 0, errors.New("no affinity") }, 0, logger)).To(Equal(1))
		Expect(logBuf.String()).To(Equal("the container's CPUs cannot be counted (no affinity); the guest gets 1 vCPU\n"))
		logBuf.Reset()
		Expect(guestVCPUCount(backend.VMFirecracker, cpus(0), 0, logger)).To(Equal(1))
		Expect(logBuf.String()).To(Equal("the container reports 0 CPUs; the guest gets 1 vCPU\n"))
	})

	It("counts the CPUs of this process, at least one and no more than the machine has", func() {
		n, err := containerCPUs()
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeNumerically(">=", 1))
	})

	It("gives the count to QEMU's -smp and Firecracker's vcpu_count", func() {
		nw := &network{ports: []int{8080}}
		Expect(optionAfter(qemuArgvWithVCPUs(goldenArt, goldenInitrd, 320, 4, nw, nil, 0), "-smp", "")).To(Equal("4"))
		Expect(optionAfter(qemuArgv(goldenArt, goldenInitrd, 320, nw, nil, 0), "-smp", "")).To(Equal("1"))

		var cfg firecrackerConfig
		raw, err := json.Marshal(newFirecrackerConfigWithVCPUs(goldenArt, goldenInitrd, 832, 2, nw, nil, "", nil))
		Expect(err).NotTo(HaveOccurred())
		Expect(json.Unmarshal(raw, &cfg)).To(Succeed())
		Expect(cfg.MachineConfig).To(Equal(firecrackerMachineConfig{VCPUCount: 2, MemSizeMiB: 832}))
	})

	It("takes --max-vcpus, which is 0 by default, and refuses a negative one", func() {
		Expect(usage).To(ContainSubstring("[--max-vcpus N]"))
		Expect(maxVCPUsFlag).To(Equal("max-vcpus"))
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.maxVCPUs).To(Equal(0))
		cfg, err = parseArgs([]string{"--backend", "vm-firecracker", "--max-vcpus", "4", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.maxVCPUs).To(Equal(4))
		_, err = parseArgs([]string{"--backend", "vm-qemu", "--max-vcpus=-1", "--", "true"})
		Expect(err).To(MatchError(ContainSubstring("--max-vcpus must be 0 or more")))
		_, err = parseArgs([]string{"--backend", "vm-qemu", "--max-vcpus=two", "--", "true"})
		Expect(err).To(HaveOccurred())
	})

	Describe("run", func() {
		var (
			art    string
			runBuf *bytes.Buffer
		)

		BeforeEach(func() {
			art = makeArtifacts()
			GinkgoT().Setenv("TMPDIR", GinkgoT().TempDir())
			GinkgoT().Setenv("MEMORY_LIMIT", "1024m")
			runBuf = &bytes.Buffer{}
			saved := countContainerCPUs
			DeferCleanup(func() { countContainerCPUs = saved })
			countContainerCPUs = cpus(4)
		})

		runVM := func(args ...string) int {
			argv := append([]string{"--artifacts", art}, args...)
			return run(append(argv, "--", "/tmp/lifecycle/launcher", "app", "true", ""), log.New(runBuf, "", 0))
		}

		It("boots QEMU with a vCPU for each CPU the container may run on", func() {
			argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
			Expect(runVM("--backend", "vm-qemu")).To(Equal(0), runBuf.String())
			argv, err := os.ReadFile(argvFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(argv)).To(ContainSubstring("\n-smp\n4\n"))
		})

		It("boots Firecracker with the count lowered to --max-vcpus", func() {
			fcCopy := filepath.Join(GinkgoT().TempDir(), "fc.json")
			writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"),
				`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`)
			Expect(runVM("--backend", "vm-firecracker", "--max-vcpus", "2")).To(Equal(0), runBuf.String())
			raw, err := os.ReadFile(fcCopy)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(raw)).To(ContainSubstring(`"machine-config":{"vcpu_count":2,"mem_size_mib":926}`))
			Expect(runBuf.String()).To(ContainSubstring("the operator maximum is 2"))
			Expect(strings.Count(runBuf.String(), "vCPUs")).To(Equal(1))
		})
	})
})

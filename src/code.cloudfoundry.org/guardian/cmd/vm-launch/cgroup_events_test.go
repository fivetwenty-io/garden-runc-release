//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Every spec starts with an empty container cgroup, so that a spec that ends
// a hypervisor early does not read the cgroup of the machine it runs on.
var _ = BeforeEach(func() {
	saved := containerCgroupDir
	DeferCleanup(func() { containerCgroupDir = saved })
	containerCgroupDir = GinkgoT().TempDir()
})

var _ = Describe("the container's cgroup events after the hypervisor died", func() {
	write := func(name, content string) {
		Expect(os.WriteFile(filepath.Join(containerCgroupDir, name), []byte(content), 0o644)).To(Succeed())
	}

	exitedWith := func(args ...string) *os.ProcessState {
		cmd := exec.Command(args[0], args[1:]...)
		_ = cmd.Run()
		Expect(cmd.ProcessState).NotTo(BeNil())
		return cmd.ProcessState
	}

	Describe("cgroupEventsMessage", func() {
		It("puts each file on one line, in order, with the event counts", func() {
			write("memory.events", "low 0\nhigh 0\nmax 12\noom 1\noom_kill 1\noom_group_kill 0\n")
			write("memory.max", "1073741824\n")
			write("memory.current", "1073700000\n")
			write("memory.peak", "1073741824\n")
			msg, ok := cgroupEventsMessage()
			Expect(ok).To(BeTrue())
			Expect(msg).To(Equal("the container's cgroup after the hypervisor died: " +
				"memory.events=[low 0 high 0 max 12 oom 1 oom_kill 1 oom_group_kill 0] memory.max=[1073741824] memory.current=[1073700000] memory.peak=[1073741824]"))
		})

		It("leaves out a file the container does not have, such as memory.peak on an older kernel", func() {
			write("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
			write("memory.max", "max\n")
			msg, ok := cgroupEventsMessage()
			Expect(ok).To(BeTrue())
			Expect(msg).To(Equal("the container's cgroup after the hypervisor died: memory.events=[low 0 high 0 max 0 oom 0 oom_kill 0] memory.max=[max]"))
		})

		It("names a file it cannot read with the system's error and no path", func() {
			Expect(os.Mkdir(filepath.Join(containerCgroupDir, "memory.events"), 0o755)).To(Succeed())
			msg, ok := cgroupEventsMessage()
			Expect(ok).To(BeTrue())
			Expect(msg).To(Equal("the container's cgroup after the hypervisor died: memory.events=[unreadable: is a directory]"))
		})

		It("reports nothing for a container without the cgroup files", func() {
			_, ok := cgroupEventsMessage()
			Expect(ok).To(BeFalse())
			containerCgroupDir = filepath.Join(containerCgroupDir, "missing")
			_, ok = cgroupEventsMessage()
			Expect(ok).To(BeFalse())
		})

		It("does not begin with the text that Guardian reads as an out-of-memory event", func() {
			write("memory.events", "oom_kill 4\n")
			msg, _ := cgroupEventsMessage()
			Expect(msg).NotTo(HavePrefix(oomLinePrefix))
		})
	})

	Describe("hypervisorDied", func() {
		It("holds for a hypervisor that exited or was killed with no status and no signal to vm-launch", func() {
			Expect(hypervisorDied(runResult{state: exitedWith("sh", "-c", "exit 3")})).To(BeTrue())
			Expect(hypervisorDied(runResult{state: exitedWith("sh", "-c", "kill -9 $$")})).To(BeTrue())
		})

		It("does not hold when the guest reported a status, when a signal came first, or without a state", func() {
			state := exitedWith("sh", "-c", "exit 3")
			Expect(hypervisorDied(runResult{state: state, markerFound: true})).To(BeFalse())
			Expect(hypervisorDied(runResult{state: state, received: syscall.SIGTERM})).To(BeFalse())
			Expect(hypervisorDied(runResult{})).To(BeFalse())
		})
	})
})

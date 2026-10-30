//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// bootRealGuest boots a guest with contents g, the guest's busybox, and the
// real kernel under TCG, as vm-launch would with QEMU, and returns the
// console output. It fails the spec unless QEMU exits 0, and skips it
// where the real kernel, the guest's busybox, or an x86 QEMU is missing.
func bootRealGuest(g guestContents) string {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	f, err := newInitramfs(guestBusybox(), g)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)
	files, _, initrdPath, _ := hypervisorFiles(nil, f, nil)
	argv := tcgArgv(qemu, qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, "", 0))
	code, stdout, stderr := runRealQEMU(argv, files, "", 5*time.Minute)
	Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
	Expect(stdout).To(ContainSubstring(startTag(testNonce)), stdout)
	return stdout
}

var _ = Describe("the guest userland against a real QEMU", func() {
	It("gives the command the CA bundle at the standard path, with SSL_CERT_FILE naming it", func() {
		dir := GinkgoT().TempDir()
		rootfs := filepath.Join(dir, "ca-certificates.crt")
		Expect(os.WriteFile(rootfs, []byte(newFixtureCert("rootfs").pem), 0o644)).To(Succeed())
		certDir := filepath.Join(dir, "system")
		Expect(os.Mkdir(certDir, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(certDir, "trusted-ca-1.crt"), []byte(newFixtureCert("system").pem), 0o644)).To(Succeed())
		logger := log.New(GinkgoWriter, "", 0)
		bundle, err := guestCABundle([]string{rootfs}, lookupIn(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		envFile, err := buildGuestEnv(map[string]string{sslCertFileEnv: guestCABundlePath}, minGuestMemoryMiB, logger)
		Expect(err).NotTo(HaveOccurred())
		sum := sha256.Sum256(bundle)

		g := taskGuest(`echo "certs=$(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt) file=$SSL_CERT_FILE"
sha256sum /etc/ssl/certs/ca-certificates.crt
ls -ld /etc/ssl/certs/ca-certificates.crt`)
		g.env = envFile
		g.caBundle = bundle
		out := bootRealGuest(g)
		Expect(out).To(ContainSubstring("certs=2 file=" + guestCABundlePath))
		Expect(out).To(ContainSubstring(hex.EncodeToString(sum[:]) + "  " + guestCABundlePath))
		Expect(out).To(MatchRegexp(`-rw-r--r-- +1 0 +0 .*` + guestCABundlePath))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	It("gives the command the container's open files limit above the kernel's default fs.nr_open", func() {
		g := taskGuest(`echo "soft=$(ulimit -S -n) hard=$(ulimit -H -n) nr_open=$(cat /proc/sys/fs/nr_open) file_max=$(cat /proc/sys/fs/file-max)"
echo "init=$(sed -n 's/^Max open files *\([0-9]*\) *\([0-9]*\).*/\1 \2/p' /proc/1/limits)"`)
		g.nofile = nofileLimit{soft: 1500000, hard: 2000000}
		out := bootRealGuest(g)
		Expect(out).To(ContainSubstring("soft=1500000 hard=2000000 nr_open=2000000 file_max=9223372036854775807"))
		// /init keeps the kernel's own limit; only the command gets the
		// container's.
		Expect(out).To(MatchRegexp(`init=\d+ \d+`))
		Expect(out).NotTo(ContainSubstring("init=1500000 2000000"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	It("gives the command a /dev/shm tmpfs of half the guest's memory, mounted as Garden mounts it", func() {
		out := bootRealGuest(taskGuest(`grep ' /dev/shm ' /proc/mounts
ls -ld /dev/shm
echo "memtotal=$(sed -n 's/^MemTotal: *\([0-9]*\) kB$/\1/p' /proc/meminfo)"
echo "shm_kib=$(df -k /dev/shm | sed -n '2s/^[^ ]*  *\([0-9]*\) .*/\1/p')"
echo shared >/dev/shm/probe && echo "wrote=$(cat /dev/shm/probe)"
cp /bin/busybox /dev/shm/bb && chmod 755 /dev/shm/bb
/dev/shm/bb true && echo exec=allowed || echo exec=denied`))
		m := regexp.MustCompile(`(?m)^tmpfs /dev/shm tmpfs (\S+) 0 0\r?$`).FindStringSubmatch(out)
		Expect(m).NotTo(BeNil(), out)
		opts := strings.Split(m[1], ",")
		Expect(opts).To(ContainElements("rw", "nosuid", "nodev", "noexec"), out)
		// The kernel leaves mode=1777 out of the options, because it is the
		// tmpfs default, so the mode is checked on the directory.
		Expect(out).To(MatchRegexp(`(?m)^drwxrwxrwt +\d+ 0 +0 .* /dev/shm\r?$`))
		// The kernel also leaves the size out when it equals the tmpfs
		// default of half the memory at the time it shows the options, which
		// moves as the kernel frees boot memory, so the size comes from df.
		kib := func(name string) uint64 {
			m := regexp.MustCompile(name + `=(\d+)`).FindStringSubmatch(out)
			Expect(m).NotTo(BeNil(), out)
			n, err := strconv.ParseUint(m[1], 10, 64)
			Expect(err).NotTo(HaveOccurred())
			return n
		}
		sizeKiB, memKiB := kib("shm_kib"), kib("memtotal")
		// tmpfs takes half of the guest's pages, so the size is within a
		// page of half of MemTotal.
		Expect(sizeKiB).To(BeNumerically("~", memKiB/2, 4), out)
		Expect(sizeKiB).To(BeNumerically("<=", minGuestMemoryMiB*1024/2), out)
		Expect(out).To(ContainSubstring("wrote=shared"))
		Expect(out).To(ContainSubstring("exec=denied"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})
})

// portProbe records what a connection to a port finds, over time: "closed"
// when the connection is refused, "serves" when an HTTP request through it
// gets an HTTP reply, and "accepts" when the connection opens but no reply
// comes, which is a forwarding rule with nothing behind it. Runs of the same
// state count once.
type portProbe struct {
	mu     sync.Mutex
	states []string
}

func (p *portProbe) observe(addr string) {
	state := "closed"
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		state = "accepts"
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err == nil {
			head := make([]byte, 7)
			if _, err := io.ReadFull(c, head); err == nil && string(head) == "HTTP/1." {
				state = "serves"
			}
		}
		c.Close()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.states) == 0 || p.states[len(p.states)-1] != state {
		p.states = append(p.states, state)
	}
}

func (p *portProbe) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.states...)
}

var _ = Describe("the port gate against a real QEMU", func() {
	It("keeps PORT closed until the guest listens on it, forwards it while it does, and closes it after", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		port := l.Addr().(*net.TCPAddr).Port
		Expect(l.Close()).To(Succeed())
		p := strconv.Itoa(port)
		reservation, err := reservePort(port)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(reservation.Close)

		nw := taskNetwork()
		nw.port = port
		// The guest boots, waits, serves PORT for a while, and stops
		// serving it well before it exits.
		g := taskGuest(`mkdir -p /tmp/www && echo hello >/tmp/www/index.html
sleep 4
httpd -f -p ` + p + ` -h /tmp/www &
h=$!
sleep 8
kill $h
wait $h
sleep 6
echo served`)
		g.nw = nw
		f, err := newInitramfs(guestBusybox(), g)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		monitor, qemuEnd, err := newQMPSocket()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(monitor.Close)
		// The supervisor closes vm-launch's copy of QEMU's end once QEMU
		// has it; this closes it when QEMU never started.
		DeferCleanup(func() { _ = qemuEnd.Close() })
		files, _, initrdPath, monitorFD := hypervisorFiles(nil, f, qemuEnd)
		cmd := newHypervisorCmd(tcgArgv(qemu, qemuArgv(art, initrdPath, minGuestMemoryMiB, nw, "", monitorFD)), files)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		logBuf := &safeBuffer{}
		gate := startPortGate(qmpPort{monitor: newQMPMonitor(monitor), port: port}, port, log.New(logBuf, "", 0))
		var out safeBuffer
		sup := supervisor{
			stdout:  &out,
			logger:  log.New(logBuf, "", 0),
			signals: make(chan os.Signal),
			grace:   killGrace,
			started: func() { _ = qemuEnd.Close() },
			listen:  gate.set,
		}

		probe := &portProbe{}
		stopProbe := make(chan struct{})
		probed := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(probed)
			for {
				probe.observe(net.JoinHostPort("127.0.0.1", p))
				select {
				case <-stopProbe:
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
		}()

		type result struct {
			res runResult
			err error
		}
		ran := make(chan result, 1)
		go func() {
			res, err := sup.run(cmd, testNonce)
			ran <- result{res, err}
		}()
		var r result
		Eventually(ran, 5*time.Minute).Should(Receive(&r))
		gate.end()
		close(stopProbe)
		<-probed

		Expect(r.err).NotTo(HaveOccurred())
		code, reason := exitCode(r.res)
		Expect(code).To(Equal(0), "%s\n%s\n%s", reason, stderr.String(), out.String())
		Expect(out.String()).To(ContainSubstring("served"))
		Expect(out.String()).NotTo(ContainSubstring("RVM_LISTEN_"))

		// A connection may open and find nothing in the moment between the
		// guest's server stopping and the watcher's next look; it may never
		// open before the guest listens.
		states := probe.got()
		GinkgoWriter.Printf("port %s went %q\n", p, states)
		Expect(states[0]).To(Equal("closed"), "%q", states)
		served := []string{}
		for _, s := range states {
			if s != "accepts" {
				served = append(served, s)
			}
		}
		Expect(served).To(Equal([]string{"closed", "serves", "closed"}), "%q\n%s", states, logBuf.String())
		Expect(states[:slices.Index(states, "serves")]).NotTo(ContainElement("accepts"), "%q", states)
		Expect(logBuf.String()).To(Equal("the guest listens on port " + p + "; it is open in the container\n" +
			"the guest no longer listens on port " + p + "; it is closed in the container\n"))
	})
})

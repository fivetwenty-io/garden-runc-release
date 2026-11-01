//go:build linux

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("sidecars", func() {
	Describe("parseSidecars", func() {
		describe := func(json string) map[string]string {
			return map[string]string{sidecarsEnvVar: json}
		}

		It("names the variable that rep sets", func() {
			Expect(sidecarsEnvVar).To(Equal("CF_VM_SIDECARS"))
		})

		It("returns nil and no error when the variable is absent or empty", func() {
			got, err := parseSidecars(map[string]string{})
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(BeNil())

			got, err = parseSidecars(describe(""))
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(BeNil())
		})

		It("reads every field of every sidecar in order", func() {
			got, err := parseSidecars(describe(`{"version":1,"sidecars":[
				{"args":["/bin/envoy","--id","1"],"env":["A=b","C=d=e"],"unset":["X"],"log_source":"ENVOY"},
				{"args":["sleep","1"]}]}`))
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal([]vmSidecar{
				{Args: []string{"/bin/envoy", "--id", "1"}, Env: []string{"A=b", "C=d=e"}, Unset: []string{"X"}, LogSource: "ENVOY"},
				{Args: []string{"sleep", "1"}},
			}))
		})

		It("accepts a description with no sidecars", func() {
			got, err := parseSidecars(describe(`{"version":1,"sidecars":[]}`))
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(BeEmpty())
		})

		It("accepts eight sidecars and refuses nine", func() {
			side := `{"args":["x"]}`
			eight := strings.TrimSuffix(strings.Repeat(side+",", 8), ",")
			got, err := parseSidecars(describe(`{"version":1,"sidecars":[` + eight + `]}`))
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(HaveLen(8))

			_, err = parseSidecars(describe(`{"version":1,"sidecars":[` + eight + `,` + side + `]}`))
			Expect(err).To(MatchError(ContainSubstring("9 sidecars")))
		})

		DescribeTable("refuses",
			func(raw, message string) {
				got, err := parseSidecars(describe(raw))
				Expect(err).To(MatchError(ContainSubstring(message)))
				Expect(got).To(BeNil())
			},
			Entry("another version", `{"version":3,"sidecars":[{"args":["x"]}]}`, "version 3"),
			Entry("version 2 with no key", `{"version":2,"sidecars":[{"args":["x"]}]}`, "relay_key"),
			Entry("version 2 with an empty key", `{"version":2,"relay_key":"","sidecars":[{"args":["x"]}]}`, "relay_key"),
			Entry("version 2 with a short key", `{"version":2,"relay_key":"abc","sidecars":[{"args":["x"]}]}`, "relay_key"),
			Entry("version 2 with an upper-case key", `{"version":2,"relay_key":"`+strings.Repeat("A", 32)+`","sidecars":[{"args":["x"]}]}`, "relay_key"),
			Entry("no version", `{"sidecars":[{"args":["x"]}]}`, "version 0"),
			Entry("empty arguments", `{"version":1,"sidecars":[{"args":[]}]}`, "sidecar 1 in"),
			Entry("missing arguments", `{"version":1,"sidecars":[{"args":["x"]},{"env":["A=b"]}]}`, "sidecar 2 in"),
			Entry("malformed JSON", `{"version":1,`, "not valid JSON"),
			Entry("a JSON string", `"x"`, "not valid JSON"),
		)
	})

	Describe("parseSidecarsKeyed", func() {
		key := strings.Repeat("ab", 16)
		describe := func(json string) map[string]string {
			return map[string]string{sidecarsEnvVar: json}
		}

		It("reads the relay key and every sidecar of a version 2 description, in order", func() {
			got, gotKey, err := parseSidecarsKeyed(describe(`{"version":2,"relay_key":"` + key + `","sidecars":[
				{"args":["/bin/envoy"],"log_source":"ENVOY"},
				{"args":["sleep","1"]}]}`))
			Expect(err).NotTo(HaveOccurred())
			Expect(gotKey).To(Equal(key))
			Expect(got).To(Equal([]vmSidecar{
				{Args: []string{"/bin/envoy"}, LogSource: "ENVOY"},
				{Args: []string{"sleep", "1"}},
			}))
		})

		It("returns no key for a version 1 description, whatever it carries", func() {
			got, gotKey, err := parseSidecarsKeyed(describe(`{"version":1,"relay_key":"` + key + `","sidecars":[{"args":["x"]}]}`))
			Expect(err).NotTo(HaveOccurred())
			Expect(gotKey).To(BeEmpty())
			Expect(got).To(HaveLen(1))
		})

		It("returns no key and no sidecars when the variable is absent", func() {
			got, gotKey, err := parseSidecarsKeyed(map[string]string{})
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(BeNil())
			Expect(gotKey).To(BeEmpty())
		})

		It("is what parseSidecars reads, so parseSidecars accepts version 2", func() {
			got, err := parseSidecars(describe(`{"version":2,"relay_key":"` + key + `","sidecars":[{"args":["x"]}]}`))
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(HaveLen(1))
		})

		It("refuses nine sidecars in a version 2 description", func() {
			nine := strings.TrimSuffix(strings.Repeat(`{"args":["x"]},`, 9), ",")
			_, _, err := parseSidecarsKeyed(describe(`{"version":2,"relay_key":"` + key + `","sidecars":[` + nine + `]}`))
			Expect(err).To(MatchError(ContainSubstring("9 sidecars")))
		})
	})

	Describe("the relay hub wiring", func() {
		key := strings.Repeat("cd", 16)
		logger := func() *log.Logger { return log.New(GinkgoWriter, "", 0) }

		It("makes no hub without a key", func() {
			hub, err := newSidecarRelayHub(filepath.Join(GinkgoT().TempDir(), "r.sock"), "", 2, logger())
			Expect(err).NotTo(HaveOccurred())
			Expect(hub).To(BeNil())
		})

		It("makes no hub without sidecars", func() {
			hub, err := newSidecarRelayHub(filepath.Join(GinkgoT().TempDir(), "r.sock"), key, 0, logger())
			Expect(err).NotTo(HaveOccurred())
			Expect(hub).To(BeNil())
		})

		It("makes a hub that listens when there is a key and a sidecar", func() {
			path := filepath.Join(GinkgoT().TempDir(), "r.sock")
			hub, err := newSidecarRelayHub(path, key, 1, logger())
			Expect(err).NotTo(HaveOccurred())
			Expect(hub).NotTo(BeNil())
			defer hub.close()
			Expect(path).To(BeAnExistingFile())
		})

		It("leaves both callbacks nil without a hub", func() {
			logs, first := relayCallbacks(nil)
			Expect(logs).To(BeNil())
			Expect(first).To(BeNil())
		})

		It("passes the hub's methods as the callbacks with a hub", func() {
			hub, err := newSidecarRelayHub(filepath.Join(GinkgoT().TempDir(), "r.sock"), key, 1, logger())
			Expect(err).NotTo(HaveOccurred())
			defer hub.close()
			logs, first := relayCallbacks(hub)
			Expect(logs).NotTo(BeNil())
			Expect(first).NotTo(BeNil())
		})

		It("sends relay to the relay and everything else to the launch", func() {
			var logBuf strings.Builder
			Expect(dispatch([]string{"relay", "extra"}, log.New(&logBuf, "", 0))).To(Equal(1))
			Expect(logBuf.String()).To(BeEmpty(), "the relay logs to its own stderr, not to the launch's logger")

			code := dispatch([]string{"--no-such-flag"}, log.New(&logBuf, "", 0))
			Expect(code).NotTo(BeZero())
			Expect(logBuf.String()).NotTo(BeEmpty())
		})
	})

	Describe("sidecarGuestFiles", func() {
		nasty := []string{"plain", "it's", `say "hi"`, "$HOME `id` $(id)", `back\slash`, "two\nlines\n", "", "  spaced  ", "'", "a;b|c&d>e"}

		// roundTrip runs file in shell and returns what it prints, with an
		// otherwise empty environment.
		runIn := func(shell guestShell, script string, args ...string) string {
			cmd := exec.Command(shell.argv[0], append(shell.argv[1:], append([]string{"-c", script, "sh"}, args...)...)...)
			cmd.Env = []string{}
			out, err := cmd.Output()
			Expect(err).NotTo(HaveOccurred())
			return string(out)
		}

		DescribeTable("puts the launcher in front of the arguments and keeps each byte for byte through eval",
			func(shellOf func() guestShell) {
				shell := shellOf()
				argv, _, err := sidecarGuestFiles(vmSidecar{Args: nasty}, nil)
				Expect(err).NotTo(HaveOccurred())

				got := runIn(shell, `eval "set -- $1"; printf "%s\n" "$@"; echo "n=$#"`, argv)
				want := stackLauncherPath + "\n" + strings.Join(nasty, "\n") + "\nn=" + "11\n"
				Expect(got).To(Equal(want), shell.name)
				Expect("/tmp/rvm-pwned").NotTo(BeAnExistingFile())
			},
			shellEntries(""),
		)

		DescribeTable("keeps an environment value byte for byte when a shell sources it",
			func(shellOf func() guestShell) {
				shell := shellOf()
				value := "it's a \"quoted\"\nvalue with $HOME and `id`\n"
				_, env, err := sidecarGuestFiles(vmSidecar{
					Env:   []string{"PLAIN=x", "HARD=" + value, "WITH_EQ=a=b", "EMPTY="},
					Unset: []string{"GONE"},
					Args:  []string{"x"},
				}, nil)
				Expect(err).NotTo(HaveOccurred())

				path := filepath.Join(GinkgoT().TempDir(), "env")
				Expect(os.WriteFile(path, []byte(env), 0o600)).To(Succeed())
				cmd := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", `GONE=still; export GONE; . "$1"; exec /usr/bin/env -0`, "sh", path)...)
				cmd.Env = []string{}
				out, err := cmd.Output()
				Expect(err).NotTo(HaveOccurred())
				Expect(parseEnvDump(out)).To(Equal(map[string]string{
					"PLAIN": "x", "HARD": value, "WITH_EQ": "a=b", "EMPTY": "",
				}), shell.name)
				Expect("/tmp/rvm-pwned").NotTo(BeAnExistingFile())
			},
			shellEntries(""),
		)

		It("writes export lines before unset lines, in the order given", func() {
			_, env, err := sidecarGuestFiles(vmSidecar{Args: []string{"x"}, Env: []string{"B=2", "A=1"}, Unset: []string{"Z", "Y"}}, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(env).To(Equal("export B='2'\nexport A='1'\nunset Z\nunset Y\n"))
		})

		It("leaves out denied names and names that are not shell identifiers", func() {
			_, env, err := sidecarGuestFiles(vmSidecar{
				Args:  []string{"x"},
				Env:   []string{"HOME=/root", "OK=1", "spring.profiles=x", "1BAD=y", "__GARDEN_X=z", "CF_VM_SIDECARS={}", "=novalue"},
				Unset: []string{"PATH", "KEEP_OUT", "a-b"},
			}, map[string]bool{"HOME": true, "PATH": true, sidecarsEnvVar: true})
			Expect(err).NotTo(HaveOccurred())
			Expect(env).To(Equal("export OK='1'\nunset KEEP_OUT\n"))
		})

		It("refuses an entry with no =, and a NUL byte in an argument or a value", func() {
			_, _, err := sidecarGuestFiles(vmSidecar{Args: []string{"x"}, Env: []string{"NOEQUALS"}}, nil)
			Expect(err).To(HaveOccurred())
			_, _, err = sidecarGuestFiles(vmSidecar{Args: []string{"x"}, Env: []string{"A=b\x00c"}}, nil)
			Expect(err).To(MatchError(ContainSubstring("NUL")))
			_, _, err = sidecarGuestFiles(vmSidecar{Args: []string{"a\x00b"}}, nil)
			Expect(err).To(MatchError(ContainSubstring("NUL")))
		})
	})

	Describe("guestExtrasLine", func() {
		It("names each sidecar's log source, quoted, and adds nothing without sidecars or an identity", func() {
			Expect(guestExtrasLine(nil, nil)).To(BeEmpty())
			Expect(guestExtrasLine([]vmSidecar{{LogSource: "APP/PROC/WEB/SIDECAR/ONE"}}, nil)).To(Equal(`; 1 sidecar runs beside the app, with the log source "APP/PROC/WEB/SIDECAR/ONE"`))
			three := []vmSidecar{{LogSource: "A"}, {LogSource: "B\nC"}, {}}
			Expect(guestExtrasLine(three, nil)).To(Equal(`; 3 sidecars run beside the app, with the log sources "A", "B\nC", and ""`))
		})
	})
})

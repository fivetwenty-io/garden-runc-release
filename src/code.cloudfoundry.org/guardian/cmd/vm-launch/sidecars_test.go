//go:build linux

package main

import (
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
			Entry("another version", `{"version":2,"sidecars":[{"args":["x"]}]}`, "version 2"),
			Entry("no version", `{"sidecars":[{"args":["x"]}]}`, "version 0"),
			Entry("empty arguments", `{"version":1,"sidecars":[{"args":[]}]}`, "sidecar 0"),
			Entry("missing arguments", `{"version":1,"sidecars":[{"args":["x"]},{"env":["A=b"]}]}`, "sidecar 1"),
			Entry("malformed JSON", `{"version":1,`, "not valid JSON"),
			Entry("a JSON string", `"x"`, "not valid JSON"),
		)
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

		DescribeTable("keeps an argument vector byte for byte through eval",
			func(shellOf func() guestShell) {
				shell := shellOf()
				argv, _, err := sidecarGuestFiles(vmSidecar{Args: nasty}, nil)
				Expect(err).NotTo(HaveOccurred())

				got := runIn(shell, `eval "set -- $1"; printf "%s\n" "$@"; echo "n=$#"`, argv)
				want := strings.Join(nasty, "\n") + "\nn=" + "10\n"
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
})

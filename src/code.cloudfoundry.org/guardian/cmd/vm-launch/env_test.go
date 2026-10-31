//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// guestShell is a POSIX shell to run the guest's files in.
type guestShell struct {
	name string
	argv []string
}

// hostShell is /bin/sh.
func hostShell() guestShell {
	return guestShell{name: "/bin/sh", argv: []string{"/bin/sh"}}
}

// guestBusyboxShell is the guest's own busybox sh. It skips the spec when
// guestBusyboxEnv is unset, and never stands in another shell, because the
// guest's build imports and drops names differently from other builds.
func guestBusyboxShell() guestShell {
	return guestShell{name: "the guest's busybox sh", argv: []string{guestBusybox(), "sh"}}
}

// shellEntries returns one table entry for /bin/sh and one for the guest's
// busybox sh, each passing its shell function and then params. A spec calls
// the function, so the busybox entry skips on its own when the guest's
// busybox is missing.
func shellEntries(label string, params ...any) []TableEntry {
	entries := []TableEntry{}
	for _, shell := range []struct {
		name string
		of   func() guestShell
	}{{"/bin/sh", hostShell}, {"the guest's busybox sh", guestBusyboxShell}} {
		description := shell.name
		if label != "" {
			description = label + " in " + shell.name
		}
		entries = append(entries, Entry(description, append([]any{shell.of}, params...)...))
	}
	return entries
}

// shellOwnVars are the variables a shell or env sets for itself, which a
// dump of the environment leaves out.
var shellOwnVars = []string{"PWD", "OLDPWD", "SHLVL", "_", "PATH"}

// parseEnvDump parses the output of env -0.
func parseEnvDump(out []byte) map[string]string {
	env := map[string]string{}
	if len(out) == 0 {
		return env
	}
	for _, kv := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		name, value, ok := strings.Cut(kv, "=")
		Expect(ok).To(BeTrue(), kv)
		env[name] = value
	}
	for _, own := range shellOwnVars {
		delete(env, own)
	}
	return env
}

// sourceAndDumpEnv sources file in a POSIX shell (argv of the shell
// command) with an otherwise empty environment and returns the resulting
// environment, less the variables the shell sets itself.
func sourceAndDumpEnv(shell []string, file string) map[string]string {
	cmd := exec.Command(shell[0], append(shell[1:], "-c", `. "$1"; exec /usr/bin/env -0`, "sh", file)...)
	cmd.Env = []string{}
	out, err := cmd.Output()
	Expect(err).NotTo(HaveOccurred())
	return parseEnvDump(out)
}

// guestBin returns a directory holding sh for shell, the cat that the
// command line of /init reads /rvm/cmd with, and the sleep that the stop
// reader polls with, to be the whole PATH of a guest run, as /bin is in the
// guest. The guest's busybox runs cat and sleep as applets of the same
// binary; /bin/sh gets the host's.
func guestBin(shell guestShell) string {
	bin := filepath.Join(GinkgoT().TempDir(), "bin")
	Expect(os.Mkdir(bin, 0o755)).To(Succeed())
	// busybox runs as the applet its link names, as it does in the guest.
	Expect(os.Symlink(shell.argv[0], filepath.Join(bin, "sh"))).To(Succeed())
	for _, tool := range []string{"cat", "sleep"} {
		path := shell.argv[0]
		if shell.argv[0] == hostShell().argv[0] {
			var err error
			path, err = exec.LookPath(tool)
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(os.Symlink(path, filepath.Join(bin, tool))).To(Succeed())
	}
	return bin
}

// guestFiles writes envFile and the command cmd where a guest run reads
// them, and returns a replacer from the guest paths to them, the command's
// pid file included. The guest's console becomes the spec's stdout, which
// /init then opens on its own, as it opens the console in the guest.
func guestFiles(envFile, cmd string) *strings.Replacer {
	dir := GinkgoT().TempDir()
	Expect(os.WriteFile(filepath.Join(dir, "env"), []byte(envFile), 0o600)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "cmd"), []byte(cmd), 0o600)).To(Succeed())
	return strings.NewReplacer(
		"/rvm/env", filepath.Join(dir, "env"),
		"/rvm/cmd", filepath.Join(dir, "cmd"),
		guestAppPid, filepath.Join(dir, "app-pid"),
		"reboot -nf", "echo REBOOT",
		"/dev/console", "/dev/stdout",
	)
}

// exportedNames returns the names /rvm/env exports, in file order.
func exportedNames(envFile string) []string {
	var names []string
	for _, line := range strings.Split(envFile, "\n") {
		if name, ok := strings.CutPrefix(line, "export "); ok {
			name, _, _ = strings.Cut(name, "=")
			names = append(names, name)
		}
	}
	return names
}

// hostileValues are values that a careless quoting would change or run.
var hostileValues = map[string]string{
	"SINGLE_QUOTES": `it's a "quoted" value`,
	"ONLY_QUOTES":   "'''",
	"COMMAND_SUBST": "$(touch /tmp/rvm-pwned) ${HOME} $HOME",
	"BACKTICKS":     "`touch /tmp/rvm-pwned`",
	"BACKSLASHES":   `\ \\ \n \' \"`,
	"CR_LF":         "one\r\ntwo\rthree\n",
	"TRAILING_NL":   "value\n\n\n",
	"EMPTY":         "",
	"NOT_UTF8":      "\xff\xfe\x80 bytes",
	"EQUALS":        "a=b==c=",
	"BIG_64K":       strings.Repeat("0123456789abcdef", 4<<10),
	"GLOB":          "* ? [a-z] ~",
}

var _ = Describe("guest environment", func() {
	var (
		logBuf *bytes.Buffer
		logger *log.Logger
	)

	BeforeEach(func() {
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
	})

	build := func(env map[string]string) string {
		envFile, err := buildGuestEnv(env, 320, logger)
		Expect(err).NotTo(HaveOccurred())
		return envFile
	}

	Describe("lastWinsEnv", func() {
		It("keeps the last value of a name that appears twice, as runc and bash do", func() {
			env := lastWinsEnv([]string{"A=image", "B=b", "A=diego", "C=x=y", "D="}, logger)
			Expect(env).To(Equal(map[string]string{"A": "diego", "B": "b", "C": "x=y", "D": ""}))
			Expect(logBuf.String()).To(BeEmpty())
		})

		It("leaves out entries without = and counts them without repeating one", func() {
			env := lastWinsEnv([]string{"A=1", secretSentinel, "also" + secretSentinel}, logger)
			Expect(env).To(Equal(map[string]string{"A": "1"}))
			Expect(logBuf.String()).To(Equal("leaving out 2 environment entries that have no =\n"))
		})

		It("gives the volume and the guest the same VCAP_SERVICES", func() {
			volDir := GinkgoT().TempDir()
			first := `{"p-mysql":[{"credentials":{}}]}`
			last := vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}})
			env := lastWinsEnv([]string{
				"VCAP_SERVICES=" + first,
				"VCAP_APPLICATION=" + vcapApp,
				"CF_INSTANCE_INDEX=0",
				"VCAP_SERVICES=" + last,
			}, logger)

			vols, err := volumesFromEnv(lookupIn(env))
			Expect(err).NotTo(HaveOccurred())
			Expect(vols).To(HaveLen(1))
			Expect(vols[0].ContainerDir).To(Equal(volDir))

			envFile := build(env)
			Expect(sourceAndDumpEnv([]string{"/bin/sh"}, writeTempFile("env", envFile))).To(HaveKeyWithValue("VCAP_SERVICES", last))
		})
	})

	Describe("/rvm/env", func() {
		container := map[string]string{
			"PATH":                       "/usr/local/bin:/usr/bin:/bin",
			"HOME":                       "/home/vcap",
			"TMPDIR":                     "/home/vcap/tmp",
			"USER":                       "vcap",
			"PWD":                        "/home/vcap",
			"OLDPWD":                     "/",
			"DEPS_DIR":                   "/home/vcap/deps",
			"CF_INSTANCE_CERT":           "/etc/cf-instance-credentials/instance.crt",
			"CF_INSTANCE_KEY":            "/etc/cf-instance-credentials/instance.key",
			"CF_SYSTEM_CERT_PATH":        "/etc/cf-system-certificates",
			"SERVICE_BINDING_ROOT":       "/etc/cf-service-bindings",
			"VCAP_SERVICES_FILE_PATH":    "/etc/cf-service-bindings/vcap_services",
			"VCAP_PLATFORM_OPTIONS":      `{"credhub-uri":"https://credhub.service.cf.internal:8844"}`,
			"__GARDEN_VM_LAUNCH_WRAPPED": "1",
			"__GARDEN_OTHER":             "1",
			"__GARDEN_not.an.identifier": "1",
			"IFS":                        "0123456789",
			"ENV":                        "/tmp/evil",
			"CDPATH":                     "/",
			"PS1":                        "$ ",
			"PS2":                        "> ",
			"PS4":                        "+ ",
			"OPTIND":                     "9",
			"OPTARG":                     "x",
			"PPID":                       "1",
			"LINENO":                     "1",
			"RANDOM":                     "4",
			"SECONDS":                    "0",
			"HISTFILE":                   "/tmp/h",
			"SHLVL":                      "7",
			"_":                          "/usr/bin/env",
			"PORT":                       "8080",
			"CF_INSTANCE_GUID":           "g",
			"CF_INSTANCE_INDEX":          "0",
			"CF_INSTANCE_IP":             "10.0.0.5",
			"CF_INSTANCE_INTERNAL_IP":    "10.255.0.5",
			"CF_INSTANCE_PORT":           "",
			"INSTANCE_GUID":              "i",
			"INSTANCE_INDEX":             "0",
			"LANG":                       "en_US.UTF-8",
			"CF_EXECUTION_BACKEND":       "vm-qemu",
			"CREDHUB_SKIP_INTERPOLATION": "true",
			"MY_SETTING":                 "on",
			"_leading_underscore":        "ok",
		}
		passed := []string{
			"CDPATH", "CF_EXECUTION_BACKEND", "CF_INSTANCE_GUID", "CF_INSTANCE_INDEX", "CF_INSTANCE_INTERNAL_IP", "CF_INSTANCE_IP", "CF_INSTANCE_PORT",
			"CREDHUB_SKIP_INTERPOLATION", "ENV", "HISTFILE", "INSTANCE_GUID", "INSTANCE_INDEX", "LANG", "LINENO", "MY_SETTING", "OPTARG", "PORT",
			"PS1", "PS2", "PS4", "RANDOM", "SECONDS", "_", "_leading_underscore",
		}

		It("exports every identifier variable except the denylist and the shell's own, sorted, once each, and names the shell's own", func() {
			envFile := build(container)
			Expect(exportedNames(envFile)).To(Equal(passed))
			Expect(sort.StringsAreSorted(exportedNames(envFile))).To(BeTrue())
			Expect(logBuf.String()).To(Equal("leaving out 4 environment variables that the guest shell sets for itself: IFS, OPTIND, PPID, SHLVL\n"))
		})

		It("leaves out every shell-owned name and never logs its value", func() {
			env := map[string]string{"PLAIN": "1"}
			for name := range shellOwnedNames {
				env[name] = secretSentinel
			}
			Expect(build(env)).To(Equal("export PLAIN='1'\n"))
			Expect(logBuf.String()).To(Equal("leaving out 4 environment variables that the guest shell sets for itself: IFS, OPTIND, PPID, SHLVL\n"))
		})

		It("never exports container paths, identities, platform options, or Garden's markers", func() {
			envFile := build(container)
			for _, name := range []string{"PATH", "HOME", "TMPDIR", "USER", "PWD", "OLDPWD", "CF_INSTANCE_CERT", "CF_INSTANCE_KEY", "CF_SYSTEM_CERT_PATH",
				"VCAP_PLATFORM_OPTIONS", "SERVICE_BINDING_ROOT", "VCAP_SERVICES_FILE_PATH", "DEPS_DIR"} {
				Expect(exportedNames(envFile)).NotTo(ContainElement(name))
			}
			for _, text := range []string{"__GARDEN_", "credhub-uri"} {
				Expect(envFile).NotTo(ContainSubstring(text))
			}
		})

		It("keeps an empty value set", func() {
			envFile := build(map[string]string{"CF_INSTANCE_PORT": ""})
			Expect(envFile).To(Equal("export CF_INSTANCE_PORT=''\n"))
			Expect(sourceAndDumpEnv([]string{"/bin/sh"}, writeTempFile("env", envFile))).To(Equal(map[string]string{"CF_INSTANCE_PORT": ""}))
		})

		DescribeTable("keeps every value byte for byte when a shell sources it",
			func(shellOf func() guestShell) {
				shell := shellOf()
				envFile := build(hostileValues)
				path := writeTempFile("env", envFile)
				Expect(sourceAndDumpEnv(shell.argv, path)).To(Equal(hostileValues), shell.name)
				Expect("/tmp/rvm-pwned").NotTo(BeAnExistingFile())
			},
			shellEntries(""),
		)
	})

	Describe("names that are not shell identifiers", func() {
		odd := map[string]string{
			"spring.profiles.active": secretSentinel,
			"my-var":                 secretSentinel,
			"-starts-with-a-dash":    secretSentinel,
			"BASH_FUNC_x%%":          "() {  echo " + secretSentinel + "\n}",
		}

		It("leaves them out with one line that names them and never a value", func() {
			env := map[string]string{"PLAIN": "1"}
			for name, value := range odd {
				env[name] = value
			}
			Expect(build(env)).To(Equal("export PLAIN='1'\n"))
			Expect(logBuf.String()).To(Equal("leaving out 4 environment variables whose names are not shell identifiers, which the guest shell drops: " +
				`"-starts-with-a-dash", "BASH_FUNC_x%%", "my-var", "spring.profiles.active"` + "\n"))
		})

		It("names the first 20 in the log line and counts the rest", func() {
			env := map[string]string{}
			for i := 0; i < 25; i++ {
				env[fmt.Sprintf("odd.%02d", i)] = secretSentinel
			}
			Expect(build(env)).To(BeEmpty())
			listed := []string{}
			for i := 0; i < 20; i++ {
				listed = append(listed, fmt.Sprintf(`"odd.%02d"`, i))
			}
			Expect(logBuf.String()).To(Equal("leaving out 25 environment variables whose names are not shell identifiers, which the guest shell drops: " +
				strings.Join(listed, ", ") + ", and 5 more\n"))
		})

		It("lists exactly 20 names without a count", func() {
			env := map[string]string{}
			for i := 0; i < 20; i++ {
				env[fmt.Sprintf("odd.%02d", i)] = "x"
			}
			Expect(build(env)).To(BeEmpty())
			Expect(logBuf.String()).To(HaveSuffix(`"odd.19"` + "\n"))
		})

		It("cuts a long name in the log line", func() {
			Expect(build(map[string]string{strings.Repeat("a.", 200): "x"})).To(BeEmpty())
			Expect(logBuf.String()).To(ContainSubstring(`"` + strings.Repeat("a.", maxLoggedValueLen/2) + `"...` + "\n"))
		})

		It("never counts them toward the size limits", func() {
			Expect(build(map[string]string{"big.name": strings.Repeat("x", maxGuestEnvBytes*2)})).To(BeEmpty())
		})

		It("leaves out an entry with an empty name and says so without its value", func() {
			Expect(build(map[string]string{"": secretSentinel, "A": "1"})).To(Equal("export A='1'\n"))
			Expect(logBuf.String()).To(Equal("leaving out an environment entry with an empty name\n"))
		})
	})

	Describe("the launcher's VCAP_APPLICATION rewrite", func() {
		decode := func(s string) map[string]any {
			var m map[string]any
			Expect(json.Unmarshal([]byte(s), &m)).To(Succeed())
			return m
		}
		ccApp := `{"application_id":"` + testAppID + `","application_name":"app","name":"app","space_name":"s","organization_name":"o",` +
			`"uris":["app.example.com"],"application_uris":["app.example.com"],"cf_api":"https://api.example.com",` +
			`"limits":{"disk":1024,"fds":16384,"mem":512},"process_type":"web","version":"v","application_version":"v",` +
			`"host":"10.0.0.1","port":61000,"instance_index":9,"instance_id":"old"}`

		It("munges VCAP_APPLICATION as the launcher does", func() {
			// The launcher's own case: PORT, INSTANCE_GUID, and INSTANCE_INDEX
			// over {"foo":1}.
			out, ok := rewriteVCAPApplication(`{"foo":1}`, envMap(map[string]string{
				"PORT": "8080", "INSTANCE_GUID": "some-instance-guid", "INSTANCE_INDEX": "123",
			}), 320)
			Expect(ok).To(BeTrue())
			Expect(decode(out)).To(Equal(map[string]any{
				"host": "0.0.0.0", "port": float64(8080), "instance_index": float64(123), "instance_id": "some-instance-guid", "foo": float64(1),
			}))
		})

		It("sets host, instance_id, port, instance_index, and limits.mem, and leaves every other field equal", func() {
			out, ok := rewriteVCAPApplication(ccApp, envMap(map[string]string{"PORT": "8080", "INSTANCE_GUID": "guid", "INSTANCE_INDEX": "2"}), 320)
			Expect(ok).To(BeTrue())
			want := decode(ccApp)
			want["host"] = "0.0.0.0"
			want["instance_id"] = "guid"
			want["port"] = float64(8080)
			want["instance_index"] = float64(2)
			want["limits"] = map[string]any{"disk": float64(1024), "fds": float64(16384), "mem": float64(320)}
			Expect(decode(out)).To(Equal(want))
		})

		It("encodes the result as the launcher does, with sorted keys", func() {
			out, ok := rewriteVCAPApplication(`{"z":1,"a":{"y":2,"b":3}}`, envMap(map[string]string{}), 320)
			Expect(ok).To(BeTrue())
			Expect(out).To(Equal(`{"a":{"b":3,"y":2},"host":"0.0.0.0","instance_id":"","z":1}`))
		})

		It("sets instance_id to the empty string without INSTANCE_GUID, and adds no port for a task", func() {
			out, ok := rewriteVCAPApplication(ccApp, envMap(map[string]string{"INSTANCE_INDEX": "0"}), 320)
			Expect(ok).To(BeTrue())
			got := decode(out)
			Expect(got).To(HaveKeyWithValue("instance_id", ""))
			Expect(got).To(HaveKeyWithValue("port", float64(61000)), "the port CC set stays")

			out, ok = rewriteVCAPApplication(`{"name":"task"}`, envMap(map[string]string{}), 320)
			Expect(ok).To(BeTrue())
			Expect(decode(out)).NotTo(HaveKey("port"))
			Expect(decode(out)).NotTo(HaveKey("instance_index"))
		})

		It("leaves port and instance_index alone when PORT and INSTANCE_INDEX do not parse", func() {
			out, ok := rewriteVCAPApplication(`{}`, envMap(map[string]string{"PORT": "eighty", "INSTANCE_INDEX": "1.5"}), 320)
			Expect(ok).To(BeTrue())
			Expect(decode(out)).To(Equal(map[string]any{"host": "0.0.0.0", "instance_id": ""}))
		})

		DescribeTable("leaves limits unchanged when it cannot hold the guest size",
			func(app string) {
				out, ok := rewriteVCAPApplication(app, envMap(map[string]string{}), 320)
				Expect(ok).To(BeTrue())
				want := decode(app)
				want["host"] = "0.0.0.0"
				want["instance_id"] = ""
				Expect(decode(out)).To(Equal(want))
			},
			Entry("no limits", `{"name":"app"}`),
			Entry("limits that is not an object", `{"limits":"512"}`),
			Entry("limits that is null", `{"limits":null}`),
			Entry("limits without mem", `{"limits":{"disk":1024}}`),
		)

		DescribeTable("passes a value that is not a JSON object through unchanged",
			func(app string) {
				out, ok := rewriteVCAPApplication(app, envMap(map[string]string{"PORT": "8080"}), 320)
				Expect(ok).To(BeFalse())
				Expect(out).To(Equal(app))
			},
			Entry("invalid JSON", `{"name":"`+secretSentinel),
			Entry("null", `null`),
			Entry("an array", `[1,2]`),
			Entry("a string", `"app"`),
			Entry("empty", ``),
		)

		It("logs one line that names VCAP_APPLICATION and never its value", func() {
			bad := `{"name":"` + secretSentinel
			envFile := build(map[string]string{"VCAP_APPLICATION": bad})
			Expect(logBuf.String()).To(Equal("VCAP_APPLICATION is not a JSON object; the guest gets it unchanged\n"))
			Expect(sourceAndDumpEnv([]string{"/bin/sh"}, writeTempFile("env", envFile))).To(HaveKeyWithValue("VCAP_APPLICATION", bad))
		})

		It("puts the rewritten value in /rvm/env", func() {
			envFile := build(map[string]string{"VCAP_APPLICATION": ccApp, "PORT": "8080"})
			got := sourceAndDumpEnv([]string{"/bin/sh"}, writeTempFile("env", envFile))
			Expect(decode(got["VCAP_APPLICATION"])["limits"]).To(HaveKeyWithValue("mem", float64(320)))
			Expect(decode(got["VCAP_APPLICATION"])).To(HaveKeyWithValue("port", float64(8080)))
		})
	})

	Describe("limits.disk", func() {
		diskOf := func(vcap string) (int64, error) {
			return diskLimitMiB(envMap(map[string]string{"VCAP_APPLICATION": vcap}))
		}
		ccLimits := `{"application_id":"` + testAppID + `","application_name":"app","name":"app","space_name":"s",` +
			`"limits":{"disk":1024,"fds":16384,"mem":512},"process_type":"web","host":"10.0.0.1","port":61000,"instance_index":9}`

		DescribeTable("is the app's disk quota in MiB",
			func(vcap string, want int64) {
				got, err := diskOf(vcap)
				Expect(err).NotTo(HaveOccurred())
				Expect(got).To(Equal(want))
			},
			Entry("next to the other limits", `{"limits":{"disk":1024,"fds":16384,"mem":512},"name":"app"}`, int64(1024)),
			Entry("first among them", `{"limits":{"disk":2048,"mem":512}}`, int64(2048)),
			Entry("the only limit", `{"limits":{"disk":1}}`, int64(1)),
			Entry("a quota of many TiB", `{"limits":{"disk":9007199254740993}}`, int64(9007199254740993)),
			Entry("after an unrelated disk key", `{"disk":7,"limits":{"disk":300}}`, int64(300)),
			Entry("with white space", " {\n \"limits\" : { \"disk\" : 640 } }\n", int64(640)),
			Entry("the cloud controller's own shape", ccLimits, int64(1024)),
		)

		DescribeTable("is reported as missing, apart from a real quota",
			func(set bool, vcap string) {
				env := map[string]string{}
				if set {
					env["VCAP_APPLICATION"] = vcap
				}
				got, err := diskLimitMiB(envMap(env))
				Expect(got).To(BeZero())
				Expect(err).To(HaveOccurred())
			},
			Entry("VCAP_APPLICATION unset", false, ""),
			Entry("VCAP_APPLICATION empty", true, ""),
			Entry("no limits", true, `{"name":"app"}`),
			Entry("a null limits", true, `{"limits":null}`),
			Entry("an empty limits", true, `{"limits":{}}`),
			Entry("limits without disk", true, `{"limits":{"mem":512}}`),
			Entry("a null disk", true, `{"limits":{"disk":null}}`),
			Entry("JSON null", true, `null`),
			Entry("limits that is not an object", true, `{"limits":"1024"}`),
			Entry("limits that is a list", true, `{"limits":[1024]}`),
			Entry("VCAP_APPLICATION that is not an object", true, `[{"limits":{"disk":1024}}]`),
			Entry("VCAP_APPLICATION that is not JSON", true, `disk=1024`),
			Entry("a disk quota in a string", true, `{"limits":{"disk":"1024"}}`),
			Entry("a boolean", true, `{"limits":{"disk":true}}`),
			Entry("zero", true, `{"limits":{"disk":0}}`),
			Entry("a negative quota", true, `{"limits":{"disk":-1024}}`),
			Entry("a fraction", true, `{"limits":{"disk":1024.5}}`),
			Entry("a whole number written as a float", true, `{"limits":{"disk":1024.0}}`),
			Entry("an exponent", true, `{"limits":{"disk":1e3}}`),
			Entry("a list", true, `{"limits":{"disk":[1024]}}`),
			Entry("an object", true, `{"limits":{"disk":{"mb":1024}}}`),
			Entry("a number too large to hold", true, `{"limits":{"disk":99999999999999999999}}`),
		)

		It("says why, in a message that never holds a value", func() {
			for vcap, want := range map[string]string{
				`{"limits":{"disk":"sekret-value"}}`:    "VCAP_APPLICATION limits.disk is not a positive whole number of MiB",
				`{"limits":"sekret-value"}`:             "VCAP_APPLICATION limits is not a JSON object",
				`sekret-value`:                          "VCAP_APPLICATION is not a JSON object",
				`{"limits":{"mem":1},"x":"sekret"}`:     "VCAP_APPLICATION has no limits.disk",
				`{"limits":{"disk":null},"x":"sekret"}`: "VCAP_APPLICATION has no limits.disk",
				`{"x":"sekret"}`:                        "VCAP_APPLICATION has no limits.disk",
			} {
				_, err := diskOf(vcap)
				Expect(err).To(MatchError(want), vcap)
			}
			_, err := diskLimitMiB(envMap(nil))
			Expect(err).To(MatchError("VCAP_APPLICATION is not set"))
		})

		It("survives the launcher's rewrite, which changes limits.mem alone", func() {
			env := map[string]string{"VCAP_APPLICATION": `{"limits":{"disk":4096,"mem":512}}`}
			rewritten, ok := rewriteVCAPApplication(env["VCAP_APPLICATION"], envMap(env), 320)
			Expect(ok).To(BeTrue())
			got, err := diskOf(rewritten)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(int64(4096)))
		})
	})

	Describe("MEMORY_LIMIT", func() {
		It("becomes the guest size when it is set", func() {
			Expect(build(map[string]string{"MEMORY_LIMIT": "512m"})).To(Equal("export MEMORY_LIMIT='320m'\n"))
			Expect(build(map[string]string{"MEMORY_LIMIT": "nonsense"})).To(Equal("export MEMORY_LIMIT='320m'\n"))
		})

		It("is not added when it is unset", func() {
			Expect(build(map[string]string{"PORT": "8080"})).To(Equal("export PORT='8080'\n"))
		})
	})

	Describe("DATABASE_URL", func() {
		services := func(uris ...string) string {
			var bindings []string
			for _, u := range uris {
				bindings = append(bindings, `{"credentials":{"uri":"`+u+`"}}`)
			}
			return `{"db":[` + strings.Join(bindings, ",") + `]}`
		}

		DescribeTable("follows the launcher's scheme table",
			func(vcap, want string) {
				Expect(databaseURL(vcap)).To(Equal(want))
			},
			Entry("mysql becomes mysql2", services("mysql://username:password@host/db"), "mysql2://username:password@host/db"),
			Entry("mysql2 stays", services("mysql2://username:password@host/db"), "mysql2://username:password@host/db"),
			Entry("postgres stays", services("postgres://username:password@host/db"), "postgres://username:password@host/db"),
			Entry("postgresql becomes postgres", services("postgresql://username:password@host/db"), "postgres://username:password@host/db"),
			Entry("the first of two databases", services("postgres://username:password@host/db1", "postgres://username:password@host/db2"), "postgres://username:password@host/db1"),
			Entry("an invalid uri", services(`postgresql://invalid:password@host/%a`), ""),
			Entry("an invalid uri before a valid one", services(`postgresql://invalid:password@host/%a`, "mysql://u:p@h/d"), "mysql2://u:p@h/d"),
			Entry("a service that is not a database", services("sendgrid://foo:bar@host/db"), ""),
			Entry("no services", `{}`, ""),
			Entry("bindings without a uri", `{"eg":[{}],"def":[{"other":"data"}],"ghi":[{"credentials":{"other":"data"}}]}`, ""),
			Entry("VCAP_SERVICES that does not decode", `{"db":`, ""),
			Entry("labels in sorted order", `{"zz":[{"credentials":{"uri":"postgres://z/db"}}],"aa":[{"credentials":{"uri":"mysql://a/db"}}]}`, "mysql2://a/db"),
		)

		It("replaces a DATABASE_URL that is already set, and keeps it when nothing replaces it", func() {
			envFile := build(map[string]string{"VCAP_SERVICES": services("postgresql://u:p@h/d"), "DATABASE_URL": "original content"})
			Expect(sourceAndDumpEnv([]string{"/bin/sh"}, writeTempFile("env", envFile))).To(HaveKeyWithValue("DATABASE_URL", "postgres://u:p@h/d"))

			envFile = build(map[string]string{"VCAP_SERVICES": services("sendgrid://h"), "DATABASE_URL": "original content"})
			Expect(sourceAndDumpEnv([]string{"/bin/sh"}, writeTempFile("env", envFile))).To(HaveKeyWithValue("DATABASE_URL", "original content"))
		})

		It("is not set without VCAP_SERVICES", func() {
			Expect(build(map[string]string{"PORT": "8080"})).NotTo(ContainSubstring("DATABASE_URL"))
		})
	})

	Describe("size limits", func() {
		It("takes an entry of 131071 bytes and rejects one of 131072, naming it and its size only", func() {
			_, err := buildGuestEnv(map[string]string{"BIG": strings.Repeat("x", maxEnvEntryBytes-4)}, 320, logger)
			Expect(err).NotTo(HaveOccurred())

			_, err = buildGuestEnv(map[string]string{"BIG": secretSentinel + strings.Repeat("x", maxEnvEntryBytes-3-len(secretSentinel))}, 320, logger)
			Expect(err).To(MatchError("the environment variable BIG is 131072 bytes as NAME=value, over the 131071 bytes one guest variable may have"))
		})

		// fill returns variables of name prefix that bring /rvm/env to exactly
		// total bytes, the first being the largest.
		fill := func(prefix string, total int) map[string]string {
			env := map[string]string{}
			for i := 0; i < 8; i++ {
				env[prefix+strings.Repeat("0", i+1)] = strings.Repeat("x", 120000)
			}
			env[prefix+"0"] = strings.Repeat("x", 120500)
			env[prefix+"pad"] = "x"
			env[prefix+"pad"] = strings.Repeat("x", 1+total-len(build(env)))
			return env
		}

		It("takes a guest environment of exactly 1 MiB and rejects one byte more, naming the largest variable", func() {
			Expect(build(fill("V", maxGuestEnvBytes))).To(HaveLen(maxGuestEnvBytes))

			_, err := buildGuestEnv(fill("V", maxGuestEnvBytes+1), 320, logger)
			Expect(err).To(MatchError("the guest environment is 1048577 bytes, over the 1048576 bytes a guest may have; the largest variable is V0 at 120503 bytes as NAME=value"))
		})

		It("checks the value after the rewrites", func() {
			// MEMORY_LIMIT is rewritten to the guest size, so a long value of
			// its own never counts.
			_, err := buildGuestEnv(map[string]string{"MEMORY_LIMIT": strings.Repeat("9", 200000)}, 320, logger)
			Expect(err).NotTo(HaveOccurred())
		})

		It("rejects a value holding a NUL byte without repeating it", func() {
			_, err := buildGuestEnv(map[string]string{"VCAP_SERVICES": `{"a":"` + secretSentinel + "\x00" + `"}`}, 320, logger)
			Expect(err).To(MatchError("the environment variable VCAP_SERVICES holds a NUL byte, which no process environment can carry"))
		})
	})

	It("never logs a value", func() {
		for _, env := range []map[string]string{
			{"VCAP_APPLICATION": "x" + secretSentinel},
			{"": secretSentinel},
			{"big.name": secretSentinel},
			{"BIG": strings.Repeat(secretSentinel, maxEnvEntryBytes/len(secretSentinel)+1)},
			{"NUL": secretSentinel + "\x00"},
			{"VCAP_SERVICES": `{"db":[{"credentials":{"uri":"postgres://u:` + secretSentinel + `@h/d"}}]}`},
		} {
			_, err := buildGuestEnv(env, 320, logger)
			if err != nil {
				Expect(err.Error()).NotTo(ContainSubstring(secretSentinel[len(secretSentinel)-12:]))
			}
		}
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel[len(secretSentinel)-12:]))
	})

})

var _ = Describe("the guest command line of /init", func() {
	// initTail is /init from the environment checks on, with the guest paths
	// replaced and reboot turned into a line the spec can see. The limits
	// /rvm/limits would set are the shell's own, which any user may set.
	// The stop reader reads /dev/null, so it ends at once without a request
	// (see "the stop reader" for its runs).
	initTail := func(paths *strings.Replacer, volume bool) string {
		script := initScript(testNonce, volume)
		tail := script[strings.Index(script, guestEnvChecks):]
		Expect(strings.Count(tail, guestStopReader(testNonce))).To(Equal(1))
		tail = strings.Replace(tail, guestStopReader(testNonce), stopReaderAt("/dev/null", filepath.Join(GinkgoT().TempDir(), "oom_score_adj")), 1)
		if volume {
			tail = strings.Replace(tail, guestVolumeSetup, "", 1)
			tail = strings.Replace(tail, guestVolumeTeardown, "", 1)
		}
		limits := "RVM_NOFILE_SOFT=$(ulimit -S -n)\nRVM_NOFILE_HARD=$(ulimit -H -n)\n"
		return paths.Replace(guestFailFunc + limits + tail)
	}

	// runInit runs the tail of /init and returns its console output and its
	// exit status: 0 after the command ran, and 1 when rvm_fail stopped it.
	runInit := func(shell guestShell, envFile, cmd string, volume bool) (string, int) {
		paths := guestFiles(envFile, cmd)
		c := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", initTail(paths, volume))...)
		c.Env = []string{"PATH=" + guestBin(shell)}
		out, err := c.CombinedOutput()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return string(out), exitErr.ExitCode()
		}
		Expect(err).NotTo(HaveOccurred(), "%s: %s", shell.name, out)
		return string(out), 0
	}

	// statusOf reads the exit line as vm-launch does.
	statusOf := func(out string) (int, bool) {
		var sink bytes.Buffer
		f := newSerialFilter(&sink, testNonce)
		_, _ = f.Write([]byte(out))
		f.finish()
		return f.status, f.markerFound()
	}

	DescribeTable("reports the command's status, and keeps the guest environment out of /init's own steps",
		func(shellOf func() guestShell) {
			shell := shellOf()
			for _, volume := range []bool{false, true} {
				// /rvm/env never sets IFS, but if it did, only the command's
				// subshell would see it, and the unquoted status in the exit
				// line would still parse. A shell does not take IFS from its
				// environment, so the command cannot check it.
				out, code := runInit(shell, "IFS='0123456789'\nexport A='1'\n", `[ "$A" = 1 ] || exit 1; exit 37`, volume)
				Expect(code).To(Equal(0), "%s: %s", shell.name, out)
				Expect(out).To(HavePrefix("RVM_START_" + testNonce + "\n"))
				Expect(out).To(HaveSuffix("REBOOT\n"))
				Expect(out).NotTo(ContainSubstring("vm-launch guest setup"))
				status, found := statusOf(out)
				Expect(found).To(BeTrue(), "%s: %s", shell.name, out)
				Expect(status).To(Equal(37), "%s volume=%v", shell.name, volume)
			}
		},
		shellEntries(""),
	)

	// runCommandEnv runs the tail of /init in shell with envFile as /rvm/env
	// and /usr/bin/env -0 as the command, and returns what env printed.
	runCommandEnv := func(shell guestShell, envFile string) []byte {
		dump := filepath.Join(GinkgoT().TempDir(), "dump")
		out, code := runInit(shell, envFile, "/usr/bin/env -0 > "+shellQuote(dump)+"\nexit 0\n", false)
		Expect(code).To(Equal(0), "%s: %s", shell.name, out)
		status, found := statusOf(out)
		Expect(found).To(BeTrue(), "%s: %s", shell.name, out)
		Expect(status).To(Equal(0), "%s: %s", shell.name, out)
		raw, err := os.ReadFile(dump)
		Expect(err).NotTo(HaveOccurred())
		return raw
	}

	DescribeTable("passes the real files of a hostile environment through to the command",
		func(shellOf func() guestShell) {
			shell := shellOf()
			envFile, err := buildGuestEnv(hostileValues, 320, log.New(GinkgoWriter, "", 0))
			Expect(err).NotTo(HaveOccurred())
			Expect(parseEnvDump(runCommandEnv(shell, envFile))).To(Equal(hostileValues), shell.name)
			Expect("/tmp/rvm-pwned").NotTo(BeAnExistingFile())
		},
		shellEntries(""),
	)

	// The spec exports each name a shell might own from /rvm/env, with a
	// value that no shell computes for itself. The guest's busybox sh must
	// replace exactly the names in shellOwnedNames and pass every other one
	// to the command unchanged.
	It("replaces exactly the shell-owned names in the guest's busybox sh, and passes every other shell name through", func() {
		shell := guestBusyboxShell()
		const value = "99999"
		names := []string{"CDPATH", "ENV", "EPOCHREALTIME", "EPOCHSECONDS", "HISTFILE", "IFS", "LINENO", "OPTARG", "OPTIND",
			"PPID", "PS1", "PS2", "PS4", "RANDOM", "SECONDS", "SHLVL", "_"}
		for name := range shellOwnedNames {
			Expect(names).To(ContainElement(name))
		}
		var envFile strings.Builder
		for _, name := range names {
			envFile.WriteString("export " + name + "=" + shellQuote(value) + "\n")
		}
		got := map[string]string{}
		for _, kv := range strings.Split(strings.TrimSuffix(string(runCommandEnv(shell, envFile.String())), "\x00"), "\x00") {
			name, v, _ := strings.Cut(kv, "=")
			got[name] = v
		}
		replaced := []string{}
		for _, name := range names {
			if v, ok := got[name]; !ok || v != value {
				replaced = append(replaced, name)
			}
		}
		owned := []string{}
		for name := range shellOwnedNames {
			owned = append(owned, name)
		}
		sort.Strings(owned)
		Expect(replaced).To(Equal(owned))
	})

	DescribeTable("fails a broken /rvm/env as a setup step, before the start tag",
		func(shellOf func() guestShell, envFile, step string) {
			shell := shellOf()
			out, code := runInit(shell, envFile, "exit 0", false)
			Expect(code).To(Equal(1), "%s: %s", shell.name, out)
			// The guest paths in the step are the spec's temporary files.
			Expect(out).To(MatchRegexp(`vm-launch guest setup: `+step+`\nREBOOT\n$`), shell.name)
			Expect(out).NotTo(ContainSubstring("RVM_START_"), shell.name)
		},
		shellEntries("/rvm/env with a syntax error", "export A='unterminated\n", `reading \S+/env failed`),
		shellEntries("/rvm/env that fails", "export A='1'\nfalse\n", `reading \S+/env failed`),
	)
})

var _ = Describe("run with the full guest environment", func() {
	var (
		art     string
		tmp     string
		scratch string
		logBuf  *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		scratch = GinkgoT().TempDir()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		logBuf = &bytes.Buffer{}
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	It("puts the launcher's environment in the initramfs and nowhere else", func() {
		GinkgoT().Setenv("MEMORY_LIMIT", "512m")
		GinkgoT().Setenv("VCAP_APPLICATION", `{"application_id":"`+testAppID+`","name":"`+secretSentinel+`","limits":{"mem":512}}`)
		GinkgoT().Setenv("VCAP_SERVICES", `{"db":[{"credentials":{"uri":"postgresql://u:`+secretSentinel+`@h/d"}}]}`)
		GinkgoT().Setenv("VCAP_PLATFORM_OPTIONS", `{}`)
		GinkgoT().Setenv("CF_INSTANCE_KEY", "/etc/cf-instance-credentials/instance.key")
		GinkgoT().Setenv("spring.profiles.active", secretSentinel)
		GinkgoT().Setenv("__GARDEN_VM_LAUNCH_WRAPPED", "1")

		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			hv := "qemu/ld-linux-x86-64.so.2"
			if kind == backend.VMFirecracker {
				hv = "firecracker/firecracker"
			}
			initrdCopy := filepath.Join(scratch, string(kind)+".initrd")
			writeFakeHypervisor(filepath.Join(art, hv), `cat "$initrd" > `+shellQuote(initrdCopy)+`
gzip -dc "$initrd" | grep -a -q -F `+shellQuote(secretSentinel)+` || { echo "no sentinel in the initramfs" >&2; exit 1; }
! grep -r -q -F `+shellQuote(secretSentinel)+` `+shellQuote(tmp)+` || { echo "sentinel under TMPDIR" >&2; exit 1; }
! env | grep -q -F `+shellQuote(secretSentinel)+` || { echo "sentinel in the hypervisor environment" >&2; exit 1; }
! printf '%s\n' "$@" | grep -q -F `+shellQuote(secretSentinel)+` || { echo "sentinel in the hypervisor argv" >&2; exit 1; }
`)
			Expect(runVM(kind)).To(Equal(0), logBuf.String())
			Expect(os.ReadDir(tmp)).To(BeEmpty())

			raw, err := os.ReadFile(initrdCopy)
			Expect(err).NotTo(HaveOccurred())
			_, byName := archiveEntries(raw)
			Expect(byName["rvm/env"].mode).To(Equal(uint32(0o100600)))
			envFile := string(byName["rvm/env"].data)

			envPath := filepath.Join(scratch, string(kind)+".env")
			Expect(os.WriteFile(envPath, []byte(envFile), 0o600)).To(Succeed())
			got := sourceAndDumpEnv([]string{"/bin/sh"}, envPath)
			Expect(got).To(HaveKeyWithValue("MEMORY_LIMIT", "320m"))
			Expect(got).To(HaveKeyWithValue("DATABASE_URL", "postgres://u:"+secretSentinel+"@h/d"))
			Expect(got["VCAP_APPLICATION"]).To(ContainSubstring(`"limits":{"mem":320}`))
			Expect(got["VCAP_APPLICATION"]).To(ContainSubstring(`"host":"0.0.0.0"`))
			Expect(got).To(HaveKey("VCAP_SERVICES"))
			for _, name := range []string{"PATH", "HOME", "TMPDIR", "USER", "CF_INSTANCE_KEY", "VCAP_PLATFORM_OPTIONS", "__GARDEN_VM_LAUNCH_WRAPPED"} {
				Expect(got).NotTo(HaveKey(name), "%s %s", kind, name)
			}
			Expect(got).NotTo(HaveKey("spring.profiles.active"))
			Expect(logBuf.String()).To(ContainSubstring(`which the guest shell drops: "spring.profiles.active"`))
			Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
		}
	})

	It("exits 125 for an entry over 128 KiB before it creates anything, naming only the variable and its size", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		GinkgoT().Setenv("BIG", secretSentinel+strings.Repeat("x", maxEnvEntryBytes-3-len(secretSentinel)))
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("the environment variable BIG is 131072 bytes as NAME=value"))
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("exits 125 for an environment over 1 MiB before it creates anything", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		for i := 0; i < 9; i++ {
			GinkgoT().Setenv("FILL"+strings.Repeat("0", i+1), secretSentinel+strings.Repeat("x", 120000))
		}
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(MatchRegexp(`the guest environment is \d+ bytes, over the 1048576 bytes a guest may have; the largest variable is FILL000000000 at 120044 bytes as NAME=value`))
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})
})

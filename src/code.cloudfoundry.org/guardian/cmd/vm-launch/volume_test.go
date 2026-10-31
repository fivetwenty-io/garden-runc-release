//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// secretSentinel stands for the credentials VCAP_SERVICES carries. No error
// line may repeat it.
const secretSentinel = "SENTINEL-s3cr3t-0f-the-binding"

// vcapWith returns VCAP_SERVICES JSON with one binding per label, each with
// the given volume mounts and a credentials block holding secretSentinel.
func vcapWith(labelMounts map[string][]string) string {
	var labels []string
	for label, mounts := range labelMounts {
		labels = append(labels, `"`+label+`":[{"name":"b-`+label+`","credentials":{"password":"`+secretSentinel+`"},"volume_mounts":[`+strings.Join(mounts, ",")+`]}]`)
	}
	return "{" + strings.Join(labels, ",") + "}"
}

// testAppID is a valid application_id, and vcapApp the VCAP_APPLICATION
// that carries it.
const (
	testAppID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	vcapApp   = `{"application_id":"` + testAppID + `","process_type":"web","name":"app"}`
)

func mountJSON(dir, mode string) string {
	return `{"container_dir":"` + dir + `","mode":"` + mode + `","device_type":"shared"}`
}

var _ = Describe("volumesFromEnv", func() {
	lookup := func(vars map[string]string) func(string) (string, bool) { return envMap(vars) }

	It("returns no volume without VCAP_SERVICES", func() {
		vol, err := volumesFromEnv(lookup(map[string]string{"CF_INSTANCE_INDEX": "not checked"}))
		Expect(err).NotTo(HaveOccurred())
		Expect(vol).To(BeNil())
	})

	It("returns no volume when no binding has volume mounts, without checking CF_INSTANCE_INDEX", func() {
		for _, vcap := range []string{
			`{}`,
			`null`,
			`{"p-mysql":[]}`,
			`{"p-mysql":[{"name":"db","credentials":{"password":"` + secretSentinel + `"}}]}`,
			`{"juicefs":[{"name":"jfs","volume_mounts":[]}]}`,
			`{"juicefs":[{"name":"jfs","volume_mounts":null}]}`,
		} {
			vol, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "CF_INSTANCE_INDEX": "01"}))
			Expect(err).NotTo(HaveOccurred(), vcap)
			Expect(vol).To(BeNil(), vcap)
		}
	})

	It("fails closed for a task, which has no CF_INSTANCE_INDEX, and says volumes are not supported for tasks", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
		for name, vars := range map[string]map[string]string{
			"no index and no process_type": {"VCAP_APPLICATION": `{"application_id":"` + testAppID + `"}`},
			"no index":                     {"VCAP_APPLICATION": vcapApp},
			"no process_type":              {"VCAP_APPLICATION": `{"application_id":"` + testAppID + `"}`, "CF_INSTANCE_INDEX": "0"},
			"an empty process_type":        {"VCAP_APPLICATION": `{"application_id":"` + testAppID + `","process_type":""}`, "CF_INSTANCE_INDEX": "0"},
		} {
			vars["VCAP_SERVICES"] = vcap
			vol, err := volumesFromEnv(lookup(vars))
			Expect(vol).To(BeNil(), name)
			Expect(err).To(MatchError(ContainSubstring("volumes are not supported for tasks on VM backends")), name)
			Expect(err.Error()).NotTo(ContainSubstring("SENTINEL"), name)
		}
	})

	It("names the image after the application, the process type, and CF_INSTANCE_INDEX", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/var/vcap/data/0d1e", "rw")}})
		for index, name := range map[string]string{"0": "rvm-disk-" + testAppID + "-web-0.img", "3": "rvm-disk-" + testAppID + "-web-3.img", "65535": "rvm-disk-" + testAppID + "-web-65535.img"} {
			vol, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": vcapApp, "CF_INSTANCE_INDEX": index}))
			Expect(err).NotTo(HaveOccurred())
			n, err := strconv.Atoi(index)
			Expect(err).NotTo(HaveOccurred())
			Expect(vol).To(Equal([]guestVolume{{ContainerDir: "/var/vcap/data/0d1e", ImageName: name, Index: n}}))
		}
	})

	DescribeTable("rejects a CF_INSTANCE_INDEX that is not canonical decimal 0..65535",
		func(index string) {
			vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
			_, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": vcapApp, "CF_INSTANCE_INDEX": index}))
			Expect(err).To(MatchError(ContainSubstring("is not an instance index")))
		},
		Entry("leading zero", "01"),
		Entry("negative", "-1"),
		Entry("plus sign", "+1"),
		Entry("letters", "x"),
		Entry("too large", "65536"),
		Entry("empty", ""),
		Entry("space", " 1"),
		Entry("path", "../0"),
	)

	It("keeps two applications bound to one service instance on separate images", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
		other := "ffffffff-0000-4000-8000-000000000001"
		blue, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": vcapApp, "CF_INSTANCE_INDEX": "0"}))
		Expect(err).NotTo(HaveOccurred())
		green, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": `{"application_id":"` + other + `","process_type":"web"}`, "CF_INSTANCE_INDEX": "0"}))
		Expect(err).NotTo(HaveOccurred())
		Expect(green[0].ImageName).To(Equal("rvm-disk-" + other + "-web-0.img"))
		Expect(green[0].ImageName).NotTo(Equal(blue[0].ImageName))
	})

	It("keeps the process types of one application on separate images, whatever their instance indexes", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
		names := map[string]bool{}
		for _, pt := range []string{"web", "worker", "web-1", "web_1", "w"} {
			app := `{"application_id":"` + testAppID + `","process_type":"` + pt + `"}`
			for _, index := range []string{"0", "1"} {
				vol, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": app, "CF_INSTANCE_INDEX": index}))
				Expect(err).NotTo(HaveOccurred(), pt+" "+index)
				Expect(names).NotTo(HaveKey(vol[0].ImageName))
				names[vol[0].ImageName] = true
			}
		}
		Expect(names).To(HaveLen(10))
		Expect(names).To(HaveKey("rvm-disk-" + testAppID + "-worker-0.img"))
		Expect(names).To(HaveKey("rvm-disk-" + testAppID + "-web-1-1.img"))
	})

	DescribeTable("rejects a process_type that is not a short lowercase name and never repeats it",
		func(processType string) {
			vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
			app, err := json.Marshal(map[string]string{"application_id": testAppID, "process_type": processType})
			Expect(err).NotTo(HaveOccurred())
			vol, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": string(app), "CF_INSTANCE_INDEX": "0"}))
			Expect(vol).To(BeNil())
			Expect(err).To(MatchError("VCAP_APPLICATION process_type is not 1 to 63 lowercase letters, digits, underscores, or hyphens, starting with a letter or digit"))
		},
		Entry("a path", "../web"),
		Entry("a slash", "web/x"),
		Entry("a leading hyphen", "-web"),
		Entry("a leading underscore", "_web"),
		Entry("a leading dot", ".web"),
		Entry("a dot", "we.b"),
		Entry("uppercase", "Web"),
		Entry("a space", "we b"),
		Entry("a trailing newline", "web\n"),
		Entry("a NUL", "we\x00b"),
		Entry("a multibyte letter", "w\u00e9b"),
		Entry("64 characters", strings.Repeat("a", 64)),
	)

	It("accepts a process_type of 1 and of 63 characters", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
		for _, pt := range []string{"a", "0", "a-_b", strings.Repeat("a", 63)} {
			app := `{"application_id":"` + testAppID + `","process_type":"` + pt + `"}`
			vol, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": app, "CF_INSTANCE_INDEX": "7"}))
			Expect(err).NotTo(HaveOccurred(), pt)
			Expect(len(vol[0].ImageName)).To(BeNumerically("<=", 255))
			Expect(vol[0].ImageName).To(Equal("rvm-disk-" + testAppID + "-" + pt + "-7.img"))
		}
	})

	DescribeTable("rejects a VCAP_APPLICATION without a lowercase UUID application_id and never repeats it",
		func(vars map[string]string, msg string) {
			vars["VCAP_SERVICES"] = vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
			_, err := volumesFromEnv(lookup(vars))
			Expect(err).To(MatchError(msg))
			Expect(err.Error()).NotTo(ContainSubstring("SENTINEL"))
		},
		Entry("unset", map[string]string{}, "VCAP_APPLICATION is not set, so the volume image cannot be named after the application"),
		Entry("not JSON", map[string]string{"VCAP_APPLICATION": "x" + secretSentinel}, "VCAP_APPLICATION is not valid JSON for an application"),
		Entry("a JSON string", map[string]string{"VCAP_APPLICATION": `"` + secretSentinel + `"`}, "VCAP_APPLICATION is not valid JSON for an application"),
		Entry("application_id of the wrong type", map[string]string{"VCAP_APPLICATION": `{"application_id":1}`}, "VCAP_APPLICATION is not valid JSON for an application"),
		Entry("no application_id", map[string]string{"VCAP_APPLICATION": `{"name":"` + secretSentinel + `"}`}, "VCAP_APPLICATION application_id is not a lowercase UUID"),
		Entry("empty", map[string]string{"VCAP_APPLICATION": `{"application_id":""}`}, "VCAP_APPLICATION application_id is not a lowercase UUID"),
		Entry("uppercase", map[string]string{"VCAP_APPLICATION": `{"application_id":"0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D"}`}, "VCAP_APPLICATION application_id is not a lowercase UUID"),
		Entry("a path", map[string]string{"VCAP_APPLICATION": `{"application_id":"../` + testAppID + `"}`}, "VCAP_APPLICATION application_id is not a lowercase UUID"),
		Entry("a trailing newline", map[string]string{"VCAP_APPLICATION": `{"application_id":"` + testAppID + `\n"}`}, "VCAP_APPLICATION application_id is not a lowercase UUID"),
		Entry("no hyphens", map[string]string{"VCAP_APPLICATION": `{"application_id":"0a1b2c3d4e5f4a6b8c7d9e0f1a2b3c4d"}`}, "VCAP_APPLICATION application_id is not a lowercase UUID"),
		Entry("a non-hex digit", map[string]string{"VCAP_APPLICATION": `{"application_id":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4g"}`}, "VCAP_APPLICATION application_id is not a lowercase UUID"),
	)

	It("does not read VCAP_APPLICATION when the app has no volume", func() {
		vol, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": `{}`, "VCAP_APPLICATION": "not json"}))
		Expect(err).NotTo(HaveOccurred())
		Expect(vol).To(BeNil())
	})

	It("rejects image names with imageNameFor directly", func() {
		name, err := imageNameFor(testAppID, "web", "0", true)
		Expect(err).NotTo(HaveOccurred())
		Expect(name).To(Equal("rvm-disk-" + testAppID + "-web-0.img"))
		_, err = imageNameFor(testAppID, "web", "", false)
		Expect(err).To(MatchError(ContainSubstring("volumes are not supported for tasks on VM backends")))
		_, err = imageNameFor(testAppID, "web", "007", true)
		Expect(err).To(MatchError(`CF_INSTANCE_INDEX "007" is not an instance index from 0 to 65535`))
		_, err = imageNameFor("../x", "web", "0", true)
		Expect(err).To(MatchError(`application id "../x" is not a lowercase UUID`))
	})

	Describe("several volume mounts", func() {
		withApp := func(vcap string) map[string]string {
			return map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": vcapApp, "CF_INSTANCE_INDEX": "1"}
		}
		image := "rvm-disk-" + testAppID + "-web-1.img"
		volumesAt := func(dirs ...string) []guestVolume {
			vols := make([]guestVolume, len(dirs))
			for i, d := range dirs {
				vols[i] = guestVolume{ContainerDir: d, ImageName: image, Index: 1}
			}
			return vols
		}

		It("accepts up to four, across labels and within a binding, in the byte order of their paths", func() {
			vcap := vcapWith(map[string][]string{
				"nfs":     {mountJSON("/var/z", "rw"), mountJSON("/data", "rw")},
				"juicefs": {mountJSON("/data-old", "rw")},
				"a-label": {mountJSON("/data2", "rw")},
			})
			vols, err := volumesFromEnv(lookup(withApp(vcap)))
			Expect(err).NotTo(HaveOccurred())
			// Byte order puts "/data-old" before "/data2", and both before "/var/z".
			Expect(vols).To(Equal(volumesAt("/data", "/data-old", "/data2", "/var/z")))
		})

		It("accepts paths that only share a name prefix, since neither is under the other", func() {
			vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw"), mountJSON("/data-old", "rw"), mountJSON("/database", "rw"), mountJSON("/dat", "rw")}})
			vols, err := volumesFromEnv(lookup(withApp(vcap)))
			Expect(err).NotTo(HaveOccurred())
			Expect(vols).To(Equal(volumesAt("/dat", "/data", "/data-old", "/database")))
		})

		It("rejects a volume path on or under another volume path, whatever order the mounts come in, and names both", func() {
			for name, c := range map[string]struct {
				labels       map[string][]string
				inner, outer string
			}{
				"a child of a path":      {map[string][]string{"juicefs": {mountJSON("/data", "rw"), mountJSON("/data/inner", "rw")}}, "/data/inner", "/data"},
				"in the other order":     {map[string][]string{"a": {mountJSON("/data/inner", "rw")}, "b": {mountJSON("/data", "rw")}}, "/data/inner", "/data"},
				"a deeper descendant":    {map[string][]string{"juicefs": {mountJSON("/a/b/c/d", "rw"), mountJSON("/a", "rw")}}, "/a/b/c/d", "/a"},
				"past a path between":    {map[string][]string{"juicefs": {mountJSON("/data", "rw"), mountJSON("/data-old", "rw"), mountJSON("/data/inner", "rw")}}, "/data/inner", "/data"},
				"among four, across all": {map[string][]string{"a": {mountJSON("/z", "rw")}, "b": {mountJSON("/m/n", "rw")}, "c": {mountJSON("/a", "rw")}, "d": {mountJSON("/m", "rw")}}, "/m/n", "/m"},
			} {
				_, err := volumesFromEnv(lookup(withApp(vcapWith(c.labels))))
				Expect(err).To(MatchError(fmt.Sprintf("volume path %q is on or under volume path %q; VM backends need every volume path to be outside every other volume path, so give each volume a path of its own", c.inner, c.outer)), name)
			}
		})

		It("rejects a path and the same path with a trailing slash, which clean to one path", func() {
			_, err := volumesFromEnv(lookup(withApp(vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw"), mountJSON("/data/", "rw")}}))))
			Expect(err).To(MatchError(`volume path "/data/" is not a clean path`))
		})

		It("refuses nested paths, and paths that clean to nested ones, in checkNotNested", func() {
			Expect(checkNotNested([]string{"/data", "/data/"})).To(MatchError(ContainSubstring(`volume path "/data/" is on or under volume path "/data"`)))
			Expect(checkNotNested([]string{"/data/", "/data"})).To(MatchError(ContainSubstring(`volume path "/data" is on or under volume path "/data/"`)))
			Expect(checkNotNested([]string{"/data", "/data/x/../inner"})).To(MatchError(ContainSubstring(`volume path "/data/x/../inner" is on or under volume path "/data"`)))
			Expect(checkNotNested([]string{"/data", "/data-old", "/data2", "/dat"})).To(Succeed())
			Expect(checkNotNested(nil)).To(Succeed())
			Expect(checkNotNested([]string{"/data"})).To(Succeed())
		})

		It("reports a repeated path before a nested one", func() {
			_, err := volumesFromEnv(lookup(withApp(vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw"), mountJSON("/data", "rw"), mountJSON("/data/inner", "rw")}}))))
			Expect(err).To(MatchError(ContainSubstring(`volume path "/data" has 2 volume mounts`)))
		})

		It("gives the same order whatever order the labels and bindings come in", func() {
			dirs := []string{"/d", "/c", "/b", "/a"}
			want := volumesAt("/a", "/b", "/c", "/d")
			// vcapWith writes the labels in Go's map order, which changes from
			// one call to the next, and each permutation also reorders them.
			for _, perm := range [][]int{{0, 1, 2, 3}, {3, 2, 1, 0}, {1, 3, 0, 2}, {2, 0, 3, 1}} {
				for range 8 {
					labels := map[string][]string{}
					for i, p := range perm {
						labels["l"+strconv.Itoa(i)] = []string{mountJSON(dirs[p], "rw")}
					}
					vols, err := volumesFromEnv(lookup(withApp(vcapWith(labels))))
					Expect(err).NotTo(HaveOccurred())
					Expect(vols).To(Equal(want), "%v", perm)
				}
				one := make([]string, len(perm))
				for i, p := range perm {
					one[i] = mountJSON(dirs[p], "rw")
				}
				vols, err := volumesFromEnv(lookup(withApp(vcapWith(map[string][]string{"juicefs": one}))))
				Expect(err).NotTo(HaveOccurred())
				Expect(vols).To(Equal(want), "%v in one binding", perm)
			}
		})

		It("gives every volume of an instance the same image name, since each image is in its own volume", func() {
			vols, err := volumesFromEnv(lookup(withApp(vcapWith(map[string][]string{"juicefs": {mountJSON("/a", "rw"), mountJSON("/b", "rw")}}))))
			Expect(err).NotTo(HaveOccurred())
			Expect(vols).To(HaveLen(2))
			Expect(vols[0].ImageName).To(Equal(image))
			Expect(vols[1].ImageName).To(Equal(image))
		})

		It("rejects a fifth mount across labels and names the count, whatever the modes and paths", func() {
			for name, labels := range map[string]map[string][]string{
				"five labels":          {"a": {mountJSON("/a", "rw")}, "b": {mountJSON("/b", "rw")}, "c": {mountJSON("/c", "rw")}, "d": {mountJSON("/d", "rw")}, "e": {mountJSON("/e", "rw")}},
				"five in one binding":  {"juicefs": {mountJSON("/a", "rw"), mountJSON("/b", "r"), mountJSON("/etc", "rw"), mountJSON("/a", "rw"), mountJSON("", "x")}},
				"six across two kinds": {"juicefs": {mountJSON("/a", "rw"), mountJSON("/b", "rw"), mountJSON("/c", "rw")}, "nfs": {mountJSON("/d", "rw"), mountJSON("/e", "rw"), mountJSON("/f", "rw")}},
			} {
				_, err := volumesFromEnv(lookup(withApp(vcapWith(labels))))
				Expect(err).To(HaveOccurred(), name)
				Expect(err.Error()).To(MatchRegexp(`^VM backends support up to 4 volume mounts; this app has [56]$`), name)
				Expect(err.Error()).NotTo(ContainSubstring("SENTINEL"), name)
			}
		})

		It("rejects two mounts on one path, across labels or within a binding, and names the path", func() {
			for name, labels := range map[string]map[string][]string{
				"two labels":     {"juicefs": {mountJSON("/data", "rw")}, "nfs": {mountJSON("/data", "rw")}},
				"one binding":    {"juicefs": {mountJSON("/a", "rw"), mountJSON("/data", "rw"), mountJSON("/data", "rw")}},
				"among four":     {"a": {mountJSON("/z", "rw")}, "b": {mountJSON("/data", "rw")}, "c": {mountJSON("/a", "rw")}, "d": {mountJSON("/data", "rw")}},
				"three, one dir": {"a": {mountJSON("/data", "rw")}, "b": {mountJSON("/data", "rw")}, "c": {mountJSON("/data", "rw")}},
			} {
				_, err := volumesFromEnv(lookup(withApp(vcapWith(labels))))
				Expect(err).To(HaveOccurred(), name)
				Expect(err.Error()).To(MatchRegexp(`^volume path "/data" has [23] volume mounts; each volume mount on a VM backend needs a path of its own$`), name)
			}
		})

		It("checks the mode and the path of every mount, not only the first", func() {
			_, err := volumesFromEnv(lookup(withApp(vcapWith(map[string][]string{"juicefs": {mountJSON("/a", "rw"), mountJSON("/b", "r")}}))))
			Expect(err).To(MatchError(`volume path "/b": read-only volume mounts are not supported on VM backends`))
			_, err = volumesFromEnv(lookup(withApp(vcapWith(map[string][]string{"juicefs": {mountJSON("/a", "rw")}, "nfs": {mountJSON("/proc/x", "rw")}}))))
			Expect(err).To(MatchError(`volume path "/proc/x" is on or under /proc, which the guest needs for itself`))
		})

		It("reports the first bad mount in volume order, so every start gives the same line", func() {
			labels := map[string][]string{"a": {mountJSON("/z", "bad-z")}, "b": {mountJSON("/m", "bad-m")}, "c": {mountJSON("/c", "rw")}}
			for range 16 {
				_, err := volumesFromEnv(lookup(withApp(vcapWith(labels))))
				Expect(err).To(MatchError(`volume path "/m": volume mount mode "bad-m" is not supported on VM backends; want "rw"`))
			}
		})

		It("checks the application only after every mount", func() {
			vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/a", "rw"), mountJSON("/a", "rw")}})
			_, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
			Expect(err).To(MatchError(ContainSubstring("has 2 volume mounts")))
		})
	})

	It("rejects a read-only mount and names its path", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "r")}})
		_, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
		Expect(err).To(MatchError(`volume path "/data": read-only volume mounts are not supported on VM backends`))
	})

	It("rejects any other mode", func() {
		for _, mode := range []string{"", "RW", "rwx"} {
			vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", mode)}})
			_, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
			Expect(err).To(MatchError(ContainSubstring("is not supported on VM backends; want \"rw\"")), mode)
		}
	})

	DescribeTable("rejects a container_dir the guest cannot mount on",
		func(dir, reason string) {
			Expect(checkVolumeDir(dir)).To(MatchError(ContainSubstring(reason)))
		},
		Entry("empty", "", "is empty"),
		Entry("relative", "data", "is not absolute"),
		Entry("trailing slash", "/data/", "is not a clean path"),
		Entry("double slash", "//data", "is not a clean path"),
		Entry("dot", "/./data", "is not a clean path"),
		Entry("dot dot", "/data/../etc", "is not a clean path"),
		Entry("root", "/", "is the guest root"),
		Entry("NUL", "/da\x00ta", "contains a NUL or control character"),
		Entry("newline", "/da\nta", "contains a NUL or control character"),
		Entry("tab", "/da\tta", "contains a NUL or control character"),
		Entry("DEL", "/da\x7fta", "contains a NUL or control character"),
		Entry("too long", "/"+strings.Repeat("d", maxVolumePathLen), "is longer than 1024 bytes"),
		Entry("/bin", "/bin", "on or under /bin"),
		Entry("under /bin", "/bin/data", "on or under /bin"),
		Entry("/dev", "/dev", "on or under /dev"),
		Entry("under /dev", "/dev/shm", "on or under /dev"),
		Entry("/etc", "/etc", "on or under /etc"),
		Entry("under /etc", "/etc/data", "on or under /etc"),
		Entry("/init", "/init", "on or under /init"),
		Entry("/proc", "/proc", "on or under /proc"),
		Entry("under /proc", "/proc/self", "on or under /proc"),
		Entry("/rvm", "/rvm", "on or under /rvm"),
		Entry("under /rvm", "/rvm/cmd", "on or under /rvm"),
		Entry("/sys", "/sys", "on or under /sys"),
		Entry("under /sys", "/sys/fs", "on or under /sys"),
	)

	It("accepts paths that only share a prefix with a reserved directory", func() {
		for _, dir := range []string{"/binaries", "/devdata", "/etcetera", "/initial", "/process", "/rvmdata", "/system", "/data", "/var/vcap/data/x", "/tmp/data", "/it's a $dir"} {
			Expect(checkVolumeDir(dir)).To(Succeed(), dir)
		}
		Expect(checkVolumeDir("/" + strings.Repeat("d", maxVolumePathLen-1))).To(Succeed())
	})

	It("reports a bad container_dir from VCAP_SERVICES", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/etc", "rw")}})
		_, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
		Expect(err).To(MatchError(`volume path "/etc" is on or under /etc, which the guest needs for itself`))
	})

	DescribeTable("never repeats VCAP_SERVICES content in an error",
		func(vcap, msg string) {
			_, err := volumesFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
			Expect(err).To(MatchError(ContainSubstring(msg)))
			Expect(err.Error()).NotTo(ContainSubstring("SENTINEL"))
			Expect(err.Error()).NotTo(ContainSubstring("s3cr3t"))
		},
		Entry("truncated JSON", `{"juicefs":[{"credentials":{"password":"`+secretSentinel, "VCAP_SERVICES is not valid JSON"),
		Entry("bad token after the secret", `{"juicefs":[{"credentials":{"password":"`+secretSentinel+`"}x`, "VCAP_SERVICES is not valid JSON"),
		Entry("a bare string", `"`+secretSentinel+`"`, "VCAP_SERVICES is not valid JSON"),
		Entry("a label that is not a list", `{"juicefs":"`+secretSentinel+`"}`, "VCAP_SERVICES is not valid JSON"),
		Entry("a container_dir that is not a string", `{"juicefs":[{"credentials":{"password":"`+secretSentinel+`"},"volume_mounts":[{"container_dir":1,"mode":"rw"}]}]}`, "VCAP_SERVICES is not valid JSON"),
		Entry("five mounts", vcapWith(map[string][]string{"a": {mountJSON("/a", "rw"), mountJSON("/b", "rw"), mountJSON("/c", "rw")}, "b": {mountJSON("/d", "rw"), mountJSON("/e", "rw")}}), "this app has 5"),
		Entry("two mounts on one path", vcapWith(map[string][]string{"a": {mountJSON("/a", "rw")}, "b": {mountJSON("/a", "rw")}}), "has 2 volume mounts"),
		Entry("read-only", vcapWith(map[string][]string{"a": {mountJSON("/a", "r")}}), "read-only"),
	)

	It("bounds rejected values in error lines", func() {
		_, err := imageNameFor(testAppID, "web", strings.Repeat("9", 4096), true)
		Expect(err).To(HaveOccurred())
		Expect(len(err.Error())).To(BeNumerically("<", 160))
		Expect(err.Error()).To(ContainSubstring(`"... is not an instance index`))
		_, err = imageNameFor(strings.Repeat("a", 4096), "web", "0", true)
		Expect(err).To(HaveOccurred())
		Expect(len(err.Error())).To(BeNumerically("<", 160))
		Expect(len(checkVolumeDir("/" + strings.Repeat("d", 100000)).Error())).To(BeNumerically("<", 160))
	})
})

// mountinfoLine is one /proc/self/mountinfo line for a mount at point with
// the given filesystem type.
func mountinfoLine(id int, point, fstype string) string {
	return fmt.Sprintf("%d 29 0:%d / %s rw,relatime shared:%d - %s src rw\n", id, id, point, id, fstype)
}

var _ = Describe("findVolumeProvider", func() {
	infoFile := func(lines ...string) string {
		return writeTempFile("mountinfo", strings.Join(lines, ""))
	}

	It("accepts a JuiceFS mount", func() {
		Expect(findVolumeProviderErr(infoFile(mountinfoLine(40, "/data", "fuse.juicefs")), "/data")).To(Succeed())
	})

	It("accepts a JuiceFS mount among other mounts and a line with optional fields", func() {
		info := infoFile(
			mountinfoLine(30, "/", "overlay"),
			"41 30 0:41 / /data rw,nosuid shared:5 master:2 propagate_from:3 - fuse.juicefs JuiceFS:vol rw,user_id=0\n",
			mountinfoLine(42, "/proc", "proc"),
		)
		Expect(findVolumeProviderErr(info, "/data")).To(Succeed())
	})

	It("accepts a line with no optional fields", func() {
		Expect(findVolumeProviderErr(infoFile("41 30 0:41 / /data rw - fuse.juicefs JuiceFS:vol rw\n"), "/data")).To(Succeed())
	})

	It("refuses every other filesystem type and names it", func() {
		for _, fstype := range []string{"cifs", "ext4", "fuse", "juicefs", "fuse.juicefs2", "FUSE.JUICEFS"} {
			err := findVolumeProviderErr(infoFile(mountinfoLine(40, "/data", fstype)), "/data")
			Expect(err).To(HaveOccurred(), fstype)
			Expect(err.Error()).To(ContainSubstring(strconv.Quote(fstype)), fstype)
			Expect(err.Error()).To(ContainSubstring("VM backends support only BOSH disk, JuiceFS, and NFS volumes today"), fstype)
			Expect(err.Error()).To(ContainSubstring(`"/data"`), fstype)
		}
	})

	It("refuses a volume path with no mount entry", func() {
		for name, c := range map[string]struct{ info, dir string }{
			"an empty file":        {"", "/data"},
			"only other paths":     {mountinfoLine(30, "/", "fuse.juicefs") + mountinfoLine(31, "/data2", "fuse.juicefs"), "/data"},
			"only a parent":        {mountinfoLine(30, "/data", "fuse.juicefs"), "/data/sub"},
			"only a child":         {mountinfoLine(30, "/data/sub/dir", "fuse.juicefs"), "/data/sub"},
			"a malformed line":     {"garbage\n41 30 0:41\n", "/data"},
			"a line with no dash":  {"41 30 0:41 / /data rw shared:1 fuse.juicefs src rw\n", "/data"},
			"a dash and no fstype": {"41 30 0:41 / /data rw -\n", "/data"},
		} {
			err := findVolumeProviderErr(infoFile(c.info), c.dir)
			Expect(err).To(HaveOccurred(), name)
			Expect(err.Error()).To(ContainSubstring("no mount"), name)
			Expect(err.Error()).To(ContainSubstring("VM backends support only BOSH disk, JuiceFS, and NFS volumes today"), name)
		}
	})

	It("refuses when the mount table cannot be read", func() {
		err := findVolumeProviderErr(filepath.Join(GinkgoT().TempDir(), "absent"), "/data")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading"))
	})

	It("refuses when reading the mount table fails part way", func() {
		err := findVolumeProviderErr(GinkgoT().TempDir(), "/data")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading"))

		long := mountinfoLine(40, "/data", "fuse.juicefs") + strings.Repeat("x", 2<<20) + "\n"
		err = findVolumeProviderErr(infoFile(long), "/data")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading"))
	})

	It("matches the mount point exactly, not by prefix", func() {
		info := infoFile(mountinfoLine(40, "/data", "fuse.juicefs"), mountinfoLine(41, "/data/vol", "cifs"), mountinfoLine(42, "/data-old", "ext4"))
		Expect(findVolumeProviderErr(info, "/data")).To(Succeed())
		err := findVolumeProviderErr(info, "/data/vol")
		Expect(err).To(MatchError(ContainSubstring(`"cifs"`)))
		err = findVolumeProviderErr(info, "/data-old")
		Expect(err).To(MatchError(ContainSubstring(`"ext4"`)))
	})

	It("decodes the octal escapes in a mount point", func() {
		info := infoFile(
			mountinfoLine(40, `/my\040data`, "fuse.juicefs"),
			mountinfoLine(41, `/tab\011dir`, "fuse.juicefs"),
			mountinfoLine(42, `/back\134slash`, "fuse.juicefs"),
			mountinfoLine(43, `/nl\012dir`, "cifs"),
			mountinfoLine(44, `/data\040`, "ext4"),
		)
		Expect(findVolumeProviderErr(info, "/my data")).To(Succeed())
		Expect(findVolumeProviderErr(info, "/tab\tdir")).To(Succeed())
		Expect(findVolumeProviderErr(info, `/back\slash`)).To(Succeed())
		Expect(findVolumeProviderErr(info, "/nl\ndir")).To(MatchError(ContainSubstring(`"cifs"`)))
		// The escaped text is not the path.
		Expect(findVolumeProviderErr(info, `/my\040data`)).To(MatchError(ContainSubstring("no mount")))
		Expect(findVolumeProviderErr(info, "/data ")).To(MatchError(ContainSubstring(`"ext4"`)))
	})

	It("leaves a malformed escape as written", func() {
		info := infoFile(mountinfoLine(40, `/a\04`, "fuse.juicefs"), mountinfoLine(41, `/b\9zz`, "fuse.juicefs"))
		Expect(findVolumeProviderErr(info, `/a\04`)).To(Succeed())
		Expect(findVolumeProviderErr(info, `/b\9zz`)).To(Succeed())
	})

	It("leaves an escape above \\377 as written, since it is not a byte", func() {
		info := infoFile(mountinfoLine(40, `/a\400b`, "fuse.juicefs"), mountinfoLine(41, `/c\777`, "fuse.juicefs"))
		Expect(findVolumeProviderErr(info, `/a\400b`)).To(Succeed())
		Expect(findVolumeProviderErr(info, `/c\777`)).To(Succeed())
		Expect(findVolumeProviderErr(info, "/a\x00b")).To(MatchError(ContainSubstring("no mount")))
	})

	It("never repeats VCAP_SERVICES", func() {
		err := findVolumeProviderErr(infoFile(mountinfoLine(40, "/data", "cifs")), "/data")
		Expect(err.Error()).NotTo(ContainSubstring(secretSentinel))
		Expect(err.Error()).NotTo(ContainSubstring("VCAP_SERVICES"))
	})
})

var _ = Describe("findVolumeProviders", func() {
	// findAll is findVolumeProviders for volumes at dirs, with the kernel's
	// answers taken from the mount table lines.
	findAll := func(dirs []string, lines ...string) ([]selectedVolume, error) {
		info := writeTempFile("mountinfo", strings.Join(lines, ""))
		saved := volumeProbe
		defer func() { volumeProbe = saved }()
		volumeProbe = mountIDByPath(func() string { return info })
		vols := make([]guestVolume, len(dirs))
		for i, d := range dirs {
			vols[i] = guestVolume{ContainerDir: d, ImageName: "rvm-disk-x.img"}
		}
		return findVolumeProviders(info, vols)
	}

	It("selects a provider and a mount for each volume, in the volumes' order", func() {
		selected, err := findAll([]string{"/a", "/b", "/c"},
			mountinfoLine(42, "/c", "fuse.juicefs"), mountinfoLine(40, "/a", "fuse.juicefs"), mountinfoLine(41, "/b", "fuse.juicefs"))
		Expect(err).NotTo(HaveOccurred())
		Expect(selected).To(HaveLen(3))
		for i, want := range []struct {
			dir string
			id  uint64
		}{{"/a", 40}, {"/b", 41}, {"/c", 42}} {
			Expect(selected[i].Volume.ContainerDir).To(Equal(want.dir))
			Expect(selected[i].Mount.MountID).To(Equal(want.id))
			Expect(selected[i].Mount.ContainerDir).To(Equal(want.dir))
			Expect(selected[i].Provider.Name()).To(Equal("JuiceFS"))
		}
	})

	It("selects nothing for no volumes", func() {
		selected, err := findAll(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(selected).To(BeEmpty())
	})

	It("stops at the first volume it refuses", func() {
		_, err := findAll([]string{"/a", "/b", "/c"},
			mountinfoLine(40, "/a", "fuse.juicefs"), mountinfoLine(41, "/b", "cifs"), mountinfoLine(42, "/c", "ext4"))
		Expect(err).To(MatchError(`volume path "/b" is a "cifs" mount; VM backends support only BOSH disk, JuiceFS, and NFS volumes today`))
	})

	It("refuses two volumes that show one directory of one filesystem", func() {
		_, err := findAll([]string{"/a", "/b"},
			"40 29 0:52 /share /a rw shared:40 - fuse.juicefs JuiceFS:vol rw\n",
			"41 29 0:52 /share /b rw shared:41 - fuse.juicefs JuiceFS:vol rw\n")
		Expect(err).To(MatchError(`volume paths "/a" and "/b" are the same directory of one filesystem (device 0:52, root "/share"), so they would share one disk image; bind each volume to a directory of its own`))
	})

	It("accepts two directories of one filesystem and one directory of two filesystems", func() {
		_, err := findAll([]string{"/a", "/b"},
			"40 29 0:52 /share/a /a rw shared:40 - fuse.juicefs JuiceFS:vol rw\n",
			"41 29 0:52 /share/b /b rw shared:41 - fuse.juicefs JuiceFS:vol rw\n")
		Expect(err).NotTo(HaveOccurred())
		_, err = findAll([]string{"/a", "/b"},
			"40 29 0:52 /share /a rw shared:40 - fuse.juicefs JuiceFS:one rw\n",
			"41 29 0:53 /share /b rw shared:41 - fuse.juicefs JuiceFS:two rw\n")
		Expect(err).NotTo(HaveOccurred())
	})
})

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

var _ = Describe("volumeFromEnv", func() {
	lookup := func(vars map[string]string) func(string) (string, bool) { return envMap(vars) }

	It("returns no volume without VCAP_SERVICES", func() {
		vol, err := volumeFromEnv(lookup(map[string]string{"CF_INSTANCE_INDEX": "not checked"}))
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
			vol, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "CF_INSTANCE_INDEX": "01"}))
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
			vol, err := volumeFromEnv(lookup(vars))
			Expect(vol).To(BeNil(), name)
			Expect(err).To(MatchError(ContainSubstring("volumes are not supported for tasks on VM backends")), name)
			Expect(err.Error()).NotTo(ContainSubstring("SENTINEL"), name)
		}
	})

	It("names the image after the application, the process type, and CF_INSTANCE_INDEX", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/var/vcap/data/0d1e", "rw")}})
		for index, name := range map[string]string{"0": "rvm-disk-" + testAppID + "-web-0.img", "3": "rvm-disk-" + testAppID + "-web-3.img", "65535": "rvm-disk-" + testAppID + "-web-65535.img"} {
			vol, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": vcapApp, "CF_INSTANCE_INDEX": index}))
			Expect(err).NotTo(HaveOccurred())
			Expect(vol).To(Equal(&guestVolume{ContainerDir: "/var/vcap/data/0d1e", ImageName: name}))
		}
	})

	DescribeTable("rejects a CF_INSTANCE_INDEX that is not canonical decimal 0..65535",
		func(index string) {
			vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
			_, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": vcapApp, "CF_INSTANCE_INDEX": index}))
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
		blue, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": vcapApp, "CF_INSTANCE_INDEX": "0"}))
		Expect(err).NotTo(HaveOccurred())
		green, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": `{"application_id":"` + other + `","process_type":"web"}`, "CF_INSTANCE_INDEX": "0"}))
		Expect(err).NotTo(HaveOccurred())
		Expect(green.ImageName).To(Equal("rvm-disk-" + other + "-web-0.img"))
		Expect(green.ImageName).NotTo(Equal(blue.ImageName))
	})

	It("keeps the process types of one application on separate images, whatever their instance indexes", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
		names := map[string]bool{}
		for _, pt := range []string{"web", "worker", "web-1", "web_1", "w"} {
			app := `{"application_id":"` + testAppID + `","process_type":"` + pt + `"}`
			for _, index := range []string{"0", "1"} {
				vol, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": app, "CF_INSTANCE_INDEX": index}))
				Expect(err).NotTo(HaveOccurred(), pt+" "+index)
				Expect(names).NotTo(HaveKey(vol.ImageName))
				names[vol.ImageName] = true
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
			vol, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": string(app), "CF_INSTANCE_INDEX": "0"}))
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
			vol, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap, "VCAP_APPLICATION": app, "CF_INSTANCE_INDEX": "7"}))
			Expect(err).NotTo(HaveOccurred(), pt)
			Expect(len(vol.ImageName)).To(BeNumerically("<=", 255))
			Expect(vol.ImageName).To(Equal("rvm-disk-" + testAppID + "-" + pt + "-7.img"))
		}
	})

	DescribeTable("rejects a VCAP_APPLICATION without a lowercase UUID application_id and never repeats it",
		func(vars map[string]string, msg string) {
			vars["VCAP_SERVICES"] = vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}})
			_, err := volumeFromEnv(lookup(vars))
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
		vol, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": `{}`, "VCAP_APPLICATION": "not json"}))
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

	It("rejects two mounts across two labels and names the count", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}, "nfs": {mountJSON("/other", "rw")}})
		_, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
		Expect(err).To(MatchError("VM backends support one volume mount; this app has 2"))
	})

	It("rejects several mounts in one binding, whatever their modes", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/a", "rw"), mountJSON("/b", "r"), mountJSON("/c", "rw")}})
		_, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
		Expect(err).To(MatchError("VM backends support one volume mount; this app has 3"))
	})

	It("rejects a read-only mount", func() {
		vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "r")}})
		_, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
		Expect(err).To(MatchError("read-only volume mounts are not supported on VM backends"))
	})

	It("rejects any other mode", func() {
		for _, mode := range []string{"", "RW", "rwx"} {
			vcap := vcapWith(map[string][]string{"juicefs": {mountJSON("/data", mode)}})
			_, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
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
		_, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
		Expect(err).To(MatchError(`volume path "/etc" is on or under /etc, which the guest needs for itself`))
	})

	DescribeTable("never repeats VCAP_SERVICES content in an error",
		func(vcap, msg string) {
			_, err := volumeFromEnv(lookup(map[string]string{"VCAP_SERVICES": vcap}))
			Expect(err).To(MatchError(ContainSubstring(msg)))
			Expect(err.Error()).NotTo(ContainSubstring("SENTINEL"))
			Expect(err.Error()).NotTo(ContainSubstring("s3cr3t"))
		},
		Entry("truncated JSON", `{"juicefs":[{"credentials":{"password":"`+secretSentinel, "VCAP_SERVICES is not valid JSON"),
		Entry("bad token after the secret", `{"juicefs":[{"credentials":{"password":"`+secretSentinel+`"}x`, "VCAP_SERVICES is not valid JSON"),
		Entry("a bare string", `"`+secretSentinel+`"`, "VCAP_SERVICES is not valid JSON"),
		Entry("a label that is not a list", `{"juicefs":"`+secretSentinel+`"}`, "VCAP_SERVICES is not valid JSON"),
		Entry("a container_dir that is not a string", `{"juicefs":[{"credentials":{"password":"`+secretSentinel+`"},"volume_mounts":[{"container_dir":1,"mode":"rw"}]}]}`, "VCAP_SERVICES is not valid JSON"),
		Entry("two mounts", vcapWith(map[string][]string{"a": {mountJSON("/a", "rw")}, "b": {mountJSON("/b", "rw")}}), "this app has 2"),
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

var _ = Describe("checkVolumeProvider", func() {
	infoFile := func(lines ...string) string {
		return writeTempFile("mountinfo", strings.Join(lines, ""))
	}

	It("accepts a JuiceFS mount", func() {
		Expect(checkVolumeProvider(infoFile(mountinfoLine(40, "/data", "fuse.juicefs")), "/data")).To(Succeed())
	})

	It("accepts a JuiceFS mount among other mounts and a line with optional fields", func() {
		info := infoFile(
			mountinfoLine(30, "/", "overlay"),
			"41 30 0:41 / /data rw,nosuid shared:5 master:2 propagate_from:3 - fuse.juicefs JuiceFS:vol rw,user_id=0\n",
			mountinfoLine(42, "/proc", "proc"),
		)
		Expect(checkVolumeProvider(info, "/data")).To(Succeed())
	})

	It("accepts a line with no optional fields", func() {
		Expect(checkVolumeProvider(infoFile("41 30 0:41 / /data rw - fuse.juicefs JuiceFS:vol rw\n"), "/data")).To(Succeed())
	})

	It("refuses every other filesystem type and names it", func() {
		for _, fstype := range []string{"nfs", "nfs4", "fuse.mapfs", "ext4", "fuse", "juicefs", "fuse.juicefs2", "FUSE.JUICEFS"} {
			err := checkVolumeProvider(infoFile(mountinfoLine(40, "/data", fstype)), "/data")
			Expect(err).To(HaveOccurred(), fstype)
			Expect(err.Error()).To(ContainSubstring(strconv.Quote(fstype)), fstype)
			Expect(err.Error()).To(ContainSubstring("VM backends support only JuiceFS volumes today"), fstype)
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
			err := checkVolumeProvider(infoFile(c.info), c.dir)
			Expect(err).To(HaveOccurred(), name)
			Expect(err.Error()).To(ContainSubstring("no mount"), name)
			Expect(err.Error()).To(ContainSubstring("VM backends support only JuiceFS volumes today"), name)
		}
	})

	It("refuses when the mount table cannot be read", func() {
		err := checkVolumeProvider(filepath.Join(GinkgoT().TempDir(), "absent"), "/data")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading"))
	})

	It("refuses when reading the mount table fails part way", func() {
		err := checkVolumeProvider(GinkgoT().TempDir(), "/data")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading"))

		long := mountinfoLine(40, "/data", "fuse.juicefs") + strings.Repeat("x", 2<<20) + "\n"
		err = checkVolumeProvider(infoFile(long), "/data")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading"))
	})

	It("matches the mount point exactly, not by prefix", func() {
		info := infoFile(mountinfoLine(40, "/data", "fuse.juicefs"), mountinfoLine(41, "/data/vol", "nfs4"), mountinfoLine(42, "/data-old", "ext4"))
		Expect(checkVolumeProvider(info, "/data")).To(Succeed())
		err := checkVolumeProvider(info, "/data/vol")
		Expect(err).To(MatchError(ContainSubstring(`"nfs4"`)))
		err = checkVolumeProvider(info, "/data-old")
		Expect(err).To(MatchError(ContainSubstring(`"ext4"`)))
	})

	It("decodes the octal escapes in a mount point", func() {
		info := infoFile(
			mountinfoLine(40, `/my\040data`, "fuse.juicefs"),
			mountinfoLine(41, `/tab\011dir`, "fuse.juicefs"),
			mountinfoLine(42, `/back\134slash`, "fuse.juicefs"),
			mountinfoLine(43, `/nl\012dir`, "nfs4"),
			mountinfoLine(44, `/data\040`, "ext4"),
		)
		Expect(checkVolumeProvider(info, "/my data")).To(Succeed())
		Expect(checkVolumeProvider(info, "/tab\tdir")).To(Succeed())
		Expect(checkVolumeProvider(info, `/back\slash`)).To(Succeed())
		Expect(checkVolumeProvider(info, "/nl\ndir")).To(MatchError(ContainSubstring(`"nfs4"`)))
		// The escaped text is not the path.
		Expect(checkVolumeProvider(info, `/my\040data`)).To(MatchError(ContainSubstring("no mount")))
		Expect(checkVolumeProvider(info, "/data ")).To(MatchError(ContainSubstring(`"ext4"`)))
	})

	It("leaves a malformed escape as written", func() {
		info := infoFile(mountinfoLine(40, `/a\04`, "fuse.juicefs"), mountinfoLine(41, `/b\9zz`, "fuse.juicefs"))
		Expect(checkVolumeProvider(info, `/a\04`)).To(Succeed())
		Expect(checkVolumeProvider(info, `/b\9zz`)).To(Succeed())
	})

	It("leaves an escape above \\377 as written, since it is not a byte", func() {
		info := infoFile(mountinfoLine(40, `/a\400b`, "fuse.juicefs"), mountinfoLine(41, `/c\777`, "fuse.juicefs"))
		Expect(checkVolumeProvider(info, `/a\400b`)).To(Succeed())
		Expect(checkVolumeProvider(info, `/c\777`)).To(Succeed())
		Expect(checkVolumeProvider(info, "/a\x00b")).To(MatchError(ContainSubstring("no mount")))
	})

	It("uses the last entry when a later mount shadows the same path", func() {
		both := func(first, second string) string {
			return infoFile(mountinfoLine(40, "/data", first), mountinfoLine(50, "/proc", "proc"), mountinfoLine(60, "/data", second))
		}
		Expect(checkVolumeProvider(both("nfs4", "fuse.juicefs"), "/data")).To(Succeed())
		err := checkVolumeProvider(both("fuse.juicefs", "ext4"), "/data")
		Expect(err).To(MatchError(ContainSubstring(`"ext4"`)))
	})

	It("never repeats VCAP_SERVICES", func() {
		err := checkVolumeProvider(infoFile(mountinfoLine(40, "/data", "nfs4")), "/data")
		Expect(err.Error()).NotTo(ContainSubstring(secretSentinel))
		Expect(err.Error()).NotTo(ContainSubstring("VCAP_SERVICES"))
	})
})

var _ = Describe("volumeProviders", func() {
	It("registers JuiceFS and only JuiceFS", func() {
		Expect(volumeProviders).To(HaveLen(1))
		p, ok := providerForFSType("fuse.juicefs")
		Expect(ok).To(BeTrue())
		Expect(p.Name).To(Equal("JuiceFS"))
		for _, other := range []string{"", "nfs", "fuse.mapfs", "ext4"} {
			_, ok := providerForFSType(other)
			Expect(ok).To(BeFalse(), other)
		}
	})

	It("names every provider in the table when it refuses a volume", func() {
		original := volumeProviders
		DeferCleanup(func() { volumeProviders = original })
		for _, table := range []struct {
			providers []volumeProvider
			names     string
		}{
			{nil, "no"},
			{[]volumeProvider{{Name: "A", FSType: "fuse.a"}}, "A"},
			{[]volumeProvider{{Name: "A", FSType: "fuse.a"}, {Name: "B", FSType: "fuse.b"}}, "A and B"},
			{[]volumeProvider{{Name: "A", FSType: "fuse.a"}, {Name: "B", FSType: "fuse.b"}, {Name: "C", FSType: "fuse.c"}}, "A, B, and C"},
		} {
			volumeProviders = table.providers
			err := checkVolumeProvider(writeTempFile("mountinfo", mountinfoLine(40, "/data", "nfs4")), "/data")
			Expect(err).To(MatchError(HaveSuffix("; VM backends support only "+table.names+" volumes today")), table.names)
		}
		volumeProviders = []volumeProvider{{Name: "A", FSType: "fuse.a"}, {Name: "B", FSType: "fuse.b"}}
		Expect(checkVolumeProvider(writeTempFile("mountinfo", mountinfoLine(40, "/data", "fuse.b")), "/data")).To(Succeed())
	})
})

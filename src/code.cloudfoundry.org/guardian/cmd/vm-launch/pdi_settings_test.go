//go:build linux

package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("parseVolumeSize", func() {
	DescribeTable("accepts a whole number followed by a binary unit, in any case",
		func(text string, wantBytes int64) {
			n, unit, ok := parseVolumeSize(text)
			Expect(ok).To(BeTrue(), text)
			Expect(n * unit).To(Equal(wantBytes))
		},
		Entry("M", "64M", int64(64<<20)),
		Entry("MB", "64MB", int64(64<<20)),
		Entry("MiB", "64MiB", int64(64<<20)),
		Entry("m", "64m", int64(64<<20)),
		Entry("mb", "64mb", int64(64<<20)),
		Entry("mib", "64mib", int64(64<<20)),
		Entry("MIB", "64MIB", int64(64<<20)),
		Entry("G", "20G", int64(20<<30)),
		Entry("GB", "20GB", int64(20<<30)),
		Entry("GiB", "20GiB", int64(20<<30)),
		Entry("g", "20g", int64(20<<30)),
		Entry("gIb", "20gIb", int64(20<<30)),
		Entry("T", "2T", int64(2<<40)),
		Entry("TB", "2TB", int64(2<<40)),
		Entry("TiB", "2TiB", int64(2<<40)),
		Entry("t", "2t", int64(2<<40)),
		Entry("one", "1G", int64(1<<30)),
		Entry("nine digits", "999999999M", int64(999999999)<<20),
	)

	DescribeTable("refuses what is not a whole number directly followed by M, G, or T",
		func(text string) {
			_, _, ok := parseVolumeSize(text)
			Expect(ok).To(BeFalse(), text)
		},
		Entry("empty", ""),
		Entry("no unit", "20"),
		Entry("no number", "G"),
		Entry("a space before the unit", "20 G"),
		Entry("a space before the number", " 20G"),
		Entry("a space after the unit", "20G "),
		Entry("a newline", "20G\n"),
		Entry("a decimal", "1.5G"),
		Entry("a comma", "1,5G"),
		Entry("an exponent", "1e3M"),
		Entry("a plus sign", "+20G"),
		Entry("a minus sign", "-20G"),
		Entry("zero", "0G"),
		Entry("a leading zero", "020G"),
		Entry("ten digits", "1000000000M"),
		Entry("kilobytes", "65536K"),
		Entry("petabytes", "1P"),
		Entry("bytes", "1000000B"),
		Entry("a bare i", "20Gi"),
		Entry("a doubled unit", "20GG"),
		Entry("a unit before the number", "G20"),
		Entry("a unicode digit", "２０G"),
		Entry("a unicode unit", "20Ｇ"),
		Entry("a dotless i that Unicode upper-cases to I", "64M\u0131b"),
		Entry("a dotless i in GiB", "1G\u0131b"),
		Entry("a dotless i in TiB, in lower case", "2t\u0131b"),
		Entry("a long s that Unicode upper-cases to S", "20\u017f"),
		Entry("a Kelvin sign", "20\u212a"),
		Entry("hex", "0x20G"),
		Entry("a trailing word", "20G please"),
	)
})

var _ = Describe("parseVolumeSettings", func() {
	dirs := []string{"/data", "/shared", "/home/vcap/data"}

	refused := func(raw, want string) {
		GinkgoHelper()
		got, err := parseVolumeSettings(raw, dirs)
		Expect(err).To(MatchError(want), raw)
		Expect(got).To(BeNil())
	}

	It("gives every volume the defaults when the variable is empty", func() {
		got, err := parseVolumeSettings("", dirs)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})

	It("accepts an empty object and an object with empty settings", func() {
		for _, raw := range []string{`{}`, ` { } `, "\n{}\n", `{"/data":{}}`, `{"/data": {}, "/shared": {}}`} {
			got, err := parseVolumeSettings(raw, dirs)
			Expect(err).NotTo(HaveOccurred(), raw)
			for _, s := range got {
				Expect(s).To(Equal(volumeSettings{}))
				Expect(s.RequestedBytes()).To(Equal(int64(defaultImageSize)))
				Expect(s.SizeSet()).To(BeFalse())
			}
		}
	})

	It("reads a size and a mode for each volume", func() {
		got, err := parseVolumeSettings(`{"/home/vcap/data": {"size": "20G"}, "/shared": {"mode": "share"}, "/data": {"mode": "private", "size": "64m"}}`, dirs)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(map[string]volumeSettings{
			"/home/vcap/data": {Mode: volumePrivate, SizeBytes: 20 << 30},
			"/shared":         {Mode: volumeShare},
			"/data":           {Mode: volumePrivate, SizeBytes: 64 << 20},
		}))
		Expect(got["/home/vcap/data"].SizeSet()).To(BeTrue())
		Expect(got["/home/vcap/data"].RequestedBytes()).To(Equal(int64(20 << 30)))
		Expect(got["/shared"].RequestedBytes()).To(Equal(int64(defaultImageSize)))
	})

	It("takes the setting order and the white space as they come", func() {
		got, err := parseVolumeSettings("{\n\t\"/data\" :\t{ \"size\" : \"2T\" , \"mode\" : \"private\" }\n}\n", dirs)
		Expect(err).NotTo(HaveOccurred())
		Expect(got["/data"].SizeBytes).To(Equal(int64(2 << 40)))
	})

	It("accepts the minimum, the largest count of each unit that fits, and the 2^62 limit", func() {
		got, err := parseVolumeSettings(`{"/data":{"size":"64MiB"}}`, dirs)
		Expect(err).NotTo(HaveOccurred())
		Expect(got["/data"].SizeBytes).To(Equal(int64(64 << 20)))
		got, err = parseVolumeSettings(`{"/data":{"size":"4194304TiB"}}`, dirs)
		Expect(err).NotTo(HaveOccurred())
		Expect(got["/data"].SizeBytes).To(Equal(int64(1 << 62)))
		got, err = parseVolumeSettings(`{"/data":{"size":"4398046511104M"}}`, dirs)
		Expect(err).To(HaveOccurred(), "twelve digits is not a count")
		Expect(got).To(BeNil())
	})

	It("matches a key byte for byte", func() {
		refused(`{"/data/":{}}`, `VM_VOLUMES names "/data/", which no volume binding of this app mounts`)
		refused(`{"/Data":{}}`, `VM_VOLUMES names "/Data", which no volume binding of this app mounts`)
		refused(`{"data":{}}`, `VM_VOLUMES names "data", which no volume binding of this app mounts`)
		refused(`{" /data":{}}`, `VM_VOLUMES names " /data", which no volume binding of this app mounts`)
		refused(`{"":{}}`, `VM_VOLUMES names "", which no volume binding of this app mounts`)
		refused(`{"/data\u0000":{}}`, `VM_VOLUMES names "/data\x00", which no volume binding of this app mounts`)
		refused(`{"/data":{"mode":"share","size":"1G"}}`, `VM_VOLUMES "/data" sets a size, but a share has no image; its space is the volume's own quota`)
	})

	Describe("refusals", func() {
		DescribeTable("a value that is not a JSON object of volume paths",
			func(raw string) {
				refused(raw, "VM_VOLUMES is not a JSON object of volume paths")
			},
			Entry("a space", " "),
			Entry("text", "garbage"),
			Entry("a path", "/data"),
			Entry("a string", `"/data"`),
			Entry("a number", `20`),
			Entry("true", `true`),
			Entry("null", `null`),
			Entry("an array", `[]`),
			Entry("an array of objects", `[{"/data":{}}]`),
			Entry("an unterminated object", `{"/data":{}`),
			Entry("a missing closing brace", `{"/data":{"size":"1G"}`),
			Entry("a trailing comma", `{"/data":{},}`),
			Entry("a leading comma", `{,"/data":{}}`),
			Entry("single quotes", `{'/data':{}}`),
			Entry("a key without a value", `{"/data"}`),
			Entry("a missing colon", `{"/data" {}}`),
			Entry("a second object after the first", `{"/data":{}}{"/shared":{}}`),
			Entry("text after the object", `{"/data":{}} x`),
			Entry("a comment", `{"/data":{}} // size`),
			Entry("a byte order mark", "\xef\xbb\xbf{}"),
			Entry("invalid UTF-8 outside a string", "{\xff}"),
			Entry("a number for a volume", `{"/data":5}`),
			Entry("a string for a volume", `{"/data":"20G"}`),
			Entry("a bare size for a volume", `{"/data":20}`),
			Entry("null for a volume", `{"/data":null}`),
			Entry("an array for a volume", `{"/data":["size"]}`),
			Entry("true for a volume", `{"/data":true}`),
			Entry("a settings object with a trailing comma", `{"/data":{"size":"1G",}}`),
		)

		It("names a path no volume binding mounts", func() {
			refused(`{"/x":{}}`, `VM_VOLUMES names "/x", which no volume binding of this app mounts`)
			refused(`{"/data":{},"/x":{}}`, `VM_VOLUMES names "/x", which no volume binding of this app mounts`)
			refused(`{"/x":{"size":"20 G"}}`, `VM_VOLUMES names "/x", which no volume binding of this app mounts`)
			refused(`{"/x":{}}`+"\n", `VM_VOLUMES names "/x", which no volume binding of this app mounts`)
		})

		It("refuses every entry when the app binds no volume", func() {
			_, err := parseVolumeSettings(`{"/data":{}}`, nil)
			Expect(err).To(MatchError(`VM_VOLUMES names "/data", which no volume binding of this app mounts`))
			got, err := parseVolumeSettings(`{}`, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(BeEmpty())
		})

		It("names a path more than once, whatever the settings", func() {
			refused(`{"/data":{},"/data":{}}`, `VM_VOLUMES names "/data" more than once`)
			refused(`{"/data":{"size":"1G"},"/shared":{},"/data":{"size":"2G"}}`, `VM_VOLUMES names "/data" more than once`)
			refused(`{"/data":{"size":"1G"},"/data":{"size":"bad"}}`, `VM_VOLUMES names "/data" more than once`)
			refused(`{"/data":{},"/data":{}}`, `VM_VOLUMES names "/data" more than once`)
		})

		It("names a setting more than once", func() {
			refused(`{"/data":{"size":"1G","size":"2G"}}`, `VM_VOLUMES "/data" names the setting "size" more than once`)
			refused(`{"/data":{"mode":"private","mode":"share"}}`, `VM_VOLUMES "/data" names the setting "mode" more than once`)
		})

		It("refuses an unknown setting, with the settings that exist", func() {
			refused(`{"/data":{"sizes":"1G"}}`, `VM_VOLUMES "/data" has an unknown setting "sizes"; the settings are mode and size`)
			refused(`{"/data":{"Size":"1G"}}`, `VM_VOLUMES "/data" has an unknown setting "Size"; the settings are mode and size`)
			refused(`{"/data":{"MODE":"share"}}`, `VM_VOLUMES "/data" has an unknown setting "MODE"; the settings are mode and size`)
			refused(`{"/data":{"":1}}`, `VM_VOLUMES "/data" has an unknown setting ""; the settings are mode and size`)
			refused(`{"/data":{"mode":"private","readonly":true}}`, `VM_VOLUMES "/data" has an unknown setting "readonly"; the settings are mode and size`)
			refused(`{"/data":{"size":"1G","quota":"2G"}}`, `VM_VOLUMES "/data" has an unknown setting "quota"; the settings are mode and size`)
		})

		It("refuses a mode other than private or share", func() {
			refused(`{"/data":{"mode":"shared"}}`, `VM_VOLUMES "/data" mode "shared" is not private or share`)
			refused(`{"/data":{"mode":"Share"}}`, `VM_VOLUMES "/data" mode "Share" is not private or share`)
			refused(`{"/data":{"mode":"PRIVATE"}}`, `VM_VOLUMES "/data" mode "PRIVATE" is not private or share`)
			refused(`{"/data":{"mode":" share"}}`, `VM_VOLUMES "/data" mode " share" is not private or share`)
			refused(`{"/data":{"mode":""}}`, `VM_VOLUMES "/data" mode "" is not private or share`)
			refused(`{"/data":{"mode":"rw"}}`, `VM_VOLUMES "/data" mode "rw" is not private or share`)
			refused(`{"/data":{"mode":null}}`, `VM_VOLUMES "/data" mode null is not private or share`)
			refused(`{"/data":{"mode":true}}`, `VM_VOLUMES "/data" mode true is not private or share`)
			refused(`{"/data":{"mode":1}}`, `VM_VOLUMES "/data" mode 1 is not private or share`)
			refused(`{"/data":{"mode":"1"}}`, `VM_VOLUMES "/data" mode "1" is not private or share`)
			refused(`{"/data":{"mode":["share"]}}`, `VM_VOLUMES "/data" mode ["share"] is not private or share`)
			refused(`{"/data":{"mode": [ "share" , 1 ] }}`, `VM_VOLUMES "/data" mode ["share",1] is not private or share`)
		})

		It("refuses a size that is not a whole number followed by M, G, or T", func() {
			// shown is what the line holds for the size: a string in quotes,
			// and any other value as its JSON text.
			for _, c := range []struct{ json, shown string }{
				{`"20 G"`, `"20 G"`},
				{`""`, `""`},
				{`"20"`, `"20"`},
				{`"G"`, `"G"`},
				{`"1.5G"`, `"1.5G"`},
				{`"-1G"`, `"-1G"`},
				{`"0G"`, `"0G"`},
				{`"020G"`, `"020G"`},
				{`"1000000000M"`, `"1000000000M"`},
				{`"10K"`, `"10K"`},
				{`"1P"`, `"1P"`},
				{`"20Gi"`, `"20Gi"`},
				{`"20G\n"`, `"20G\n"`},
				{`"unlimited"`, `"unlimited"`},
				{`"64M\u0131b"`, "\"64M\u0131b\""},
				{`"1G\u0131b"`, "\"1G\u0131b\""},
				{`"32m\u0131b"`, "\"32m\u0131b\""},
				{`20`, `20`},
				{`20.5`, `20.5`},
				{`null`, `null`},
				{`true`, `true`},
				{`["20G"]`, `["20G"]`},
				{"[ \"20G\" ,\n 1 ]", `["20G",1]`},
				{`{"a":1}`, `{"a":1}`},
				{`{ "a" : "b\u00e9" }`, `{"a":"b\u00e9"}`},
			} {
				want := `VM_VOLUMES "/data" size ` + c.shown + ` is not a whole number followed by M, G, or T`
				refused(`{"/data":{"size":`+c.json+`}}`, want)
			}
		})

		It("shows a number and the string of the same digits differently", func() {
			_, numberErr := parseVolumeSettings(`{"/data":{"size":1}}`, dirs)
			_, stringErr := parseVolumeSettings(`{"/data":{"size":"1"}}`, dirs)
			Expect(numberErr).To(MatchError(`VM_VOLUMES "/data" size 1 is not a whole number followed by M, G, or T`))
			Expect(stringErr).To(MatchError(`VM_VOLUMES "/data" size "1" is not a whole number followed by M, G, or T`))
			_, numberErr = parseVolumeSettings(`{"/data":{"mode":1}}`, dirs)
			_, stringErr = parseVolumeSettings(`{"/data":{"mode":"1"}}`, dirs)
			Expect(numberErr).To(MatchError(`VM_VOLUMES "/data" mode 1 is not private or share`))
			Expect(stringErr).To(MatchError(`VM_VOLUMES "/data" mode "1" is not private or share`))
		})

		It("keeps a value that is not a string to one line, bounded, in printable ASCII", func() {
			long := strings.Repeat("a", 500)
			for _, setting := range []string{"mode", "size"} {
				_, err := parseVolumeSettings(`{"/data":{"`+setting+`":["`+long+`"]}}`, dirs)
				Expect(err).To(HaveOccurred(), setting)
				Expect(len(err.Error())).To(BeNumerically("<", 250), setting)
				Expect(err.Error()).To(ContainSubstring(`...`), setting)
				Expect(err.Error()).NotTo(ContainSubstring("\n"), setting)
			}
			_, err := parseVolumeSettings("{\"/data\":{\"size\":[\"\xff\u00e9\\u0001\"]}}", dirs)
			Expect(err).To(MatchError(`VM_VOLUMES "/data" size ["\xff\xc3\xa9\u0001"] is not a whole number followed by M, G, or T`))
		})

		It("accepts only ASCII letters in the unit, and quotes the size in every line that shows it", func() {
			refused(`{"/data":{"size":"64M\u0131b"}}`, "VM_VOLUMES \"/data\" size \"64M\u0131b\" is not a whole number followed by M, G, or T")
			refused(`{"/data":{"size":"1G\u0131B"}}`, "VM_VOLUMES \"/data\" size \"1G\u0131B\" is not a whole number followed by M, G, or T")
			refused(`{"/data":{"size":"32M"}}`, `VM_VOLUMES "/data" size "32M" is below the 64M minimum`)
			refused(`{"/data":{"size":"4194305TIB"}}`, `VM_VOLUMES "/data" size "4194305TIB" is over the 4 EiB limit`)
			got, err := parseVolumeSettings(`{"/data":{"size":"64mIb"}}`, dirs)
			Expect(err).NotTo(HaveOccurred())
			Expect(got["/data"].SizeBytes).To(Equal(int64(64 << 20)))
		})

		It("refuses a size below the 64M minimum, in the writer's own spelling", func() {
			refused(`{"/data":{"size":"32M"}}`, `VM_VOLUMES "/data" size "32M" is below the 64M minimum`)
			refused(`{"/data":{"size":"1MiB"}}`, `VM_VOLUMES "/data" size "1MiB" is below the 64M minimum`)
			refused(`{"/data":{"size":"63mb"}}`, `VM_VOLUMES "/data" size "63mb" is below the 64M minimum`)
			refused(`{"/data":{"size":"1"}}`, `VM_VOLUMES "/data" size "1" is not a whole number followed by M, G, or T`)
		})

		It("refuses a size over the 2^62-byte limit", func() {
			refused(`{"/data":{"size":"4194305TiB"}}`, `VM_VOLUMES "/data" size "4194305TiB" is over the 4 EiB limit`)
			refused(`{"/data":{"size":"999999999T"}}`, `VM_VOLUMES "/data" size "999999999T" is over the 4 EiB limit`)
			refused(`{"/data":{"size":"4294967297G"}}`, `VM_VOLUMES "/data" size "4294967297G" is not a whole number followed by M, G, or T`)
		})

		It("refuses a size on a share, whichever setting comes first", func() {
			want := `VM_VOLUMES "/shared" sets a size, but a share has no image; its space is the volume's own quota`
			refused(`{"/shared":{"mode":"share","size":"20G"}}`, want)
			refused(`{"/shared":{"size":"20G","mode":"share"}}`, want)
			refused(`{"/shared":{"size":"64M","mode":"share"}}`, want)
		})

		It("reports a bad setting before the size-on-a-share conflict", func() {
			refused(`{"/shared":{"mode":"share","size":"20 G"}}`, `VM_VOLUMES "/shared" size "20 G" is not a whole number followed by M, G, or T`)
			refused(`{"/shared":{"mode":"share","size":"1M"}}`, `VM_VOLUMES "/shared" size "1M" is below the 64M minimum`)
			refused(`{"/shared":{"mode":"share","size":"2G","extra":1}}`, `VM_VOLUMES "/shared" has an unknown setting "extra"; the settings are mode and size`)
		})

		It("reports the first bad entry in the order written", func() {
			refused(`{"/x":{"size":"1M"},"/data":{"sizes":"1G"}}`, `VM_VOLUMES names "/x", which no volume binding of this app mounts`)
			refused(`{"/shared":{"mode":"bad"},"/data":{"size":"1M"}}`, `VM_VOLUMES "/shared" mode "bad" is not private or share`)
			refused(`{"/data":{"size":"1M"},"/shared":{"mode":"bad"}}`, `VM_VOLUMES "/data" size "1M" is below the 64M minimum`)
		})

		It("bounds the text of a long rejected value", func() {
			long := strings.Repeat("x", 500)
			_, err := parseVolumeSettings(`{"/data":{"size":"`+long+`"}}`, dirs)
			Expect(err).To(HaveOccurred())
			Expect(len(err.Error())).To(BeNumerically("<", 250))
			Expect(err.Error()).To(HaveSuffix(`"... is not a whole number followed by M, G, or T`))
			_, err = parseVolumeSettings(`{"`+long+`":{}}`, dirs)
			Expect(err).To(HaveOccurred())
			Expect(len(err.Error())).To(BeNumerically("<", 250))
			_, err = parseVolumeSettings(`{"/data":{"`+long+`":1}}`, dirs)
			Expect(err).To(HaveOccurred())
			Expect(len(err.Error())).To(BeNumerically("<", 250))
			_, err = parseVolumeSettings(`{"/data":{"mode":"`+long+`"}}`, dirs)
			Expect(err).To(HaveOccurred())
			Expect(len(err.Error())).To(BeNumerically("<", 250))
		})
	})
})

var _ = Describe("applyVolumeSettings", func() {
	vols := func() []guestVolume {
		return []guestVolume{{ContainerDir: "/a", ImageName: "i"}, {ContainerDir: "/b", ImageName: "i"}}
	}
	env := func(v string, set bool) func(string) (string, bool) {
		return func(name string) (string, bool) {
			if name == "VM_VOLUMES" {
				return v, set
			}
			return "", false
		}
	}

	It("leaves every volume as volumesFromEnv made it when the variable is unset or empty", func() {
		for _, lookup := range []func(string) (string, bool){env("", false), env("", true), env("{}", true)} {
			v := vols()
			Expect(applyVolumeSettings(lookup, v)).To(Succeed())
			Expect(v).To(Equal(vols()))
		}
	})

	It("records each volume's settings and leaves a volume with no entry at the defaults", func() {
		v := vols()
		Expect(applyVolumeSettings(env(`{"/b":{"size":"3G"}}`, true), v)).To(Succeed())
		Expect(v[0].Settings).To(Equal(volumeSettings{}))
		Expect(v[1].Settings).To(Equal(volumeSettings{SizeBytes: 3 << 30}))
		Expect(v[1].ContainerDir).To(Equal("/b"))
		Expect(v[1].ImageName).To(Equal("i"))
	})

	It("passes a parse refusal through and changes nothing", func() {
		v := vols()
		Expect(applyVolumeSettings(env(`{"/a":{"size":"3G"},"/c":{}}`, true), v)).To(MatchError(`VM_VOLUMES names "/c", which no volume binding of this app mounts`))
		Expect(v).To(Equal(vols()))
	})

	It("refuses a share, which this vm-launch cannot attach yet, instead of giving the app a private disk", func() {
		v := vols()
		err := applyVolumeSettings(env(`{"/b":{"mode":"share"}}`, true), v)
		Expect(err).To(MatchError(`VM_VOLUMES "/b" mode "share" is not supported by this vm-launch yet; shares need a later release`))
		Expect(v).To(Equal(vols()))
	})

	It("accepts an explicit private mode", func() {
		v := vols()
		Expect(applyVolumeSettings(env(`{"/a":{"mode":"private"}}`, true), v)).To(Succeed())
		Expect(v[0].Settings).To(Equal(volumeSettings{Mode: volumePrivate}))
	})
})

var _ = Describe("run with VM_VOLUMES", func() {
	var (
		art    string
		tmp    string
		volDir string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		volDir = GinkgoT().TempDir()
		infoDir := GinkgoT().TempDir()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}}))
		logBuf = &bytes.Buffer{}
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = filepath.Join(infoDir, "mountinfo")
		Expect(os.WriteFile(mountInfoPath, []byte(mountinfoLine(40, volDir, "fuse.juicefs")), 0o644)).To(Succeed())

		saved := defaultImageOptions
		DeferCleanup(func() { defaultImageOptions = saved })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.LockWait = 300 * time.Millisecond
		defaultImageOptions.LockPoll = 20 * time.Millisecond
	})

	runVM := func() int {
		return run([]string{"--backend", string(backend.VMQemu), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	// refusedBeforeAnything checks that run exits 125 with exactly one line,
	// before it asks CredHub anything, reads the mount table, creates a work
	// directory, or touches the volume.
	refusedBeforeAnything := func(value, wantLine string) {
		GinkgoHelper()
		GinkgoT().Setenv("VM_VOLUMES", value)
		logBuf.Reset()
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM()).To(Equal(exitLaunchError), value)
		Expect(logBuf.String()).To(Equal(wantLine+"\n"), value)
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
	}

	It("exits 125 for each malformed or unmatched entry before it creates anything", func() {
		for _, c := range []struct{ value, line string }{
			{`not json`, `VM_VOLUMES is not a JSON object of volume paths`},
			{`[]`, `VM_VOLUMES is not a JSON object of volume paths`},
			{`{"` + volDir + `":5}`, `VM_VOLUMES is not a JSON object of volume paths`},
			{`{"/data":5}`, `VM_VOLUMES names "/data", which no volume binding of this app mounts`},
			{`{"/x":{}}`, `VM_VOLUMES names "/x", which no volume binding of this app mounts`},
			{`{"` + volDir + `":{},"` + volDir + `":{}}`, `VM_VOLUMES names ` + quoteForLog(volDir) + ` more than once`},
			{`{"` + volDir + `":{"sizes":"1G"}}`, `VM_VOLUMES ` + quoteForLog(volDir) + ` has an unknown setting "sizes"; the settings are mode and size`},
			{`{"` + volDir + `":{"mode":"shared"}}`, `VM_VOLUMES ` + quoteForLog(volDir) + ` mode "shared" is not private or share`},
			{`{"` + volDir + `":{"size":"20 G"}}`, `VM_VOLUMES ` + quoteForLog(volDir) + ` size "20 G" is not a whole number followed by M, G, or T`},
			{`{"` + volDir + `":{"size":"32M"}}`, `VM_VOLUMES ` + quoteForLog(volDir) + ` size "32M" is below the 64M minimum`},
			{`{"` + volDir + `":{"mode":"share","size":"1G"}}`, `VM_VOLUMES ` + quoteForLog(volDir) + ` sets a size, but a share has no image; its space is the volume's own quota`},
			{`{"` + volDir + `":{"mode":"share"}}`, `VM_VOLUMES ` + quoteForLog(volDir) + ` mode "share" is not supported by this vm-launch yet; shares need a later release`},
		} {
			refusedBeforeAnything(c.value, c.line)
		}
	})

	It("exits 125 before it reserves PORT, which another listener holds", func() {
		held, err := net.Listen("tcp", "0.0.0.0:0")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(held.Close)
		port := held.Addr().(*net.TCPAddr).Port
		GinkgoT().Setenv("PORT", strconv.Itoa(port))

		// The same start without a VM_VOLUMES refusal does reserve PORT and
		// stops on the held one, so a refusal that logs none of it came first.
		GinkgoT().Setenv("VM_VOLUMES", `{}`)
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM()).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("reserving port " + strconv.Itoa(port)))

		for _, c := range []struct{ value, line string }{
			{`not json`, `VM_VOLUMES is not a JSON object of volume paths`},
			{`{"/x":{}}`, `VM_VOLUMES names "/x", which no volume binding of this app mounts`},
			{`{"` + volDir + `":{"size":"32M"}}`, `VM_VOLUMES ` + quoteForLog(volDir) + ` size "32M" is below the 64M minimum`},
			{`{"` + volDir + `":{"mode":"share"}}`, `VM_VOLUMES ` + quoteForLog(volDir) + ` mode "share" is not supported by this vm-launch yet; shares need a later release`},
		} {
			refusedBeforeAnything(c.value, c.line)
			Expect(logBuf.String()).NotTo(ContainSubstring("reserving port"), c.value)
		}
	})

	It("refuses before CredHub is asked anything", func() {
		GinkgoT().Setenv("VCAP_SERVICES", `{"user-provided":[{"name":"db","credentials":{"credhub-ref":"/c/`+secretSentinel+`"},"volume_mounts":[`+mountJSON(volDir, "rw")+`]}]}`)
		refusedBeforeAnything(`{"/x":{}}`, `VM_VOLUMES names "/x", which no volume binding of this app mounts`)
	})

	It("refuses an entry for an app with no volume", func() {
		GinkgoT().Setenv("VCAP_SERVICES", `{}`)
		refusedBeforeAnything(`{"/data":{"size":"1G"}}`, `VM_VOLUMES names "/data", which no volume binding of this app mounts`)
	})

	It("reports a volume binding error before a VM_VOLUMES error", func() {
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "r")}}))
		refusedBeforeAnything(`not json`, `volume path `+quoteForLog(volDir)+`: read-only volume mounts are not supported on VM backends`)
	})

	It("starts as it did before when VM_VOLUMES is unset, empty, or empty settings for the volume", func() {
		for _, value := range []*string{nil, ptr(""), ptr("{}"), ptr(`{"` + volDir + `":{}}`), ptr(`{"` + volDir + `":{"mode":"private"}}`)} {
			if value == nil {
				GinkgoT().Setenv("VM_VOLUMES", "")
				Expect(os.Unsetenv("VM_VOLUMES")).To(Succeed())
				_, set := os.LookupEnv("VM_VOLUMES")
				Expect(set).To(BeFalse())
			} else {
				GinkgoT().Setenv("VM_VOLUMES", *value)
			}
			logBuf.Reset()
			argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
			Expect(runVM()).To(Equal(0), logBuf.String())
			Expect(argvFile).To(BeAnExistingFile())
			Expect(logBuf.String()).NotTo(ContainSubstring("VM_VOLUMES"))
			entries, err := os.ReadDir(volDir)
			Expect(err).NotTo(HaveOccurred())
			for _, e := range entries {
				info, err := e.Info()
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Size()).To(Equal(int64(defaultImageSize)), "the image keeps its default size until sizes are applied")
			}
		}
	})

	It("accepts a valid entry for the bound volume and still creates the default-size image", func() {
		GinkgoT().Setenv("VM_VOLUMES", `{"`+volDir+`":{"size":"2G"}}`)
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM()).To(Equal(0), logBuf.String())
		Expect(logBuf.String()).NotTo(ContainSubstring("VM_VOLUMES"))
	})
})

func ptr[T any](v T) *T { return &v }

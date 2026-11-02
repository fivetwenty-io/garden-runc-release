//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the volumes of the stack guest", func() {
	Describe("stage 2", func() {
		It("formats a blank image for uid 2000 in the stack guest only, and checks, grows, and mounts it as the busybox guest does", func() {
			Expect(strings.Count(guestVolumeSetup, guestVolumeMke2fsArgs)).To(Equal(1))
			Expect(guestStackVolumeMke2fsArgs).To(Equal(guestVolumeMke2fsArgs + ",root_owner=2000:2000"))
			Expect(guestStackVolumeSetup).To(ContainSubstring(" " + guestStackVolumeMke2fsArgs + " \"$rvm_vdev\""))
			Expect(strings.Replace(guestStackVolumeSetup, guestStackVolumeMke2fsArgs, guestVolumeMke2fsArgs, 1)).To(Equal(guestVolumeSetup))
			Expect(guestVolumeSetup).NotTo(ContainSubstring("root_owner"))
			Expect(initScript(testNonce, true)).NotTo(ContainSubstring("root_owner"))
			Expect(initScript(testNonce, true)).NotTo(ContainSubstring(guestStackVolumeBinds))
			Expect(initScript(testNonce, true)).NotTo(ContainSubstring(guestAppRoot + "$rvm_vpath"))
		})

		It("is the stack guest's own with the volume setup and the binds before the start tag, and the stack teardown after the run section", func() {
			s := &guestStack{}
			plain := s.initScript(testNonce)
			Expect(plain).NotTo(ContainSubstring("/rvm/mounts"))
			setup := guestRunSetup(false, s.processes())
			Expect(strings.Count(plain, setup)).To(Equal(1))
			script := s.initScriptWithVolumes(testNonce, true)
			start := strings.Index(script, "echo "+startTag(testNonce)+"\n")
			Expect(start).To(BeNumerically(">", 0))
			binds := strings.Index(script, guestStackVolumeSetup+guestStackVolumeBinds)
			Expect(binds).To(BeNumerically(">", 0))
			Expect(binds + len(guestStackVolumeSetup+guestStackVolumeBinds)).To(BeNumerically("<=", start))
			procs := s.processes()
			Expect(script).To(Equal(strings.NewReplacer(
				setup, setup+guestStackVolumeSetup+guestStackVolumeBinds,
				guestRunSection(testNonce, procs, false, stackExec), guestRunSectionWithin(testNonce, procs, false, stackExec, guestVolumeTimeoutSeconds),
				guestOOMReport(testNonce), guestOOMReport(testNonce)+guestStackRunVolumeTeardown,
			).Replace(plain)))
			Expect(script).NotTo(ContainSubstring(guestVolumeSetup))
		})

		It("binds the volumes in a guest whose app runs through the run section too, which winds down within guestVolumeWindDown and has the teardown with no SIGTERM wait", func() {
			s := &guestStack{sidecars: []guestSidecar{{argv: "'sidecar'"}}}
			script := s.initScriptWithVolumes(testNonce, true)
			start := strings.Index(script, "echo "+startTag(testNonce)+"\n")
			Expect(strings.Index(script, guestStackVolumeBinds)).To(BeNumerically("<", start))
			section := guestRunSectionWithin(testNonce, s.processes(), false, stackExec, guestVolumeTimeoutSeconds)
			Expect(strings.Index(script, section)).To(BeNumerically(">", start))
			Expect(strings.Index(script, guestStackRunVolumeTeardown)).To(BeNumerically(">", strings.Index(script, section)))
			Expect(script).NotTo(ContainSubstring(guestStackVolumeTeardown))
			Expect(script).To(ContainSubstring("sleep " + guestVolumeTimeoutSeconds + " &\n"))
			Expect(script).NotTo(ContainSubstring("sleep " + guestTimeoutSeconds + " &\n"))

			// Without volumes, the section keeps the longer wind-down.
			Expect(s.initScriptWithVolumes(testNonce, false)).To(ContainSubstring(guestRunSection(testNonce, s.processes(), false, stackExec)))
		})

		It("unbinds each volume in that volume's own pass, after the processes the command left are stopped, and right before the volume's last flush and unmount", func() {
			Expect(guestVolumeTeardown).To(Equal(guestVolumeTeardownStop + guestVolumeTeardownUnmount))
			Expect(guestVolumeTeardownStop).To(Equal(guestVolumeTeardownFlush + guestVolumeTeardownTerm + guestVolumeTeardownKill))
			Expect(guestVolumeTeardownKill).To(HaveSuffix("rvm_vbad=\n"))
			Expect(strings.Count(guestVolumeTeardownUnmount, guestVolumeLastFlush)).To(Equal(1))
			Expect(guestStackVolumeTeardownUnmount).To(Equal(strings.Replace(guestVolumeTeardownUnmount, guestVolumeLastFlush, "\t\trvm_vunbind\n"+guestVolumeLastFlush, 1)))
			// The call follows the pass's case, so a volume that the pass
			// skips is never unbound in it.
			Expect(strings.Index(guestStackVolumeTeardownUnmount, "rvm_vunbind")).To(BeNumerically(">", strings.Index(guestStackVolumeTeardownUnmount, "\t\tesac\n")))
			Expect(guestStackVolumeTeardown).To(Equal(guestVolumeTeardownStop + guestStackVolumeUnbind + guestStackVolumeTeardownUnmount))
			Expect(guestStackRunVolumeTeardown).To(Equal(guestVolumeTeardownFlush + guestVolumeTeardownKill + guestStackVolumeUnbind + guestStackVolumeTeardownUnmount))
			Expect(guestVolumeTeardownTerm).To(ContainSubstring("kill -TERM -1"))
			Expect(guestStackVolumeUnbind).To(ContainSubstring(`umount "$rvm_vat"`))
			Expect(guestStackVolumeUnbind).NotTo(ContainSubstring("sync"))
			Expect(guestStackVolumeUnbind).NotTo(ContainSubstring("kill"))
			// The busybox guest has no binds, so its teardown never unbinds.
			Expect(guestVolumeTeardown).NotTo(ContainSubstring("rvm_vunbind"))
			Expect(initScript(testNonce, true)).NotTo(ContainSubstring("rvm_vunbind"))
		})

		It("fits a run section's wind-down and the one wait of the volume teardown after it 2 seconds before the host's stop deadline", func() {
			Expect(guestVolumeWindDown + guestTeardownKillWait + 2*time.Second).To(BeNumerically("<=", stopDeadline))
			Expect(guestVolumeTimeoutSeconds).To(Equal(strconv.Itoa(int(guestVolumeWindDown / time.Second))))
			Expect(guestVolumeWindDown % time.Second).To(BeZero())
			Expect(guestStackRunVolumeTeardown).NotTo(ContainSubstring("kill -TERM"))
			Expect(strings.Count(guestStackRunVolumeTeardown, "sleep ")).To(Equal(strings.Count(guestVolumeTeardownKill, "sleep ")))
		})
	})

	Describe("the initramfs", func() {
		stackGuest := func() guestContents {
			f, err := os.Open(writeTempFile("launcher", "#!/bin/sh\n"))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(f.Close)
			g := taskGuest("")
			g.drives.stackID, g.drives.dropletID = qemuStackSerial, qemuDropletSerial
			g.stack = &guestStack{
				launcher: guestTool{name: "launcher", file: f, size: int64(len("#!/bin/sh\n"))},
				argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", ""}),
				cwd:      "/home/vcap/app",
				hostname: "stack-guest-0",
				hosts:    []byte("127.0.0.1 localhost\n"),
			}
			g.vols = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "rvm-disk-0.img"}, {ContainerDir: "/data", ImageName: "rvm-disk-1.img"}}
			g.drives.volumes = qemuImageDrives(defaultImageSize, defaultImageSize)
			return g
		}
		archive := func(g guestContents) map[string]cpioEntry {
			var archive bytes.Buffer
			Expect(writeInitramfsArchive(&archive, strings.NewReader("busybox"), int64(len("busybox")), g)).To(Succeed())
			_, byName := archiveEntries(archive.Bytes())
			return byName
		}

		It("runs the stack guest's stage 2 with the volumes, and gives the busybox guest it falls back to a stage 2 that mounts them as root's", func() {
			g := stackGuest()
			g.stack.fallback, g.stack.fallbackEnv = true, "export FOR_BUSYBOX=1\n"
			byName := archive(g)
			Expect(string(byName["init"].data)).To(Equal(guestStackInit))
			Expect(string(byName["rvm/init"].data)).To(Equal(g.stack.initScriptWithVolumes(testNonce, true)))
			Expect(string(byName["rvm/init"].data)).To(ContainSubstring("root_owner=2000:2000"))
			Expect(string(byName["rvm/mounts"].data)).To(Equal("RVM_VOLUMES=2\nRVM_SYNC_MOUNTS=true\n" +
				"RVM_VOL0_KIND=image\nRVM_VOL0_PATH='/home/vcap/data'\nRVM_VOL0_IMAGE='rvm-disk-0.img'\n" +
				"RVM_VOL1_KIND=image\nRVM_VOL1_PATH='/data'\nRVM_VOL1_IMAGE='rvm-disk-1.img'\n"))
			Expect(string(byName["rvm/disks"].data)).To(ContainSubstring("RVM_VOLUMES=2\n"))
			Expect(string(byName["rvm/disks"].data)).To(HaveSuffix("RVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID=rvm-droplet\n"))
			fallback := string(byName[strings.TrimPrefix(guestFallbackInit, "/")].data)
			Expect(fallback).To(Equal(initScript(testNonce, true)))
			Expect(fallback).NotTo(ContainSubstring("root_owner"))
		})

		It("runs the stack guest's stage 2 with a share and a BOSH disk beside an image, each by its volume index, and gives the busybox guest it falls back to the same volumes", func() {
			g := stackGuest()
			g.stack.fallback = true
			g.vols = []guestVolume{
				{ContainerDir: "/home/vcap/data", ImageName: "rvm-disk-0.img"},
				{ContainerDir: "/home/vcap/shared", Settings: volumeSettings{Mode: volumeShare}},
				{ContainerDir: "/home/vcap/disk"},
			}
			g.drives.volumes = []guestDrive{
				{id: qemuVolumeSerial(0), kind: driveImage, bytes: defaultImageSize},
				{id: qemuVolumeSerial(2), kind: driveBlock, bytes: defaultImageSize},
			}
			byName := archive(g)
			Expect(string(byName["init"].data)).To(Equal(guestStackInit))
			Expect(string(byName["rvm/init"].data)).To(Equal(g.stack.initScriptWithVolumes(testNonce, true)))
			Expect(string(byName["rvm/mounts"].data)).To(Equal("RVM_VOLUMES=3\nRVM_SYNC_MOUNTS=true\n" +
				"RVM_VOL0_KIND=image\nRVM_VOL0_PATH='/home/vcap/data'\nRVM_VOL0_IMAGE='rvm-disk-0.img'\n" +
				"RVM_VOL1_KIND=share\nRVM_VOL1_PATH='/home/vcap/shared'\n" +
				"RVM_VOL2_KIND=block\nRVM_VOL2_PATH='/home/vcap/disk'\n"))
			Expect(string(byName["rvm/disks"].data)).To(ContainSubstring("RVM_VOL1_KIND=share\nRVM_VOL2_KIND=block\nRVM_VOL2_ID=rvm-vol2\n"))
			Expect(string(byName[strings.TrimPrefix(guestFallbackInit, "/")].data)).To(Equal(initScript(testNonce, true)))
		})

		It("gives the busybox guest that a stack guest without volumes falls back to a stage 2 without them", func() {
			g := stackGuest()
			g.vols, g.drives.volumes = nil, nil
			g.stack.fallback = true
			byName := archive(g)
			Expect(string(byName["rvm/init"].data)).To(Equal(g.stack.initScript(testNonce)))
			Expect(string(byName[strings.TrimPrefix(guestFallbackInit, "/")].data)).To(Equal(initScript(testNonce, false)))
			Expect(byName).NotTo(HaveKey("rvm/mounts"))
		})
	})

	Describe("in the guest's shell", func() {
		var dir, bin, app, callLog, owners, ids string

		BeforeEach(func() {
			dir = GinkgoT().TempDir()
			bin = filepath.Join(dir, "bin")
			app = filepath.Join(dir, "app")
			callLog = filepath.Join(dir, "calls")
			Expect(os.MkdirAll(filepath.Join(app, "home", "vcap"), 0o755)).To(Succeed())
			Expect(os.Mkdir(bin, 0o755)).To(Succeed())
			// Each stub records its argv, with the test directory as
			// $DIR, and fails when its first operand is the one that
			// FAIL_AT names for it.
			stub := func(name, body string) {
				script := "#!/bin/sh\nline=\"" + name + " $*\"\necho \"$line\" | sed \"s|" + dir + "|\\$DIR|g\" >>" + shellQuote(callLog) + "\n" + body + "\n"
				Expect(os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755)).To(Succeed())
			}
			stub("mkdir", `exec /bin/mkdir "$@"`)
			stub("mount", `case "$2" in
remount,*) [ "${REMOUNT_FAIL_AT:-}" != "$3" ] || exit 32 ;;
*) [ "${MOUNT_FAIL_AT:-}" != "$4" ] || exit 32 ;;
esac`)
			stub("umount", `[ "${UMOUNT_FAIL_AT:-}" != "$1" ] || { echo "umount: can't unmount $1: Device or resource busy" >&2; exit 1; }`)
			stub("sync", `[ "${SYNC_FAIL_AT:-}" != "$2" ] || { echo "sync: $2: Input/output error" >&2; exit 1; }`)
			stub("kill", `exit 0`)
			stub("sleep", `echo "the teardown waited, though no other process runs" >&2; exit 1`)
			stub("chown", `[ "${CHOWN_FAIL_AT:-}" != "$2" ] || { echo "chown: $2: Read-only file system" >&2; exit 1; }`)
			// stat records nothing, and fails for the path STAT_FAIL_AT
			// names. For an owner, it prints the one that the file owners
			// lists for its path, or 2000:2000 for a path that owners does
			// not list. For a device and an inode, it prints the identity
			// that the file ids lists for its path, or one made from the
			// path with the app root taken off, so that a volume and its
			// path in the app root match unless ids says otherwise.
			owners = filepath.Join(dir, "owners")
			ids = filepath.Join(dir, "ids")
			Expect(os.WriteFile(filepath.Join(bin, "stat"), []byte(`#!/bin/sh
if [ "${STAT_FAIL_AT:-}" = "$3" ]; then
	echo "stat: can't stat '$3': No such file or directory" >&2
	exit 1
fi
if [ "$2" = %d:%i ]; then
	if [ -e `+shellQuote(ids)+` ]; then
		while IFS=' ' read -r rvm_i rvm_p; do
			[ "$rvm_p" != "$3" ] || { echo "$rvm_i"; exit 0; }
		done <`+shellQuote(ids)+`
	fi
	rvm_a=`+shellQuote(app)+`
	echo "id:${3#"$rvm_a"}"
	exit 0
fi
if [ -e `+shellQuote(owners)+` ]; then
	while IFS=' ' read -r rvm_o rvm_p; do
		[ "$rvm_p" != "$3" ] || { echo "$rvm_o"; exit 0; }
	done <`+shellQuote(owners)+`
fi
echo 2000:2000
`), 0o755)).To(Succeed())
		})

		// kindMounts is the part of /rvm/mounts that the binds and the
		// teardown read, for a volume at each of paths of the kind at the
		// same place in kinds. An image volume has an image name, and a
		// share has no device.
		kindMounts := func(kinds []string, paths ...string) string {
			GinkgoHelper()
			Expect(kinds).To(HaveLen(len(paths)))
			m := "RVM_VOLUMES=" + string(rune('0'+len(paths))) + "\n"
			for i, p := range paths {
				n := string(rune('0' + i))
				m += "RVM_VOL" + n + "_KIND=" + kinds[i] + "\nRVM_VOL" + n + "_PATH=" + shellQuote(p) + "\n"
				if kinds[i] == string(driveImage) {
					m += "RVM_VOL" + n + "_IMAGE=volume.img\n"
				}
				if kinds[i] != volumeKindShare {
					m += "rvm_vdev_" + n + "=/dev/vd" + string(rune('b'+i)) + "\n"
				}
			}
			return m
		}
		// mountsFor is kindMounts for an image volume at each of paths.
		mountsFor := func(paths ...string) string {
			kinds := make([]string, len(paths))
			for i := range kinds {
				kinds[i] = string(driveImage)
			}
			return kindMounts(kinds, paths...)
		}

		// runScript runs rvm_fail, pre, and script in shell, with the app
		// root moved into the test directory, the commands that change
		// mounts or processes called as the stubs by path, because the
		// guest's busybox runs its own applets before anything on PATH,
		// the teardown's /proc moved to an empty directory, so that no
		// other process seems to run, and reboot replaced by a marker. It
		// returns the output and the calls the stubs recorded.
		runScript := func(shell guestShell, pre, script string, env ...string) (string, string) {
			GinkgoHelper()
			moved := strings.NewReplacer(
				guestAppRoot, app,
				`mkdir "`, filepath.Join(bin, "mkdir")+` "`,
				"mount -o bind ", filepath.Join(bin, "mount")+" -o bind ",
				"mount -o remount,", filepath.Join(bin, "mount")+" -o remount,",
				`umount "`, filepath.Join(bin, "umount")+` "`,
				`sync -f "`, filepath.Join(bin, "sync")+` -f "`,
				"kill -", filepath.Join(bin, "kill")+" -",
				"\tsleep ", "\t"+filepath.Join(bin, "sleep")+" ",
				"$(stat -c ", "$("+filepath.Join(bin, "stat")+" -c ",
				"chown "+guestAppUID+":", filepath.Join(bin, "chown")+" "+guestAppUID+":",
				guestProcDir+"/[0-9]*", shellQuote(filepath.Join(dir, "proc"))+"/[0-9]*",
			).Replace(script)
			Expect(moved).NotTo(ContainSubstring(guestAppRoot))
			Expect(strings.Count(moved, "mount -o ")).To(Equal(strings.Count(moved, filepath.Join(bin, "mount")+" -o ")))
			Expect(strings.Count(moved, "mkdir ")).To(Equal(strings.Count(moved, filepath.Join(bin, "mkdir")+" ")))
			Expect(strings.Count(moved, "umount ")).To(Equal(strings.Count(moved, filepath.Join(bin, "umount")+" ")))
			Expect(strings.Count(moved, "stat -c ")).To(Equal(strings.Count(moved, filepath.Join(bin, "stat")+" -c ")))
			Expect(strings.Count(moved, "chown ")).To(Equal(strings.Count(moved, filepath.Join(bin, "chown")+" ")))
			Expect(os.MkdirAll(filepath.Join(dir, "proc"), 0o755)).To(Succeed())
			full := strings.Replace(guestFailFunc, "reboot -nf", "echo REBOOT", 1) + pre + moved
			cmd := exec.Command(shell.argv[0], append(slices.Clone(shell.argv[1:]), "-c", full)...)
			cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, env...)
			out, _ := cmd.CombinedOutput()
			calls, err := os.ReadFile(callLog)
			if os.IsNotExist(err) {
				err = nil
			}
			Expect(err).NotTo(HaveOccurred())
			return string(out), string(calls)
		}

		// bindCalls are the calls that bind the volume at path, after
		// rvm_vwalk makes each directory in made and gives it to uid 2000.
		bindCalls := func(path string, made ...string) string {
			calls := ""
			for _, m := range made {
				calls += "mkdir $DIR/app" + m + "\nchown 2000:2000 $DIR/app" + m + "\n"
			}
			return calls + "mount -o bind " + path + " $DIR/app" + path + "\nmount -o remount,bind,nosuid,nodev,noatime $DIR/app" + path + "\n"
		}

		DescribeTable("binds each volume to the same path in the app root, in volume order, with nosuid and nodev, making each directory on the way that does not exist for uid 2000",
			func(shellOf func() guestShell) {
				shell := shellOf()
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/my data"), guestStackVolumeBinds+"echo BOUND\n")
				Expect(out).To(Equal("BOUND\n"), shell.name)
				Expect(calls).To(Equal(bindCalls("/home/vcap/data", "/home/vcap/data")+bindCalls("/srv/my data", "/srv", "/srv/my data")), shell.name)
				Expect(filepath.Join(app, "srv", "my data")).To(BeADirectory())
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot with a line that names the path, and binds nothing more, when a volume's path crosses a symbolic link in the app root",
			func(shellOf func() guestShell, link, path string) {
				shell := shellOf()
				Expect(os.Symlink(link, filepath.Join(app, "home", "vcap", "linked"))).To(Succeed())
				out, calls := runScript(shell, mountsFor("/srv/first", path, "/srv/third"), guestStackVolumeBinds+"echo BOUND\n")
				Expect(out).To(Equal("vm-launch guest setup: the volume path "+path+" crosses the symbolic link /home/vcap/linked in the app root, so the guest will not bind the volume there\nREBOOT\n"), shell.name)
				Expect(calls).To(Equal(bindCalls("/srv/first", "/srv", "/srv/first")), shell.name)
				Expect("/rvm-s5-elsewhere").NotTo(BeAnExistingFile())
			},
			slices.Concat(
				shellEntries("an absolute link on the way", "/rvm-s5-elsewhere", "/home/vcap/linked/data"),
				shellEntries("a relative link on the way", "../../srv", "/home/vcap/linked/data"),
				shellEntries("an absolute link at the mount point", "/rvm-s5-elsewhere", "/home/vcap/linked"),
				shellEntries("a relative link at the mount point", "../../srv", "/home/vcap/linked"),
			),
		)

		DescribeTable("fails the boot with a line that names the path when the bind fails",
			func(shellOf func() guestShell) {
				shell := shellOf()
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/two"), guestStackVolumeBinds+"echo BOUND\n", "MOUNT_FAIL_AT="+filepath.Join(app, "home", "vcap", "data"))
				Expect(out).To(Equal("vm-launch guest setup: binding the volume at /home/vcap/data into the app root failed\nREBOOT\n"), shell.name)
				Expect(calls).To(Equal("mkdir $DIR/app/home/vcap/data\nchown 2000:2000 $DIR/app/home/vcap/data\nmount -o bind /home/vcap/data $DIR/app/home/vcap/data\n"), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot with a line that names the path when the bind cannot be made nosuid and nodev",
			func(shellOf func() guestShell) {
				shell := shellOf()
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/two"), guestStackVolumeBinds+"echo BOUND\n", "REMOUNT_FAIL_AT="+filepath.Join(app, "home", "vcap", "data"))
				Expect(out).To(Equal("vm-launch guest setup: making the bind of the volume at /home/vcap/data in the app root nosuid and nodev failed\nREBOOT\n"), shell.name)
				Expect(calls).To(Equal(bindCalls("/home/vcap/data", "/home/vcap/data")), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot with a line that names the path when the mount point cannot be made",
			func(shellOf func() guestShell) {
				shell := shellOf()
				Expect(os.WriteFile(filepath.Join(app, "srv"), nil, 0o644)).To(Succeed())
				out, _ := runScript(shell, mountsFor("/srv/data"), guestStackVolumeBinds+"echo BOUND\n")
				Expect(out).To(HaveSuffix("vm-launch guest setup: creating the mount point of the volume at /srv/data in the app root failed\nREBOOT\n"), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot with a line that names the directory when a directory it made on the way cannot be given to uid 2000",
			func(shellOf func() guestShell) {
				shell := shellOf()
				out, calls := runScript(shell, mountsFor("/srv/data"), guestStackVolumeBinds+"echo BOUND\n", "CHOWN_FAIL_AT="+filepath.Join(app, "srv"))
				Expect(out).To(HaveSuffix("vm-launch guest setup: giving /srv, which the guest made for the volume at /srv/data, to uid 2000 failed\nREBOOT\n"), shell.name)
				Expect(calls).To(Equal("mkdir $DIR/app/srv\nchown 2000:2000 $DIR/app/srv\n"), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("gives a volume's top directory that belongs to root:root, and that directory alone, to uid 2000 before its bind, and leaves any other owner as it is",
			func(shellOf func() guestShell) {
				shell := shellOf()
				Expect(os.WriteFile(owners, []byte("0:0 /home/vcap/data\n0:1000 /srv/group\n1000:0 /srv/user\n0:0 /srv/my data\n"), 0o644)).To(Succeed())
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/group", "/srv/user", "/srv/vcap", "/srv/my data"), guestStackVolumeBinds+"echo BOUND\n")
				Expect(out).To(Equal("BOUND\n"), shell.name)
				Expect(calls).To(Equal("chown 2000:2000 /home/vcap/data\n"+bindCalls("/home/vcap/data", "/home/vcap/data")+
					bindCalls("/srv/group", "/srv", "/srv/group")+
					bindCalls("/srv/user", "/srv/user")+
					bindCalls("/srv/vcap", "/srv/vcap")+
					"chown 2000:2000 /srv/my data\n"+bindCalls("/srv/my data", "/srv/my data")), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("gives the root:root top directory of a block volume to uid 2000 as it does an image's, and never reads or changes the owner of a share, which binds as the others do",
			func(shellOf func() guestShell) {
				shell := shellOf()
				Expect(os.WriteFile(owners, []byte("0:0 /home/vcap/data\n0:0 /home/vcap/shared\n0:0 /home/vcap/disk\n"), 0o644)).To(Succeed())
				// A stat of the share would fail and print a line.
				out, calls := runScript(shell, kindMounts([]string{string(driveImage), volumeKindShare, string(driveBlock)}, "/home/vcap/data", "/home/vcap/shared", "/home/vcap/disk"),
					guestStackVolumeBinds+"echo BOUND\n", "STAT_FAIL_AT=/home/vcap/shared")
				Expect(out).To(Equal("BOUND\n"), shell.name)
				Expect(calls).To(Equal("chown 2000:2000 /home/vcap/data\n"+bindCalls("/home/vcap/data", "/home/vcap/data")+
					bindCalls("/home/vcap/shared", "/home/vcap/shared")+
					"chown 2000:2000 /home/vcap/disk\n"+bindCalls("/home/vcap/disk", "/home/vcap/disk")), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("prints a line that names the volume and goes on to bind every volume when its owner cannot be read or changed",
			func(shellOf func() guestShell, env, line string) {
				shell := shellOf()
				Expect(os.WriteFile(owners, []byte("0:0 /home/vcap/data\n0:0 /srv/two\n"), 0o644)).To(Succeed())
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/two"), guestStackVolumeBinds+"echo BOUND\n", env)
				Expect(out).To(Equal(line+"BOUND\n"), shell.name)
				Expect(calls).To(HaveSuffix("chown 2000:2000 /srv/two\n"+bindCalls("/srv/two", "/srv", "/srv/two")), shell.name)
				Expect(calls).To(ContainSubstring(bindCalls("/home/vcap/data", "/home/vcap/data")), shell.name)
			},
			append(shellEntries("a stat that fails", "STAT_FAIL_AT=/home/vcap/data",
				"vm-launch guest setup: reading the owner of the volume at /home/vcap/data failed (stat: can't stat '/home/vcap/data': No such file or directory); leaving its owner as it is\n"),
				shellEntries("a chown that fails", "CHOWN_FAIL_AT=/home/vcap/data",
					"vm-launch guest setup: giving the top directory of the volume at /home/vcap/data to uid 2000 failed (chown: /home/vcap/data: Read-only file system); the app may not create files there\n")...),
		)

		DescribeTable("keeps a status of 0 after a chown that fails",
			func(shellOf func() guestShell) {
				shell := shellOf()
				Expect(os.WriteFile(owners, []byte("0:0 /home/vcap/data\n"), 0o644)).To(Succeed())
				out, _ := runScript(shell, mountsFor("/home/vcap/data"), guestStackVolumeBinds+"(exit 0)\nrvm_status=$?\n"+guestStackVolumeTeardown+"echo \"status=$rvm_status\"\n", "CHOWN_FAIL_AT=/home/vcap/data")
				Expect(out).To(HavePrefix("vm-launch guest setup: giving the top directory of the volume at /home/vcap/data to uid 2000 failed"), shell.name)
				Expect(out).To(HaveSuffix("; the app may not create files there\nstatus=0\n"), shell.name)
			},
			shellEntries(""),
		)

		// unbindCalls are the calls of a teardown of image volumes at paths
		// after the stop, with nothing failing: for each volume, last first,
		// its unbind, its last flush, and its unmount.
		unbindCalls := func(paths ...string) string {
			calls := ""
			for i := len(paths) - 1; i >= 0; i-- {
				calls += "umount $DIR/app" + paths[i] + "\nsync -f " + paths[i] + "\numount " + paths[i] + "\n"
			}
			return calls
		}
		// earlyCalls are the calls of the early flush of image volumes at
		// paths, last first.
		earlyCalls := func(paths ...string) string {
			calls := ""
			for i := len(paths) - 1; i >= 0; i-- {
				calls += "sync -f " + paths[i] + "\n"
			}
			return calls
		}
		// teardownCalls are the calls of a teardown of image volumes at
		// paths, with no process left behind and nothing failing: the early
		// flush and the stop, and then each volume's unbind, last flush, and
		// unmount, last first.
		teardownCalls := func(paths ...string) string {
			return earlyCalls(paths...) + "kill -TERM -1\nkill -KILL -1\n" + unbindCalls(paths...)
		}
		teardownWith := func(shell guestShell, script, mounts, status string, env ...string) (string, string) {
			GinkgoHelper()
			return runScript(shell, mounts+"(exit "+status+")\nrvm_status=$?\n", guestStackVolumeWalk+script+"echo \"status=$rvm_status\"\n", env...)
		}
		teardownOf := func(shell guestShell, script, status string, paths []string, env ...string) (string, string) {
			GinkgoHelper()
			return teardownWith(shell, script, mountsFor(paths...), status, env...)
		}
		teardown := func(shell guestShell, status string, paths []string, env ...string) (string, string) {
			GinkgoHelper()
			return teardownOf(shell, guestStackVolumeTeardown, status, paths, env...)
		}
		flushFailLine := "vm-launch guest: the command exited 0, but a volume did not flush or unmount, so the guest reports the status " + guestFlushFailStatus + "\n"

		DescribeTable("unbinds each volume from the app root after the stop, last first, right before that volume's own last flush and unmount, and keeps a status of 0",
			func(shellOf func() guestShell) {
				shell := shellOf()
				paths := []string{"/home/vcap/data", "/srv/two", "/srv/three"}
				out, calls := teardown(shell, "0", paths)
				Expect(out).To(Equal("status=0\n"), shell.name)
				Expect(calls).To(Equal(teardownCalls(paths...)), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("reports the failure status for a bind that does not unmount, with a line that names the volume, and still unbinds, flushes, and unmounts the others",
			func(shellOf func() guestShell, status, want string) {
				shell := shellOf()
				paths := []string{"/home/vcap/data", "/srv/two"}
				out, calls := teardown(shell, status, paths, "UMOUNT_FAIL_AT="+filepath.Join(app, "srv", "two"))
				line := "vm-launch guest: unbinding the volume at /srv/two from the app root failed (umount: can't unmount " + filepath.Join(app, "srv", "two") + ": Device or resource busy), so the guest cannot unmount the volume cleanly\n"
				if status == "0" {
					line += "vm-launch guest: the command exited 0, but a volume did not flush or unmount, so the guest reports the status " + guestFlushFailStatus + "\n"
				}
				Expect(out).To(Equal(line+"status="+want+"\n"), shell.name)
				Expect(calls).To(Equal(teardownCalls(paths...)), shell.name)
			},
			append(shellEntries("after a command that exited 0", "0", guestFlushFailStatus),
				shellEntries("after a command that failed, which keeps its status", "3", "3")...),
		)

		DescribeTable("never unmounts what the app root holds at a volume's path once that path crosses a symbolic link, reports the volume as one that did not unmount, and still unbinds, flushes, and unmounts the others",
			func(shellOf func() guestShell, link, path string) {
				shell := shellOf()
				Expect(os.Symlink(link, filepath.Join(app, "home", "vcap", "linked"))).To(Succeed())
				paths := []string{path, "/srv/two"}
				out, calls := teardown(shell, "0", paths)
				Expect(out).To(Equal("vm-launch guest: the path of the volume at "+path+" in the app root now crosses the symbolic link /home/vcap/linked, so the guest cannot unbind the volume or unmount it cleanly\n"+
					flushFailLine+"status="+guestFlushFailStatus+"\n"), shell.name)
				Expect(calls).To(Equal(earlyCalls(paths...)+"kill -TERM -1\nkill -KILL -1\n"+
					"umount $DIR/app/srv/two\n"+
					"sync -f /srv/two\numount /srv/two\nsync -f "+path+"\numount "+path+"\n"), shell.name)
			},
			slices.Concat(
				shellEntries("an absolute link on the way", "/rvm-s5-elsewhere", "/home/vcap/linked/data"),
				shellEntries("a relative link on the way", "../../srv", "/home/vcap/linked/data"),
				shellEntries("an absolute link at the mount point", "/rvm-s5-elsewhere", "/home/vcap/linked"),
				shellEntries("a relative link at the mount point", "../../srv", "/home/vcap/linked"),
			),
		)

		DescribeTable("never unmounts what the app root holds at a volume's path when it is not the volume's own top directory, or cannot be read, and reports the volume as one that did not unmount",
			func(shellOf func() guestShell, idsOf func() string, env func() []string, lineOf func() string) {
				shell := shellOf()
				Expect(os.WriteFile(ids, []byte(idsOf()), 0o644)).To(Succeed())
				paths := []string{"/home/vcap/data", "/srv/two"}
				out, calls := teardown(shell, "0", paths, env()...)
				Expect(out).To(Equal(lineOf()+flushFailLine+"status="+guestFlushFailStatus+"\n"), shell.name)
				Expect(calls).To(Equal(earlyCalls(paths...)+"kill -TERM -1\nkill -KILL -1\n"+
					"sync -f /srv/two\numount /srv/two\n"+
					"umount $DIR/app/home/vcap/data\nsync -f /home/vcap/data\numount /home/vcap/data\n"), shell.name)
			},
			slices.Concat(
				shellEntries("a directory that is not the volume's",
					func() string { return "64768:2 " + filepath.Join(app, "srv", "two") + "\n" },
					func() []string { return nil },
					func() string {
						return "vm-launch guest: the volume at /srv/two is no longer what the app root holds at its path, so the guest cannot unbind the volume or unmount it cleanly\n"
					}),
				shellEntries("a volume whose top directory cannot be read",
					func() string { return "" },
					func() []string { return []string{"STAT_FAIL_AT=/srv/two"} },
					func() string {
						return "vm-launch guest: reading the top directory of the volume at /srv/two failed (stat: can't stat '/srv/two': No such file or directory), so the guest cannot unbind the volume or unmount it cleanly\n"
					}),
				shellEntries("a path in the app root that cannot be read",
					func() string { return "" },
					func() []string { return []string{"STAT_FAIL_AT=" + filepath.Join(app, "srv", "two")} },
					func() string {
						return "vm-launch guest: reading what the app root holds at the path of the volume at /srv/two failed (stat: can't stat '" + filepath.Join(app, "srv", "two") + "': No such file or directory), so the guest cannot unbind the volume or unmount it cleanly\n"
					}),
			),
		)

		// mixedKinds and mixedPaths are the volumes of a guest with an image, a
		// share, a BOSH disk, and a second share, in volume order.
		mixedKinds := []string{string(driveImage), volumeKindShare, string(driveBlock), volumeKindShare}
		mixedPaths := []string{"/home/vcap/data", "/home/vcap/shared", "/home/vcap/disk", "/srv/more"}
		// mixedCalls are the calls of a teardown of the mixed volumes, with
		// nothing failing: the early flush of the image and the BOSH disk,
		// the stop, and then each drive volume's unbind, last flush, and
		// unmount, last first, before each share's, last first.
		mixedCalls := "sync -f /home/vcap/disk\nsync -f /home/vcap/data\nkill -TERM -1\nkill -KILL -1\n" +
			unbindCalls("/home/vcap/data", "/home/vcap/disk") + unbindCalls("/home/vcap/shared", "/srv/more")

		DescribeTable("unbinds, flushes, and unmounts every image and block volume before it unbinds any share, so a share that hangs never keeps a disk from its last flush",
			func(shellOf func() guestShell) {
				shell := shellOf()
				out, calls := teardownWith(shell, guestStackVolumeTeardown, kindMounts(mixedKinds, mixedPaths...), "0")
				Expect(out).To(Equal("status=0\n"), shell.name)
				Expect(calls).To(Equal(mixedCalls), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("reports the failure status for a share whose bind does not unmount, after every drive volume is flushed and unmounted, and still unmounts the share and the others",
			func(shellOf func() guestShell, status, want string) {
				shell := shellOf()
				out, calls := teardownWith(shell, guestStackVolumeTeardown, kindMounts(mixedKinds, mixedPaths...), status, "UMOUNT_FAIL_AT="+filepath.Join(app, "home", "vcap", "shared"))
				line := "vm-launch guest: unbinding the volume at /home/vcap/shared from the app root failed (umount: can't unmount " + filepath.Join(app, "home", "vcap", "shared") + ": Device or resource busy), so the guest cannot unmount the volume cleanly\n"
				if status == "0" {
					line += flushFailLine
				}
				Expect(out).To(Equal(line+"status="+want+"\n"), shell.name)
				Expect(calls).To(Equal(mixedCalls), shell.name)
			},
			append(shellEntries("after a command that exited 0", "0", guestFlushFailStatus),
				shellEntries("after a command that failed, which keeps its status", "3", "3")...),
		)

		DescribeTable("after a run section, sends what is left SIGKILL with no SIGTERM first, and then unbinds, flushes, and unmounts every volume, last first",
			func(shellOf func() guestShell) {
				shell := shellOf()
				paths := []string{"/home/vcap/data", "/srv/two"}
				out, calls := teardownOf(shell, guestStackRunVolumeTeardown, "0", paths)
				Expect(out).To(Equal("status=0\n"), shell.name)
				Expect(calls).To(Equal(earlyCalls(paths...)+"kill -KILL -1\n"+unbindCalls(paths...)), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("still reports a volume that does not flush after its bind unmounted",
			func(shellOf func() guestShell) {
				shell := shellOf()
				out, _ := teardown(shell, "0", []string{"/home/vcap/data"}, "SYNC_FAIL_AT=/home/vcap/data")
				Expect(out).To(ContainSubstring("vm-launch guest: flushing the volume image volume.img on /dev/vdb at /home/vcap/data with sync -f failed"), shell.name)
				Expect(out).To(HaveSuffix("status=" + guestFlushFailStatus + "\n"))
			},
			shellEntries(""),
		)
	})
})

// The owner fields of an ext4 inode, which the low and high 16 bits of the
// uid and the gid make up.
const (
	extInodeUID     = 0x02
	extInodeGID     = 0x18
	extInodeUIDHigh = 0x78
	extInodeGIDHigh = 0x7a
)

// rootOwner returns the uid and gid of the root directory of the ext4
// filesystem on img, as "uid:gid".
func rootOwner(img *os.File) string {
	GinkgoHelper()
	inode, _ := readExtImage(img).rootInode()
	field := func(lo, hi int) uint32 {
		return uint32(binary.LittleEndian.Uint16(inode[lo:])) | uint32(binary.LittleEndian.Uint16(inode[hi:]))<<16
	}
	return fmt.Sprintf("%d:%d", field(extInodeUID, extInodeUIDHigh), field(extInodeGID, extInodeGIDHigh))
}

// hostOwner returns the uid and gid of path on the host, as "uid:gid".
func hostOwner(path string) string {
	GinkgoHelper()
	info, err := os.Stat(path)
	Expect(err).NotTo(HaveOccurred())
	st, ok := info.Sys().(*syscall.Stat_t)
	Expect(ok).To(BeTrue())
	return fmt.Sprintf("%d:%d", st.Uid, st.Gid)
}

// realStackVolumeLauncher is the test launcher of the stack guest with a
// volume at /home/vcap/data. It prints who it runs as, the volume's line in
// the app's mount table, and who owns the volume's root, prints the file that
// an earlier boot left there, if any, and then writes the file and prints who
// owns it.
const realStackVolumeLauncher = `#!/bin/sh
echo "vol-id=$(id -u)"
echo "vol-mount=$(/bin/busybox grep ' /home/vcap/data ' /proc/self/mounts)"
echo "vol-root=$(stat -c %u:%g /home/vcap/data)"
if [ -e /home/vcap/data/proof ]; then
	echo "vol-found=$(cat /home/vcap/data/proof)"
fi
echo "written-by-$(id -u)" >/home/vcap/data/proof && echo "vol-wrote=$(stat -c %u:%g /home/vcap/data/proof)"
`

// realStackVolume is one volume of a real stack guest at path: an image or
// block volume of kind on img, or, with no kind, a share of the host
// directory dir.
type realStackVolume struct {
	path string
	kind driveKind
	img  *os.File
	dir  string
}

// serveStackShare serves dir with the real virtiofsd as the share of the
// volume at index, on a socket in a short directory of its own, since a Unix
// socket path is short, and returns the share's socket.
func serveStackShare(index int, dir string) shareSocket {
	GinkgoHelper()
	vfs := realShareVirtiofsd()
	sockDir, err := os.MkdirTemp("", "rvm-s")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { os.RemoveAll(sockDir) })
	tag := shareTag(index)
	sock := filepath.Join(sockDir, shareSocketName(tag))
	serveRealShare(vfs, sock, dir)
	return shareSocket{Index: index, Tag: tag, Path: sock}
}

var _ = Describe("the stack guest with a volume against a real QEMU", func() {
	// bootStackVolumes boots a real guest under TCG with the test stack, a
	// droplet, the launcher realStackVolumeLauncher, and vols in volume
	// order, with a guest root image when withRoot is set, and returns the
	// console output without carriage returns and with the app's lines
	// unframed. The real virtiofsd serves
	// each share. tweak, when it is not nil, may change the guest and its
	// stack drives before the drives are numbered. It fails the spec unless
	// QEMU exits 0 and the guest started its command.
	bootStackVolumes := func(withRoot bool, vols []realStackVolume, tweak func(*guestContents, *stackDrives)) string {
		GinkgoHelper()
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}
		lf, err := os.Open(writeTempFile("launcher", realStackVolumeLauncher))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(lf.Close)
		g := taskGuest("")
		g.stack = &guestStack{
			launcher: guestTool{name: "launcher", file: lf, size: int64(len(realStackVolumeLauncher))},
			argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", "{}"}),
			cwd:      "/home/vcap",
			hostname: "stack-guest-0",
			hosts:    []byte("127.0.0.1 localhost\n"),
		}
		var atts []*attachment
		var volumeDrives []guestDrive
		var shares []shareSocket
		for i, v := range vols {
			if v.kind == "" {
				g.vols = append(g.vols, guestVolume{ContainerDir: v.path, Settings: volumeSettings{Mode: volumeShare}})
				shares = append(shares, serveStackShare(i, v.dir))
				continue
			}
			vol := guestVolume{ContainerDir: v.path}
			if v.kind == driveImage {
				vol.ImageName = "volume.img"
			}
			g.vols = append(g.vols, vol)
			info, err := v.img.Stat()
			Expect(err).NotTo(HaveOccurred())
			// A block volume's file is a regular file here, which QEMU opens
			// as it does an image, and only the drive's kind tells the guest
			// that it is a block volume.
			atts = append(atts, &attachment{File: v.img, Mode: attachFileImage, ID: qemuVolumeSerial(i), Index: i, Release: func() error { return nil }})
			volumeDrives = append(volumeDrives, guestDrive{id: qemuVolumeSerial(i), kind: v.kind, bytes: info.Size()})
		}
		var root *os.File
		if withRoot {
			withRealRoot(&g)
			root = realRootImage()
		}
		if tweak != nil {
			tweak(&g, sd)
		}
		g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, root, sd)
		Expect(err).NotTo(HaveOccurred())
		g.drives.volumes = volumeDrives

		f := newRealInitramfs(g)
		files, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(atts, withUserspaceMark(f), nil, root, sd)
		hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd, shares...)
		Expect(err).NotTo(HaveOccurred())
		code, stdout, stderr := bootRealQEMU(markedArgv(tcgArgv(qemu, hvArgv)), files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		Expect(stdout).To(ContainSubstring(startTag(testNonce)), stdout)
		return unframeApp(strings.ReplaceAll(stdout, "\r", ""), testNonce)
	}
	// bootStackVolume is bootStackVolumes with img as the one volume, an
	// image volume at /home/vcap/data.
	bootStackVolume := func(img *os.File, withRoot bool) string {
		GinkgoHelper()
		return bootStackVolumes(withRoot, []realStackVolume{{path: "/home/vcap/data", kind: driveImage, img: img}}, nil)
	}

	DescribeTable("formats a new volume image for vcap, lets the app write to it as uid 2000 through a nosuid and nodev bind, stops with status 0 after a clean unmount, and finds the file at the next boot",
		func(withRoot bool) {
			img := openSizedFile(defaultImageSize)
			out := bootStackVolume(img, withRoot)
			Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
			Expect(out).To(MatchRegexp(`(?m)^vol-id=2000$`), out)
			Expect(out).To(MatchRegexp(`(?m)^vol-mount=\S+ /home/vcap/data ext4 \S*\bnosuid\b`), out)
			Expect(out).To(MatchRegexp(`(?m)^vol-mount=\S+ /home/vcap/data ext4 \S*\bnodev\b`), out)
			Expect(out).To(MatchRegexp(`(?m)^vol-root=2000:2000$`), out)
			Expect(out).To(MatchRegexp(`(?m)^vol-wrote=2000:2000$`), out)
			Expect(out).NotTo(ContainSubstring("vol-found="), out)
			Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
			Expect(extLabel(img)).To(Equal("rvm-volume"))

			// A bind left mounted would have kept the filesystem mounted
			// past the volume's unmount, and its journal would need
			// recovery now.
			out = bootStackVolume(img, withRoot)
			Expect(out).NotTo(ContainSubstring("recovering journal"), out)
			Expect(out).To(MatchRegexp(`(?m)^rvm-volume: clean, [0-9]+/[0-9]+ files, [0-9]+/[0-9]+ blocks$`), out)
			Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
			Expect(out).To(MatchRegexp(`(?m)^vol-found=written-by-2000$`), out)
			Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		},
		Entry("on a guest root disk", true),
		Entry("with the app root's upper layer in RAM", false),
	)

	It("gives the top directory of a volume image whose root belongs to root:root, as the busybox guest formats one, to uid 2000, so the app can write there", func() {
		img := openSizedFile(defaultImageSize)
		out := bootStackVolume(img, false)
		Expect(out).To(MatchRegexp(`(?m)^vol-wrote=2000:2000$`), out)
		readExtImage(img).editRoot(func(inode []byte) {
			for _, off := range []int{extInodeUID, extInodeGID, extInodeUIDHigh, extInodeGIDHigh} {
				binary.LittleEndian.PutUint16(inode[off:], 0)
			}
		})
		Expect(rootOwner(img)).To(Equal("0:0"))

		out = bootStackVolume(img, false)
		Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
		Expect(out).To(MatchRegexp(`(?m)^rvm-volume: clean, [0-9]+/[0-9]+ files, [0-9]+/[0-9]+ blocks$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-root=2000:2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-found=written-by-2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-wrote=2000:2000$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(rootOwner(img)).To(Equal("2000:2000"))
	})

	It("binds a share that the real virtiofsd serves with nosuid and nodev, leaves its top directory's owner as it is, lets the app write to it as uid 2000, and finds the file at the next boot", func() {
		dir := GinkgoT().TempDir()
		// Anyone may write to the top directory, which belongs to whoever
		// runs the spec, so a guest that gave it to uid 2000 would show on
		// the host, and the app can write there either way.
		Expect(os.Chmod(dir, 0o777)).To(Succeed())
		owner := hostOwner(dir)
		share := []realStackVolume{{path: "/home/vcap/data", dir: dir}}
		out := bootStackVolumes(false, share, nil)
		Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-id=2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-mount=`+shareTag(0)+` /home/vcap/data virtiofs \S*\bnosuid\b`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-mount=`+shareTag(0)+` /home/vcap/data virtiofs \S*\bnodev\b`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-root=`+owner+`$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-wrote=2000:2000$`), out)
		Expect(out).NotTo(ContainSubstring("vol-found="), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(hostOwner(dir)).To(Equal(owner))
		proof := filepath.Join(dir, "proof")
		Expect(os.ReadFile(proof)).To(Equal([]byte("written-by-2000\n")))
		Expect(hostOwner(proof)).To(Equal("2000:2000"))

		out = bootStackVolumes(false, share, nil)
		Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-found=written-by-2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-wrote=2000:2000$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(hostOwner(dir)).To(Equal(owner))
	})

	// formatAsImage makes the filesystem that a BOSH disk already holds on
	// img with a boot of the stack guest that mounts img as an image volume,
	// and gives its root to root:root, as the BOSH agent formats a disk. It
	// returns the filesystem's UUID.
	formatAsImage := func(img *os.File) string {
		GinkgoHelper()
		out := bootStackVolume(img, false)
		Expect(out).To(MatchRegexp(`(?m)^vol-wrote=2000:2000$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		readExtImage(img).editRoot(func(inode []byte) {
			for _, off := range []int{extInodeUID, extInodeGID, extInodeUIDHigh, extInodeGIDHigh} {
				binary.LittleEndian.PutUint16(inode[off:], 0)
			}
		})
		Expect(rootOwner(img)).To(Equal("0:0"))
		return readExtImage(img).uuid()
	}

	// expectCleanImage boots the stack guest with img as an image volume,
	// whose check before the mount finds the filesystem clean only if the
	// boot before unmounted it, and expects the file the stack guest wrote.
	expectCleanImage := func(img *os.File) {
		GinkgoHelper()
		out := bootStackVolume(img, false)
		Expect(out).NotTo(ContainSubstring("recovering journal"), out)
		Expect(out).To(MatchRegexp(`(?m)^rvm-volume: clean, [0-9]+/[0-9]+ files, [0-9]+/[0-9]+ blocks$`), out)
		Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-found=written-by-2000$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
	}

	It("mounts a BOSH disk as a block volume without formatting or checking it, gives its root:root top directory to uid 2000 through a nosuid and nodev bind, and unmounts it cleanly", func() {
		img := openSizedFile(defaultImageSize)
		uuid := formatAsImage(img)

		out := bootStackVolumes(false, []realStackVolume{{path: "/home/vcap/data", kind: driveBlock, img: img}}, nil)
		Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
		Expect(out).NotTo(ContainSubstring("rvm-volume: clean"), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-id=2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-mount=\S+ /home/vcap/data ext4 \S*\bnosuid\b`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-mount=\S+ /home/vcap/data ext4 \S*\bnodev\b`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-root=2000:2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-found=written-by-2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^vol-wrote=2000:2000$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(rootOwner(img)).To(Equal("2000:2000"))
		Expect(readExtImage(img).uuid()).To(Equal(uuid), "the block volume was formatted")

		expectCleanImage(img)
	})

	It("falls back to the busybox guest with a share and a BOSH disk when the stack image does not mount, which mounts both as root's and unmounts them cleanly", func() {
		img := openSizedFile(defaultImageSize)
		formatAsImage(img)
		dir := GinkgoT().TempDir()
		Expect(os.Chmod(dir, 0o755)).To(Succeed())

		vols := []realStackVolume{{path: "/home/vcap/shared", dir: dir}, {path: "/home/vcap/disk", kind: driveBlock, img: img}}
		out := bootStackVolumes(false, vols, func(g *guestContents, sd *stackDrives) {
			// The superblock is gone, so the squashfs mount fails.
			image, err := io.ReadAll(io.NewSectionReader(sd.stack, 0, 1<<30))
			Expect(err).NotTo(HaveOccurred())
			copy(image, make([]byte, 4096))
			f, err := os.Open(writeTempFile("corrupt-stack", string(image)))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(f.Close)
			sd.stack = f

			g.command = `echo "fallback-ran uid=$(id -u)"
echo "disk-found=$(cat /home/vcap/disk/proof)"
echo from-the-fallback >/home/vcap/shared/note
grep -E ' /home/vcap/(shared|disk) ' /proc/mounts | cut -d ' ' -f 2,3 | sed 's/^/fallback-mount=/'`
			g.stack.fallback = true
		})
		Expect(out).To(MatchRegexp(`(?m)^busybox guest: mounting the stack image /dev/vd[a-z] failed`), out)
		Expect(out).To(MatchRegexp(`(?m)^fallback-ran uid=0$`), out)
		Expect(out).To(MatchRegexp(`(?m)^disk-found=written-by-2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^fallback-mount=/home/vcap/shared virtiofs$`), out)
		Expect(out).To(MatchRegexp(`(?m)^fallback-mount=/home/vcap/disk ext4$`), out)
		Expect(out).NotTo(ContainSubstring("vol-id="), out)
		Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(os.ReadFile(filepath.Join(dir, "note"))).To(Equal([]byte("from-the-fallback\n")))
		// The busybox guest leaves the owner of a BOSH disk's root as it is.
		Expect(rootOwner(img)).To(Equal("0:0"))

		expectCleanImage(img)
	})
})

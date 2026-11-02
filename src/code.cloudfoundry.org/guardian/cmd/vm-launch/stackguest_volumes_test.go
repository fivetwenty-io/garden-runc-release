//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the volumes of the stack guest", func() {
	Describe("stackModeAllowsVolumes", func() {
		image := func(path string) selectedVolume {
			return selectedVolume{Volume: guestVolume{ContainerDir: path}, Provider: fake("JuiceFS")}
		}
		share := func(path string) selectedVolume {
			v := image(path)
			v.Volume.Settings.Mode = volumeShare
			return v
		}
		boshDisk := func(path string) selectedVolume {
			p := fake("BOSH disk")
			p.caps = capabilities{Modes: []attachMode{attachBlock}, Fence: fenceExclusiveOpen}
			return selectedVolume{Volume: guestVolume{ContainerDir: path}, Provider: p}
		}

		It("allows an app without volumes and an app whose volumes are all private disk images", func() {
			for _, selected := range [][]selectedVolume{nil, {image("/home/vcap/data")}, {image("/data"), image("/home/vcap/more")}} {
				ok, why := stackModeAllowsVolumes(selected)
				Expect(ok).To(BeTrue(), why)
				Expect(why).To(BeEmpty())
			}
		})

		It("allows a provider that offers both modes, which gives a private volume a disk image", func() {
			v := image("/data")
			v.Provider.(*fakeDiskProvider).caps = capabilities{Modes: []attachMode{attachBlock, attachFileImage}, Fence: fenceDistributedFlock}
			ok, why := stackModeAllowsVolumes([]selectedVolume{v})
			Expect(ok).To(BeTrue(), why)
		})

		DescribeTable("keeps the busybox guest for a share or a BOSH disk, naming the first such volume",
			func(selected []selectedVolume, want string) {
				ok, why := stackModeAllowsVolumes(selected)
				Expect(ok).To(BeFalse())
				Expect(why).To(Equal(want))
			},
			Entry("a share", []selectedVolume{share("/home/vcap/shared")},
				`the volume at "/home/vcap/shared" is a share, which the stack guest does not mount yet`),
			Entry("a BOSH disk", []selectedVolume{boshDisk("/home/vcap/disk")},
				`the volume at "/home/vcap/disk" is a BOSH disk, which the stack guest does not mount yet`),
			Entry("a share after an image and before a BOSH disk", []selectedVolume{image("/a"), share("/b"), boshDisk("/c")},
				`the volume at "/b" is a share, which the stack guest does not mount yet`),
			Entry("a share that the provider would serve as a disk image", []selectedVolume{share("/data")},
				`the volume at "/data" is a share, which the stack guest does not mount yet`),
			Entry("a volume without a provider", []selectedVolume{{Volume: guestVolume{ContainerDir: "/x"}}},
				`the volume at "/x" has no provider, so the stack guest cannot tell what kind of disk it is`),
		)
	})

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

		It("is the stack guest's own with the volume setup and the binds before the start tag, and the stack teardown after the command", func() {
			s := &guestStack{}
			plain := s.initScript(testNonce)
			Expect(plain).To(Equal(stackInitScript(testNonce)))
			Expect(plain).NotTo(ContainSubstring("/rvm/mounts"))
			script := s.initScriptWithVolumes(testNonce, true)
			start := strings.Index(script, "echo "+startTag(testNonce)+"\n")
			Expect(start).To(BeNumerically(">", 0))
			setup := strings.Index(script, guestStackVolumeSetup+guestStackVolumeBinds)
			Expect(setup).To(BeNumerically(">", 0))
			Expect(setup + len(guestStackVolumeSetup+guestStackVolumeBinds)).To(BeNumerically("<=", start))
			Expect(script).To(Equal(strings.NewReplacer(
				guestStopReader(testNonce), guestStackVolumeSetup+guestStackVolumeBinds+guestStopReader(testNonce),
				guestOOMReport(testNonce), guestOOMReport(testNonce)+guestStackVolumeTeardown,
			).Replace(plain)))
			Expect(script).NotTo(ContainSubstring(guestVolumeSetup))
		})

		It("binds and unbinds the volumes in a guest whose app runs through the run section too", func() {
			s := &guestStack{sidecars: []guestSidecar{{argv: "'sidecar'"}}}
			script := s.initScriptWithVolumes(testNonce, true)
			start := strings.Index(script, "echo "+startTag(testNonce)+"\n")
			Expect(strings.Index(script, guestStackVolumeBinds)).To(BeNumerically("<", start))
			Expect(strings.Index(script, guestStackVolumeTeardown)).To(BeNumerically(">", start))
			Expect(strings.Index(script, guestStackVolumeTeardown)).To(BeNumerically(">", strings.Index(script, guestRunSection(testNonce, s.processes(), false, stackExec))))
		})

		It("unbinds after the processes the command left are stopped, and before any volume's last flush and unmount", func() {
			Expect(guestVolumeTeardown).To(Equal(guestVolumeTeardownStop + guestVolumeTeardownUnmount))
			Expect(guestVolumeTeardownStop).To(HaveSuffix("rvm_vbad=\n"))
			Expect(guestStackVolumeTeardown).To(HavePrefix(guestVolumeTeardownStop))
			Expect(guestStackVolumeTeardown).To(HaveSuffix(guestVolumeTeardownUnmount))
			unbind := strings.TrimSuffix(strings.TrimPrefix(guestStackVolumeTeardown, guestVolumeTeardownStop), guestVolumeTeardownUnmount)
			Expect(unbind).To(ContainSubstring(`umount "` + guestAppRoot + `$rvm_vpath"`))
			Expect(unbind).NotTo(ContainSubstring("sync"))
			Expect(unbind).NotTo(ContainSubstring("kill"))
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

		It("gives the busybox guest that a stack guest without volumes falls back to a stage 2 without them", func() {
			g := stackGuest()
			g.vols, g.drives.volumes = nil, nil
			g.stack.fallback = true
			byName := archive(g)
			Expect(string(byName["rvm/init"].data)).To(Equal(stackInitScript(testNonce)))
			Expect(string(byName[strings.TrimPrefix(guestFallbackInit, "/")].data)).To(Equal(initScript(testNonce, false)))
			Expect(byName).NotTo(HaveKey("rvm/mounts"))
		})
	})

	Describe("in the guest's shell", func() {
		var dir, bin, app, callLog, owners string

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
			stub("mount", `[ "${MOUNT_FAIL_AT:-}" != "$4" ] || exit 32`)
			stub("umount", `[ "${UMOUNT_FAIL_AT:-}" != "$1" ] || { echo "umount: can't unmount $1: Device or resource busy" >&2; exit 1; }`)
			stub("sync", `[ "${SYNC_FAIL_AT:-}" != "$2" ] || { echo "sync: $2: Input/output error" >&2; exit 1; }`)
			stub("kill", `exit 0`)
			stub("sleep", `echo "the teardown waited, though no other process runs" >&2; exit 1`)
			stub("chown", `[ "${CHOWN_FAIL_AT:-}" != "$2" ] || { echo "chown: $2: Read-only file system" >&2; exit 1; }`)
			// stat records nothing. It prints the owner that the file
			// owners lists for its path, or 2000:2000 for a path that
			// owners does not list, and fails for the path STAT_FAIL_AT
			// names.
			owners = filepath.Join(dir, "owners")
			Expect(os.WriteFile(filepath.Join(bin, "stat"), []byte(`#!/bin/sh
if [ "${STAT_FAIL_AT:-}" = "$3" ]; then
	echo "stat: can't stat '$3': No such file or directory" >&2
	exit 1
fi
if [ -e `+shellQuote(owners)+` ]; then
	while IFS=' ' read -r rvm_o rvm_p; do
		[ "$rvm_p" != "$3" ] || { echo "$rvm_o"; exit 0; }
	done <`+shellQuote(owners)+`
fi
echo 2000:2000
`), 0o755)).To(Succeed())
		})

		// mountsFor is the part of /rvm/mounts that the binds and the
		// teardown read, for an image volume at each of paths.
		mountsFor := func(paths ...string) string {
			m := "RVM_VOLUMES=" + string(rune('0'+len(paths))) + "\n"
			for i, p := range paths {
				n := string(rune('0' + i))
				m += "RVM_VOL" + n + "_KIND=image\nRVM_VOL" + n + "_PATH=" + shellQuote(p) + "\nRVM_VOL" + n + "_IMAGE=volume.img\nrvm_vdev_" + n + "=/dev/vd" + string(rune('b'+i)) + "\n"
			}
			return m
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
				`mkdir -p "`, filepath.Join(bin, "mkdir")+` -p "`,
				"mount -o bind ", filepath.Join(bin, "mount")+" -o bind ",
				`umount "`, filepath.Join(bin, "umount")+` "`,
				`sync -f "`, filepath.Join(bin, "sync")+` -f "`,
				"kill -", filepath.Join(bin, "kill")+" -",
				"\tsleep ", "\t"+filepath.Join(bin, "sleep")+" ",
				"$(stat -c ", "$("+filepath.Join(bin, "stat")+" -c ",
				"$(chown ", "$("+filepath.Join(bin, "chown")+" ",
				guestProcDir+"/[0-9]*", shellQuote(filepath.Join(dir, "proc"))+"/[0-9]*",
			).Replace(script)
			Expect(moved).NotTo(ContainSubstring(guestAppRoot))
			Expect(strings.Count(moved, "mount -o bind")).To(Equal(strings.Count(moved, filepath.Join(bin, "mount")+" -o bind")))
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

		DescribeTable("binds each volume to the same path in the app root, in volume order, making the mount point first",
			func(shellOf func() guestShell) {
				shell := shellOf()
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/my data"), guestStackVolumeBinds+"echo BOUND\n")
				Expect(out).To(Equal("BOUND\n"), shell.name)
				Expect(calls).To(Equal("mkdir -p $DIR/app/home/vcap/data\n"+
					"mount -o bind /home/vcap/data $DIR/app/home/vcap/data\n"+
					"mkdir -p $DIR/app/srv/my data\n"+
					"mount -o bind /srv/my data $DIR/app/srv/my data\n"), shell.name)
				Expect(filepath.Join(app, "srv", "my data")).To(BeADirectory())
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot with a line that names the path, and binds nothing more, when a volume's path crosses a symbolic link in the app root",
			func(shellOf func() guestShell, link string) {
				shell := shellOf()
				Expect(os.Symlink(link, filepath.Join(app, "home", "vcap", "linked"))).To(Succeed())
				out, calls := runScript(shell, mountsFor("/srv/first", "/home/vcap/linked/data", "/srv/third"), guestStackVolumeBinds+"echo BOUND\n")
				Expect(out).To(Equal("vm-launch guest setup: the volume path /home/vcap/linked/data crosses the symbolic link /home/vcap/linked in the app root, so the guest will not bind the volume there\nREBOOT\n"), shell.name)
				Expect(calls).To(Equal("mkdir -p $DIR/app/srv/first\nmount -o bind /srv/first $DIR/app/srv/first\n"), shell.name)
				Expect("/rvm-s5-elsewhere").NotTo(BeAnExistingFile())
			},
			append(shellEntries("an absolute link", "/rvm-s5-elsewhere"),
				shellEntries("a relative link", "../../srv")...),
		)

		DescribeTable("fails the boot with a line that names the path when the bind fails",
			func(shellOf func() guestShell) {
				shell := shellOf()
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/two"), guestStackVolumeBinds+"echo BOUND\n", "MOUNT_FAIL_AT="+filepath.Join(app, "home", "vcap", "data"))
				Expect(out).To(Equal("vm-launch guest setup: binding the volume at /home/vcap/data into the app root failed\nREBOOT\n"), shell.name)
				Expect(calls).To(Equal("mkdir -p $DIR/app/home/vcap/data\nmount -o bind /home/vcap/data $DIR/app/home/vcap/data\n"), shell.name)
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

		DescribeTable("gives a volume's top directory that belongs to root:root, and that directory alone, to uid 2000 before its bind, and leaves any other owner as it is",
			func(shellOf func() guestShell) {
				shell := shellOf()
				Expect(os.WriteFile(owners, []byte("0:0 /home/vcap/data\n0:1000 /srv/group\n1000:0 /srv/user\n0:0 /srv/my data\n"), 0o644)).To(Succeed())
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/group", "/srv/user", "/srv/vcap", "/srv/my data"), guestStackVolumeBinds+"echo BOUND\n")
				Expect(out).To(Equal("BOUND\n"), shell.name)
				Expect(calls).To(Equal("chown 2000:2000 /home/vcap/data\n"+
					"mkdir -p $DIR/app/home/vcap/data\nmount -o bind /home/vcap/data $DIR/app/home/vcap/data\n"+
					"mkdir -p $DIR/app/srv/group\nmount -o bind /srv/group $DIR/app/srv/group\n"+
					"mkdir -p $DIR/app/srv/user\nmount -o bind /srv/user $DIR/app/srv/user\n"+
					"mkdir -p $DIR/app/srv/vcap\nmount -o bind /srv/vcap $DIR/app/srv/vcap\n"+
					"chown 2000:2000 /srv/my data\n"+
					"mkdir -p $DIR/app/srv/my data\nmount -o bind /srv/my data $DIR/app/srv/my data\n"), shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("prints a line that names the volume and goes on to bind every volume when its owner cannot be read or changed",
			func(shellOf func() guestShell, env, line string) {
				shell := shellOf()
				Expect(os.WriteFile(owners, []byte("0:0 /home/vcap/data\n0:0 /srv/two\n"), 0o644)).To(Succeed())
				out, calls := runScript(shell, mountsFor("/home/vcap/data", "/srv/two"), guestStackVolumeBinds+"echo BOUND\n", env)
				Expect(out).To(Equal(line+"BOUND\n"), shell.name)
				Expect(calls).To(HaveSuffix("chown 2000:2000 /srv/two\nmkdir -p $DIR/app/srv/two\nmount -o bind /srv/two $DIR/app/srv/two\n"), shell.name)
				Expect(calls).To(ContainSubstring("mount -o bind /home/vcap/data $DIR/app/home/vcap/data\n"), shell.name)
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

		// teardownCalls are the calls of a teardown of image volumes at
		// paths, with no process left behind and nothing failing: the early
		// flush and the stop, then the unbinds, and then each volume's last
		// flush and unmount, all last first.
		teardownCalls := func(paths ...string) string {
			calls := ""
			for i := len(paths) - 1; i >= 0; i-- {
				calls += "sync -f " + paths[i] + "\n"
			}
			calls += "kill -TERM -1\nkill -KILL -1\n"
			for i := len(paths) - 1; i >= 0; i-- {
				calls += "umount $DIR/app" + paths[i] + "\n"
			}
			for i := len(paths) - 1; i >= 0; i-- {
				calls += "sync -f " + paths[i] + "\numount " + paths[i] + "\n"
			}
			return calls
		}
		teardown := func(shell guestShell, status string, paths []string, env ...string) (string, string) {
			GinkgoHelper()
			return runScript(shell, mountsFor(paths...)+"(exit "+status+")\nrvm_status=$?\n", guestStackVolumeTeardown+"echo \"status=$rvm_status\"\n", env...)
		}

		DescribeTable("unbinds every volume from the app root, last first, after the stop and before the volumes' own flushes and unmounts, and keeps a status of 0",
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

// realStackVolumeLauncher is the test launcher of the stack guest with a
// volume at /home/vcap/data. It prints who it runs as and who owns the
// volume's root, prints the file that an earlier boot left there, if any,
// and then writes the file and prints who owns it.
const realStackVolumeLauncher = `#!/bin/sh
echo "vol-id=$(id -u)"
echo "vol-root=$(stat -c %u:%g /home/vcap/data)"
if [ -e /home/vcap/data/proof ]; then
	echo "vol-found=$(cat /home/vcap/data/proof)"
fi
echo "written-by-$(id -u)" >/home/vcap/data/proof && echo "vol-wrote=$(stat -c %u:%g /home/vcap/data/proof)"
`

var _ = Describe("the stack guest with a volume against a real QEMU", func() {
	// bootStackVolume boots a real guest under TCG with the test stack, a
	// droplet, the launcher realStackVolumeLauncher, and img as an image
	// volume at /home/vcap/data, with a guest root image when withRoot is
	// set, and returns the console output without carriage returns. It
	// fails the spec unless QEMU exits 0 and the guest started the launcher.
	bootStackVolume := func(img *os.File, withRoot bool) string {
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
		g.vols = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "volume.img"}}
		var root *os.File
		if withRoot {
			withRealRoot(&g)
			root = realRootImage()
		}
		g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, root, sd)
		Expect(err).NotTo(HaveOccurred())
		info, err := img.Stat()
		Expect(err).NotTo(HaveOccurred())
		g.drives.volumes = qemuImageDrives(info.Size())

		f := newRealInitramfs(g)
		files, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(imageAttachments(img), withUserspaceMark(f), nil, root, sd)
		hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd)
		Expect(err).NotTo(HaveOccurred())
		code, stdout, stderr := bootRealQEMU(markedArgv(tcgArgv(qemu, hvArgv)), files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		Expect(stdout).To(ContainSubstring(startTag(testNonce)), stdout)
		return strings.ReplaceAll(stdout, "\r", "")
	}

	DescribeTable("formats a new volume image for vcap, lets the app write to it as uid 2000 through the bind, stops with status 0 after a clean unmount, and finds the file at the next boot",
		func(withRoot bool) {
			img := openSizedFile(defaultImageSize)
			out := bootStackVolume(img, withRoot)
			Expect(out).NotTo(ContainSubstring("vm-launch guest"), out)
			Expect(out).To(MatchRegexp(`(?m)^vol-id=2000$`), out)
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
})

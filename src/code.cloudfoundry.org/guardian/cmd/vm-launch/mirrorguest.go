//go:build linux

package main

import (
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
)

// fileTag returns the prefix of every console input line of a push of a
// mirrored file, with its "=" (see mirrorFrames).
func fileTag(nonce string) string { return "RVM_FILE_" + nonce + "=" }

// fileOKTag returns the tag of the console output line that reports a pushed
// file the guest installed, with its "=". The sequence follows the tag.
func fileOKTag(nonce string) string { return "RVM_FILEOK_" + nonce + "=" }

// fileBadTag returns the tag of the console output line that reports a
// pushed file the guest refused, with its "=". The sequence follows the tag.
func fileBadTag(nonce string) string { return "RVM_FILEBAD_" + nonce + "=" }

// fileOnTag returns the tag of the console output line, before the start
// tag, with which a guest says that its console no longer echoes its input
// and that it takes pushes of mirrored files. vm-launch pushes none to a
// guest that never says so (see mountMirror.guestSetup).
func fileOnTag(nonce string) string { return "RVM_FILEON_" + nonce }

// mirrorOffTag returns the tag of the console output line, before the start
// tag, with which a stack guest that fell back to the busybox guest says that
// it removed its mirrored mounts (see mountMirror.fallbackPrep).
func mirrorOffTag(nonce string) string { return "RVM_MIRROROFF_" + nonce }

// fallbackPrep is the commands with which a stack guest that falls back to
// the busybox guest removes the staged copies of its mirrored mounts and
// says so on the console. The busybox guest runs its command as root on the
// initramfs, where the copies are, so it gets none of them, as it gets none
// at launch. A nil mirror has no commands, which leaves the fallback as it
// is without mirrored mounts.
func (m *mountMirror) fallbackPrep(nonce string) string {
	if m == nil {
		return ""
	}
	return "rm -rf " + guestMirrorStage + " " + guestMirrorNext + ` || rvm_fail "removing the mirrored mounts for the busybox guest failed"
echo ` + mirrorOffTag(nonce) + " >/dev/console 2>/dev/null || echo " + mirrorOffTag(nonce) + "\n"
}

// Symlink adds a symbolic link to target.
func (c *cpioWriter) Symlink(name, target string) error {
	return c.ownedSymlink(name, target, 0, 0)
}

// ownedSymlink is Symlink for a link that uid and gid own.
func (c *cpioWriter) ownedSymlink(name, target string, uid, gid uint32) error {
	if err := c.ownedEntry(name, cpioTypeSymlink, 0o777, uid, gid, 1, uint32(len(target))); err != nil {
		return err
	}
	if _, err := io.WriteString(c.w, target); err != nil {
		return fmt.Errorf("cpio entry %q: writing the link's target: %w", name, err)
	}
	return c.pad(int64(len(target)))
}

// ownedEntry is entry for an entry that uid and gid own, without a device.
func (c *cpioWriter) ownedEntry(name string, fileType, perm, uid, gid, nlink, size uint32) error {
	if name == "" || name == cpioTrailer || strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.ContainsRune(name, 0) {
		return fmt.Errorf("cpio entry name %q must be a clean relative path", name)
	}
	if perm&^cpioPermMask != 0 {
		return fmt.Errorf("cpio entry %q: permission bits %o outside %o", name, perm, cpioPermMask)
	}
	c.ino++
	return c.ownedHeader(name, c.ino, fileType|perm, uid, gid, nlink, size, 0, 0)
}

// ownedFile adds a regular file that uid and gid own, holding data.
func (c *cpioWriter) ownedFile(name string, perm, uid, gid uint32, data []byte) error {
	if int64(len(data)) > cpioMaxSize {
		return fmt.Errorf("cpio entry %q: size %d outside newc range 0..%d", name, len(data), uint32(cpioMaxSize))
	}
	if err := c.ownedEntry(name, cpioTypeRegular, perm, uid, gid, 1, uint32(len(data))); err != nil {
		return err
	}
	if _, err := c.w.Write(data); err != nil {
		return fmt.Errorf("cpio entry %q: copying data: %w", name, err)
	}
	return c.pad(int64(len(data)))
}

// stage returns the initramfs path of mount i, counted from 0.
func mirrorStage(i int) string { return guestMirrorStage + "/" + strconv.Itoa(i+1) }

// stackSteps are the initramfs entries of the mirrored mounts: each mount's
// copy at its staging path, with the owners and permission bits that the
// container shows, and guestMirrorNext when the guest takes pushes. A nil
// mirror adds nothing.
func (m *mountMirror) stackSteps(cw *cpioWriter) []func() error {
	if m == nil {
		return nil
	}
	steps := []func() error{func() error { return cw.Dir(strings.TrimPrefix(guestMirrorStage, "/"), 0o755) }}
	if m.watching() {
		steps = append(steps, func() error { return cw.Dir(strings.TrimPrefix(guestMirrorNext, "/"), 0o700) })
	}
	for i, mm := range m.mounts {
		stage := strings.TrimPrefix(mirrorStage(i), "/")
		for _, e := range mm.entries {
			name := stage
			if e.rel != "" {
				name += "/" + e.rel
			}
			steps = append(steps, mirrorEntryStep(cw, name, e))
		}
	}
	return steps
}

func mirrorEntryStep(cw *cpioWriter, name string, e mirrorEntry) func() error {
	return func() error {
		switch e.kind {
		case mirrorDir:
			return cw.ownedEntry(name, cpioTypeDir, e.perm, e.uid, e.gid, 2, 0)
		case mirrorLink:
			return cw.ownedSymlink(name, e.target, e.uid, e.gid)
		default:
			return cw.ownedFile(name, e.perm, e.uid, e.gid, e.data)
		}
	}
}

// guestSetup is the setup step of a guest with mirrored mounts, before the
// start tag. For each mount, parents first, it refuses a symbolic link at
// any component of the mount's path in the app root, because stage 2 runs
// outside the app root and would follow the link to a path of the guest's
// own, creates the mount point, binds the staged copy onto it, and remounts
// the bind read-only, nosuid, and nodev, and noexec when the container's
// mount had it. A bind takes a remount for those, because the kernel ignores
// them on the bind itself. A file's mount point is created empty only when
// nothing is there. Any failure is a named setup step, because an app that
// expects a mounted file should not start without it.
//
// A guest that takes pushes then says so with fileOnTag, unless its console
// still echoes (see guestIdentityEchoCheck, which sets rvm_echo and which
// initScriptWithVolumes runs first).
func (m *mountMirror) guestSetup(nonce string) string {
	if m == nil {
		return ""
	}
	var b strings.Builder
	for i, mm := range m.mounts {
		dest := guestAppRoot + mm.path
		var links []string
		for p := dest; len(p) > len(guestAppRoot); p = path.Dir(p) {
			links = append([]string{"[ ! -L " + shellQuote(p) + " ]"}, links...)
		}
		q := shellQuote(dest)
		where := quoteForLog(mm.path)
		b.WriteString(strings.Join(links, " && ") + ` || rvm_fail "a component of the mirrored mount ` + shellEscapeDQ(where) + ` in the app root is a symbolic link, so it cannot be mounted there"
`)
		if mm.dir {
			b.WriteString(`mkdir -p ` + q + ` || rvm_fail "creating the mirrored mount point ` + shellEscapeDQ(where) + ` in the app root failed"
`)
		} else {
			b.WriteString(`mkdir -p ` + shellQuote(path.Dir(dest)) + ` && { [ -e ` + q + ` ] || printf '' >` + q + `; } || rvm_fail "creating the mirrored mount point ` + shellEscapeDQ(where) + ` in the app root failed"
`)
		}
		opts := "remount,bind,ro,nosuid,nodev"
		if mm.noexec {
			opts += ",noexec"
		}
		b.WriteString(`mount -o bind ` + mirrorStage(i) + ` ` + q + ` || rvm_fail "binding the mirrored mount ` + shellEscapeDQ(where) + ` into the app root failed"
mount -o ` + opts + ` ` + q + ` || rvm_fail "making the mirrored mount ` + shellEscapeDQ(where) + ` in the app root read-only failed"
`)
	}
	if m.watching() {
		b.WriteString(`[ -n "$rvm_echo" ] || echo ` + fileOnTag(nonce) + "\n")
	}
	return b.String()
}

// shellEscapeDQ escapes s for the inside of a double-quoted shell word.
func shellEscapeDQ(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`")
	return r.Replace(s)
}

// guestFileReader defines rvm_file, which the control reader calls with the
// rest of each file push line after the prefix, and the state it keeps
// between lines. A push is a begin line with its sequence number and the
// number of the watched file, a data line for each piece of the file's
// bytes in base64, and an end line with the sequence number, the file's
// number, the count of data lines, the size, the mode in octal, and the hex
// sha256 of the bytes (see mirrorFrames).
//
// rvm_fpath maps a watched file's number to its staging path, to whether the
// guest rewrites it in place, which a file mount needs, and to its owner.
// Only those paths are ever written, so a push cannot name a path of its
// own. A begin line for an unknown number opens a frame that is answered
// with the bad line. The data lines append to a scratch file in
// guestMirrorNext with printf, so no line is ever evaluated. The end line
// closes the frame, and the file is installed only when the sequence and
// file numbers match the begin line, the line count matches, the decoded
// size and digest match, and the mode is octal. A file mount is rewritten in
// place, which is what a running container sees of a bound file that the
// host rewrites, and a file in a tree is renamed over the old one from the
// scratch directory, which is on the same filesystem, so a reader in the
// app never sees half of it. The answer is the OK line or the bad line,
// with the end line's own sequence number. A frame that a new begin line
// interrupts is discarded without an answer, and so is one that the stop
// request interrupts.
//
// Every redirection is on a regular builtin, never on a special builtin such
// as :, because a redirection that fails on a special builtin ends the
// shell, and with it the reader.
func (m *mountMirror) guestFileReader(nonce string) string {
	next := guestMirrorNext
	var table strings.Builder
	for _, w := range m.watched {
		inPlace := ""
		if w.inPlace {
			inPlace = "1"
		}
		fmt.Fprintf(&table, "\t\t%d) rvm_ft=%s rvm_fi=%s rvm_fo=%d:%d ;;\n", w.number, shellQuote(w.guest), inPlace, w.uid, w.gid)
	}
	return `	rvm_fseq=
	rvm_fpath() {
		case "$1" in
` + table.String() + `		*) return 1 ;;
		esac
	}
	rvm_finstall() {
		base64 -d <` + next + `/data >` + next + `/file 2>/dev/null || return 1
		rvm_got=$(stat -c %s ` + next + `/file) && [ "$rvm_got" = "$rvm_fsize" ] || return 1
		rvm_got=$(sha256sum <` + next + `/file) && [ "${rvm_got%% *}" = "$rvm_fsum" ] || return 1
		if [ -n "$rvm_fi" ]; then
			cat ` + next + `/file >"$rvm_ft" && chmod "$rvm_fmode" "$rvm_ft"
		else
			chown "$rvm_fo" ` + next + `/file && chmod "$rvm_fmode" ` + next + `/file && mv -f ` + next + `/file "$rvm_ft"
		fi
	}
	rvm_file() {
		case "$1" in
		"begin "*)
			rvm_b=${1#begin }
			rvm_fseq=${rvm_b%% *}
			rvm_fk=${rvm_b#* }
			case "$rvm_fseq" in
			'' | *[!0-9]*)
				rvm_fseq=
				return
				;;
			esac
			rvm_fbad=
			rvm_fn=0
			case "$rvm_fk" in
			'' | *[!0-9]*) rvm_fbad=1 ;;
			*) rvm_fpath "$rvm_fk" || rvm_fbad=1 ;;
			esac
			{ printf '' >` + next + `/data; } 2>/dev/null || rvm_fbad=1
			;;
		"data "*)
			[ -n "$rvm_fseq" ] || return
			rvm_fn=$((rvm_fn + 1))
			printf '%s\n' "${1#data }" >>` + next + `/data || rvm_fbad=1
			;;
		"end "*)
			rvm_e=${1#end }
			rvm_es=${rvm_e%% *}
			rvm_e=${rvm_e#* }
			rvm_ek=${rvm_e%% *}
			rvm_e=${rvm_e#* }
			rvm_en=${rvm_e%% *}
			rvm_e=${rvm_e#* }
			rvm_fsize=${rvm_e%% *}
			rvm_e=${rvm_e#* }
			rvm_fmode=${rvm_e%% *}
			rvm_fsum=${rvm_e#* }
			rvm_open=$rvm_fseq
			rvm_fseq=
			case "$rvm_es" in
			'' | *[!0-9]*) return ;;
			esac
			case "$rvm_fmode" in
			[0-7][0-7][0-7] | [0-7][0-7][0-7][0-7]) ;;
			*) rvm_fbad=1 ;;
			esac
			case "$rvm_fsize" in
			'' | *[!0-9]*) rvm_fbad=1 ;;
			esac
			if [ -n "$rvm_open" ] && [ -z "$rvm_fbad" ] && [ "$rvm_es" = "$rvm_open" ] && [ "$rvm_ek" = "$rvm_fk" ] && [ "$rvm_en" = "$rvm_fn" ] && rvm_finstall; then
				echo "` + fileOKTag(nonce) + `$rvm_es" >/dev/console
			else
				echo "` + fileBadTag(nonce) + `$rvm_es" >/dev/console
			fi
			rm -f ` + next + `/data ` + next + `/file
			;;
		esac
	}
`
}

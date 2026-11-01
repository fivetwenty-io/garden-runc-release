//go:build linux

package main

import (
	"strconv"
	"strings"
)

// Guest paths of the instance identity. The initramfs carries the pair that
// vm-launch read at boot as guestIdentityCert and guestIdentityKey, and the
// control reader assembles each pair that vm-launch pushes later in
// guestIdentityNext. The app sees the pair in guestCredDir, a tmpfs in the
// app root, at the path where Garden binds it in a container.
const (
	guestIdentityCert = "/rvm/identity/instance.crt"
	guestIdentityKey  = "/rvm/identity/instance.key"
	guestIdentityNext = "/rvm/identity/next"
	guestCredDir      = "/rvm/app/etc/cf-instance-credentials"
)

// guestEvents is the FIFO on which the run section learns that a process
// has exited or that vm-launch asked for a stop. Setup creates it (see
// guestRunSetup), the run section holds it open, and the control reader
// writes the stop to it.
const guestEvents = "/rvm/events"

// guestIdentitySetup installs the boot pair for the app, as a setup step
// before the start tag (see guestRunSetup), so before any process starts. It creates
// /etc/cf-instance-credentials in the app root when the root lacks it,
// mounts a tmpfs there with the options that keep the pair out of reach of
// writes, devices, and programs, and copies both files into it with mode
// 0644, owned by root, as Diego leaves them in a container's directory. The
// app can then read the pair and cannot change it. It refuses an /etc or an
// /etc/cf-instance-credentials that is a symbolic link, because stage 2 runs
// outside the app root and would follow the link to a path of the guest's
// own. It also creates guestIdentityNext, where the control reader assembles
// a pushed pair. Any failure is a named setup step, because an app that
// expects its identity should not start without it.
const guestIdentitySetup = `[ ! -L ` + guestAppRootEtc + ` ] && [ ! -L ` + guestCredDir + ` ] || rvm_fail "the app root's /etc or /etc/cf-instance-credentials is a symbolic link, so the instance identity cannot be installed there"
mkdir -p ` + guestCredDir + ` || rvm_fail "creating /etc/cf-instance-credentials in the app root failed"
mount -t tmpfs -o mode=0755,size=1m,nosuid,nodev,noexec tmpfs ` + guestCredDir + ` || rvm_fail "mounting a tmpfs at /etc/cf-instance-credentials in the app root failed"
cp ` + guestIdentityCert + ` ` + guestCredDir + `/instance.crt && chmod 0644 ` + guestCredDir + `/instance.crt || rvm_fail "copying the instance identity certificate into the app root failed"
cp ` + guestIdentityKey + ` ` + guestCredDir + `/instance.key && chmod 0644 ` + guestCredDir + `/instance.key || rvm_fail "copying the instance identity key into the app root failed"
mkdir -p ` + guestIdentityNext + ` && chmod 0700 ` + guestIdentityNext + ` || rvm_fail "creating ` + guestIdentityNext + ` for the pushed instance identity pairs failed"
`

// guestIdentityEchoCheck is the setup step, before the start tag, of a
// guest with an instance identity. A console that still echoes its input
// would copy each line of a push, the private key included, into the
// command's output, so the step turns echo off once more, as
// guestConsoleSetup did, and a guest whose console refuses again takes no
// pushes. The step then sets rvm_echo, so that the control reader leaves
// every frame line alone, and prints credOffTag, which tells vm-launch not
// to push any. The app still gets the boot pair. guestConsoleSetup has
// already warned about the failure, so stty's own message goes to
// /dev/null.
func guestIdentityEchoCheck(nonce string) string {
	return "rvm_echo=\nstty -echo </dev/console 2>/dev/null || { rvm_echo=1; echo " + credOffTag(nonce) + "; }\n"
}

// guestAppRootEtc is the app root's /etc, which holds guestCredDir.
const guestAppRootEtc = "/rvm/app/etc"

// guestControlReader is the stop reader of a guest that runs the app and
// its sidecars through the run section. It keeps every property of the stop
// reader (see guestStopReader): it starts in the background with its
// standard input on /dev/null, sets its own oom_score_adj to -1000, opens the
// console for itself, compares each line with the stop request exactly and
// never evaluates one, and uses only the shell's builtins on the stop path,
// apart from the sleep of its poll. It sets rvm_reader, so that
// guestStopReaderStop stops it.
//
// On the stop request it first writes stop to guestEvents, when the FIFO
// exists, so that the run section knows that the exits which follow come
// from the stop. It opens the FIFO for reading and writing, which never
// waits for a reader. It then sends SIGTERM to the process whose pid each of
// pidFiles holds. It polls every 50 ms for the files that do not hold a pid
// yet, as the stop reader polls for the app's, and it signals each one as
// soon as its pid is there, so that a process that has not recorded its pid
// never holds back the signal to the others.
//
// With identity set, the reader also installs each pair that vm-launch
// pushes (see guestCredReader), unless the console still echoes its input
// (see guestIdentityEchoCheck).
func guestControlReader(nonce string, pidFiles []string, identity bool) string {
	cred, match := "", ""
	if identity {
		prefix := credTag(nonce)
		cred = guestCredReader(nonce)
		match = `		case "$rvm_line" in
		"` + prefix + `"*) [ -n "$rvm_echo" ] || rvm_cred "${rvm_line#"` + prefix + `"}" ;;
		esac
`
	}
	return `(
	echo -1000 >/proc/self/oom_score_adj
	rvm_stop=
` + cred + `	while IFS= read -r rvm_line; do
		if [ "$rvm_line" = "` + stopTag(nonce) + `" ]; then
			rvm_stop=1
			break
		fi
` + match + `	done </dev/console
	[ -n "$rvm_stop" ] || exit 0
	if [ -p ` + guestEvents + ` ]; then
		echo stop 1<>` + guestEvents + `
	fi
` + guestSignalPidFiles(pidFiles) + `) </dev/null &
rvm_reader=$!
`
}

// guestSignalPidFiles is the stop path of the control reader: it sends
// SIGTERM once to the pid in each of pidFiles, polling every 50 ms for the
// files that are still missing or empty.
func guestSignalPidFiles(pidFiles []string) string {
	if len(pidFiles) == 0 {
		return ""
	}
	var b strings.Builder
	sent := make([]string, len(pidFiles))
	for i := range pidFiles {
		sent[i] = "rvm_sent_" + strconv.Itoa(i)
		b.WriteString("\t" + sent[i] + "=\n")
	}
	b.WriteString("\twhile :; do\n")
	for i, file := range pidFiles {
		b.WriteString(`		if [ -z "$` + sent[i] + `" ] && read -r rvm_pid 2>/dev/null <` + file + ` && [ -n "$rvm_pid" ]; then
			` + sent[i] + `=1
			kill -TERM "$rvm_pid"
		fi
`)
	}
	all := make([]string, len(sent))
	for i, name := range sent {
		all[i] = `[ -n "$` + name + `" ]`
	}
	b.WriteString(`		if ` + strings.Join(all, " && ") + `; then
			break
		fi
		sleep 0.05
	done
`)
	return b.String()
}

// guestCredReader defines rvm_cred, which the control reader calls with the
// rest of each frame line after the prefix, and the state it keeps between
// lines. A push is a begin line with its sequence number, a crt line for
// each line of the certificate, a key line for each line of the key, and an
// end line with the sequence number, the two line counts, and the hex sha256
// of the certificate followed by the key, each file a line of text for each
// line it had.
//
// A begin line opens a frame and empties both files in guestIdentityNext,
// and the crt and key lines append to them with printf, so no line is ever
// evaluated. The end line closes the frame. The pair is installed only when
// the sequence numbers and both counts match, the certificate starts and ends
// with a certificate's PEM boundaries, the key starts and ends with a private
// key's, and the checksum matches. The reader then copies both files into
// the app's tmpfs under temporary names, sets mode 0644, and renames the key
// and then the certificate, which is the order in which Diego renames them,
// so that a program that watches the directory sees the renames it sees in a
// container, and a program that reads the certificate first never gets a new
// certificate with the old key. It answers every end line on the console
// through its own open, with the end line's own sequence number, which is the
// push that vm-launch waits on. The answer is the OK line for a pair it
// installed and the bad line for any other, an end line without an open frame
// included, so that vm-launch can push the pair again at once. A frame that
// a new begin line interrupts is discarded without an answer, and so is one
// that the stop request interrupts.
//
// Every redirection is on a regular builtin, never on a special builtin such
// as :, because a redirection that fails on a special builtin ends the
// shell, and with it the reader.
func guestCredReader(nonce string) string {
	next := guestIdentityNext
	cred := guestCredDir
	return `	rvm_seq=
	rvm_pem() {
		[ "$rvm_c1" = "-----BEGIN CERTIFICATE-----" ] && [ "$rvm_cn" = "-----END CERTIFICATE-----" ] || return 1
		case "$rvm_k1" in
		"-----BEGIN "*"PRIVATE KEY-----") ;;
		*) return 1 ;;
		esac
		case "$rvm_kn" in
		"-----END "*"PRIVATE KEY-----") ;;
		*) return 1 ;;
		esac
	}
	rvm_install() {
		rvm_got=$(cat ` + next + `/instance.crt ` + next + `/instance.key | sha256sum) && [ "${rvm_got%% *}" = "$rvm_esum" ] || return 1
		cp ` + next + `/instance.key ` + cred + `/instance.key.tmp && chmod 0644 ` + cred + `/instance.key.tmp &&
			cp ` + next + `/instance.crt ` + cred + `/instance.crt.tmp && chmod 0644 ` + cred + `/instance.crt.tmp &&
			mv -f ` + cred + `/instance.key.tmp ` + cred + `/instance.key &&
			mv -f ` + cred + `/instance.crt.tmp ` + cred + `/instance.crt
	}
	rvm_cred() {
		case "$1" in
		"begin "*)
			rvm_seq=${1#begin }
			case "$rvm_seq" in
			'' | *[!0-9]*)
				rvm_seq=
				return
				;;
			esac
			rvm_bad=
			rvm_nc=0
			rvm_nk=0
			rvm_c1=
			rvm_cn=
			rvm_k1=
			rvm_kn=
			{ printf '' >` + next + `/instance.crt && printf '' >` + next + `/instance.key; } 2>/dev/null || rvm_bad=1
			;;
		"crt "*)
			[ -n "$rvm_seq" ] || return
			rvm_l=${1#crt }
			[ "$rvm_nc" -gt 0 ] || rvm_c1=$rvm_l
			rvm_cn=$rvm_l
			rvm_nc=$((rvm_nc + 1))
			printf '%s\n' "$rvm_l" >>` + next + `/instance.crt || rvm_bad=1
			;;
		"key "*)
			[ -n "$rvm_seq" ] || return
			rvm_l=${1#key }
			[ "$rvm_nk" -gt 0 ] || rvm_k1=$rvm_l
			rvm_kn=$rvm_l
			rvm_nk=$((rvm_nk + 1))
			printf '%s\n' "$rvm_l" >>` + next + `/instance.key || rvm_bad=1
			;;
		"end "*)
			rvm_e=${1#end }
			rvm_es=${rvm_e%% *}
			rvm_e=${rvm_e#* }
			rvm_ec=${rvm_e%% *}
			rvm_e=${rvm_e#* }
			rvm_ek=${rvm_e%% *}
			rvm_esum=${rvm_e#* }
			rvm_open=$rvm_seq
			rvm_seq=
			case "$rvm_es" in
			'' | *[!0-9]*) return ;;
			esac
			if [ -n "$rvm_open" ] && [ -z "$rvm_bad" ] && [ "$rvm_es" = "$rvm_open" ] && [ "$rvm_ec" = "$rvm_nc" ] && [ "$rvm_ek" = "$rvm_nk" ] && rvm_pem && rvm_install; then
				echo "` + credOKTag(nonce) + `$rvm_es" >/dev/console
			else
				echo "` + credBadTag(nonce) + `$rvm_es" >/dev/console
			fi
			;;
		esac
	}
`
}

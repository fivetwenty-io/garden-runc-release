//go:build linux

package main

import "strings"

// The stack guest's command files. /rvm/argv holds the launcher's whole
// argv, each argument quoted for the shell by shellJoin, and /rvm/cwd holds
// the app's working directory, a path in the app root.
const (
	guestArgv = "/rvm/argv"
	guestCwd  = "/rvm/cwd"
)

// guestRunPrefix is how the command's subshell starts in every guest (see
// guestRunCommand, which starts with the same text, as a spec checks): it
// gives stage 2's standard error to fd 3, records the subshell's pid in
// guestAppPid, sets the open-files limit, and sources /rvm/env. What follows
// it becomes the command.
const guestRunPrefix = "command exec 3>&2 2>/dev/null\n( command exec 2>&3 3>&-; { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >" + guestAppPid + "; } || echo \"vm-launch guest: recording the command's pid in " + guestAppPid + " failed; a stop request cannot reach the command\"; " +
	guestSetLimits + " && . /rvm/env && "

// guestStackRunCommand runs the app in the stack guest. Its subshell starts
// as the rvm.6 guest's does (see guestRunPrefix), so the pid it records, its
// open-files limit, and the guest environment are the same. It then sets its
// arguments from /rvm/argv with eval, which the quoting makes exact for any
// bytes, newlines and quotes included, moves the loader variables out of the
// environment and into the arguments (see guestLoaderHold), and execs busybox
// chroot into the app root. There the stack's setpriv sets the real,
// effective, and saved uid and gid to 2000, takes vcap's supplementary groups
// from the stack's /etc/group, and sets no_new_privs, as Garden does for a
// container's processes. It then execs the stack's env, as uid 2000, which
// enters the working directory from /rvm/cwd, puts the loader variables back,
// and execs the launcher with the rest of the argv. The working directory is
// entered only after the drop, so a link in the droplet cannot make root
// resolve it. Every one of those programs execs in place, so the recorded pid
// is the launcher's, then bash's, and then the start command's own, as it is
// under runC, and the stop reader's SIGTERM reaches the app.
//
// Nothing after the source of /rvm/env reads a shell variable that the
// guest environment can set, because the guest environment may set any
// name; the arguments and the working directory come from the files each
// time, and guestLoaderHold reads only the loader variables, by names it
// sets itself. A PATH from /rvm/env does not reach chroot or cat, which are
// applets the guest's busybox runs before anything on PATH, and the stack's
// programs are named by their paths.
var guestStackRunCommand = guestRunPrefix + `eval "set -- $(cat ` + guestArgv + `)" && ` + guestLoaderHold + `exec chroot ` + guestAppRoot + ` ` + guestStackDrop(`"$(cat `+guestCwd+`)"`) + ` ) </dev/null
`

// guestStackDrop is the end of the line that runs a process in the stack
// guest, after busybox chroot: the stack's setpriv drops to uid 2000 and
// execs the stack's env, which enters the working directory cwd, a word
// already quoted for the shell, puts back the loader variables that
// guestLoaderHold moved into the arguments, and execs the process's own argv.
func guestStackDrop(cwd string) string {
	return guestStackSetpriv + ` --reuid=` + guestAppUID + ` --regid=` + guestAppUID + ` --init-groups --no-new-privs -- ` + guestStackEnv + ` -C ` + cwd + ` "$@"`
}

// guestLoaderNames are the environment variables with which glibc's dynamic
// loader and its libc choose code to load or change how they run: every
// variable that glibc drops for a program it runs in secure-execution mode,
// and every other variable its loader reads. A buildpack sets some of them
// for the app, LD_LIBRARY_PATH most often, so the app and its sidecars must
// get them, as they do under runC. The stack's env and setpriv are
// dynamically linked and start as root, though, and with LD_PRELOAD or
// LD_AUDIT from the app's environment they would load the droplet's code as
// guest root. The process line therefore keeps these names away from both,
// and the stack's env puts them back only after setpriv has dropped to uid
// 2000 (see guestLoaderHold).
var guestLoaderNames = []string{
	"GCONV_PATH", "GETCONF_DIR", "GLIBC_TUNABLES", "HOSTALIASES",
	"LD_ASSUME_KERNEL", "LD_AUDIT", "LD_BIND_NOT", "LD_BIND_NOW", "LD_DEBUG", "LD_DEBUG_OUTPUT",
	"LD_DYNAMIC_WEAK", "LD_HWCAP_MASK", "LD_LIBRARY_PATH", "LD_ORIGIN_PATH", "LD_PREFER_MAP_32BIT_EXEC",
	"LD_PRELOAD", "LD_PROFILE", "LD_PROFILE_OUTPUT", "LD_SHOW_AUXV", "LD_TRACE_LOADED_OBJECTS",
	"LD_TRACE_PRELINKING", "LD_USE_LOAD_BIAS", "LD_VERBOSE", "LD_WARN",
	"LOCALDOMAIN", "LOCPATH",
	"MALLOC_ARENA_MAX", "MALLOC_ARENA_TEST", "MALLOC_CHECK_", "MALLOC_MMAP_MAX_", "MALLOC_MMAP_THRESHOLD_",
	"MALLOC_PERTURB_", "MALLOC_TOP_PAD_", "MALLOC_TRACE", "MALLOC_TRIM_THRESHOLD_",
	"NIS_PATH", "NLSPATH", "RESOLV_HOST_CONF", "RES_OPTIONS", "TMPDIR", "TZDIR",
}

// guestLoaderHold is the step of a stack process's line that runs after its
// environment files are sourced and its arguments are set, and before busybox
// chroot, which is static. For each of guestLoaderNames that is set, even to
// an empty value, it puts NAME=value in front of the arguments and unsets the
// variable, so the stack's env and setpriv start without it, and the stack's
// env after the drop (see guestStackDrop) takes the word as an assignment
// and sets it again, byte for byte, for the process. The argv of every
// process starts with the launcher, whose path holds no "=", so env never
// takes the process's own first argument for an assignment. The eval sees
// only names from the list and the quoted expansions of the variable, so no
// value is ever evaluated.
var guestLoaderHold = `for rvm_ld in ` + strings.Join(guestLoaderNames, " ") + `; do eval "[ -z \"\${$rvm_ld+x}\" ] || { set -- \"$rvm_ld=\$$rvm_ld\" \"\$@\" && unset $rvm_ld; }"; done && `

// guestStackChecks makes a broken /rvm/argv or /rvm/cwd a failed setup step,
// with the console shown, instead of a command that fails to start, as
// guestEnvChecks does for /rvm/env. The argv must parse and give at least
// one argument, and the working directory must be an absolute path. Both
// checks run in a subshell, so stage 2 keeps its own arguments, which are the
// volumes' devices.
const guestStackChecks = `( eval "set -- $(cat ` + guestArgv + `)" && [ "$#" -gt 0 ] ) || rvm_fail "reading the app's arguments from ` + guestArgv + ` failed"
( rvm_cwd=$(cat ` + guestCwd + `) && case "$rvm_cwd" in /*) ;; *) exit 1 ;; esac ) || rvm_fail "` + guestCwd + ` holds no absolute working directory for the app"
`

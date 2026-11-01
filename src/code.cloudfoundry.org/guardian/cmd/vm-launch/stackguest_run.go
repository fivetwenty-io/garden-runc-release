//go:build linux

package main

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
// bytes, newlines and quotes included, and execs busybox chroot into the app
// root. There the stack's env enters the working directory from /rvm/cwd,
// and the stack's setpriv sets the real, effective, and saved uid and gid to
// 2000, takes vcap's supplementary groups from the stack's /etc/group, and
// sets no_new_privs, as Garden does for a container's processes, before it
// execs the launcher with the rest of the argv. Every one of those programs
// execs in place, so the recorded pid is the launcher's, then bash's, and
// then the start command's own, as it is under runC, and the stop reader's
// SIGTERM reaches the app.
//
// Nothing after the source of /rvm/env reads a shell variable, because the
// guest environment may set any name; the arguments and the working
// directory come from the files each time. A PATH from /rvm/env does not
// reach chroot or cat, which are applets the guest's busybox runs before
// anything on PATH, and the stack's programs are named by their paths.
const guestStackRunCommand = guestRunPrefix + `eval "set -- $(cat ` + guestArgv + `)" && exec chroot ` + guestAppRoot + ` ` + guestStackEnv + ` -C "$(cat ` + guestCwd + `)" ` +
	guestStackSetpriv + ` --reuid=` + guestAppUID + ` --regid=` + guestAppUID + ` --init-groups --no-new-privs -- "$@" ) </dev/null
`

// guestStackChecks makes a broken /rvm/argv or /rvm/cwd a failed setup step,
// with the console shown, instead of a command that fails to start, as
// guestEnvChecks does for /rvm/env. The argv must parse and give at least
// one argument, and the working directory must be an absolute path. Both
// checks run in a subshell, so stage 2 keeps its own arguments, which are the
// volumes' devices.
const guestStackChecks = `( eval "set -- $(cat ` + guestArgv + `)" && [ "$#" -gt 0 ] ) || rvm_fail "reading the app's arguments from ` + guestArgv + ` failed"
( rvm_cwd=$(cat ` + guestCwd + `) && case "$rvm_cwd" in /*) ;; *) exit 1 ;; esac ) || rvm_fail "` + guestCwd + ` holds no absolute working directory for the app"
`

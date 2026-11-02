//go:build linux

package main

import (
	"strconv"
	"strings"
	"time"
)

// guestProcess is one process that the run section starts in the app root.
type guestProcess struct {
	index    int      // 0 is the app, and 1 to 8 are the sidecars
	argvPath string   // a file of shell-quoted arguments
	envPaths []string // files of export and unset lines, sourced in order
	dir      string   // the working directory inside the root
	pidPath  string   // where the process records its own pid
}

// guestExec returns the line that runs p in the app root as uid 2000. The
// line runs in a subshell that has already recorded its pid at p.pidPath
// and set the open-files limit, and it should exec the process, so that the
// recorded pid stays the process's own. The stack owns the one
// implementation.
type guestExec func(p guestProcess) string

// guestSidecarFile returns the guest path of one of sidecar index's files,
// which are argv, env, and pid. Sidecars are numbered from 1, because the
// app is process 0.
func guestSidecarFile(index int, name string) string {
	return "/rvm/sidecar/" + strconv.Itoa(index) + "/" + name
}

// guestWindDown bounds the wind-down in the guest once one process has
// exited or vm-launch has asked for a stop, as stopDeadline bounds it on the
// host after a signal. The guest's timer starts only once the stop line has
// crossed the console and the event loop has read it, and the host kills the
// hypervisor at stopDeadline whatever the guest is doing, so the timer has
// to end well before the host's deadline. Otherwise the guest never sends
// SIGKILL, never reports the app's status, and loses its OOM report. Six
// seconds is the most grace that still leaves 2 seconds, as Diego leaves
// vm-launch after stopDeadline, for the stop line's trip, the SIGKILL, which
// can wait up to a second for a pid file that is still empty, the OOM
// report, and the exit line's trip back. guestTimeoutSeconds is the same
// time as the text the guest's shell takes, and a spec keeps the two in step
// and the gap in place.
//
// A stack guest with volumes runs its volume teardown after the section,
// and the teardown shares that time too (see guestStackRunVolumeTeardown).
// That guest's wind-down is guestVolumeWindDown, which leaves the 2 seconds
// and guestTeardownKillWait, the one wait of that teardown.
const (
	guestWindDown       = 6 * time.Second
	guestTimeoutSeconds = "6"

	guestVolumeWindDown       = 5 * time.Second
	guestVolumeTimeoutSeconds = "5"
)

// guestRunSection is the part of stage 2 that runs the app and its sidecars
// once the app root is ready, in place of the single command subshell and
// the stop reader. procs holds the app as process 0 and then each sidecar,
// and exec gives the line that runs each one in the app root. With identity
// set, its control reader installs each pair that vm-launch pushes. The
// boot pair and guestEvents are already in place, from the setup steps
// before the start tag (see guestRunSetup).
//
// The section holds guestEvents open for reading and writing on fd 4, so
// its reads never see the end of the FIFO. It starts the control
// reader with every process's pid file, defines the framer (see
// guestFrameFunc) and the drain check, and then runs every process and the
// event loop as the elements of one pipeline. Their standard input and
// output are not the pipe: each wrapper gets /dev/null and stage 2's
// console, which fd 5 keeps for them. A pipeline is the one way in which the
// shell runs commands side by side and keeps the default action of SIGINT
// and SIGQUIT in each, as runC does for a container's processes; a command
// that the shell starts in the background, without job control, ignores
// both. The status of a pipeline is that of its last element, which is the
// event loop, and the shell returns only once every element has ended.
//
// Each process runs in a wrapper subshell (see guestProcessWrapper), which
// frames the process's output on the console and writes one line,
// "exit <index> <status>", to the FIFO when the process ends. A short write
// to a FIFO is atomic, so lines from several wrappers never mix. No process
// holds the console, so none can read the stop request's nonce from it or
// write a line that vm-launch would take for the guest's own. The wrappers
// and the event loop set their oom_score_adj to -1000, as the stop reader
// does, so the guest kernel never picks one of them and leaves a process
// whose exit no one reports; each process sets its own back to 0, the value
// it would have had from stage 2.
//
// The event loop picks the status (see guestEventLoop). The section ends
// with the status in rvm_status, the FIFO and fd 5 closed, and the control
// reader stopped.
func guestRunSection(nonce string, procs []guestProcess, identity bool, exec guestExec) string {
	return guestRunSectionWithin(nonce, procs, identity, exec, guestTimeoutSeconds)
}

// guestRunSectionWithin is guestRunSection with a wind-down of timeout
// seconds, in the text the guest's shell takes, in place of
// guestTimeoutSeconds.
func guestRunSectionWithin(nonce string, procs []guestProcess, identity bool, exec guestExec, timeout string) string {
	var b strings.Builder
	b.WriteString(`command exec 4<>` + guestEvents + ` || rvm_fail "opening the event FIFO ` + guestEvents + ` failed"
`)
	pidFiles := make([]string, len(procs))
	for i, p := range procs {
		pidFiles[i] = p.pidPath
	}
	b.WriteString(guestControlReader(nonce, pidFiles, identity))
	b.WriteString(guestFrameFunc(nonce) + guestDrainFunc)
	b.WriteString("command exec 5>&1\n")
	for _, p := range procs {
		b.WriteString(guestProcessWrapper(p, exec) + " |\n")
	}
	b.WriteString(guestEventLoopWithin(nonce, procs, timeout))
	b.WriteString("rvm_status=$?\ncommand exec 4>&- 5>&-\n" + guestStopReaderStop)
	return b.String()
}

// guestRunSetup is the setup step of a guest that runs the run section for
// procs, which stage 2 runs with the other setup steps, before the start
// tag. With identity set, it installs the boot pair (see
// guestIdentitySetup), and it then creates guestEvents and the log FIFOs of
// procs (see guestLogSetup). A failure of any of them is then a setup
// failure, with the console shown, as every other setup step's is, and never
// output of the command.
func guestRunSetup(identity bool, procs []guestProcess) string {
	setup := ""
	if identity {
		setup = guestIdentitySetup
	}
	return setup + `mkfifo -m 0600 ` + guestEvents + ` || rvm_fail "creating the event FIFO ` + guestEvents + ` failed"
` + guestLogSetup(procs)
}

// guestProcessName is how the guest's lines name process index.
func guestProcessName(index int) string {
	if index == 0 {
		return "the app"
	}
	return "sidecar " + strconv.Itoa(index)
}

// guestProcessWrapper is the pipeline element that runs p, frames its
// output, and reports its exit on the FIFO (see guestRunSection).
//
// The wrapper takes the console from fd 5 as its standard output and gives
// its own standard error to /dev/null, as stage 2 does while it waits for
// the single command, so the shell's report of a process that a signal ended
// never reaches the console. It keeps stage 2's standard error, which is the
// console too, on fd 3 for its one line about log FIFOs that do not open. It
// starts a framer on each of p's FIFOs in the background (see
// guestFrameFunc), with the console as its output and with fd 3 and fd 4
// closed. A FIFO's open waits for the other end, so each framer starts
// reading as the process's subshell opens the FIFO for writing.
//
// Inside the wrapper, the process's own subshell makes the two FIFOs its
// standard output and standard error and closes fd 3 and fd 4, so the
// process holds /dev/null, its two FIFOs, and nothing of stage 2's. A FIFO
// that does not open ends the subshell before anything runs, so a process
// never starts on the console. The subshell then records its pid, as the
// app's does in the single-process guest (see guestRunCommand), sets the
// open-files limit, and runs the line from exec. The pid is read from
// /proc/self/stat with the shell's builtin read, so it is the subshell's and
// not that of a child, and the exec line keeps it.
//
// Once the process has ended, the wrapper keeps its status and waits for
// both framers to end (see guestDrainFunc), so that the process's last
// lines are on the console before its exit line reaches the event loop and
// the loop names the first exit.
func guestProcessWrapper(p guestProcess, exec guestExec) string {
	name := guestProcessName(p.index)
	idx := strconv.Itoa(p.index)
	out, errs := guestLogFIFO(p.index, "out"), guestLogFIFO(p.index, "err")
	return `(
	command exec >&5 5>&- </dev/null 3>&2 2>/dev/null
	echo -1000 >/proc/self/oom_score_adj
	read -r rvm_wrapper rvm_rest </proc/self/stat
	rvm_frame ` + idx + ` o <` + out + ` 3>&- 4>&- &
	rvm_out=$!
	rvm_frame ` + idx + ` e <` + errs + ` 3>&- 4>&- &
	rvm_err=$!
	(
		command exec >` + out + ` 2>` + errs + ` 3>&- 4>&- || { echo "vm-launch guest: opening the log FIFOs of ` + name + ` failed; not starting it" >&3; exit 1; }
		echo 0 >/proc/self/oom_score_adj
		{ read -r rvm_self rvm_rest </proc/self/stat && echo "$rvm_self" >` + p.pidPath + `; } || echo "vm-launch guest: recording the pid of ` + name + ` in ` + p.pidPath + ` failed; a stop request cannot reach it"
		` + guestSetLimits + ` || exit
		` + exec(p) + `
	)
	rvm_s=$?
	rvm_drain "$rvm_out" "$rvm_err"
	echo "exit ` + idx + ` $rvm_s" >&4
)`
}

// guestDrainFunc defines rvm_drain, with which a wrapper waits for the two
// framers whose pids it is given to end, and rvm_live, which reports
// whether one still runs. A framer ends once every holder of its FIFO's
// write end has closed it and it has written the last frame. The process
// may have left a descendant that still holds the FIFO, though, so the wait
// checks every 50 ms, up to 10 times, and a descendant holds back the exit
// line by at most half a second; its framer goes on framing what the
// descendant writes. rvm_live reads /proc/<pid>/stat with the shell's
// builtin read. A framer that is a zombie or gone has ended, and so has a
// pid whose parent is not the wrapper, which is a pid that the kernel gave
// to another process after the shell reaped the framer.
const guestDrainFunc = `rvm_live() {
	read -r rvm_st 2>/dev/null </proc/"$1"/stat || return 1
	rvm_st=${rvm_st##*") "}
	case "$rvm_st" in
	"Z "*) return 1 ;;
	esac
	rvm_st=${rvm_st#* }
	[ "${rvm_st%% *}" = "$rvm_wrapper" ]
}
rvm_drain() {
	rvm_n=0
	while [ "$rvm_n" -lt 10 ] && { rvm_live "$1" || rvm_live "$2"; }; do
		sleep 0.05
		rvm_n=$((rvm_n + 1))
	done
}
`

// guestEventLoop is the last element of the run section's pipeline. It
// reads the events from fd 4 until every process has exited, and its own
// status is the status the guest reports.
//
// On the first exit, the status is that process's own. The loop then prints
// the first-exit line (see firstTag), which vm-launch takes off the output,
// and, with sidecars, a line that names the process and its status, sends
// SIGTERM to every process that has not exited, and starts a timer. The
// process's wrapper has waited for its framers before it reported the exit,
// so the first-exit line follows the process's last frame. On a stop, which the
// control reader writes before it signals any process, the status is the
// app's, because that is the process Diego asked to stop, and the loop
// starts the timer. When the timer fires after guestTimeoutSeconds, the loop
// says so, sends SIGKILL to every process that has not exited, and ends. The
// guest reboots right after the section, which would end those processes
// anyway; killing them first lets the pipeline return. After a stop, an app
// that the timer ended has the status 137, as a process that SIGKILL ended
// has in a container.
//
// The loop finds each process's pid in its pid file, and it waits up to a
// second for a pid file that is still empty, because a process that has just
// started may not have recorded its pid yet. A process that has exited is
// never signaled, so its pid, which the kernel may give to another process,
// is never used.
//
// The timer is a subshell that sleeps in the background and writes timeout
// to the FIFO. Its trap only sets a flag, and it kills its sleep whatever
// the flag, so the loop's SIGTERM never leaves the sleep behind, whenever it
// arrives, and it waits for the sleep before it exits. A SIGTERM that comes
// before the trap is set ends the timer at once, before its sleep starts.
// The shell's reports of a sleep or a timer that SIGTERM ended go to
// /dev/null.
func guestEventLoop(nonce string, procs []guestProcess) string {
	return guestEventLoopWithin(nonce, procs, guestTimeoutSeconds)
}

// guestEventLoopWithin is guestEventLoop with a timer of timeout seconds, in
// the text the guest's shell takes, in place of guestTimeoutSeconds.
func guestEventLoopWithin(nonce string, procs []guestProcess, timeout string) string {
	var signal, names strings.Builder
	for _, p := range procs {
		idx := strconv.Itoa(p.index)
		signal.WriteString("\t\trvm_kill \"$1\" " + idx + " " + p.pidPath + "\n")
		names.WriteString("\t\t\t\t" + idx + `) echo "vm-launch guest: ` + guestProcessName(p.index) + ` exited with status $rvm_s; stopping ` + guestOthers(p.index, len(procs)-1) + `" ;;
`)
	}
	first := ""
	if len(procs) > 1 {
		first = `				case "$rvm_i" in
` + names.String() + `				esac
				rvm_signal TERM
				rvm_timer_start
`
	}
	return `(
	command exec </dev/null 5>&-
	echo -1000 >/proc/self/oom_score_adj
	rvm_left=` + strconv.Itoa(len(procs)) + `
	rvm_by=
	rvm_status=
	rvm_app=
	rvm_timer=
	rvm_done=" "
	rvm_kill() {
		case "$rvm_done" in
		*" $2 "*) return ;;
		esac
		rvm_n=0
		until read -r rvm_pid 2>/dev/null <"$3" && [ -n "$rvm_pid" ]; do
			rvm_n=$((rvm_n + 1))
			[ "$rvm_n" -le 20 ] || return
			sleep 0.05
		done
		kill -"$1" "$rvm_pid" 2>/dev/null
	}
	rvm_signal() {
` + signal.String() + `	}
	rvm_timer_start() {
		(
			rvm_term=
			trap 'rvm_term=1' TERM
			sleep ` + timeout + ` &
			rvm_sleep=$!
			[ -n "$rvm_term" ] || wait "$rvm_sleep"
			kill "$rvm_sleep" 2>/dev/null
			wait "$rvm_sleep" 2>/dev/null
			[ -n "$rvm_term" ] || echo timeout >&4
		) &
		rvm_timer=$!
	}
	while [ "$rvm_left" -gt 0 ]; do
		read -r rvm_ev rvm_i rvm_s <&4 || continue
		case "$rvm_ev" in
		exit)
			rvm_left=$((rvm_left - 1))
			rvm_done="$rvm_done$rvm_i "
			if [ "$rvm_i" = 0 ]; then
				rvm_app=$rvm_s
			fi
			if [ -z "$rvm_by" ]; then
				rvm_by=exit
				rvm_status=$rvm_s
				echo "` + firstTag(nonce) + `$rvm_i $rvm_s"
` + first + `			fi
			;;
		stop)
			if [ -z "$rvm_by" ]; then
				rvm_by=stop
				rvm_timer_start
			fi
			;;
		timeout)
			echo "vm-launch guest: the app and its sidecars did not all exit within ` + timeout + ` seconds; ending the rest"
			rvm_signal KILL
			break
			;;
		esac
	done
	if [ -n "$rvm_timer" ]; then
		kill "$rvm_timer" 2>/dev/null
		wait "$rvm_timer" 2>/dev/null
	fi
	if [ "$rvm_by" = stop ]; then
		rvm_status=${rvm_app:-137}
	fi
	exit "$rvm_status"
)
`
}

// guestOthers names the processes that the first exit of process index
// stops, in a guest whose app has the given number of sidecars.
func guestOthers(index, sidecars int) string {
	if index == 0 {
		if sidecars == 1 {
			return "the sidecar"
		}
		return "the sidecars"
	}
	switch sidecars {
	case 1:
		return "the app"
	case 2:
		return "the app and the other sidecar"
	}
	return "the app and the other sidecars"
}

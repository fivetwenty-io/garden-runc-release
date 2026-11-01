//go:build linux

package main

import (
	"strconv"
	"strings"
)

// logTag starts each log frame that the guest's framers write on the serial
// console, as RVM_LOG_<nonce>=<i><s> <payload>, where i is the process's
// index, 0 for the app, and s is o or e for the last piece of a stdout or
// stderr line and O or E when more pieces of the line follow. No guest
// process holds the console, so only the root framers can write a frame.
func logTag(nonce string) string { return "RVM_LOG_" + nonce + "=" }

// firstTag starts the line, RVM_FIRST_<nonce>=<i> <status>, with which the
// guest's event loop names the process that exited first and its status,
// before it stops the others.
func firstTag(nonce string) string { return "RVM_FIRST_" + nonce + "=" }

// guestLogDir holds the FIFOs through which each process of the run section
// writes its output (see guestLogFIFO). It sits outside the app root, and
// only root can enter it, so no process can reach a FIFO by its path.
const guestLogDir = "/rvm/log"

// guestFramePayload is the most bytes of a line that one log frame carries.
// A frame of that payload, with its tag, index, letter, space, and the
// console's CRLF, stays under 1 KiB, so each framer writes it in one write
// call, and the console's write lock keeps it whole. It also stays well
// inside maxFrameBytes, the most that the host takes for a frame.
const guestFramePayload = 960

// guestLogFIFO returns the path of process index's FIFO for stream, which is
// "out" for its stdout and "err" for its stderr.
func guestLogFIFO(index int, stream string) string {
	return guestLogDir + "/" + strconv.Itoa(index) + "." + stream
}

// guestLogSetup is the setup step that creates guestLogDir with mode 0700
// and, in it, both FIFOs of every process in procs with mode 0600. It runs
// before the start tag, so a failure is a setup failure, with the console
// shown, and never output of the command.
func guestLogSetup(procs []guestProcess) string {
	fifos := make([]string, 0, 2*len(procs))
	for _, p := range procs {
		fifos = append(fifos, guestLogFIFO(p.index, "out"), guestLogFIFO(p.index, "err"))
	}
	return `mkdir -m 0700 ` + guestLogDir + ` || rvm_fail "creating the log FIFO directory ` + guestLogDir + ` failed"
mkfifo -m 0600 ` + strings.Join(fifos, " ") + ` || rvm_fail "creating the log FIFOs in ` + guestLogDir + ` failed"
`
}

// guestFrameFunc defines rvm_frame, the framer, which the run section starts
// twice for each process, as rvm_frame <index> o for its stdout FIFO and
// rvm_frame <index> e for its stderr FIFO on standard input, with the
// console as standard output (see guestProcessWrapper). It sets its own
// oom_score_adj to -1000, as the wrappers do, so the guest kernel never ends
// a framer and leaves its process writing into a pipe that no one reads.
// That is sound only because a framer's memory is bounded: it holds at most
// one piece of a line, whatever its process writes.
//
// busybox tr drops each NUL byte, which no shell variable can hold. A busybox
// sh then reads the stream with read -n, which stops at a newline or after
// guestFramePayload bytes, whichever comes first, and writes each piece as
// one frame (see logTag) as soon as it has it, with the upper-case letter on
// a full piece, which a further piece continues, and the lower-case letter
// on the last piece of a line. A line of exactly a multiple of
// guestFramePayload bytes therefore ends with an empty last piece, and the
// end of the stream ends a line that has no newline. The shell writes each
// frame with one printf, which leaves in one write. LC_ALL=C makes ${#} count
// bytes, as read -n does, where a UTF-8 locale would count characters.
//
// The framer reads a byte at a time, so it passes on about 1.5 MB/s of one
// stream. busybox awk passes on far more, but it holds a line until its
// newline comes, so a process that writes one endless line would grow a
// framer that the kernel never ends. busybox fold could bound the line, but
// it buffers its output into a pipe until a few KiB have come or the stream
// ends, which would hold back the lines of a quiet process, and head -c waits
// for all its bytes in the same way.
//
// The tag, which holds the nonce and the index, reaches the shell as RVM_TAG
// in its environment, which only root can read, and never in an argv, which
// every process can read in /proc. Both programs are named by the busybox
// binary's path, as guestRootCat names cat, and the framer's script is one
// line.
func guestFrameFunc(nonce string) string {
	n := strconv.Itoa(guestFramePayload)
	return `rvm_frame() {
	echo -1000 >/proc/self/oom_score_adj
	/bin/busybox tr -d '\000' | LC_ALL=C RVM_TAG='` + logTag(nonce) + `'"$1" /bin/busybox sh -c 'case $1 in o) rvm_m=O ;; e) rvm_m=E ;; esac; rvm_more=; while IFS= read -r -n ` + n + ` rvm_l; do if [ "${#rvm_l}" -eq ` + n + ` ]; then rvm_s=$rvm_m rvm_more=1; else rvm_s=$1 rvm_more=; fi; printf "%s\n" "$RVM_TAG$rvm_s $rvm_l"; done; if [ -n "$rvm_l" ] || [ -n "$rvm_more" ]; then printf "%s\n" "$RVM_TAG$1 $rvm_l"; fi' rvm_frame "$2"
}
`
}

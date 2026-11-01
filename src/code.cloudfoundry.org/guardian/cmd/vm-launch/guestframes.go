//go:build linux

package main

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

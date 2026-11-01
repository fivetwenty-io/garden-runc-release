//go:build linux

package main

import "sync"

// This file stands in for what the initramfs wiring adds to the stack guest,
// so that run compiles and its specs run before that wiring merges. The
// wiring replaces every definition here: guestSidecar and hasAppRoot keep
// their names, and the two guestStack fields replace the table below.

// guestSidecar is one sidecar's two guest files: its quoted argv and its
// environment file.
type guestSidecar struct{ argv, env string }

// hasAppRoot reports whether the guest that s describes has a root at
// /rvm/app. A nil s is the busybox guest, which has none.
func (s *guestStack) hasAppRoot() bool { return s != nil }

// stackGuestExtrasTable holds, for each guestStack, what its sidecars and
// identity fields will hold.
var stackGuestExtrasTable = struct {
	sync.Mutex
	m map[*guestStack]stackGuestExtrasEntry
}{m: map[*guestStack]stackGuestExtrasEntry{}}

type stackGuestExtrasEntry struct {
	sidecars []guestSidecar
	identity *instanceIdentity
}

// setStackGuestExtras stands in for
// "s.sidecars, s.identity = sidecars, identity".
func setStackGuestExtras(s *guestStack, sidecars []guestSidecar, identity *instanceIdentity) {
	stackGuestExtrasTable.Lock()
	defer stackGuestExtrasTable.Unlock()
	stackGuestExtrasTable.m[s] = stackGuestExtrasEntry{sidecars: sidecars, identity: identity}
}

// stackGuestExtras stands in for reading s.sidecars and s.identity.
func stackGuestExtras(s *guestStack) ([]guestSidecar, *instanceIdentity) {
	stackGuestExtrasTable.Lock()
	defer stackGuestExtrasTable.Unlock()
	e := stackGuestExtrasTable.m[s]
	return e.sidecars, e.identity
}

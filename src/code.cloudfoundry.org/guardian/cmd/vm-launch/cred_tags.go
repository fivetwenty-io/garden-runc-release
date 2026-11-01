//go:build linux

package main

// credOKTag and credBadTag frame the guest's acknowledgement of an identity
// push on the serial console, the push's sequence number following each.
func credOKTag(nonce string) string  { return "RVM_CREDOK_" + nonce + "=" }
func credBadTag(nonce string) string { return "RVM_CREDBAD_" + nonce + "=" }

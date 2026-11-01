//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// sidecarsEnvVar names the variable that rep sets on the app's launcher
	// action. It holds the sidecars that run beside the app in the guest.
	sidecarsEnvVar = "CF_VM_SIDECARS"

	// sidecarsVersion is the description that has no relay key, so its
	// sidecars' output goes to vm-launch's own output.
	sidecarsVersion = 1

	// sidecarsVersion2 is the description that carries a relay key, which
	// the sidecars' log relays present to the relay hub.
	sidecarsVersion2 = 2

	// maxSidecars is the most sidecars one app may carry into a guest.
	maxSidecars = 8
)

// vmSidecar is one sidecar process that runs in the guest beside the app:
// its argument vector, the environment entries it adds and removes, and the
// log source that Diego gives it, which the mode line names.
type vmSidecar struct {
	Args      []string
	Env       []string
	Unset     []string
	LogSource string
}

// sidecarsDescription is the JSON that sidecarsEnvVar holds.
type sidecarsDescription struct {
	Version  int    `json:"version"`
	RelayKey string `json:"relay_key"`
	Sidecars []struct {
		Args      []string `json:"args"`
		Env       []string `json:"env"`
		Unset     []string `json:"unset"`
		LogSource string   `json:"log_source"`
	} `json:"sidecars"`
}

// parseSidecars reads the sidecars that env describes in sidecarsEnvVar, and
// drops the relay key that a version 2 description carries (see
// parseSidecarsKeyed).
func parseSidecars(env map[string]string) ([]vmSidecar, error) {
	sidecars, _, err := parseSidecarsKeyed(env)
	return sidecars, err
}

// parseSidecarsKeyed reads the sidecars that env describes in sidecarsEnvVar,
// and the relay key of a version 2 description. It returns nil and no error
// when the variable is absent or empty, because the app then has no sidecars.
// It reads version 1, which has no key and so returns an empty one, and
// version 2, which must carry a key of 32 lower-case hex digits. It refuses
// malformed JSON, any other version, a version 2 description with a missing or
// malformed key, more than eight sidecars, and a sidecar with no arguments.
func parseSidecarsKeyed(env map[string]string) (sidecars []vmSidecar, relayKey string, err error) {
	raw := env[sidecarsEnvVar]
	if raw == "" {
		return nil, "", nil
	}
	var desc sidecarsDescription
	if err := json.Unmarshal([]byte(raw), &desc); err != nil {
		return nil, "", fmt.Errorf("%s is not valid JSON: %w", sidecarsEnvVar, err)
	}
	switch desc.Version {
	case sidecarsVersion:
	case sidecarsVersion2:
		if !relayKeyPattern.MatchString(desc.RelayKey) {
			return nil, "", fmt.Errorf("%s has version %d, which needs a relay_key of 32 hex digits", sidecarsEnvVar, desc.Version)
		}
		relayKey = desc.RelayKey
	default:
		return nil, "", fmt.Errorf("%s has version %d, and this vm-launch reads only versions %d and %d", sidecarsEnvVar, desc.Version, sidecarsVersion, sidecarsVersion2)
	}
	if len(desc.Sidecars) > maxSidecars {
		return nil, "", fmt.Errorf("%s describes %d sidecars, over the %d that a guest may run", sidecarsEnvVar, len(desc.Sidecars), maxSidecars)
	}
	sidecars = make([]vmSidecar, 0, len(desc.Sidecars))
	for i, sc := range desc.Sidecars {
		if len(sc.Args) == 0 {
			// The guest numbers the sidecars from 1, because the app is 0.
			return nil, "", fmt.Errorf("sidecar %d in %s has no arguments to run", i+1, sidecarsEnvVar)
		}
		sidecars = append(sidecars, vmSidecar{Args: sc.Args, Env: sc.Env, Unset: sc.Unset, LogSource: sc.LogSource})
	}
	return sidecars, relayKey, nil
}

// sidecarGuestFiles returns the two files that describe sc to the guest. argv
// is the stack's launcher followed by the sidecar's arguments, each quoted as
// one sh word and joined by spaces, so the guest can read it back with eval.
// Rep sends a sidecar's arguments as a Diego run action holds them, without
// the launcher that is the action's path, so the launcher goes in front of
// them here, as it does for the app (see stackCommand). env is the sidecar's
// environment changes as export lines for its env entries and unset lines for
// its unset entries, in that order. Names on deny and names that are not shell
// identifiers are left out, as they are for the app. A value with a NUL byte
// is an error, because no process environment can carry one.
func sidecarGuestFiles(sc vmSidecar, deny map[string]bool) (argv, env string, err error) {
	words := make([]string, 0, 1+len(sc.Args))
	words = append(words, sidecarQuote(stackLauncherPath))
	for i, arg := range sc.Args {
		if strings.IndexByte(arg, 0) >= 0 {
			return "", "", fmt.Errorf("argument %d of a sidecar holds a NUL byte, which no process argument can carry", i)
		}
		words = append(words, sidecarQuote(arg))
	}

	var b strings.Builder
	for _, entry := range sc.Env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			return "", "", fmt.Errorf("a sidecar environment entry has no =; every entry must be NAME=value")
		}
		if strings.IndexByte(value, 0) >= 0 {
			return "", "", fmt.Errorf("the sidecar environment variable %s holds a NUL byte, which no process environment can carry", name)
		}
		if !sidecarEnvNameUsable(name, deny) {
			continue
		}
		b.WriteString("export " + name + "=" + sidecarQuote(value) + "\n")
	}
	for _, name := range sc.Unset {
		if !sidecarEnvNameUsable(name, deny) {
			continue
		}
		b.WriteString("unset " + name + "\n")
	}
	return strings.Join(words, " "), b.String(), nil
}

// sidecarEnvNameUsable reports whether name may appear in a sidecar's
// environment file.
func sidecarEnvNameUsable(name string, deny map[string]bool) bool {
	return validEnvName(name) && !deny[name] && !strings.HasPrefix(name, guestEnvDeniedPrefix)
}

// sidecarQuote quotes s as one word for busybox sh. Inside single quotes
// every byte is literal except the single quote itself, which closes the
// quotes, appears escaped, and opens them again.
func sidecarQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

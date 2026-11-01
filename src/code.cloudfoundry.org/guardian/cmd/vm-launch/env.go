//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The guest environment. vm-launch replaces the CF launcher, so it does the
// launcher's environment work itself (buildpackapplifecycle env.CalcEnv)
// before it hands the container's environment to the guest command: it
// rewrites VCAP_APPLICATION, derives DATABASE_URL, and drops
// VCAP_PLATFORM_OPTIONS. It also gives MEMORY_LIMIT the guest's size. It
// does not copy what the launcher does after CalcEnv, which needs the
// droplet: changing into the app directory, sourcing profile.d scripts and
// .profile, and running the command with bash.
const (
	memoryLimitEnv     = "MEMORY_LIMIT"
	databaseURLEnv     = "DATABASE_URL"
	portEnv            = "PORT"
	instanceGUIDEnv    = "INSTANCE_GUID"
	instanceOrdinalEnv = "INSTANCE_INDEX"
	platformOptionsEnv = "VCAP_PLATFORM_OPTIONS"

	// maxGuestEnvBytes caps /rvm/env. Linux limits a process's arguments and
	// environment together to a quarter of its stack limit, 2 MiB with the
	// default 8 MiB stack, and the guest's execve of the command must carry
	// all of it.
	maxGuestEnvBytes = 1 << 20

	// maxEnvEntryBytes caps one NAME=value entry. Linux limits one argument
	// or environment string to 128 KiB including its NUL.
	maxEnvEntryBytes = 128<<10 - 1

	// guestEnvDeniedPrefix starts the names of Garden's own markers.
	guestEnvDeniedPrefix = "__GARDEN_"
)

// guestEnvDenylist names variables the guest never gets. PATH, HOME, TMPDIR,
// USER, PWD, OLDPWD, and DEPS_DIR name container paths and users; the guest
// sets its own PATH. CF_INSTANCE_CERT, CF_INSTANCE_KEY, and
// CF_SYSTEM_CERT_PATH name container files, and SERVICE_BINDING_ROOT and
// VCAP_SERVICES_FILE_PATH name file-based service bindings, which are in the
// container and not in the guest. VCAP_PLATFORM_OPTIONS belongs to the
// launcher, which unsets it before the app starts.
var guestEnvDenylist = map[string]bool{
	"PATH":                    true,
	"HOME":                    true,
	"TMPDIR":                  true,
	"USER":                    true,
	"PWD":                     true,
	"OLDPWD":                  true,
	"DEPS_DIR":                true,
	"CF_INSTANCE_CERT":        true,
	"CF_INSTANCE_KEY":         true,
	"CF_SYSTEM_CERT_PATH":     true,
	"SERVICE_BINDING_ROOT":    true,
	"VCAP_SERVICES_FILE_PATH": true,
	platformOptionsEnv:        true,
}

// stackGuestEnvDenylist is guestEnvDenylist for a guest that runs the app on
// the stack image, where the container's PATH and USER describe the guest's
// own root file system and user, and so are kept. HOME, TMPDIR, DEPS_DIR,
// PWD, and OLDPWD still name container paths, and the rest of the denylist
// stays as it is.
var stackGuestEnvDenylist = func() map[string]bool {
	deny := make(map[string]bool, len(guestEnvDenylist))
	for name := range guestEnvDenylist {
		if name != "PATH" && name != "USER" {
			deny[name] = true
		}
	}
	return deny
}()

// shellOwnedNames are the variables that the guest's busybox sh sets for
// itself when it runs /rvm/cmd: it ignores an inherited IFS, OPTIND, and
// PPID, and sets SHLVL one above the inherited value. A value from /rvm/env
// would never reach the command or its children, so /rvm/env leaves these
// out, and one line names those that are set. Every other shell variable
// passes through. A non-interactive sh does not act on ENV, CDPATH, PS1, or
// HISTFILE, and the command's children get an inherited RANDOM,
// EPOCHSECONDS, or EPOCHREALTIME unchanged until the command reads one.
var shellOwnedNames = map[string]bool{
	"IFS":    true,
	"OPTIND": true,
	"PPID":   true,
	"SHLVL":  true,
}

// maxLoggedNames caps how many names one log line lists.
const maxLoggedNames = 20

// joinLoggedNames joins names for a log line, listing at most maxLoggedNames
// of them and counting the rest.
func joinLoggedNames(names []string) string {
	if len(names) <= maxLoggedNames {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(names[:maxLoggedNames], ", "), len(names)-maxLoggedNames)
}

// databaseSchemes maps the URI schemes the launcher derives DATABASE_URL
// from to the scheme DATABASE_URL gets, or to "" to keep the scheme
// (buildpackapplifecycle databaseuri).
var databaseSchemes = map[string]string{
	"mysql":      "mysql2",
	"mysql2":     "",
	"postgres":   "",
	"postgresql": "postgres",
}

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validEnvName reports whether name is a shell identifier, which /rvm/env
// can export. The guest's busybox sh drops every other name from the
// environment it starts with, so no such name could reach the command or
// anything the command starts.
func validEnvName(name string) bool {
	return envNamePattern.MatchString(name)
}

// lastWinsEnv returns environ, in os.Environ form, as a map. When a name
// appears more than once, the last value wins, as it does under runc and
// bash: Garden lists the image's variables before the process's own, so the
// last value is Diego's. os.Getenv keeps the first one instead, which is why
// every reader of the environment goes through this map. An entry without
// "=" names nothing a process can look up; it is left out with one line that
// counts such entries and never repeats one.
func lastWinsEnv(environ []string, logger *log.Logger) map[string]string {
	env := make(map[string]string, len(environ))
	malformed := 0
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			malformed++
			continue
		}
		env[name] = value
	}
	if malformed > 0 {
		logger.Printf("leaving out %d environment entries that have no =", malformed)
	}
	return env
}

// lookupIn returns a lookup function, in the form of os.LookupEnv, over env.
func lookupIn(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

// buildGuestEnv returns the guest's /rvm/env for the container environment
// env, after the launcher's rewrites, for a guest of guestMiB MiB. env must
// already hold any VCAP_SERVICES that CredHub resolved; it is not changed.
//
// /rvm/env holds one export line for each variable whose name is a shell
// identifier, except guestEnvDenylist and shellOwnedNames, once each,
// sorted by name, with every value quoted by shellQuote. Names starting with
// __GARDEN_ are left out. So are names that are not identifiers, such as
// spring.profiles.active, which the guest shell would drop, and an entry
// with an empty name. One line names the shell-owned names that are set,
// one line names the first maxLoggedNames names that are not identifiers
// and counts the rest, and one line reports an empty name. No line holds a
// value.
//
// An entry over maxEnvEntryBytes as NAME=value, a value holding a NUL byte,
// and a file over maxGuestEnvBytes are errors. No error or log line holds a
// value.
func buildGuestEnv(env map[string]string, guestMiB int, logger *log.Logger) (string, error) {
	return buildGuestEnvDenying(env, guestMiB, logger, guestEnvDenylist)
}

// buildStackGuestEnv is buildGuestEnv for a guest that runs the app on the
// stack image. It keeps PATH, USER, and LANG, which the stack's own root file
// system makes meaningful, and still leaves out HOME, TMPDIR, DEPS_DIR, PWD,
// and OLDPWD (see stackGuestEnvDenylist).
func buildStackGuestEnv(env map[string]string, guestMiB int, logger *log.Logger) (string, error) {
	return buildGuestEnvDenying(env, guestMiB, logger, stackGuestEnvDenylist)
}

// buildGuestEnvDenying is buildGuestEnv with deny in place of
// guestEnvDenylist.
func buildGuestEnvDenying(env map[string]string, guestMiB int, logger *log.Logger, deny map[string]bool) (string, error) {
	vars := make(map[string]string, len(env))
	for name, value := range env {
		vars[name] = value
	}
	lookup := lookupIn(env)

	if raw, ok := vars[vcapApplicationEnv]; ok {
		if rewritten, ok := rewriteVCAPApplication(raw, lookup, guestMiB); ok {
			vars[vcapApplicationEnv] = rewritten
		} else {
			logger.Printf("%s is not a JSON object; the guest gets it unchanged", vcapApplicationEnv)
		}
	}
	if services := vars[vcapServicesEnv]; services != "" {
		if u := databaseURL(services); u != "" {
			vars[databaseURLEnv] = u
		}
	}
	if _, ok := vars[memoryLimitEnv]; ok {
		vars[memoryLimitEnv] = strconv.Itoa(guestMiB) + "m"
	}

	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	sort.Strings(names)

	var exports strings.Builder
	var unusable, shellOwned []string
	largestName, largestSize := "", 0
	for _, name := range names {
		value := vars[name]
		if name == "" {
			logger.Print("leaving out an environment entry with an empty name")
			continue
		}
		if strings.HasPrefix(name, guestEnvDeniedPrefix) {
			continue
		}
		if !validEnvName(name) {
			unusable = append(unusable, quoteForLog(name))
			continue
		}
		if deny[name] {
			continue
		}
		if shellOwnedNames[name] {
			shellOwned = append(shellOwned, name)
			continue
		}
		if strings.IndexByte(value, 0) >= 0 {
			return "", fmt.Errorf("the environment variable %s holds a NUL byte, which no process environment can carry", name)
		}
		size := len(name) + 1 + len(value)
		if size > maxEnvEntryBytes {
			return "", fmt.Errorf("the environment variable %s is %d bytes as NAME=value, over the %d bytes one guest variable may have", name, size, maxEnvEntryBytes)
		}
		if size > largestSize {
			largestName, largestSize = name, size
		}
		exports.WriteString("export " + name + "=" + shellQuote(value) + "\n")
	}
	if len(shellOwned) > 0 {
		logger.Printf("leaving out %d environment variables that the guest shell sets for itself: %s", len(shellOwned), strings.Join(shellOwned, ", "))
	}
	if len(unusable) > 0 {
		logger.Printf("leaving out %d environment variables whose names are not shell identifiers, which the guest shell drops: %s", len(unusable), joinLoggedNames(unusable))
	}
	envFile := exports.String()
	if len(envFile) > maxGuestEnvBytes {
		return "", fmt.Errorf("the guest environment is %d bytes, over the %d bytes a guest may have; the largest variable is %s at %d bytes as NAME=value", len(envFile), maxGuestEnvBytes, largestName, largestSize)
	}
	return envFile, nil
}

// rewriteVCAPApplication applies the launcher's VCAP_APPLICATION rewrite to
// raw: host becomes 0.0.0.0, instance_id becomes INSTANCE_GUID, the empty
// string when that is unset, port becomes PORT and instance_index becomes
// INSTANCE_INDEX when each parses as an integer. vm-launch adds one change:
// limits.mem becomes the guest size in MiB when limits is an object that
// holds mem. As in the launcher, the value is decoded into a map and encoded
// again, so the result matches what a runc app gets apart from limits.mem.
// ok is false, and raw is returned, when raw is not a JSON object.
func rewriteVCAPApplication(raw string, lookup func(string) (string, bool), guestMiB int) (rewritten string, ok bool) {
	app := map[string]interface{}{}
	if err := json.Unmarshal([]byte(raw), &app); err != nil || app == nil {
		// JSON null decodes without an error into a nil map.
		return raw, false
	}
	get := func(name string) string {
		v, _ := lookup(name)
		return v
	}
	app["host"] = "0.0.0.0"
	app["instance_id"] = get(instanceGUIDEnv)
	if port, err := strconv.Atoi(get(portEnv)); err == nil {
		app["port"] = port
	}
	if index, err := strconv.Atoi(get(instanceOrdinalEnv)); err == nil {
		app["instance_index"] = index
	}
	if limits, ok := app["limits"].(map[string]interface{}); ok {
		if _, ok := limits["mem"]; ok {
			limits["mem"] = guestMiB
		}
	}
	out, err := json.Marshal(app)
	if err != nil {
		return raw, false
	}
	return string(out), true
}

// diskLimitMiB returns VCAP_APPLICATION limits.disk, the app's disk quota in
// MiB. Diego's value is a whole number of MiB. The error says why there is no
// usable quota: VCAP_APPLICATION is unset or has no limits.disk, which is
// what a task run by hand or a spec looks like, or it is not JSON, its
// limits is not an object, or its limits.disk is not a positive whole
// number. No error repeats a value.
func diskLimitMiB(lookup func(string) (string, bool)) (int64, error) {
	raw, ok := lookup(vcapApplicationEnv)
	if !ok {
		return 0, fmt.Errorf("%s is not set", vcapApplicationEnv)
	}
	var app struct {
		Limits json.RawMessage `json:"limits"`
	}
	if err := json.Unmarshal([]byte(raw), &app); err != nil {
		return 0, fmt.Errorf("%s is not a JSON object", vcapApplicationEnv)
	}
	if app.Limits == nil {
		return 0, fmt.Errorf("%s has no limits.disk", vcapApplicationEnv)
	}
	var limits struct {
		Disk json.RawMessage `json:"disk"`
	}
	if err := json.Unmarshal(app.Limits, &limits); err != nil {
		return 0, fmt.Errorf("%s limits is not a JSON object", vcapApplicationEnv)
	}
	if limits.Disk == nil || string(limits.Disk) == "null" {
		return 0, fmt.Errorf("%s has no limits.disk", vcapApplicationEnv)
	}
	limit, err := strconv.ParseInt(string(limits.Disk), 10, 64)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("%s limits.disk is not a positive whole number of MiB", vcapApplicationEnv)
	}
	return limit, nil
}

// databaseURL returns DATABASE_URL for VCAP_SERVICES services as the
// launcher derives it (buildpackapplifecycle databaseuri): the first
// credentials uri that parses and whose scheme is in databaseSchemes, with
// the scheme mapped. It returns "" when services does not decode or holds no
// such uri. The launcher walks the service labels in Go map order, which is
// random; vm-launch walks them sorted, and the bindings of each label in
// order, so that the result is the same at every launch.
func databaseURL(services string) string {
	var data map[string][]struct {
		Credentials struct {
			URI string `json:"uri"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(services), &data); err != nil {
		return ""
	}
	labels := make([]string, 0, len(data))
	for label := range data {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		for _, binding := range data[label] {
			if binding.Credentials.URI == "" {
				continue
			}
			u, err := url.Parse(binding.Credentials.URI)
			if err != nil {
				continue
			}
			scheme, ok := databaseSchemes[u.Scheme]
			if !ok {
				continue
			}
			if scheme != "" {
				u.Scheme = scheme
			}
			return u.String()
		}
	}
	return ""
}

// shellQuote quotes s as one POSIX sh word. Inside single quotes every byte
// but the single quote is literal, so newlines, $, backslashes, and double
// quotes need nothing more.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

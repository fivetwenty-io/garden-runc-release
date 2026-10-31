//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// VM_VOLUMES is how an app chooses the mode and the size of each volume it
// binds. It is one JSON object keyed by a bound volume's container_dir, byte
// for byte, whose values are objects with the settings "mode" and "size":
//
//	{"/home/vcap/data": {"size": "20G"}, "/shared": {"mode": "share"}}
//
// An unset or empty variable leaves every volume private at the default
// size. Everything else is checked strictly, and every refusal is a plain
// error that run turns into exit status 125, before CredHub is asked
// anything, a port is reserved, or the work directory exists.
const (
	volumeSettingsEnv = "VM_VOLUMES"

	settingMode = "mode"
	settingSize = "size"

	modeNamePrivate = "private"
	modeNameShare   = "share"

	// minVolumeSize is the smallest size an app may ask for.
	minVolumeSize = 64 << 20

	// maxVolumeSize is the largest image checkImage accepts, 2^62 bytes. The
	// quota is the real bound; this keeps the arithmetic below inside int64
	// and refuses at parse time what the image guard would refuse later.
	maxVolumeSize = 1 << 62

	// maxSizeNumber is the largest count in a size, nine digits.
	maxSizeNumber = 999999999
)

// volumeMode is how a volume reaches the guest. The zero value is private.
type volumeMode int

const (
	// volumePrivate is a disk of the instance's own: an image file, or a
	// block disk.
	volumePrivate volumeMode = iota
	// volumeShare is the volume's directory itself, shared by every instance.
	volumeShare
)

func (m volumeMode) String() string {
	if m == volumeShare {
		return modeNameShare
	}
	return modeNamePrivate
}

// volumeSettings are the mode and size an app chose for one volume. The zero
// value is what an app that sets nothing gets: private, at the default size.
type volumeSettings struct {
	// Mode is private unless VM_VOLUMES said "share".
	Mode volumeMode
	// SizeBytes is the requested size when the app set one, and zero when it
	// did not. Use RequestedBytes to read it.
	SizeBytes int64
}

// SizeSet reports whether the app set a size for the volume.
func (s volumeSettings) SizeSet() bool { return s.SizeBytes != 0 }

// RequestedBytes is the size the volume is asked for: the app's, or the
// default.
func (s volumeSettings) RequestedBytes() int64 {
	if s.SizeBytes == 0 {
		return defaultImageSize
	}
	return s.SizeBytes
}

// sizeUnits maps an upper-cased unit to its binary multiplier. A size is one
// to nine decimal digits, the first not a zero, directly followed by a unit
// in any case.
var sizeUnits = map[string]int64{
	"M": 1 << 20, "MB": 1 << 20, "MIB": 1 << 20,
	"G": 1 << 30, "GB": 1 << 30, "GIB": 1 << 30,
	"T": 1 << 40, "TB": 1 << 40, "TIB": 1 << 40,
}

// parseVolumeSize turns the text of a size into bytes. ok is false when text
// is not a whole number from 1 to 999999999 directly followed by a unit; the
// text may hold no space, sign, or leading zero. The caller checks the
// minimum and the maximum, which have lines of their own.
func parseVolumeSize(text string) (n, unit int64, ok bool) {
	i := 0
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		i++
	}
	if i == 0 || i > 9 || text[0] == '0' {
		return 0, 0, false
	}
	count, err := strconv.ParseInt(text[:i], 10, 64)
	if err != nil || count < 1 || count > maxSizeNumber {
		return 0, 0, false
	}
	unit, found := sizeUnits[strings.ToUpper(text[i:])]
	if !found {
		return 0, 0, false
	}
	return count, unit, true
}

// errNotVolumeObject is the refusal of a value that is not an object of
// volume paths, at the top or for any one volume.
var errNotVolumeObject = errors.New(volumeSettingsEnv + " is not a JSON object of volume paths")

// parseVolumeSettings checks the value of VM_VOLUMES against dirs, the bound
// volumes' container paths, and returns the settings of each entry by path.
// Entries are checked in the order they were written, so the first error is
// the same on every start. A path that is bound and has no entry is not in
// the result; its settings are the zero value. Errors never repeat more of
// the value than quoteForLog allows.
func parseVolumeSettings(raw string, dirs []string) (map[string]volumeSettings, error) {
	if raw == "" {
		return nil, nil
	}
	if !json.Valid([]byte(raw)) {
		return nil, errNotVolumeObject
	}
	entries, err := objectMembers(raw)
	if err != nil {
		return nil, errNotVolumeObject
	}
	result := make(map[string]volumeSettings, len(entries))
	for _, e := range entries {
		if _, again := result[e.key]; again {
			return nil, fmt.Errorf("%s names %s more than once", volumeSettingsEnv, quoteForLog(e.key))
		}
		if !slices.Contains(dirs, e.key) {
			return nil, fmt.Errorf("%s names %s, which no volume binding of this app mounts", volumeSettingsEnv, quoteForLog(e.key))
		}
		s, err := parseOneVolume(e.key, e.value)
		if err != nil {
			return nil, err
		}
		result[e.key] = s
	}
	return result, nil
}

// parseOneVolume checks the settings object of one volume.
func parseOneVolume(dir string, value []byte) (volumeSettings, error) {
	members, err := objectMembers(string(value))
	if err != nil {
		return volumeSettings{}, errNotVolumeObject
	}
	var (
		s            volumeSettings
		haveSize     bool
		modeIsShare  bool
		seenSettings = map[string]bool{}
	)
	for _, m := range members {
		if seenSettings[m.key] {
			return volumeSettings{}, fmt.Errorf("%s %s names the setting %s more than once", volumeSettingsEnv, quoteForLog(dir), quoteForLog(m.key))
		}
		seenSettings[m.key] = true
		switch m.key {
		case settingMode:
			name, isString := jsonString(m.value)
			switch {
			case isString && name == modeNamePrivate:
			case isString && name == modeNameShare:
				modeIsShare = true
			default:
				return volumeSettings{}, fmt.Errorf("%s %s mode %s is not private or share", volumeSettingsEnv, quoteForLog(dir), quoteForLog(settingText(m.value, name, isString)))
			}
		case settingSize:
			haveSize = true
			text, isString := jsonString(m.value)
			shown := settingText(m.value, text, isString)
			count, unit, ok := parseVolumeSize(text)
			if !isString || !ok {
				return volumeSettings{}, fmt.Errorf("%s %s size %s is not a whole number followed by M, G, or T", volumeSettingsEnv, quoteForLog(dir), quoteForLog(shown))
			}
			if count > maxVolumeSize/unit {
				return volumeSettings{}, fmt.Errorf("%s %s size %s is over the 4 EiB limit", volumeSettingsEnv, quoteForLog(dir), text)
			}
			if count*unit < minVolumeSize {
				return volumeSettings{}, fmt.Errorf("%s %s size %s is below the 64M minimum", volumeSettingsEnv, quoteForLog(dir), text)
			}
			s.SizeBytes = count * unit
		default:
			return volumeSettings{}, fmt.Errorf("%s %s has an unknown setting %s; the settings are mode and size", volumeSettingsEnv, quoteForLog(dir), quoteForLog(m.key))
		}
	}
	if modeIsShare {
		s.Mode = volumeShare
		if haveSize {
			return volumeSettings{}, fmt.Errorf("%s %s sets a size, but a share has no image; its space is the volume's own quota", volumeSettingsEnv, quoteForLog(dir))
		}
	}
	return s, nil
}

// jsonString returns the string a JSON value holds, and false when the value
// is not a string.
func jsonString(value []byte) (string, bool) {
	if trimmed := bytes.TrimSpace(value); len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(value, &s); err != nil {
		return "", false
	}
	return s, true
}

// settingText is what an error line shows for a setting's value: the string
// itself, or the JSON text of a value that is not a string.
func settingText(value []byte, str string, isString bool) string {
	if isString {
		return str
	}
	return string(bytes.TrimSpace(value))
}

// member is one key and value of a JSON object, in the order written.
type member struct {
	key   string
	value []byte
}

// objectMembers walks the tokens of a JSON object and returns its members in
// the order written, keeping duplicates, which Go's decoder into a map would
// merge by keeping the last. It fails when the text is not exactly one
// object. Keys are matched exactly; the decoder's case folding never applies.
func objectMembers(text string) ([]member, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not an object")
	}
	var members []member
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("not a key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		members = append(members, member{key: key, value: value})
	}
	if tok, err := dec.Token(); err != nil {
		return nil, err
	} else if d, ok := tok.(json.Delim); !ok || d != '}' {
		return nil, errors.New("not an object")
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("data after the object")
	}
	return members, nil
}

// applyVolumeSettings reads VM_VOLUMES and records on each of vols what the
// app chose for it, share mode included. Whether a share is granted depends
// on the volume's provider, the backend, and the operator, which are known
// only after the providers are found, so grantShares decides it.
func applyVolumeSettings(lookup func(string) (string, bool), vols []guestVolume) error {
	raw, _ := lookup(volumeSettingsEnv)
	dirs := make([]string, len(vols))
	for i, v := range vols {
		dirs[i] = v.ContainerDir
	}
	settings, err := parseVolumeSettings(raw, dirs)
	if err != nil {
		return err
	}
	for i := range vols {
		s, ok := settings[vols[i].ContainerDir]
		if !ok {
			continue
		}
		vols[i].Settings = s
	}
	return nil
}

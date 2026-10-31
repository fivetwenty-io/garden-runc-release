//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The mount behind a volume is found by the kernel's own name for it. vm-launch
// opens the volume directory without following links, asks statx for the ID of
// the mount that holds it, and takes the /proc/self/mountinfo line with that
// ID. A path match could pick the wrong line when mounts stack on one mount
// point or a path needs escapes, and the kernel's answer is about the very
// directory vm-launch goes on to use.

// mountInfoPath is the mount table findVolumeProvider reads. Tests point it
// at a file.
var mountInfoPath = "/proc/self/mountinfo"

// volumeMountID returns the ID of the mount that holds dir. Tests replace it
// to return the ID of a line in a fake mount table.
var volumeMountID = statxMountID

// statxCall is the statx system call, which tests replace to stand in for a
// kernel that answers differently.
var statxCall = unix.Statx

// statxMountID returns the ID of the mount that holds dir, from statx. dir is
// opened as an O_PATH descriptor without following links, as openVolumeImage
// opens it, so the directory asked about is the one used afterwards. A kernel
// that does not set STATX_MNT_ID in the returned mask (before Linux 5.8) is an
// error, so the lookup fails closed.
func statxMountID(dir string) (uint64, error) {
	fd, err := openat2Retry(unix.AT_FDCWD, dir, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return 0, fmt.Errorf("opening volume %s: %w%s", quoteForLog(dir), err, symlinkHint(err))
	}
	defer unix.Close(fd)

	var st unix.Statx_t
	for i := 0; ; i++ {
		err = statxCall(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st)
		if err == nil || !errors.Is(err, unix.EINTR) || i >= openRetries {
			break
		}
	}
	if err != nil {
		return 0, fmt.Errorf("reading the mount ID of volume %s: statx: %w", quoteForLog(dir), err)
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, fmt.Errorf("the kernel did not report a mount ID through statx for volume %s (STATX_MNT_ID needs Linux 5.8 or later), so vm-launch cannot tell which mount holds it", quoteForLog(dir))
	}
	return st.Mnt_id, nil
}

// volumeMount returns the record of the mount with ID id in the mount table
// at mountinfo, for the volume at dir. Mount IDs are unique, so a table that
// has the ID on two lines, or has it only on a line that does not parse, is
// refused rather than guessed at.
func volumeMount(mountinfo, dir string, id uint64) (mountRecord, error) {
	f, err := os.Open(mountinfo)
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return mountRecord{}, fmt.Errorf("reading %s to find the filesystem of volume path %s: %w", mountinfo, quoteForLog(dir), err)
	}
	defer f.Close()

	want := strconv.FormatUint(id, 10)
	var found mountRecord
	var malformed error
	matches := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if first, _, _ := strings.Cut(line, " "); first != want {
			continue
		}
		rec, err := parseMountInfoRecord(line)
		if err != nil {
			malformed = fmt.Errorf("the line for mount ID %d in %s is malformed: %w", id, mountinfo, err)
			continue
		}
		found = rec
		matches++
	}
	if err := sc.Err(); err != nil {
		return mountRecord{}, fmt.Errorf("reading %s to find the filesystem of volume path %s: %w", mountinfo, quoteForLog(dir), err)
	}
	switch {
	case matches > 1:
		return mountRecord{}, fmt.Errorf("mount ID %d of volume path %s is on %d lines in %s", id, quoteForLog(dir), matches, mountinfo)
	case matches == 1:
		found.ContainerDir = dir
		return found, nil
	case malformed != nil:
		return mountRecord{}, malformed
	}
	return mountRecord{}, fmt.Errorf("volume path %s has no mount entry for its mount ID %d in %s", quoteForLog(dir), id, mountinfo)
}

// parseMountInfoRecord parses one mountinfo line, which reads
//
//	ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [OPTIONAL...] - FSTYPE SOURCE SUPEROPTIONS
//
// The optional fields end at the lone "-", and there may be none. The kernel
// writes a space, tab, newline, and backslash inside the root, mount point,
// and source as three-digit octal escapes, which are decoded here. The option
// lists are split at commas and otherwise kept as written. The returned
// record has no ContainerDir. A line without every field is an error.
func parseMountInfoRecord(line string) (mountRecord, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return mountRecord{}, fmt.Errorf("want at least 10 fields, have %d", len(fields))
	}
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	switch {
	case sep < 0:
		return mountRecord{}, errors.New("no - separator before the filesystem type")
	case len(fields)-sep-1 != 3:
		return mountRecord{}, fmt.Errorf("want a filesystem type, a source, and superblock options after the separator, have %d fields", len(fields)-sep-1)
	}

	var rec mountRecord
	var err error
	if rec.MountID, err = strconv.ParseUint(fields[0], 10, 64); err != nil {
		return mountRecord{}, fmt.Errorf("mount ID %s is not a number", quoteForLog(fields[0]))
	}
	if rec.ParentID, err = strconv.ParseUint(fields[1], 10, 64); err != nil {
		return mountRecord{}, fmt.Errorf("parent ID %s is not a number", quoteForLog(fields[1]))
	}
	majorField, minorField, ok := strings.Cut(fields[2], ":")
	if !ok {
		return mountRecord{}, fmt.Errorf("device %s is not major:minor", quoteForLog(fields[2]))
	}
	major, errMajor := strconv.ParseUint(majorField, 10, 32)
	minor, errMinor := strconv.ParseUint(minorField, 10, 32)
	if errMajor != nil || errMinor != nil {
		return mountRecord{}, fmt.Errorf("device %s is not major:minor", quoteForLog(fields[2]))
	}
	rec.Major, rec.Minor = uint32(major), uint32(minor)
	rec.Root = unescapeMountInfo(fields[3])
	rec.MountPoint = unescapeMountInfo(fields[4])
	rec.MountOptions = splitOptions(fields[5])
	if sep > 6 {
		rec.OptionalFields = append([]string(nil), fields[6:sep]...)
	}
	rec.FSType = fields[sep+1]
	rec.Source = unescapeMountInfo(fields[sep+2])
	rec.SuperOptions = splitOptions(fields[sep+3])
	return rec, nil
}

// splitOptions splits a comma-separated option list, and returns nil for an
// empty one.
func splitOptions(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// unescapeMountInfo decodes the three-digit octal escapes the kernel writes
// for a space, tab, newline, and backslash in a mountinfo path. Any other
// backslash stays as it is.
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && s[i+1] <= '3' && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

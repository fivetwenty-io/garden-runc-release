//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"code.cloudfoundry.org/guardian/backend"
)

// Drive identity. Every drive the guest formats or mounts carries an
// identity, which the guest reads from /sys/block/vdX/serial, and vm-launch
// writes each drive's identity into /rvm/disks (see disksFile), so that the
// guest can find a drive without relying on device order or size.
//
// On QEMU the identity is a serial that vm-launch chooses and passes on the
// drive's virtio-blk-device: rvm-root for the guest root image and rvm-volN
// for the volume at index N of volume order.
//
// Firecracker's drive API has no serial. Firecracker answers the guest's ID
// request with the decimal st_dev, st_rdev, and st_ino of the file it opened
// for the drive, run together and cut to the first 20 bytes. It opens each
// drive through /proc/self/fd, so it sees the inode vm-launch holds, and
// vm-launch predicts the identity from fstat on the same open file. For a
// block device that is the device node's own inode, which changes whenever
// the node is recreated, so the identity is computed at every launch and
// never stored. A grow keeps the inode and with it the identity. The digits
// run together with no separators, so two different files could in
// principle give the same identity, and a cut can make two long identities
// equal; vm-launch refuses a launch whose drives would share an identity.

// virtioBlockIDBytes is the size of the identity a virtio-blk device reports
// to the guest, and so the longest identity the guest reads back.
const virtioBlockIDBytes = 20

// The QEMU serials.
const (
	qemuRootSerial         = "rvm-root"
	qemuVolumeSerialPrefix = "rvm-vol"
)

// qemuVolumeSerial is the QEMU serial of the volume whose volume index is i
// (see selectedVolume.Index): rvm-vol0 for the first. A share before a volume
// keeps its own number, so the volume's serial and its RVM_VOLn entries in
// /rvm/disks carry the same n, and no serial ever names a share's number.
func qemuVolumeSerial(i int) string {
	return qemuVolumeSerialPrefix + strconv.Itoa(i)
}

// driveKind is what a volume drive holds, as RVM_VOLn_KIND names it: a disk
// image on a volume service's filesystem, or a whole block device. It comes
// from the attachment's mode (see driveKindOf). A share has no drive: its
// kind in /rvm/disks and /rvm/mounts comes from its volume's setting (see
// volumesOnDrives), and a drive of any other kind is refused.
type driveKind string

const (
	driveImage driveKind = "image"
	driveBlock driveKind = "block"
)

// driveKindOf is the kind of the drive that an attachment in mode m becomes.
func driveKindOf(m attachMode) (driveKind, error) {
	switch m {
	case attachFileImage:
		return driveImage, nil
	case attachBlock:
		return driveBlock, nil
	}
	return "", fmt.Errorf("%s has no volume drive kind", m)
}

// guestDrive is one volume drive as the guest learns of it: its identity,
// what it holds, and its size in bytes.
type guestDrive struct {
	id    string
	kind  driveKind
	bytes int64
}

// guestDrives are the drives the guest formats or mounts, with the identity
// the hypervisor gives each one.
type guestDrives struct {
	// rootID is the guest root image's identity, or empty without one.
	rootID string
	// volumes are the volume drives in volume order.
	volumes []guestDrive
}

// driveFileStat returns the stat of the open file f. Specs replace it to
// give two drives the numbers that collide.
var driveFileStat = func(f *os.File) (*syscall.Stat_t, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("the file system gave no device or inode numbers")
	}
	return st, nil
}

// firecrackerDriveID predicts the identity Firecracker gives the drive whose
// file vm-launch holds open as f: the decimal st_dev, st_rdev, and st_ino of
// the file, run together and cut to virtioBlockIDBytes.
func firecrackerDriveID(f *os.File) (string, error) {
	if f == nil {
		return "", errors.New("no open file")
	}
	st, err := driveFileStat(f)
	if err != nil {
		return "", err
	}
	id := strconv.FormatUint(uint64(st.Dev), 10) + strconv.FormatUint(uint64(st.Rdev), 10) + strconv.FormatUint(uint64(st.Ino), 10)
	if len(id) > virtioBlockIDBytes {
		id = id[:virtioBlockIDBytes]
	}
	return id, nil
}

// newGuestDrives returns the drives the hypervisor of kind gets, each with
// the identity the guest will read from it: the volumes in volume order,
// whose attachments are the files the hypervisor opens, and the guest root
// image root, or nil without one. On QEMU the identities are the serials that
// qemuArgv and qemuRootDrive pass, and a volume's serial carries its volume
// index (see qemuVolumeSerial), so the volumes must come in rising volume
// index, as prepare adds them. On Firecracker they are predicted from the
// open files, so they must be the files the hypervisor gets; for a block
// device that is the device node's own inode. Each volume's identity is
// recorded on its attachment (attachment.ID, with the volume index in attachment.Index), where hypervisorFiles takes it
// for the hypervisor's arguments, and each volume's kind comes from its
// attachment's mode. A drive without a usable identity or kind, and two
// drives that would share an identity, are an error, because the guest could
// then not tell which drive is which or how to treat it. The attachments are
// left unchanged on an error.
func newGuestDrives(kind backend.Kind, volumes preparedVolumes, root *os.File) (guestDrives, error) {
	if len(volumes) > maxVolumes {
		return guestDrives{}, fmt.Errorf("%d volume drives, over the %d a guest can have", len(volumes), maxVolumes)
	}
	var identify func(f *os.File, serial string) (string, error)
	switch kind {
	case backend.VMQemu:
		identify = func(_ *os.File, serial string) (string, error) { return serial, nil }
	case backend.VMFirecracker:
		identify = func(f *os.File, _ string) (string, error) { return firecrackerDriveID(f) }
	default:
		return guestDrives{}, fmt.Errorf("unsupported backend %q for drive identities", kind)
	}

	var drives guestDrives
	var named []namedDriveID
	for i, v := range volumes {
		name := "the volume at " + quoteForLog(v.Path)
		if v.Attachment == nil || v.Attachment.File == nil {
			return guestDrives{}, fmt.Errorf("%s has no open disk to identify", name)
		}
		dk, err := driveKindOf(v.Attachment.Mode)
		if err != nil {
			return guestDrives{}, fmt.Errorf("%s: %w", name, err)
		}
		if v.Index < 0 || (i > 0 && v.Index <= volumes[i-1].Index) {
			return guestDrives{}, fmt.Errorf("%s has the volume index %d, which does not follow the volume before it in volume order", name, v.Index)
		}
		id, err := identify(v.Attachment.File, qemuVolumeSerial(v.Index))
		if err != nil {
			return guestDrives{}, fmt.Errorf("predicting the %s drive identity of %s: %w", kind, name, err)
		}
		drives.volumes = append(drives.volumes, guestDrive{id: id, kind: dk, bytes: v.Bytes})
		named = append(named, namedDriveID{name: name, id: id})
	}
	if root != nil {
		id, err := identify(root, qemuRootSerial)
		if err != nil {
			return guestDrives{}, fmt.Errorf("predicting the %s drive identity of the guest root image: %w", kind, err)
		}
		drives.rootID = id
		named = append(named, namedDriveID{name: "the guest root image", id: id})
	}
	if err := checkDriveIDs(named, " on "+string(kind)); err != nil {
		return guestDrives{}, err
	}
	for i, v := range volumes {
		v.Attachment.ID = drives.volumes[i].id
		v.Attachment.Index = v.Index
	}
	return drives, nil
}

// namedDriveID is a drive's identity with the words that name the drive in a
// refusal.
type namedDriveID struct {
	name string
	id   string
}

// checkDriveIDs refuses an identity the guest could not read back or match,
// and two drives that share an identity. An identity must be 1 to
// virtioBlockIDBytes letters, digits, and hyphens: the guest reads at most
// that many bytes, and the characters keep the identity safe as a word in
// /rvm/disks, which the guest sources, and in a QEMU option. where ends the
// duplicate line, such as " on vm-qemu", or is empty.
func checkDriveIDs(drives []namedDriveID, where string) error {
	seen := make(map[string]string, len(drives))
	for _, d := range drives {
		if d.id == "" {
			return fmt.Errorf("%s has no drive identity, so the guest could not find it", d.name)
		}
		if !validDriveID(d.id) {
			return fmt.Errorf("the drive identity %q of %s is not 1 to %d letters, digits, and hyphens, so the guest could not match it", d.id, d.name, virtioBlockIDBytes)
		}
		if other, ok := seen[d.id]; ok {
			return fmt.Errorf("%s and %s would both have the drive identity %q%s, so the guest could not tell them apart", other, d.name, d.id, where)
		}
		seen[d.id] = d.name
	}
	return nil
}

// validDriveID reports whether id is 1 to virtioBlockIDBytes ASCII letters,
// digits, and hyphens.
func validDriveID(id string) bool {
	if id == "" || len(id) > virtioBlockIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
			return false
		}
	}
	return true
}

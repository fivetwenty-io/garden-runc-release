//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"
)

// The stack image. Garden builds the app's stack as a squashfs and binds its
// directory into the container, so that vm-launch can attach the image to the
// guest as a read-only drive. vm-launch checks the image before it commits to
// stack mode, so that an app whose stack is missing or unusable still boots
// the guest it always did.
const (
	// squashfsMagic is the first four bytes of a squashfs superblock, "hsqs"
	// in the little-endian order the format uses.
	squashfsMagic = 0x73717368

	// squashfsCompressorOffset is where the superblock holds the id of the
	// compressor that wrote the image, after the magic, the inode count, the
	// modification time, the block size, and the fragment count.
	squashfsCompressorOffset = 20

	// squashfsCompressorLZ4 is the compressor id for lz4. The guest kernel
	// is built with lz4 squashfs support only.
	squashfsCompressorLZ4 = 5

	// squashfsSuperblockPrefix is how many bytes of the superblock the check
	// reads, which is up to and including the compressor id.
	squashfsSuperblockPrefix = squashfsCompressorOffset + 2
)

// stackImagePath is where Garden binds the stack image into the container. It
// is a variable so that specs can point it at a temporary file.
var stackImagePath = "/opt/garden-vm/stack/rootfs.squashfs"

// openStackImage opens the stack image read-only and checks that it is a
// regular file holding an lz4 squashfs. It returns the open file, or no file
// and a one-line reason when the image is missing or unusable. The caller owns
// the returned file.
func openStackImage() (*os.File, string) {
	f, err := os.OpenFile(stackImagePath, os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Sprintf("the stack image cannot be opened: %v", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Sprintf("the stack image %s cannot be examined: %v", stackImagePath, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Sprintf("the stack image %s is not a regular file", stackImagePath)
	}
	var sb [squashfsSuperblockPrefix]byte
	if _, err := io.ReadFull(f, sb[:]); err != nil {
		_ = f.Close()
		return nil, fmt.Sprintf("the stack image %s is too short to be a squashfs", stackImagePath)
	}
	if binary.LittleEndian.Uint32(sb[:4]) != squashfsMagic {
		_ = f.Close()
		return nil, fmt.Sprintf("the stack image %s is not a squashfs", stackImagePath)
	}
	if id := binary.LittleEndian.Uint16(sb[squashfsCompressorOffset:]); id != squashfsCompressorLZ4 {
		_ = f.Close()
		return nil, fmt.Sprintf("the stack image %s uses squashfs compressor %d, and the guest reads only lz4", stackImagePath, id)
	}
	return f, ""
}

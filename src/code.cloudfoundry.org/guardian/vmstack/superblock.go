package vmstack

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// The squashfs 4.0 superblock is the first 96 bytes of an image, and every
// field in it is little-endian.
const (
	superblockSize = 96

	squashfsMagic   = 0x73717368
	lz4CompressorID = 5

	magicOffset      = 0
	compressorOffset = 20
	bytesUsedOffset  = 40
)

// checkImage reads the superblock of an open image and returns an error
// unless the image has the squashfs magic, uses the lz4 compressor, and
// claims no more bytes than the file holds. An image from a build that
// stopped part way fails these checks, because squashfs writes the superblock
// last.
func checkImage(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", f.Name())
	}

	sb := make([]byte, superblockSize)
	if _, err := f.ReadAt(sb, 0); err != nil {
		if err == io.EOF {
			return fmt.Errorf("%s holds %d bytes, which is shorter than a squashfs superblock", f.Name(), info.Size())
		}
		return err
	}

	if magic := binary.LittleEndian.Uint32(sb[magicOffset:]); magic != squashfsMagic {
		return fmt.Errorf("%s has magic %#x, not the squashfs magic %#x", f.Name(), magic, squashfsMagic)
	}
	if id := binary.LittleEndian.Uint16(sb[compressorOffset:]); id != lz4CompressorID {
		return fmt.Errorf("%s uses compressor %d, not lz4 (%d)", f.Name(), id, lz4CompressorID)
	}
	used := binary.LittleEndian.Uint64(sb[bytesUsedOffset:])
	if used < superblockSize || used > uint64(info.Size()) {
		return fmt.Errorf("%s claims %d bytes but holds %d", f.Name(), used, info.Size())
	}
	return nil
}

// checkImagePath opens the image at path and checks it with checkImage.
func checkImagePath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return checkImage(f)
}

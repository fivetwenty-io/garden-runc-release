package users

import "io"

// NewCappedReader exposes the size-capped reader to the users_test package.
func NewCappedReader(r io.Reader, limit int64, path string) io.Reader {
	return newCappedReader(r, limit, path)
}

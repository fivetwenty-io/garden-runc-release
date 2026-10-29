package users

import "errors"

// LookupImageUser resolves users inside an image root for gVisor containers,
// which exist only on Linux.
func LookupImageUser(root, name string) (*ExecUser, error) {
	return nil, errors.New("look up image user: image user lookup requires Linux")
}

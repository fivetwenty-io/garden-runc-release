package processes

import (
	"fmt"

	securejoin "github.com/cyphar/filepath-securejoin/pathrs-lite"
)

// statInRoot reports whether path exists inside rootFS, resolving every path
// component inside rootFS. It returns an error that wraps os.ErrNotExist when
// the path does not exist there. The lookup uses an O_PATH descriptor, so it
// never opens the file and a FIFO cannot block it.
func statInRoot(rootFS, path string) error {
	if rootFS == "" {
		return fmt.Errorf("stat %s in root: root filesystem path is empty", path)
	}

	handle, err := securejoin.OpenInRoot(rootFS, path)
	if err != nil {
		return err
	}

	return handle.Close()
}

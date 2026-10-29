//go:build !windows

package nerd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/containerd/errdefs"
)

func TestTaskAlreadyExited(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "not found", err: errdefs.ErrNotFound, want: true},
		{name: "wrapped not found", err: fmt.Errorf("kill: %w", errdefs.ErrNotFound), want: true},
		{name: "process already finished", err: errors.New("process already finished"), want: true},
		{name: "other", err: errors.New("boom"), want: false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := taskAlreadyExited(c.err); got != c.want {
				t.Fatalf("taskAlreadyExited(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

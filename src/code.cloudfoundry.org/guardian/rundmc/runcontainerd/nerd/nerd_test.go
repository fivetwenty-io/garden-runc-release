//go:build !windows

package nerd

import (
	"context"
	"errors"
	"fmt"
	"testing"

	v2types "github.com/containerd/containerd/api/types/runc/options"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// These tests run without containerd. The suite in nerd_suite_linux_test.go
// skips every spec unless a containerd is available, so they use the standard
// testing package instead of ginkgo.

func applyCreateOpts(t *testing.T, spec *specs.Spec, gvisor bool, runtimeConfigPath string) (containers.Container, client.TaskInfo) {
	t.Helper()

	containerOpts, taskOpts := createOpts(spec, gvisor, runtimeConfigPath, 5000, 6000)

	var c containers.Container
	for _, o := range containerOpts {
		if err := o(context.Background(), nil, &c); err != nil {
			t.Fatalf("applying container option: %v", err)
		}
	}

	var ti client.TaskInfo
	for _, o := range taskOpts {
		if err := o(context.Background(), nil, &ti); err != nil {
			t.Fatalf("applying task option: %v", err)
		}
	}

	return c, ti
}

func TestCreateOptsRuncKeepsDefaultRuntimeAndRuncTaskOptions(t *testing.T) {
	spec := &specs.Spec{Windows: &specs.Windows{}}

	c, ti := applyCreateOpts(t, spec, false, "")

	if c.Runtime.Name != "" {
		t.Errorf("runc container runtime = %q, want the client default", c.Runtime.Name)
	}
	if c.Spec == nil {
		t.Error("runc container spec was not set")
	}
	if spec.Windows == nil {
		t.Error("runc spec lost its Windows section")
	}

	opts, ok := ti.Options.(*v2types.Options)
	if !ok {
		t.Fatalf("runc task options = %T, want *options.Options", ti.Options)
	}
	if !opts.NoNewKeyring {
		t.Error("runc task options do not set NoNewKeyring")
	}
	if opts.IoUid != 5000 || opts.IoGid != 6000 {
		t.Errorf("runc task IO owner = %d:%d, want 5000:6000", opts.IoUid, opts.IoGid)
	}
}

func TestCreateOptsGvisorSelectsRunscAndDropsRuncTaskOptions(t *testing.T) {
	spec := &specs.Spec{Windows: &specs.Windows{}}

	c, ti := applyCreateOpts(t, spec, true, "")

	if c.Runtime.Name != RuntimeRunsc {
		t.Errorf("gvisor container runtime = %q, want %q", c.Runtime.Name, RuntimeRunsc)
	}
	if c.Runtime.Options != nil {
		t.Errorf("gvisor container runtime options = %v, want none when no config path is set", c.Runtime.Options)
	}
	if c.Spec == nil {
		t.Error("gvisor container spec was not set")
	}
	if spec.Windows != nil {
		t.Error("gvisor spec kept its Windows section")
	}
	if ti.Options != nil {
		t.Errorf("gvisor task options = %v, want none", ti.Options)
	}
}

func TestCreateOptsRuncIgnoresRuntimeConfigPath(t *testing.T) {
	c, ti := applyCreateOpts(t, &specs.Spec{}, false, "/etc/containerd/runsc/config.toml")

	if c.Runtime.Name != "" || c.Runtime.Options != nil {
		t.Errorf("runc container runtime = %q with options %v, want the client default and no options", c.Runtime.Name, c.Runtime.Options)
	}
	if _, ok := ti.Options.(*v2types.Options); !ok {
		t.Errorf("runc task options = %T, want *options.Options", ti.Options)
	}
}

func TestCreateOptsGvisorPassesRuntimeConfigPath(t *testing.T) {
	const configPath = "/etc/containerd/runsc/config.toml"

	c, ti := applyCreateOpts(t, &specs.Spec{}, true, configPath)

	if c.Runtime.Name != RuntimeRunsc {
		t.Errorf("gvisor container runtime = %q, want %q", c.Runtime.Name, RuntimeRunsc)
	}
	if c.Runtime.Options == nil {
		t.Fatal("gvisor container runtime options were not set")
	}
	opts := &runtimeoptions.Options{}
	if err := typeurl.UnmarshalTo(c.Runtime.Options, opts); err != nil {
		t.Fatalf("decoding gvisor runtime options: %v", err)
	}
	if opts.ConfigPath != configPath {
		t.Errorf("gvisor runtime ConfigPath = %q, want %q", opts.ConfigPath, configPath)
	}
	if ti.Options != nil {
		t.Errorf("gvisor task options = %v, want none", ti.Options)
	}
}

func TestWithRuntimeConfigPath(t *testing.T) {
	if got := New(nil, nil, "", nil).runtimeConfigPath; got != "" {
		t.Errorf("default runtimeConfigPath = %q, want empty", got)
	}
	if got := New(nil, nil, "", nil, WithRuntimeConfigPath("/x.toml")).runtimeConfigPath; got != "/x.toml" {
		t.Errorf("runtimeConfigPath = %q, want /x.toml", got)
	}
}

type statusTask struct {
	client.Task
	status      client.Status
	err         error
	statusCalls int
}

func (s *statusTask) Status(context.Context) (client.Status, error) {
	s.statusCalls++
	return s.status, s.err
}

func TestNeedsDirectDelete(t *testing.T) {
	statusErr := errors.New("status failed")

	cases := []struct {
		name        string
		runtime     string
		task        *statusTask
		want        bool
		wantErr     error
		statusCalls int
	}{
		{name: "runc created", runtime: "io.containerd.runc.v2", task: &statusTask{status: client.Status{Status: client.Created}}, want: false, statusCalls: 0},
		{name: "default runtime", runtime: "", task: &statusTask{status: client.Status{Status: client.Created}}, want: false, statusCalls: 0},
		{name: "runsc created", runtime: RuntimeRunsc, task: &statusTask{status: client.Status{Status: client.Created}}, want: true, statusCalls: 1},
		{name: "runsc running", runtime: RuntimeRunsc, task: &statusTask{status: client.Status{Status: client.Running}}, want: false, statusCalls: 1},
		{name: "runsc stopped", runtime: RuntimeRunsc, task: &statusTask{status: client.Status{Status: client.Stopped}}, want: false, statusCalls: 1},
		{name: "runsc status error", runtime: RuntimeRunsc, task: &statusTask{err: statusErr}, want: false, wantErr: statusErr, statusCalls: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := needsDirectDelete(context.Background(), tc.runtime, tc.task)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("needsDirectDelete = %t, want %t", got, tc.want)
			}
			if tc.task.statusCalls != tc.statusCalls {
				t.Errorf("status calls = %d, want %d", tc.task.statusCalls, tc.statusCalls)
			}
		})
	}
}

func TestTaskAlreadyExited(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"runsc stopped task", fmt.Errorf("no such process: %w", errdefs.ErrNotFound), true},
		{"runc exited process", fmt.Errorf("process already finished: %w", errdefs.ErrNotFound), true},
		{"message without NotFound code", errors.New("rpc error: process already finished"), true},
		{"kill timeout", errors.New("kill timeout: OCI runtime kill failed"), false},
		{"unavailable", fmt.Errorf("shim gone: %w", errdefs.ErrUnavailable), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := taskAlreadyExited(c.err); got != c.want {
				t.Fatalf("taskAlreadyExited(%q) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

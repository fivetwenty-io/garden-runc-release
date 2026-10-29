//go:build linux

package guardiancmd

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"code.cloudfoundry.org/guardian/metrics"
	"code.cloudfoundry.org/guardian/rundmc/depot"
	"code.cloudfoundry.org/guardian/rundmc/peas"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	containerdprivchecker "code.cloudfoundry.org/guardian/rundmc/runcontainerd/privchecker"
	"code.cloudfoundry.org/guardian/rundmc/runrunc"
	"code.cloudfoundry.org/guardian/rundmc/users"
	"code.cloudfoundry.org/guardian/rundmc/users/usersfakes"
	"code.cloudfoundry.org/lager/v3"
	"google.golang.org/grpc"
)

// containerdArgsFactory records what wireContainerizer hands to WireContainerd
// and then wires containerd as usual.
type containerdArgsFactory struct {
	runtimeWiringFactory
	processBuilder *processes.ProcBuilder
	userLookupper  users.UserLookupper
}

func (f *containerdArgsFactory) WireContainerd(processBuilder *processes.ProcBuilder, userLookupper users.UserLookupper, wireExecer func(runrunc.PidGetter) *runrunc.Execer, statser runcontainerd.Statser, log lager.Logger, volumizer peas.Volumizer, peaHandlesGetter runcontainerd.PeaHandlesGetter, metricsProvider *metrics.MetricsProvider) (*runcontainerd.RunContainerd, *runcontainerd.RunContainerPea, *runcontainerd.PidGetter, *containerdprivchecker.PrivilegeChecker, peas.BundleLoader, runcontainerd.RuntimePolicy, error) {
	f.processBuilder = processBuilder
	f.userLookupper = userLookupper
	return f.runtimeWiringFactory.WireContainerd(processBuilder, userLookupper, wireExecer, statser, log, volumizer, peaHandlesGetter, metricsProvider)
}

// serveEmptyContainerd listens on a socket that no containerd service backs.
// Wiring only dials it lazily, so a test that makes no containerd call needs
// nothing more.
func serveEmptyContainerd(t *testing.T) string {
	t.Helper()
	socketDir, err := os.MkdirTemp("", "gdn-wiring-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "containerd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	rpcServer := grpc.NewServer()
	go func() { _ = rpcServer.Serve(listener) }()
	t.Cleanup(rpcServer.Stop)
	return socket
}

func TestContainerdWiringResolvesExecUsersInsideTheImage(t *testing.T) {
	for _, runtimeType := range []string{"", runcontainerd.SupportedRuntimeType} {
		t.Run("runtime type "+runtimeType, func(t *testing.T) {
			cmd := &CommonCommand{}
			cmd.Containers.Dir = t.TempDir()
			cmd.Containerd.Socket = serveEmptyContainerd(t)
			cmd.Containerd.RuntimeType = runtimeType
			cmd.Containerd.UseContainerdForProcesses = true
			factory := &containerdArgsFactory{runtimeWiringFactory: runtimeWiringFactory{LinuxFactory: &LinuxFactory{config: cmd}}}
			if _, _, err := cmd.wireContainerizer(lager.NewLogger("containerd-wiring"), factory, nil, nil, 1, depot.NetworkDepot{}, nil, &executionBackends{}); err != nil {
				t.Fatal(err)
			}
			if factory.userLookupper == nil {
				t.Fatal("WireContainerd was given no user lookupper")
			}

			// The image's passwd file links to an absolute path. The host has a
			// user at that path and so does the image, with different names.
			hostDir := t.TempDir()
			hostPasswd := filepath.Join(hostDir, "passwd")
			if err := os.WriteFile(hostPasswd, []byte("hostuser:x:4001:4001::/host-home:/bin/sh\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			imageRoot := t.TempDir()
			if err := os.MkdirAll(filepath.Join(imageRoot, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(hostPasswd, filepath.Join(imageRoot, "etc", "passwd")); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(imageRoot, hostDir), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(imageRoot, hostPasswd), []byte("imageuser:x:4002:4002::/image-home:/bin/sh\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			user, err := factory.userLookupper.Lookup(imageRoot, "imageuser")
			if err != nil {
				t.Fatalf("lookup of the image's user: %v", err)
			}
			if user.Uid != 4002 || user.Home != "/image-home" {
				t.Errorf("image user = %+v, want uid 4002 and home /image-home", user)
			}
			if user, err := factory.userLookupper.Lookup(imageRoot, "hostuser"); err == nil {
				t.Errorf("lookup found the host's user %+v through a link out of the image", user)
			}
		})
	}
}

func TestWireContainerdExecUsesTheLookupperItIsGiven(t *testing.T) {
	cmd := &CommonCommand{}
	cmd.Containers.Dir = t.TempDir()
	cmd.Containerd.Socket = serveEmptyContainerd(t)
	cmd.Containerd.UseContainerdForProcesses = true
	factory := &LinuxFactory{config: cmd}

	lookupper := new(usersfakes.FakeUserLookupper)
	manager, _, _, _, _, _, err := factory.WireContainerd(nil, lookupper, func(runrunc.PidGetter) *runrunc.Execer { return nil }, nil, lager.NewLogger("lookupper"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := reflect.ValueOf(manager).Elem().FieldByName("userLookupper").Elem()
	if got.Kind() != reflect.Ptr || got.Pointer() != reflect.ValueOf(lookupper).Pointer() {
		t.Errorf("RunContainerd looks users up with %s, want the lookupper passed to WireContainerd", got.Type())
	}
}

func TestRunscCellWiresConfinedLookupsAndTaskStop(t *testing.T) {
	for _, test := range []struct {
		name        string
		runtimeType string
		want        bool
	}{
		{name: "stock cell", want: false},
		{name: "explicit stock cell", runtimeType: runcontainerd.StockRuntimeType, want: false},
		{name: "runsc cell", runtimeType: runcontainerd.SupportedRuntimeType, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := &CommonCommand{}
			cmd.Containers.Dir = t.TempDir()
			cmd.Containerd.Socket = serveEmptyContainerd(t)
			cmd.Containerd.RuntimeType = test.runtimeType
			cmd.Containerd.UseContainerdForProcesses = true
			factory := &containerdArgsFactory{runtimeWiringFactory: runtimeWiringFactory{LinuxFactory: &LinuxFactory{config: cmd}}}
			containerizer, _, err := cmd.wireContainerizer(lager.NewLogger("runsc-wiring"), factory, nil, nil, 1, depot.NetworkDepot{}, nil, &executionBackends{})
			if err != nil {
				t.Fatal(err)
			}

			if got := reflect.ValueOf(factory.processBuilder).Elem().FieldByName("confinedRootDir").Bool(); got != test.want {
				t.Errorf("process builder confines working directories to the image = %v, want %v", got, test.want)
			}
			if got := reflect.ValueOf(containerizer).Elem().FieldByName("taskStop").Bool(); got != test.want {
				t.Errorf("containerizer stops containers through their task = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRunscCellRequiresLoopbackInTheNetworker(t *testing.T) {
	for _, test := range []struct {
		name        string
		runtimeType string
		want        bool
	}{
		{name: "stock cell", want: false},
		{name: "runsc cell", runtimeType: runcontainerd.SupportedRuntimeType, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := &CommonCommand{}
			cmd.Containerd.Socket = "/run/containerd.sock"
			cmd.Containerd.RuntimeType = test.runtimeType
			cmd.Network.Plugin = FileFlag("/network-plugin")
			cmd.Network.ExternalIP = IPFlag(net.ParseIP("10.0.0.1"))
			factory := runtimeWiringFactory{LinuxFactory: &LinuxFactory{config: cmd}}

			networker, _, err := cmd.wireNetworker(lager.NewLogger("networker-wiring"), factory, nil, nil, depot.NetworkDepot{}, &executionBackends{})
			if err != nil {
				t.Fatal(err)
			}

			if got := reflect.ValueOf(networker).Elem().FieldByName("loopbackRequired").Bool(); got != test.want {
				t.Errorf("networker requires loopback = %v, want %v", got, test.want)
			}
		})
	}
}

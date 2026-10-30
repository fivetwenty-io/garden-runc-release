//go:build linux

package guardiancmd

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unsafe"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/metrics"
	"code.cloudfoundry.org/guardian/rundmc/depot"
	"code.cloudfoundry.org/guardian/rundmc/goci"
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
	runContainerd  *runcontainerd.RunContainerd
}

func (f *containerdArgsFactory) WireContainerd(processBuilder *processes.ProcBuilder, userLookupper users.UserLookupper, wireExecer func(runrunc.PidGetter) *runrunc.Execer, statser runcontainerd.Statser, log lager.Logger, volumizer peas.Volumizer, peaHandlesGetter runcontainerd.PeaHandlesGetter, metricsProvider *metrics.MetricsProvider) (*runcontainerd.RunContainerd, *runcontainerd.RunContainerPea, *runcontainerd.PidGetter, *containerdprivchecker.PrivilegeChecker, peas.BundleLoader, runcontainerd.RuntimePolicy, error) {
	f.processBuilder = processBuilder
	f.userLookupper = userLookupper
	runContainerd, peaRunner, pidGetter, privChecker, bundleLoader, policy, err := f.runtimeWiringFactory.WireContainerd(processBuilder, userLookupper, wireExecer, statser, log, volumizer, peaHandlesGetter, metricsProvider)
	f.runContainerd = runContainerd
	return runContainerd, peaRunner, pidGetter, privChecker, bundleLoader, policy, err
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

// assertLookupStaysInImage checks that lookupper reads the passwd file inside
// the image root and does not follow a link out of it.
func assertLookupStaysInImage(t *testing.T, lookupper users.UserLookupper) {
	t.Helper()

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

	user, err := lookupper.Lookup(imageRoot, "imageuser")
	if err != nil {
		t.Fatalf("lookup of the image's user: %v", err)
	}
	if user.Uid != 4002 || user.Home != "/image-home" {
		t.Errorf("image user = %+v, want uid 4002 and home /image-home", user)
	}
	if user, err := lookupper.Lookup(imageRoot, "hostuser"); err == nil {
		t.Errorf("lookup found the host's user %+v through a link out of the image", user)
	}
}

// storedLookupper returns the user lookupper that RunContainerd keeps and
// uses for exec.
func storedLookupper(t *testing.T, runContainerd *runcontainerd.RunContainerd) users.UserLookupper {
	t.Helper()
	field := reflect.ValueOf(runContainerd).Elem().FieldByName("userLookupper")
	if !field.IsValid() {
		t.Fatal("RunContainerd has no userLookupper field")
	}
	stored, ok := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(users.UserLookupper)
	if !ok || stored == nil {
		t.Fatal("RunContainerd keeps no user lookupper")
	}
	return stored
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

			assertLookupStaysInImage(t, factory.userLookupper)
			assertLookupStaysInImage(t, storedLookupper(t, factory.runContainerd))
		})
	}
}

// A cell can leave use_containerd_for_processes off and enable oci-gvisor. Only
// gVisor containers then exec through containerd, and they have to resolve the
// user and the working directory inside the image like any other gVisor exec.
func TestContainerdWiringConfinesGvisorExecsWhenContainerdDoesNotRunProcesses(t *testing.T) {
	cmd := &CommonCommand{}
	cmd.Containers.Dir = t.TempDir()
	cmd.Containerd.Socket = serveEmptyContainerd(t)
	cmd.Containerd.UseContainerdForProcesses = false
	cmd.ExecutionBackends.Enabled = []string{string(backend.OCIGvisor)}

	backends, err := cmd.wireExecutionBackends(lager.NewLogger("execution-backends"))
	if err != nil {
		t.Fatal(err)
	}
	if !backends.dispatch() {
		t.Fatal("oci-gvisor did not turn on backend dispatch")
	}
	cmd.wiredBackends = backends

	factory := &containerdArgsFactory{runtimeWiringFactory: runtimeWiringFactory{LinuxFactory: &LinuxFactory{config: cmd}}}
	if _, _, err := cmd.wireContainerizer(lager.NewLogger("containerd-wiring"), factory, nil, nil, 1, depot.NetworkDepot{}, nil, backends); err != nil {
		t.Fatal(err)
	}
	if factory.userLookupper == nil {
		t.Fatal("WireContainerd was given no user lookupper")
	}

	runContainerd := reflect.ValueOf(factory.runContainerd).Elem()
	if runContainerd.FieldByName("useContainerdForProcesses").Bool() {
		t.Error("RunContainerd runs every process through containerd, want only gVisor containers to")
	}
	if !runContainerd.FieldByName("backendDispatch").Bool() {
		t.Error("RunContainerd does not look up the backend of a container, so a gVisor exec would take the runc path")
	}

	assertLookupStaysInImage(t, factory.userLookupper)
	assertLookupStaysInImage(t, storedLookupper(t, factory.runContainerd))

	// The working directory of a gVisor process is a link that leaves the image.
	rootfs := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(rootfs, "app")); err != nil {
		t.Fatal(err)
	}
	bndl := goci.Bundle().WithRootFS(rootfs)
	bndl.Spec.Annotations = map[string]string{backend.AnnotationKey: string(backend.OCIGvisor)}
	process := factory.processBuilder.BuildProcess(bndl, garden.ProcessSpec{Path: "program", Dir: "/app"}, &users.ExecUser{Home: "/"})
	if process.Cwd != "/" {
		t.Errorf("gVisor process working directory = %q, want %q because the link leaves the image", process.Cwd, "/")
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

// wiredPeaBundleLoader returns the BundleLoader of the PeaCreator that
// containerizer creates peas with.
func wiredPeaBundleLoader(t *testing.T, containerizer interface{}) peas.BundleLoader {
	t.Helper()
	field := reflect.ValueOf(containerizer).Elem().FieldByName("peaCreator")
	if !field.IsValid() {
		t.Fatal("the containerizer has no peaCreator field")
	}
	creator, ok := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(*peas.PeaCreator)
	if !ok || creator == nil {
		t.Fatal("the containerizer keeps no *peas.PeaCreator")
	}
	return creator.BundleLoader
}

// A VM sandbox's peas are confined only when the PeaCreator can read the
// sandbox's backend, so every runtime path has to hand it a bundle loader
// once a backend beyond oci-runc is enabled, and none otherwise.
func TestPeaCreatorReadsSandboxBundlesExactlyWhenBackendsDispatch(t *testing.T) {
	vmBackends := func(t *testing.T) *executionBackends {
		registry, err := backend.NewRegistry(backend.VMQemu)
		if err != nil {
			t.Fatal(err)
		}
		return &executionBackends{registry: registry}
	}

	for _, path := range []struct {
		name       string
		containerd bool
		wantType   string
	}{
		{name: "runc", wantType: "*depot.DirectoryDepot"},
		{name: "containerd", containerd: true, wantType: "runcontainerd.BndlLoader"},
	} {
		for _, dispatch := range []bool{false, true} {
			t.Run(path.name+map[bool]string{false: " without dispatch", true: " with dispatch"}[dispatch], func(t *testing.T) {
				cmd := &CommonCommand{}
				cmd.Containers.Dir = t.TempDir()
				var factory GardenFactory = runtimeWiringFactory{LinuxFactory: &LinuxFactory{config: cmd}}
				if path.containerd {
					cmd.Containerd.Socket = serveEmptyContainerd(t)
					cmd.Containerd.UseContainerdForProcesses = true
					factory = &containerdArgsFactory{runtimeWiringFactory: runtimeWiringFactory{LinuxFactory: &LinuxFactory{config: cmd}}}
				}
				backends := &executionBackends{}
				if dispatch {
					backends = vmBackends(t)
					cmd.wiredBackends = backends
				}

				containerizer, _, err := cmd.wireContainerizer(lager.NewLogger("pea-wiring"), factory, nil, nil, 1, depot.NetworkDepot{}, nil, backends)
				if err != nil {
					t.Fatal(err)
				}
				loader := wiredPeaBundleLoader(t, containerizer)
				if !dispatch {
					if loader != nil {
						t.Errorf("the PeaCreator reads sandbox bundles (%T) with no backend beyond oci-runc enabled", loader)
					}
					return
				}
				if loader == nil {
					t.Fatal("the PeaCreator has no bundle loader, so it would not confine a VM sandbox's peas")
				}
				if got := reflect.TypeOf(loader).String(); got != path.wantType {
					t.Errorf("the PeaCreator's bundle loader is %s, want %s", got, path.wantType)
				}
			})
		}
	}
}

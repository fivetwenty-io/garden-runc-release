package guardiancmd

import (
	"encoding/json"
	"reflect"
	"testing"
	"unsafe"

	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc"
	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
	"code.cloudfoundry.org/guardian/rundmc/depot"
	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
	"code.cloudfoundry.org/lager/v3"
)

// wiredBundleRules returns the bundle rules of the containerizer that
// wireContainerizer built.
func wiredBundleRules(t *testing.T, containerizer *rundmc.Containerizer) []rundmc.BundlerRule {
	t.Helper()
	field := reflect.ValueOf(containerizer).Elem().FieldByName("bundler")
	if !field.IsValid() {
		t.Fatal("the containerizer has no bundler field")
	}
	template, ok := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(*rundmc.BundleTemplate)
	if !ok || template == nil {
		t.Fatal("the containerizer keeps no *rundmc.BundleTemplate")
	}
	return template.Rules
}

func wireVsockContainerizer(t *testing.T, denyVsock bool) (bundlerules.Base, bundlerules.ExecutionBackend) {
	t.Helper()
	cmd := &CommonCommand{}
	cmd.Containers.Dir = t.TempDir()
	cmd.Containers.DenyVsock = denyVsock
	registry, err := backend.NewRegistry(backend.VMQemu)
	if err != nil {
		t.Fatal(err)
	}
	backends := &executionBackends{registry: registry, kvmGid: 991}
	cmd.wiredBackends = backends
	factory := runtimeWiringFactory{LinuxFactory: &LinuxFactory{config: cmd}}
	containerizer, _, err := cmd.wireContainerizer(lager.NewLogger("vsock-wiring"), factory, nil, nil, 1, depot.NetworkDepot{}, nil, backends)
	if err != nil {
		t.Fatal(err)
	}
	var base *bundlerules.Base
	var vm *bundlerules.ExecutionBackend
	for _, rule := range wiredBundleRules(t, containerizer) {
		switch r := rule.(type) {
		case bundlerules.Base:
			base = &r
		case bundlerules.ExecutionBackend:
			vm = &r
		}
	}
	if base == nil || vm == nil {
		t.Fatal("the containerizer has no base rule or no execution backend rule")
	}
	return *base, *vm
}

// The containerizer's base bundles carry the profiles that containerSeccomp
// makes, and the execution backend rule learns whether the denial is on.
func TestContainerizerDeniesVsockExactlyWhenTheDenialIsOn(t *testing.T) {
	base, vm := wireVsockContainerizer(t, false)
	want, _, err := containerSeccomp(false)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(base.UnprivilegedBase.Seccomp()); string(got) != string(must(json.Marshal(want))) {
		t.Errorf("unprivileged profile with the denial off differs from Garden's profile")
	}
	if base.PrivilegedBase.Seccomp() != nil {
		t.Errorf("privileged containers got a profile with the denial off")
	}
	if vm.DenyVsock {
		t.Errorf("the execution backend rule denies vsock with the denial off")
	}

	base, vm = wireVsockContainerizer(t, true)
	if !seccompvsock.Denies(base.UnprivilegedBase.Seccomp()) {
		t.Errorf("unprivileged containers may create vsock sockets with the denial on")
	}
	if !seccompvsock.Denies(base.PrivilegedBase.Seccomp()) {
		t.Errorf("privileged containers may create vsock sockets with the denial on")
	}
	if !vm.DenyVsock {
		t.Errorf("the execution backend rule does not know the denial is on")
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

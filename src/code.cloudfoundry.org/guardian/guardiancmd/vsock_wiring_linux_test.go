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

// vsockRules are the rules of a wired containerizer that the vsock denial
// involves, and the index of each in the rule list.
type vsockRules struct {
	base                bundlerules.Base
	denial              bundlerules.VsockDenial
	vm                  bundlerules.ExecutionBackend
	denialAt, backendAt int
}

func wireVsockContainerizer(t *testing.T, denyVsock bool) vsockRules {
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
	rules := vsockRules{denialAt: -1, backendAt: -1}
	for i, rule := range wiredBundleRules(t, containerizer) {
		switch r := rule.(type) {
		case bundlerules.Base:
			rules.base = r
		case bundlerules.VsockDenial:
			rules.denial, rules.denialAt = r, i
		case bundlerules.ExecutionBackend:
			rules.vm, rules.backendAt = r, i
		}
	}
	if rules.denialAt < 0 || rules.backendAt < 0 {
		t.Fatal("the containerizer has no vsock denial rule or no execution backend rule")
	}
	return rules
}

// The base bundles carry Garden's own profiles whatever the flag, and the
// vsock denial rule, which runs before the execution backend rule, denies
// vsock to every container while the flag is on.
func TestContainerizerDeniesVsockExactlyWhenTheDenialIsOn(t *testing.T) {
	want, err := buildSeccomp()
	if err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{false, true} {
		rules := wireVsockContainerizer(t, on)
		if got, _ := json.Marshal(rules.base.UnprivilegedBase.Seccomp()); string(got) != string(must(json.Marshal(want))) {
			t.Errorf("with the denial set to %v, the unprivileged base profile differs from Garden's profile", on)
		}
		if rules.base.PrivilegedBase.Seccomp() != nil {
			t.Errorf("with the denial set to %v, privileged containers got a base profile", on)
		}
		if rules.denialAt > rules.backendAt {
			t.Errorf("the vsock denial rule runs after the execution backend rule, which then cannot give vsock back")
		}
		if rules.denial.Deny == nil || rules.vm.VsockException == nil {
			t.Fatal("the vsock rules have no gate")
		}
		if on && !rules.denial.Deny() {
			t.Errorf("the vsock denial rule does not deny with the denial on")
		}
		if !on && rules.vm.VsockException() {
			t.Errorf("the execution backend rule may give vsock back with the denial off")
		}
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

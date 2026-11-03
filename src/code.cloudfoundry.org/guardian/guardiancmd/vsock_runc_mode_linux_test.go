package guardiancmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	spec "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/guardian/rundmc"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
	"code.cloudfoundry.org/lager/v3/lagertest"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// runcModeDepot lays out a runc mode depot as gdn finds it while it creates
// the container new-container. The networker has made the container's
// directory, and nothing has written its config.json yet. Beside it run a
// container from before the denial existed, with a pea that runc runs and
// a process directory of an exec, and the depot also holds a stray file.
func runcModeDepot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	garden, err := buildSeccomp()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"new-container", "running/processes/a-pea", "running/processes/an-exec"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"running", "running/processes/a-pea"} {
		if err := (goci.BundleSaver{}).Save(goci.Bundle().WithSeccomp(garden), filepath.Join(dir, d)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "running/processes/an-exec/process.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stray"), []byte("not a container"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// In runc mode without --deny-vsock, a container that gdn creates while the
// depot already holds its directory gets Garden's own profile, as it did
// before the denial existed, and the gate logs no error.
func TestRuncModeCreateWithoutTheDenialGetsGardensProfile(t *testing.T) {
	want, err := buildSeccomp()
	if err != nil {
		t.Fatal(err)
	}
	log := lagertest.NewTestLogger("runc-mode")
	rules := wireVsockContainerizerIn(t, false, runcModeDepot(t), log)
	template := rundmc.BundleTemplate{Rules: rules.all}
	for _, privileged := range []bool{false, true} {
		bndl, err := template.Generate(spec.DesiredContainerSpec{
			Handle:     "new-container",
			Privileged: privileged,
			BaseConfig: specs.Spec{Root: &specs.Root{Path: "/rootfs"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := bndl.Spec.Annotations[seccompvsock.AnnotationKey]; ok {
			t.Errorf("privileged %v: the bundle records a vsock denial", privileged)
		}
		if privileged {
			if bndl.Seccomp() != nil {
				t.Errorf("the privileged container got a profile")
			}
			continue
		}
		if got, _ := json.Marshal(bndl.Seccomp()); string(got) != string(must(json.Marshal(want))) {
			t.Errorf("the container's profile differs from Garden's profile")
		}
	}
	if logs := string(log.Buffer().Contents()); strings.Contains(logs, "vsock-denial-not-applied-without-container-list") {
		t.Errorf("the gate could not list the containers: %s", logs)
	}
}

// In runc mode with --deny-vsock, the gate reads the same depot, skips the
// container being created, the exec, and the stray file, and refuses the
// guest agent because the container from before and its pea lack the
// denial. Once they are gone it makes the exception.
func TestRuncModeGateReadsTheDepot(t *testing.T) {
	dir := runcModeDepot(t)
	log := lagertest.NewTestLogger("runc-mode")
	rules := wireVsockContainerizerIn(t, true, dir, log)
	if !rules.denial.Deny("new-container") {
		t.Fatal("the denial rule does not deny with the denial on")
	}
	if rules.vm.VsockException("new-container") {
		t.Fatal("the gate made the exception beside a container and a pea without the denial")
	}
	contents := string(log.Buffer().Contents())
	if !containsAll(contents, "guest-agent-refused-while-containers-lack-vsock-denial", `"running"`, `"running/a-pea"`) {
		t.Fatalf("the gate did not name the container and the pea that hold the agent back: %s", contents)
	}
	if strings.Contains(contents, "guest-agent-refused-without-container-list") {
		t.Fatalf("the gate could not list the containers: %s", contents)
	}

	if err := os.RemoveAll(filepath.Join(dir, "running")); err != nil {
		t.Fatal(err)
	}
	if !rules.vm.VsockException("new-container") {
		t.Fatalf("the gate refused the exception with every other container gone: %s", log.Buffer().Contents())
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// Package backend names the execution backends a Garden container can run on
// and decides, per cell, which of them guardian is willing to start.
package backend

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/rundmc/goci"
)

// Kind identifies an execution backend.
type Kind string

const (
	OCIRunc       Kind = "oci-runc"
	OCIGvisor     Kind = "oci-gvisor"
	VMQemu        Kind = "vm-qemu"
	VMFirecracker Kind = "vm-firecracker"
)

// AnnotationKey is both the Garden container property that selects a backend
// and the bundle annotation that records the selection for the lifetime of the
// container.
const AnnotationKey = "garden.execution-backend"

var (
	// ErrUnknownBackend is returned when the requested value names no backend.
	ErrUnknownBackend = errors.New("unknown execution backend")

	// ErrBackendNotEnabled is returned when the backend exists but this cell's
	// allowlist does not include it.
	ErrBackendNotEnabled = errors.New("execution backend not enabled on this cell")

	// ErrBackendUnavailable is returned when the backend is allowed but cannot
	// currently be used, for example because a required artifact is missing.
	ErrBackendUnavailable = errors.New("execution backend unavailable")

	// ErrRootFSNotOperatorInstalled is returned when a VM backend is asked to
	// run an image that an operator did not install on the cell.
	ErrRootFSNotOperatorInstalled = errors.New("execution backend requires an operator-installed rootfs")
)

// RootFSError describes a rootfs that a backend refuses. It matches
// ErrRootFSNotOperatorInstalled under errors.Is.
type RootFSError struct {
	Backend Kind
	// Scheme is the URI scheme of the refused image. The URI itself is never
	// recorded because it can carry credentials.
	Scheme string
	// Reason is set instead of Scheme when the refusal is not about the scheme.
	Reason string
}

func (e *RootFSError) Error() string {
	detail := e.Reason
	if e.Scheme != "" {
		detail = fmt.Sprintf("image scheme %s is not allowed", e.Scheme)
	}
	return fmt.Sprintf("execution backend %s requires an operator-installed rootfs; %s", e.Backend, detail)
}

func (e *RootFSError) Unwrap() error {
	return ErrRootFSNotOperatorInstalled
}

var known = map[Kind]bool{
	OCIRunc:       true,
	OCIGvisor:     true,
	VMQemu:        true,
	VMFirecracker: true,
}

// IsKnown reports whether k names a backend guardian understands.
func IsKnown(k Kind) bool {
	return known[k]
}

// IsVM reports whether k runs the workload inside a virtual machine.
//
// The Diego rep keeps a copy of this classification as isVMBackend in
// rep/conversion_helpers.go, because the rep cannot import guardian. Change
// the two together. The "classifies every known kind" spec in backend_test.go
// fails when a kind is added here without being classified.
func IsVM(k Kind) bool {
	return k == VMQemu || k == VMFirecracker
}

// IsGvisor reports whether k runs the workload under gVisor.
func IsGvisor(k Kind) bool {
	return k == OCIGvisor
}

// Registry holds the set of backends a cell allows. The zero value and a nil
// *Registry both allow only OCIRunc.
type Registry struct {
	allowed map[Kind]bool
}

// NewRegistry builds a Registry allowing the given kinds in addition to
// OCIRunc, which is always allowed. It returns ErrUnknownBackend if any kind is
// not a known backend.
func NewRegistry(allowed ...Kind) (*Registry, error) {
	r := &Registry{allowed: map[Kind]bool{}}
	for _, k := range allowed {
		if !IsKnown(k) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownBackend, string(k))
		}
		r.allowed[k] = true
	}
	return r, nil
}

// Allowed reports whether k may be started on this cell.
func (r *Registry) Allowed(k Kind) bool {
	if k == OCIRunc {
		return true
	}
	if r == nil {
		return false
	}
	return r.allowed[k]
}

// Resolve reads the requested backend from the container properties. An absent
// or empty value, or "oci-runc", selects OCIRunc. Any other value must be a
// known backend that the registry allows.
func (r *Registry) Resolve(props garden.Properties) (Kind, error) {
	requested := Kind(props[AnnotationKey])
	if requested == "" {
		return OCIRunc, nil
	}
	if !IsKnown(requested) {
		return "", fmt.Errorf("%w: %q", ErrUnknownBackend, string(requested))
	}
	if !r.Allowed(requested) {
		return "", fmt.Errorf("%w: %q", ErrBackendNotEnabled, string(requested))
	}
	return requested, nil
}

// FromBundle returns the backend recorded in the bundle annotation, or OCIRunc
// when the annotation is absent or empty.
func FromBundle(bndl goci.Bndl) Kind {
	if v := bndl.Spec.Annotations[AnnotationKey]; v != "" {
		return Kind(v)
	}
	return OCIRunc
}

// preloadedLayerScheme is the scheme Diego gives a preloaded rootfs that has an
// application layer on top. The base of the image is still the operator's.
const preloadedLayerScheme = "preloaded+layer"

// vcapHome is where Cloud Controller extracts the droplet layer. A layer
// extracted anywhere else, such as /etc, could overlay files like
// /etc/ld.so.preload into the hypervisor process.
const vcapHome = "/home/vcap"

// underVcapHome reports whether the cleaned layer_path is /home/vcap or below
// it. The image plugin requires layer_path and has no default, so a missing or
// empty value is refused.
func underVcapHome(layerPath string) bool {
	if layerPath == "" {
		return false
	}
	p := path.Clean(layerPath)
	return p == vcapHome || strings.HasPrefix(p, vcapHome+"/")
}

// CheckRootFS refuses a VM backend whose container would run an image that the
// operator did not install. The hypervisor of a VM backend runs inside the
// container's mount namespace, so a rootfs whose /etc or library directories a
// developer controls could inject code into it. Every other backend accepts any
// image.
//
// An image is operator-installed when it is empty, which selects the cell's
// default rootfs, when it is a bare absolute path, which is what the Diego
// executor passes for a preloaded stack, or when it uses the preloaded+layer
// scheme over an absolute base path and a layer_path under /home/vcap, which is
// how Diego adds the droplet to a preloaded stack. A container spec may name its image in both Image.URI and
// RootFSPath, so every non-empty one is checked.
func CheckRootFS(k Kind, spec garden.ContainerSpec) error {
	if !IsVM(k) {
		return nil
	}
	for _, image := range []string{spec.Image.URI, spec.RootFSPath} {
		if image == "" {
			continue
		}
		if err := checkOperatorImage(k, image); err != nil {
			return err
		}
	}
	return nil
}

// StackTarball returns the absolute path of the stack tarball that a container
// spec names, or an empty string when it names none. The path comes from
// Image.URI first and RootFSPath second, and it is either a bare absolute path
// or the base path of a preloaded+layer URI. Any other scheme, a relative path,
// or an unparseable value yields an empty string.
func StackTarball(spec garden.ContainerSpec) string {
	for _, image := range []string{spec.Image.URI, spec.RootFSPath} {
		if image == "" {
			continue
		}
		u, err := url.Parse(image)
		if err != nil || u.Host != "" || u.Opaque != "" || !path.IsAbs(u.Path) {
			continue
		}
		if u.Scheme == "" || u.Scheme == preloadedLayerScheme {
			return path.Clean(u.Path)
		}
	}
	return ""
}

func checkOperatorImage(k Kind, image string) error {
	u, err := url.Parse(image)
	if err != nil {
		return &RootFSError{Backend: k, Reason: "the image URI cannot be parsed"}
	}

	absoluteBase := u.Host == "" && u.Opaque == "" && path.IsAbs(u.Path)
	switch u.Scheme {
	case "":
		if absoluteBase {
			return nil
		}
		return &RootFSError{Backend: k, Reason: "the image is not an absolute path"}
	case preloadedLayerScheme:
		if !absoluteBase {
			return &RootFSError{Backend: k, Reason: "the preloaded+layer image has no absolute base path"}
		}
		if !underVcapHome(u.Query().Get("layer_path")) {
			return &RootFSError{Backend: k, Reason: "the preloaded+layer destination must be under " + vcapHome}
		}
		return nil
	}
	return &RootFSError{Backend: k, Scheme: u.Scheme}
}

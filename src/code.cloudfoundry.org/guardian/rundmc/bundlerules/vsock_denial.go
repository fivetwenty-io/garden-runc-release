package bundlerules

import (
	spec "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
)

// VsockDenial denies vsock sockets to every process of a container whose
// bundle it applies to while Deny says so, and records the denial in the
// bundle's annotations, so that later execs and later runs of gdn know what
// the container was created with. It leaves a bundle alone while Deny says
// not to, and when Deny is nil.
//
// It runs before ExecutionBackend, which gives vsock back to the one VM
// container kind that serves a guest agent over it and turns the record
// into the one that says the container's other processes are wrapped.
type VsockDenial struct {
	Deny func() bool
}

func (r VsockDenial) Apply(bndl goci.Bndl, _ spec.DesiredContainerSpec) (goci.Bndl, error) {
	if r.Deny == nil || !r.Deny() {
		return bndl, nil
	}
	bndl = bndl.WithSeccomp(seccompvsock.Deny(bndl.Seccomp()))
	annotations := make(map[string]string, len(bndl.Spec.Annotations)+1)
	for k, v := range bndl.Spec.Annotations {
		annotations[k] = v
	}
	annotations[seccompvsock.AnnotationKey] = seccompvsock.AnnotationProfile
	bndl.Spec.Annotations = annotations
	return bndl, nil
}

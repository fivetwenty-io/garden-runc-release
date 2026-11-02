package guardiancmd

import (
	"errors"
	"sync"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
	"code.cloudfoundry.org/lager/v3"
)

// vsockBundles lists the containers on the cell and reads their bundles. The
// OCI runtime does both.
type vsockBundles interface {
	ContainerHandles() ([]string, error)
	BundleInfo(log lager.Logger, handle string) (string, goci.Bndl, error)
}

// vsockPeaBundles is the part of the containerd runtime that lists the peas,
// which it leaves out of ContainerHandles.
type vsockPeaBundles interface {
	PeaHandles() ([]string, error)
}

// vsockGate decides, for each container that gdn creates, whether it denies
// the container vsock and whether a vm-qemu container may serve the guest
// agent over vsock. It goes by --deny-vsock and by what the containers that
// already run on the cell were created with, which each one's
// seccompvsock.AnnotationKey annotation records, because a container keeps
// its seccomp profile for its whole life and gdn may restart under other
// flags, with monit, without the drain that a deploy runs first.
//
// With --deny-vsock, gdn denies every new container vsock, and a vm-qemu
// container gets the guest agent only once no container on the cell can
// create a vsock socket any more. A container created before the flag was
// set has no annotation, and while one runs, a guest agent would be open to
// it, so gdn refuses the agent and logs which containers hold it back. It
// looks again at the next vm-qemu create, and once every container is
// denied it stops looking, because every container it creates from then on
// is denied too.
//
// Without --deny-vsock, gdn gives no container the guest agent. If it finds,
// at the first create of its run, a container that serves the guest agent
// from an earlier run, it keeps denying every new container vsock for the
// rest of its run, because that agent still answers on vsock. Otherwise it
// denies nothing, and every bundle is the one it was before the denial
// existed.
//
// A container that runs under gVisor ignores its seccomp profile, so the
// gate counts an oci-gvisor container as one that can create a vsock
// socket, whatever its annotation says, and gives no container the guest
// agent on a cell whose runtime is runsc for every container.
type vsockGate struct {
	flag bool
	// gvisorCell says that every container on the cell runs under runsc.
	gvisorCell bool
	log        lager.Logger

	mu      sync.Mutex
	bundles vsockBundles
	// settled says that the gate has seen what it needs and will not look
	// at the containers again in this run of gdn.
	settled bool
	// agentsRemain says, without the flag, that a container that serves
	// the guest agent was running when the gate looked.
	agentsRemain bool
}

func newVsockGate(log lager.Logger, flag, gvisorCell bool) *vsockGate {
	return &vsockGate{flag: flag, gvisorCell: gvisorCell, log: log.Session("vsock-gate")}
}

// watch gives the gate the runtime whose containers it looks at. gdn calls
// it before it serves any create.
func (g *vsockGate) watch(bundles vsockBundles) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bundles = bundles
}

// Deny says whether a container created now is denied vsock.
func (g *vsockGate) Deny() bool {
	if g.flag {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.settled {
		denials, err := g.denials()
		if err != nil {
			g.log.Error("vsock-denial-kept-without-container-list", err)
			return true
		}
		g.settled = true
		for handle, denial := range denials {
			if denial == seccompvsock.AnnotationWrapper {
				g.agentsRemain = true
				g.log.Info("vsock-denial-kept-for-guest-agent-containers", lager.Data{"handle": handle, "needs": "a restart of gdn once no guest agent container remains"})
				break
			}
		}
	}
	return g.agentsRemain
}

// Exception says whether a vm-qemu container created now may get
// /dev/vhost-vsock, and with it vsock, for the guest agent.
func (g *vsockGate) Exception() bool {
	if !g.flag {
		return false
	}
	if g.gvisorCell {
		g.log.Info("guest-agent-refused-on-gvisor-cell")
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.settled {
		return true
	}
	denials, err := g.denials()
	if err != nil {
		g.log.Error("guest-agent-refused-without-container-list", err)
		return false
	}
	var open []string
	for handle, denial := range denials {
		if denial != seccompvsock.AnnotationProfile && denial != seccompvsock.AnnotationWrapper {
			open = append(open, handle)
		}
	}
	if len(open) > 0 {
		g.log.Info("guest-agent-refused-while-containers-lack-vsock-denial", lager.Data{"handles": open})
		return false
	}
	g.settled = true
	return true
}

// denials maps the handle of each container and pea on the cell to what
// its annotation says about vsock. A gVisor container, and one whose profile
// does not deny vsock, maps to "" even when its annotation says otherwise,
// and one that went away while the gate looked is left out.
func (g *vsockGate) denials() (map[string]string, error) {
	if g.bundles == nil {
		return nil, errors.New("no runtime to list containers from")
	}
	handles, err := g.bundles.ContainerHandles()
	if err != nil {
		return nil, err
	}
	if peas, ok := g.bundles.(vsockPeaBundles); ok {
		peaHandles, err := peas.PeaHandles()
		if err != nil {
			return nil, err
		}
		handles = append(handles, peaHandles...)
	}
	denials := make(map[string]string, len(handles))
	for _, handle := range handles {
		_, bndl, err := g.bundles.BundleInfo(g.log, handle)
		var notFound garden.ContainerNotFoundError
		if errors.As(err, &notFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		denial := bndl.Spec.Annotations[seccompvsock.AnnotationKey]
		if backend.IsGvisor(backend.FromBundle(bndl)) || denial == seccompvsock.AnnotationProfile && !seccompvsock.Denies(bndl.Seccomp()) {
			denial = ""
		}
		denials[handle] = denial
	}
	return denials, nil
}

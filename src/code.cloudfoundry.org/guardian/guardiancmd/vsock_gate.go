package guardiancmd

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/rundmc/depot"
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

// vsockPeaBundles is the part of the containerd runtime that lists the peas
// that containerd runs, which it leaves out of ContainerHandles.
type vsockPeaBundles interface {
	PeaHandles() ([]string, error)
}

// vsockProcessDirs lists the process directories of a container in the
// depot. A pea that runc runs, which it does in runc mode and in containerd
// mode without --use-containerd-for-processes, keeps its bundle there, and
// neither ContainerHandles nor PeaHandles lists it.
type vsockProcessDirs interface {
	ListProcessDirs(log lager.Logger, sandboxHandle string) ([]string, error)
}

// vsockGate decides, for each container that gdn creates, whether it denies
// the container vsock and whether a vm-qemu container may serve the guest
// agent over vsock. It goes by --deny-vsock and by what the containers and
// peas that already run on the cell were created with, which each one's
// seccompvsock.AnnotationKey annotation records, because a container keeps
// its seccomp profile for its whole life and gdn may restart under other
// flags, with monit, without the drain that a deploy runs first.
//
// With --deny-vsock, gdn denies every new container vsock, and a vm-qemu
// container gets the guest agent only once no other container or pea on the
// cell can create a vsock socket any more. A container created before the
// flag was set has no annotation, and while one runs, a guest agent would
// be open to it, so gdn refuses the agent and logs which containers hold it
// back. It looks again at the next vm-qemu create, and once every container
// is denied it stops looking, because every container and pea it creates
// from then on is denied too.
//
// Without --deny-vsock, gdn gives no container the guest agent. If it finds,
// when it first lists the containers in its run, a container that serves
// the guest agent from an earlier run, it keeps denying every new container
// vsock for the rest of its run, because that agent still answers on vsock.
// Otherwise it denies nothing, and every bundle is the one it was before the
// denial existed. When it cannot list the containers, it denies nothing,
// logs the error, and lists them again at the next create.
//
// The gate never counts the container being created, whose directory may
// already be in the depot without its bundle, and it skips any container
// whose bundle has gone, because a container with no bundle runs nothing.
//
// A container that runs under gVisor ignores its seccomp profile, but it
// cannot create a vsock socket either, because gVisor's kernel serves every
// socket call of the container and has no AF_VSOCK family, so the gate goes
// by such a container's annotation like any other's. It gives no container
// the guest agent on a cell whose runtime is runsc for every container,
// because a vm-qemu container there runs under runsc too and could not
// reach its guest over vsock.
type vsockGate struct {
	flag bool
	// gvisorCell says that every container on the cell runs under runsc.
	gvisorCell bool
	log        lager.Logger

	mu          sync.Mutex
	bundles     vsockBundles
	processDirs vsockProcessDirs
	// settled says that the gate has seen what it needs and will not look
	// at the containers again in this run of gdn.
	settled bool
	// agentsRemain says, without the flag, that a container that serves
	// the guest agent was running when the gate looked.
	agentsRemain bool
	// listFailures counts the times in a row that the gate could not list
	// the containers.
	listFailures int
	// gvisorRefusalLogged says that the gate has logged its refusal on a
	// runsc cell, which it does once.
	gvisorRefusalLogged bool
}

func newVsockGate(log lager.Logger, flag, gvisorCell bool) *vsockGate {
	return &vsockGate{flag: flag, gvisorCell: gvisorCell, log: log.Session("vsock-gate")}
}

// watch gives the gate the runtime whose containers it looks at, and the
// depot of process directories where runc keeps its peas' bundles, which
// may be nil. gdn calls it before it serves any create.
func (g *vsockGate) watch(bundles vsockBundles, processDirs vsockProcessDirs) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bundles = bundles
	g.processDirs = processDirs
}

// Deny says whether the container with the given handle, which gdn is
// creating now, is denied vsock.
func (g *vsockGate) Deny(handle string) bool {
	if g.flag {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.settled {
		denials, err := g.denials(handle)
		if err != nil {
			g.listFailed("vsock-denial-not-applied-without-container-list", err)
			return false
		}
		g.listSucceeded()
		g.settled = true
		for other, denial := range denials {
			if denial == seccompvsock.AnnotationWrapper {
				g.agentsRemain = true
				g.log.Info("vsock-denial-kept-for-guest-agent-containers", lager.Data{"handle": other, "needs": "a restart of gdn once no guest agent container remains"})
				break
			}
		}
	}
	return g.agentsRemain
}

// Exception says whether the vm-qemu container with the given handle, which
// gdn is creating now, may get /dev/vhost-vsock, and with it vsock, for the
// guest agent.
func (g *vsockGate) Exception(handle string) bool {
	if !g.flag {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gvisorCell {
		if !g.gvisorRefusalLogged {
			g.gvisorRefusalLogged = true
			g.log.Info("guest-agent-refused-on-gvisor-cell")
		}
		return false
	}
	if g.settled {
		return true
	}
	denials, err := g.denials(handle)
	if err != nil {
		g.listFailed("guest-agent-refused-without-container-list", err)
		return false
	}
	g.listSucceeded()
	var open []string
	for other, denial := range denials {
		if denial != seccompvsock.AnnotationProfile && denial != seccompvsock.AnnotationWrapper {
			open = append(open, other)
		}
	}
	if len(open) > 0 {
		sort.Strings(open)
		g.log.Info("guest-agent-refused-while-containers-lack-vsock-denial", lager.Data{"handles": open})
		return false
	}
	g.settled = true
	return true
}

// listFailed logs, at error level, that the gate could not list the
// containers, with the number of times in a row that it could not.
func (g *vsockGate) listFailed(action string, err error) {
	g.listFailures++
	g.log.Error(action, err, lager.Data{"consecutive-failures": g.listFailures})
}

func (g *vsockGate) listSucceeded() {
	if g.listFailures > 0 {
		g.log.Info("container-list-recovered", lager.Data{"after-failures": g.listFailures})
	}
	g.listFailures = 0
}

// denials maps each container and pea on the cell, other than the one
// with the handle creating, to what its annotation says about vsock. A pea
// that runc runs is keyed by its sandbox's handle and its own, joined by a
// slash. One whose profile does not deny vsock maps to "" even when its
// annotation says otherwise, and one that has no bundle, or went away while
// the gate looked, is left out.
func (g *vsockGate) denials(creating string) (map[string]string, error) {
	if g.bundles == nil {
		return nil, errors.New("no runtime to list containers from")
	}
	containers, err := g.bundles.ContainerHandles()
	if err != nil {
		return nil, fmt.Errorf("listing the containers: %w", err)
	}
	handles := containers
	if peas, ok := g.bundles.(vsockPeaBundles); ok {
		peaHandles, err := peas.PeaHandles()
		if err != nil {
			return nil, fmt.Errorf("listing the peas: %w", err)
		}
		handles = append(append([]string{}, containers...), peaHandles...)
	}
	denials := make(map[string]string, len(handles))
	for _, handle := range handles {
		if handle == creating {
			continue
		}
		_, bndl, err := g.bundles.BundleInfo(g.log, handle)
		if noBundle(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading the bundle of %s: %w", handle, err)
		}
		denials[handle] = vsockDenialOf(bndl)
	}
	if g.processDirs == nil {
		return denials, nil
	}
	var loader goci.BndlLoader
	for _, sandbox := range containers {
		if sandbox == creating {
			continue
		}
		dirs, err := g.processDirs.ListProcessDirs(g.log, sandbox)
		if errors.Is(err, depot.ErrDoesNotExist) || noBundle(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing the processes of %s: %w", sandbox, err)
		}
		for _, dir := range dirs {
			pea := filepath.Base(dir)
			if pea == creating {
				continue
			}
			// Only a pea has a bundle in its process directory. An exec
			// has none, and neither has a pea that runc has not been given
			// yet.
			bndl, err := loader.Load(dir)
			if noBundle(err) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("reading the bundle of pea %s in %s: %w", pea, sandbox, err)
			}
			denials[sandbox+"/"+pea] = vsockDenialOf(bndl)
		}
	}
	return denials, nil
}

// vsockDenialOf says what a bundle's annotation says about vsock, or "" for
// one whose profile does not deny vsock even though its annotation says it
// does.
func vsockDenialOf(bndl goci.Bndl) string {
	denial := bndl.Spec.Annotations[seccompvsock.AnnotationKey]
	if denial == seccompvsock.AnnotationProfile && !seccompvsock.Denies(bndl.Seccomp()) {
		return ""
	}
	return denial
}

// noBundle says that err means the container has no bundle to read, because
// it went away, because its directory is still waiting for its config.json,
// or because the depot entry is not a directory at all.
func noBundle(err error) bool {
	var notFound garden.ContainerNotFoundError
	return errors.As(err, &notFound) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

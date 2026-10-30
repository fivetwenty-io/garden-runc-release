//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
)

// QEMU user-mode networking. QEMU's built-in DHCP and DNS proxy use this
// network; the guest configures it statically with the same addresses.
const (
	qemuNetwork   = "10.0.2.0/24"
	qemuGuestIP   = "10.0.2.15"
	qemuGuestCIDR = qemuGuestIP + "/24"
	qemuGateway   = "10.0.2.2"
	qemuDNS       = "10.0.2.3"
)

// Firecracker guest link. Garden creates the tap device in the container's
// network namespace with the host side address, so these must match the
// Firecracker constants in guardian's netplugin package. vm-launch does not
// import netplugin, which would pull garden's server dependencies into this
// static binary; a test checks that the values agree.
const (
	fcTapName   = "tap0"
	fcHostIP    = "169.254.100.1"
	fcGuestIP   = "169.254.100.2"
	fcGuestCIDR = fcGuestIP + "/30"
	// fcGuestMAC is a locally administered unicast address. Each guest has
	// its own network namespace, so a fixed address cannot clash.
	fcGuestMAC = "06:00:a9:fe:64:02"

	// containerNIC is the container's own interface. Garden sets tap0 to its
	// MTU, and the Firecracker guest's eth0 must match, so that the guest's
	// packets fit the path the container uses. 68 is the lowest IPv4 MTU and
	// 65535 the highest a tap device accepts.
	containerNIC = "eth0"
	minGuestMTU  = 68
	maxGuestMTU  = 65535
)

// containerResolvConf is the app container's resolver configuration, which
// silk writes. The guest's resolver configuration is derived from it.
const containerResolvConf = "/etc/resolv.conf"

// maxNameservers is the number of nameservers a resolver reads (MAXNS).
const maxNameservers = 3

// network is the guest network. Every guest has one. A process that serves
// on PORT, an LRP, also gets connections to PORT forwarded to the guest. A
// process started without PORT, such as a task, has port 0: its guest
// reaches out exactly as an LRP's does, and nothing outside can connect to
// it, as for a runc task.
type network struct {
	// port is the guest port that connections to PORT on the container reach,
	// or 0 for a process without PORT.
	port int
	// address is the guest eth0 address in CIDR form, gateway its default route.
	address string
	gateway string
	// resolvConf is the guest /etc/resolv.conf.
	resolvConf string
	// mtu is the guest eth0 MTU, or 0 to leave the driver's default. Only the
	// Firecracker guest sets it: QEMU's user-mode network ends every guest TCP
	// connection in QEMU itself, which opens its own sockets from the
	// container, so the container's path MTU never constrains the guest link.
	mtu int
}

// upstream is the guest address the Firecracker port proxy connects to. It
// is meaningful only when port is set.
func (n *network) upstream() string {
	return net.JoinHostPort(fcGuestIP, strconv.Itoa(n.port))
}

// listenAddr is where the port proxy listens in the container. It is
// meaningful only when port is set.
func (n *network) listenAddr() string {
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(n.port))
}

// networkFor returns the guest network for kind. lookupEnv reads the
// environment that every part of vm-launch shares (see lastWinsEnv). Without
// PORT, as for a task, the network has port 0 and is otherwise the same. A
// PORT that is set but not a TCP port number is an error. The network holds
// only the NIC, routes, MTU, and resolver; the guest environment is built
// separately (see buildGuestEnv).
// The container resolver configuration supplies the guest's search domains
// and, for Firecracker, its nameservers (QEMU's DNS proxy resolves through
// the container's configuration itself). When it cannot be read, the guest
// still boots and serves without DNS, so that is logged rather than fatal.
// The same holds for the container's eth0 MTU, which lookupMTU reads for the
// Firecracker guest: without it the guest keeps the default MTU.
func networkFor(kind backend.Kind, lookupEnv func(string) (string, bool), resolvConfPath string, lookupMTU func(name string) (int, error), logger *log.Logger) (*network, error) {
	port := 0
	if portValue, ok := lookupEnv(portEnv); ok {
		p, err := parsePort(portValue)
		if err != nil {
			return nil, err
		}
		port = p
	}

	data, err := os.ReadFile(resolvConfPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		logger.Printf("%s does not exist; the guest gets no resolver settings from it", resolvConfPath)
	case err != nil:
		logger.Printf("reading %s: %v; the guest gets no resolver settings from it", resolvConfPath, err)
	}
	conf := parseResolvConf(data)

	n := &network{port: port}
	switch kind {
	case backend.VMQemu:
		n.address, n.gateway = qemuGuestCIDR, qemuGateway
		n.resolvConf = formatResolvConf([]string{qemuDNS}, conf.search)
	case backend.VMFirecracker:
		n.address, n.gateway = fcGuestCIDR, fcHostIP
		for _, s := range conf.skipped {
			logger.Printf("%s: not passing nameserver %q to the guest: %s", resolvConfPath, s.value, s.reason)
		}
		if len(conf.nameservers) == 0 {
			logger.Printf("no usable nameserver in %s; the guest has no DNS", resolvConfPath)
		}
		n.resolvConf = formatResolvConf(conf.nameservers, conf.search)
		n.mtu = guestMTU(lookupMTU, logger)
	default:
		return nil, fmt.Errorf("unsupported backend %q", kind)
	}
	return n, nil
}

// guestMTU returns the MTU of the container's eth0, or 0 when it cannot be
// read or is not a usable MTU, in which case the guest keeps the default.
func guestMTU(lookupMTU func(string) (int, error), logger *log.Logger) int {
	mtu, err := lookupMTU(containerNIC)
	switch {
	case err != nil:
		logger.Printf("reading the mtu of %s: %v; the guest keeps the default mtu", containerNIC, err)
		return 0
	case mtu < minGuestMTU || mtu > maxGuestMTU:
		logger.Printf("the mtu %d of %s is outside %d to %d; the guest keeps the default mtu", mtu, containerNIC, minGuestMTU, maxGuestMTU)
		return 0
	}
	return mtu
}

// interfaceMTU is the MTU of the named interface in this network namespace.
func interfaceMTU(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}

// parsePort accepts a decimal TCP port number from 1 to 65535.
func parsePort(s string) (int, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("PORT %q is not a TCP port number from 1 to 65535", s)
	}
	return int(p), nil
}

type skippedNameserver struct{ value, reason string }

type resolvConf struct {
	nameservers []string
	search      []string
	skipped     []skippedNameserver
}

// parseResolvConf reads the nameserver and search settings of a resolv.conf.
// Only IPv4 nameservers outside 127.0.0.0/8 are usable: the guest has no IPv6,
// and a loopback address would point at the guest itself. As in the
// resolver, the last search or domain line wins, and nameservers after the
// third are ignored.
func parseResolvConf(data []byte) resolvConf {
	var conf resolvConf
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], ";") {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) < 2 {
				continue
			}
			addr, err := netip.ParseAddr(fields[1])
			switch {
			case err != nil:
				conf.skipped = append(conf.skipped, skippedNameserver{fields[1], "not an IP address"})
			case !addr.Is4():
				conf.skipped = append(conf.skipped, skippedNameserver{fields[1], "the guest has no IPv6"})
			case addr.IsLoopback():
				conf.skipped = append(conf.skipped, skippedNameserver{fields[1], "a loopback address is the guest itself"})
			case len(conf.nameservers) == maxNameservers:
				conf.skipped = append(conf.skipped, skippedNameserver{fields[1], "the resolver reads only " + strconv.Itoa(maxNameservers)})
			default:
				conf.nameservers = append(conf.nameservers, addr.String())
			}
		case "search", "domain":
			conf.search = append([]string(nil), fields[1:]...)
		}
	}
	return conf
}

func formatResolvConf(nameservers, search []string) string {
	var b strings.Builder
	if len(search) > 0 {
		b.WriteString("search " + strings.Join(search, " ") + "\n")
	}
	for _, ns := range nameservers {
		b.WriteString("nameserver " + ns + "\n")
	}
	return b.String()
}

// netFile returns the guest /rvm/net, which /init sources before it
// configures eth0. A network with a port also names it as RVM_PORT, which
// the guest's listen watcher reads (see guestListenWatch).
func netFile(n *network) string {
	s := "RVM_ADDRESS=" + shellQuote(n.address) + "\n" +
		"RVM_GATEWAY=" + shellQuote(n.gateway) + "\n"
	if n.mtu > 0 {
		s += "RVM_MTU=" + shellQuote(strconv.Itoa(n.mtu)) + "\n"
	}
	if n.port > 0 {
		s += "RVM_PORT=" + shellQuote(strconv.Itoa(n.port)) + "\n"
	}
	return s
}

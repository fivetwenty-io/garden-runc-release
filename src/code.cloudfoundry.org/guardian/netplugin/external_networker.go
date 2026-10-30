package netplugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"code.cloudfoundry.org/commandrunner"
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/kawasaki"
	"code.cloudfoundry.org/lager/v3"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const NetworkPropertyPrefix = "network."

var AllowableProperties = map[string]struct{}{"log_config": {}}

// The Firecracker guest reaches the container through tap0 on a /30 link-local
// subnet. It must not overlap 169.254.0.0/30, where silk puts its veth gateway.
const (
	FirecrackerTapName = "tap0"
	FirecrackerTapCIDR = "169.254.100.1/30"
	FirecrackerGuestIP = "169.254.100.2"

	DefaultIPTablesBin = "/sbin/iptables"
	defaultProcRoot    = "/proc"

	// The IPv4 minimum link MTU, and the largest MTU a tap device accepts.
	minTapMTU = 68
	maxTapMTU = 65535
)

// mtuPattern finds the MTU in the output of ip -o link show.
var mtuPattern = regexp.MustCompile(`\bmtu (\d+)\b`)

type externalBinaryNetworker struct {
	commandRunner         commandrunner.CommandRunner
	configStore           kawasaki.ConfigStore
	externalIP            net.IP
	operatorNameservers   []net.IP
	additionalNameservers []net.IP
	resolvConfigurer      kawasaki.DnsResolvConfigurer
	path                  string
	extraArg              []string
	networkDepot          kawasaki.NetworkDepot
	iptablesBin           string
	tapGroup              uint32
	tapGroupSet           bool
	procRoot              string
	loopbackRequired      bool
	setupLoopback         func(log lager.Logger, pid int) error
}

// Option adjusts how the networker prepares the netns of a container.
type Option func(*externalBinaryNetworker)

// WithIPTablesBin sets the iptables binary run inside the container netns.
func WithIPTablesBin(path string) Option {
	return func(p *externalBinaryNetworker) { p.iptablesBin = path }
}

// WithTapGroup sets the container gid that may attach to tap0. The kernel lets a
// process open a tap device whose owning group is one of the process's groups,
// so only a process that carries this gid, as the VM launcher does, can use the
// device. Network fails for a Firecracker container when it is not set.
func WithTapGroup(gid uint32) Option {
	return func(p *externalBinaryNetworker) {
		p.tapGroup = gid
		p.tapGroupSet = true
	}
}

// WithProcRoot sets the proc mount that gid_map files are read from.
func WithProcRoot(dir string) Option {
	return func(p *externalBinaryNetworker) { p.procRoot = dir }
}

// WithLoopbackRequired makes a failure to bring up lo fail Network for every
// container. Pass it when runsc is the cell's runtime. gVisor containers
// selected by their execution backend always require lo.
func WithLoopbackRequired() Option {
	return func(p *externalBinaryNetworker) { p.loopbackRequired = true }
}

// WithLoopbackSetup replaces the function that brings up lo in the netns of
// a container's pid.
func WithLoopbackSetup(setup func(log lager.Logger, pid int) error) Option {
	return func(p *externalBinaryNetworker) { p.setupLoopback = setup }
}

func New(
	commandRunner commandrunner.CommandRunner,
	configStore kawasaki.ConfigStore,
	externalIP net.IP,
	operatorNameServers []net.IP,
	additionalNameservers []net.IP,
	resolvConfigurer kawasaki.DnsResolvConfigurer,
	path string,
	extraArg []string,
	networkDepot kawasaki.NetworkDepot,
	opts ...Option,
) ExternalNetworker {
	p := &externalBinaryNetworker{
		commandRunner:         commandRunner,
		configStore:           configStore,
		externalIP:            externalIP,
		operatorNameservers:   operatorNameServers,
		additionalNameservers: additionalNameservers,
		resolvConfigurer:      resolvConfigurer,
		path:                  path,
		extraArg:              extraArg,
		networkDepot:          networkDepot,
		iptablesBin:           DefaultIPTablesBin,
		procRoot:              defaultProcRoot,
		setupLoopback:         setupLoopback,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

type ExternalNetworker interface {
	gardener.Networker
	gardener.Starter
}

func (p *externalBinaryNetworker) Start() error { return nil }

func networkProperties(containerProperties garden.Properties) garden.Properties {
	properties := garden.Properties{}

	for k, value := range containerProperties {
		if strings.HasPrefix(k, NetworkPropertyPrefix) {
			key := strings.TrimPrefix(k, NetworkPropertyPrefix)
			properties[key] = value
		} else if _, ok := AllowableProperties[k]; ok {
			properties[k] = value
		}
	}

	return properties
}

type UpInputs struct {
	Pid        int
	Properties map[string]string
	NetOut     []garden.NetOutRule `json:"netout_rules,omitempty"`
	NetIn      []garden.NetIn      `json:"netin,omitempty"`
}

type UpOutputs struct {
	Properties    map[string]string
	DNSServers    []string `json:"dns_servers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
}

func (p *externalBinaryNetworker) SetupBindMounts(log lager.Logger, handle string, privileged bool, rootfsPath string) ([]garden.BindMount, error) {
	return p.networkDepot.SetupBindMounts(log, handle, privileged, rootfsPath)
}

func (p *externalBinaryNetworker) Network(log lager.Logger, containerSpec garden.ContainerSpec, pid int) error {
	kind := backend.Kind(containerSpec.Properties[backend.AnnotationKey])
	if kind == backend.VMFirecracker && !p.tapGroupSet {
		return fmt.Errorf("cannot network %s container %q: no tap group is configured, and one is needed to restrict tap0 to the VM launcher", backend.VMFirecracker, containerSpec.Handle)
	}

	p.configStore.Set(containerSpec.Handle, gardener.ExternalIPKey, p.externalIP.String())

	inputs := UpInputs{
		Pid:        pid,
		Properties: networkProperties(containerSpec.Properties),
		NetOut:     containerSpec.NetOut,
		NetIn:      containerSpec.NetIn,
	}

	outputs := UpOutputs{}
	err := p.exec(log, "up", containerSpec.Handle, inputs, &outputs)
	if err != nil {
		return err
	}

	// Ensure loopback interface is up in the container's network namespace.
	// External network plugins (e.g. silk CNI) typically only create a veth pair.
	// Runtimes like gVisor that build their own netstack by scraping the netns
	// need lo to be present for applications binding to 127.0.0.1.
	if err := p.setupLoopback(log, pid); err != nil {
		log.Error("setup-loopback", err)
		// runc brings up lo on its own, so only gVisor needs this.
		if p.loopbackRequired || backend.IsGvisor(kind) {
			return err
		}
	}

	// Firecracker only attaches to a tap device, so the guest NIC is created here
	// while the host still has the privileges the unprivileged container lacks.
	if kind == backend.VMFirecracker {
		if err = p.setupFirecrackerTap(log, containerSpec.Handle, pid, outputs.Properties[gardener.ContainerIPKey]); err != nil {
			return err
		}
	}

	for k, v := range outputs.Properties {
		p.configStore.Set(containerSpec.Handle, k, v)
	}

	var pluginNameservers []net.IP
	if outputs.DNSServers != nil {
		pluginNameservers = []net.IP{}
		for _, dnsServer := range outputs.DNSServers {
			pluginNameservers = append(pluginNameservers, net.ParseIP(dnsServer))
		}
	}

	containerIP, ok := p.configStore.Get(containerSpec.Handle, gardener.ContainerIPKey)

	// ipv6 address is "" if not returned by external networker
	containerIPv6, _ := p.configStore.Get(containerSpec.Handle, gardener.ContainerIPv6Key)
	if ok {
		log.Info("external-binary-write-dns-to-config", lager.Data{
			"dnsServers": pluginNameservers,
		})
		cfg := kawasaki.NetworkConfig{
			ContainerIP:           net.ParseIP(containerIP),
			ContainerIPv6:         net.ParseIP(containerIPv6),
			BridgeIP:              net.ParseIP(containerIP),
			ContainerHandle:       containerSpec.Handle,
			OperatorNameservers:   p.operatorNameservers,
			AdditionalNameservers: p.additionalNameservers,
			PluginNameservers:     pluginNameservers,
			PluginSearchDomains:   outputs.SearchDomains,
		}

		err = p.resolvConfigurer.Configure(log, cfg, pid)
		if err != nil {
			return err
		}
	}

	return nil
}

// setupLoopback enters the container's network namespace and brings up the
// loopback interface. This is needed for runtimes like gVisor that scrape the
// netns for interfaces rather than creating lo themselves.
func setupLoopback(log lager.Logger, pid int) error {
	containerNS, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("getting netns for pid %d: %w", pid, err)
	}
	defer containerNS.Close()

	// Create a netlink handle in the container's network namespace.
	nlh, err := netlink.NewHandleAt(containerNS)
	if err != nil {
		return fmt.Errorf("creating netlink handle in container netns: %w", err)
	}
	defer nlh.Close()

	lo, err := nlh.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("finding lo interface: %w", err)
	}

	if err := nlh.LinkSetUp(lo); err != nil {
		return fmt.Errorf("bringing up lo: %w", err)
	}

	log.Info("setup-loopback-success", lager.Data{"pid": pid})
	return nil
}

// setupFirecrackerTap creates tap0 in the network namespace of pid, owned by the
// host gid that the tap group maps to, and lets the guest behind it reach out
// through eth0. tap0 takes eth0's MTU so that the guest's packets fit the path
// the container uses. The guest is untrusted: it may send only from its own
// address, and nothing may open a connection into it. Those filters are in
// place before the link is up and forwarding is enabled. There is no per-device
// reverse path filter on tap0, because the kernel applies the larger of the
// "all" and per-device values and a netns inherits "all" from the host, so a
// host that sets it to loose mode would make the device setting a no-op. The
// FORWARD source rule is the spoofing control for traffic that leaves the
// container, and the INPUT source rule is the one for traffic that stays in
// it. Guest egress is translated with SNAT to containerIP, the container IP
// the network plugin reported, which is the address that application security
// groups and Diego know the container by. MASQUERADE would not do: it takes
// the first address of universe scope on the outgoing device, and silk gives
// eth0 its address with link scope, so the kernel falls back to another device
// and picks tap0's address, which silk then drops. Destroying the netns removes
// the device and the rules.
func (p *externalBinaryNetworker) setupFirecrackerTap(log lager.Logger, handle string, pid int, containerIP string) error {
	log = log.Session("setup-firecracker-tap", lager.Data{"handle": handle, "pid": pid})

	egressSource, err := guestEgressSource(containerIP)
	if err != nil {
		log.Error("guest-egress-source-failed", err)
		return fmt.Errorf("choosing the guest egress source for container netns of pid %d: %w", pid, err)
	}

	hostGID, err := p.tapHostGID(pid)
	if err != nil {
		log.Error("resolve-tap-group-failed", err)
		return fmt.Errorf("resolving tap group for container netns of pid %d: %w", pid, err)
	}

	mtu, err := p.containerMTU(log, pid)
	if err != nil {
		return fmt.Errorf("reading the eth0 mtu in container netns of pid %d: %w", pid, err)
	}

	tap := FirecrackerTapName
	guest := FirecrackerGuestIP + "/32"
	steps := []struct {
		description string
		args        []string
	}{
		{"creating " + tap, []string{"ip", "tuntap", "add", "dev", tap, "mode", "tap", "group", strconv.FormatUint(uint64(hostGID), 10)}},
		{"setting the mtu of " + tap, []string{"ip", "link", "set", tap, "mtu", strconv.Itoa(mtu)}},
		{"dropping spoofed guest sources", []string{p.iptablesBin, "-A", "FORWARD", "-i", tap, "!", "-s", guest, "-j", "DROP"}},
		{"dropping spoofed guest sources to the container", []string{p.iptablesBin, "-A", "INPUT", "-i", tap, "!", "-s", guest, "-j", "DROP"}},
		{"dropping connections opened towards the guest", []string{p.iptablesBin, "-A", "FORWARD", "-o", tap, "-m", "conntrack", "!", "--ctstate", "ESTABLISHED,RELATED", "-j", "DROP"}},
		{"addressing " + tap, []string{"ip", "addr", "add", FirecrackerTapCIDR, "dev", tap}},
		{"bringing up " + tap, []string{"ip", "link", "set", tap, "up"}},
		{"enabling ip forwarding", []string{"sysctl", "-w", "net.ipv4.ip_forward=1"}},
		{"translating guest egress to the container IP", []string{p.iptablesBin, "-t", "nat", "-A", "POSTROUTING", "-s", guest, "-o", "eth0", "-j", "SNAT", "--to-source", egressSource}},
	}
	for _, step := range steps {
		if _, err := p.runInNetns(log, pid, step.args...); err != nil {
			return fmt.Errorf("%s in container netns of pid %d: %w", step.description, pid, err)
		}
	}

	log.Info("success", lager.Data{"host-gid": hostGID, "mtu": mtu, "egress-source": egressSource})
	return nil
}

// containerMTU reads the MTU of eth0 in the network namespace of pid. It goes
// through ip, because sysfs shows the namespace it was mounted in and not the
// one nsenter enters.
func (p *externalBinaryNetworker) containerMTU(log lager.Logger, pid int) (int, error) {
	out, err := p.runInNetns(log, pid, "ip", "-o", "link", "show", "dev", "eth0")
	if err != nil {
		return 0, err
	}

	match := mtuPattern.FindStringSubmatch(out)
	if match == nil {
		return 0, fmt.Errorf("no mtu in %q", strings.TrimSpace(out))
	}
	mtu, err := strconv.Atoi(match[1])
	if err != nil || mtu < minTapMTU || mtu > maxTapMTU {
		return 0, fmt.Errorf("mtu %s is outside %d to %d", match[1], minTapMTU, maxTapMTU)
	}
	return mtu, nil
}

// guestEgressSource returns the address guest egress is translated to: the
// container IP the network plugin reported, in dotted-quad form. The guest
// network is IPv4 only, so a container without an IPv4 container IP has none.
// Private ranges such as the 10.255.0.0/16 that silk uses are fine. Loopback,
// unspecified, link-local (which includes tap0's own 169.254.100.1), multicast,
// and broadcast addresses are not addresses a packet can leave with.
func guestEgressSource(containerIP string) (string, error) {
	if containerIP == "" {
		return "", fmt.Errorf("the network plugin reported no %s", gardener.ContainerIPKey)
	}
	ip := net.ParseIP(containerIP).To4()
	if ip == nil || !ip.IsGlobalUnicast() {
		return "", fmt.Errorf("the network plugin reported %s %q, which is not an IPv4 address guest egress can leave with", gardener.ContainerIPKey, containerIP)
	}
	return ip.String(), nil
}

// runInNetns runs args with the network namespace of pid entered, returning the
// command's stdout and logging its stderr on failure.
func (p *externalBinaryNetworker) runInNetns(log lager.Logger, pid int, args ...string) (string, error) {
	cmd := exec.Command("nsenter", append([]string{fmt.Sprintf("--net=/proc/%d/ns/net", pid), "--"}, args...)...)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := p.commandRunner.Run(cmd); err != nil {
		log.Error("failed", err, lager.Data{"command": args, "stderr": stderr.String()})
		return "", err
	}

	return stdout.String(), nil
}

// tapHostGID maps the tap group through the gid_map of pid.
func (p *externalBinaryNetworker) tapHostGID(pid int) (uint32, error) {
	gidMap, err := os.ReadFile(fmt.Sprintf("%s/%d/gid_map", p.procRoot, pid))
	if err != nil {
		return 0, err
	}

	return HostGID(string(gidMap), p.tapGroup)
}

// HostGID translates containerGID using the contents of a /proc/<pid>/gid_map
// file, whose lines are "<container start> <host start> <count>". The tap
// device records the group in the host's terms, which is what the kernel
// compares against the groups of the process that opens it.
func HostGID(gidMap string, containerGID uint32) (uint32, error) {
	for _, line := range strings.Split(gidMap, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return 0, fmt.Errorf("malformed gid_map line %q", line)
		}

		var values [3]uint64
		for i, field := range fields {
			v, err := strconv.ParseUint(field, 10, 32)
			if err != nil {
				return 0, fmt.Errorf("malformed gid_map line %q: %w", line, err)
			}
			values[i] = v
		}
		containerStart, hostStart, count := values[0], values[1], values[2]

		gid := uint64(containerGID)
		if gid >= containerStart && gid-containerStart < count {
			hostGID := hostStart + (gid - containerStart)
			if hostGID > math.MaxUint32 {
				return 0, fmt.Errorf("gid_map line %q maps container gid %d beyond the gid range", line, containerGID)
			}
			return uint32(hostGID), nil
		}
	}

	return 0, fmt.Errorf("container gid %d is not mapped in gid_map", containerGID)
}

func (p *externalBinaryNetworker) Destroy(log lager.Logger, handle string) error {
	err := p.exec(log, "down", handle, nil, nil)
	if err != nil {
		return err
	}

	return p.networkDepot.Destroy(log, handle)
}

func (p *externalBinaryNetworker) Restore(log lager.Logger, handle string) error {
	return nil
}

func (p *externalBinaryNetworker) Capacity() (m uint64) {
	return math.MaxUint64
}

type NetInInputs struct {
	HostIP        string
	HostPort      uint32
	ContainerIP   string
	ContainerPort uint32
}

type NetInOutputs struct {
	HostPort      uint32 `json:"host_port"`
	ContainerPort uint32 `json:"container_port"`
}

func (p *externalBinaryNetworker) NetIn(log lager.Logger, handle string, hostPort, containerPort uint32) (uint32, uint32, error) {
	containerIP, ok := p.configStore.Get(handle, gardener.ContainerIPKey)
	if !ok {
		return 0, 0, fmt.Errorf("cannot find container [%s]\n", handle)
	}

	inputs := NetInInputs{
		HostIP:        p.externalIP.String(),
		ContainerIP:   containerIP,
		HostPort:      hostPort,
		ContainerPort: containerPort,
	}
	outputs := NetInOutputs{}

	err := p.exec(log, "net-in", handle, inputs, &outputs)
	if err != nil {
		return 0, 0, err
	}

	err = kawasaki.AddPortMapping(log, p.configStore, handle, garden.PortMapping{
		HostPort:      outputs.HostPort,
		ContainerPort: outputs.ContainerPort,
	})
	if err != nil {
		return 0, 0, err
	}

	return outputs.HostPort, outputs.ContainerPort, err
}

type NetOutInputs struct {
	ContainerIP string            `json:"container_ip"`
	NetOutRule  garden.NetOutRule `json:"netout_rule"`
}

func (p *externalBinaryNetworker) NetOut(log lager.Logger, handle string, rule garden.NetOutRule) error {
	containerIP, ok := p.configStore.Get(handle, gardener.ContainerIPKey)
	if !ok {
		return fmt.Errorf("cannot find container [%s]\n", handle)
	}

	inputs := NetOutInputs{
		ContainerIP: containerIP,
		NetOutRule:  rule,
	}

	err := p.exec(log, "net-out", handle, inputs, nil)
	if err != nil {
		return err
	}

	return nil
}

type BulkNetOutInputs struct {
	ContainerIP string              `json:"container_ip"`
	NetOutRules []garden.NetOutRule `json:"netout_rules"`
}

func (p *externalBinaryNetworker) BulkNetOut(log lager.Logger, handle string, rules []garden.NetOutRule) error {
	containerIP, ok := p.configStore.Get(handle, gardener.ContainerIPKey)
	if !ok {
		return fmt.Errorf("cannot find container [%s]\n", handle)
	}

	inputs := BulkNetOutInputs{
		ContainerIP: containerIP,
		NetOutRules: rules,
	}

	return p.exec(log, "bulk-net-out", handle, inputs, nil)
}

func (p *externalBinaryNetworker) exec(log lager.Logger, action, handle string,
	inputData interface{}, outputData interface{}) error {

	stdinBytes, err := json.Marshal(inputData)
	if err != nil {
		return err
	}

	args := append(p.extraArg, "--action", action, "--handle", handle)
	cmd := exec.Command(p.path, args...)
	stdout := &bytes.Buffer{}
	cmd.Stdout = stdout
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	cmd.Stdin = bytes.NewReader(stdinBytes)

	err = p.commandRunner.Run(cmd)

	logData := lager.Data{"action": action, "stdin": string(stdinBytes), "stderr": stderr.String(), "stdout": stdout.String()}
	if err != nil {
		log.Error("external-networker-result", err, logData)
		return fmt.Errorf("external networker encountered an error running '%s' action: %s", action, err)
	}

	if outputData != nil && stdout.Len() > 0 {
		err = json.Unmarshal(stdout.Bytes(), outputData)
		if err != nil {
			log.Error("external-networker-result", err, logData)
			return fmt.Errorf("unmarshaling result from external networker: %s", err)
		}
	}

	if stderr.Len() > 0 {
		log.Info("external-networker-result", lager.Data{"stderr": stderr.String()})
	}

	log.Debug("external-networker-result", logData)

	return nil
}

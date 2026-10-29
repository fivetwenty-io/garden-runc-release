package guardiancmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/commandrunner"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/guardiancmd/cpuentitlement"
	"code.cloudfoundry.org/guardian/idmapper"
	"code.cloudfoundry.org/guardian/imageplugin"
	"code.cloudfoundry.org/guardian/kawasaki"
	kawasakifactory "code.cloudfoundry.org/guardian/kawasaki/factory"
	"code.cloudfoundry.org/guardian/kawasaki/iptables"
	"code.cloudfoundry.org/guardian/kawasaki/mtu"
	"code.cloudfoundry.org/guardian/kawasaki/ports"
	"code.cloudfoundry.org/guardian/kawasaki/subnets"
	"code.cloudfoundry.org/guardian/logging"
	"code.cloudfoundry.org/guardian/metrics"
	"code.cloudfoundry.org/guardian/netplugin"
	locksmithpkg "code.cloudfoundry.org/guardian/pkg/locksmith"
	"code.cloudfoundry.org/guardian/properties"
	"code.cloudfoundry.org/guardian/rundmc"
	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
	gardencgroups "code.cloudfoundry.org/guardian/rundmc/cgroups"
	"code.cloudfoundry.org/guardian/rundmc/deleter"
	"code.cloudfoundry.org/guardian/rundmc/depot"
	"code.cloudfoundry.org/guardian/rundmc/execrunner"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/peas"
	runcprivchecker "code.cloudfoundry.org/guardian/rundmc/peas/privchecker"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	containerdprivchecker "code.cloudfoundry.org/guardian/rundmc/runcontainerd/privchecker"
	"code.cloudfoundry.org/guardian/rundmc/runrunc"
	"code.cloudfoundry.org/guardian/rundmc/runrunc/pid"
	"code.cloudfoundry.org/guardian/rundmc/stopper"
	"code.cloudfoundry.org/guardian/rundmc/users"
	"code.cloudfoundry.org/guardian/sysinfo"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/localip"
	"github.com/eapache/go-resiliency/retrier"
	uuid "github.com/nu7hatch/gouuid"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type GardenFactory interface {
	WireResolvConfigurer() kawasaki.DnsResolvConfigurer
	WireMkdirer() runrunc.Mkdirer
	CommandRunner() commandrunner.CommandRunner
	WireVolumizer(logger lager.Logger) gardener.Volumizer
	WireCgroupsStarter(logger lager.Logger) gardener.Starter
	WireExecRunner(runcRoot string, containerRootUID, containerRootGID uint32, bundleSaver depot.BundleSaver, bundleLookupper depot.BundleLookupper, processDepot execrunner.ProcessDepot) runrunc.ExecRunner
	WireContainerd(*processes.ProcBuilder, users.UserLookupper, func(runrunc.PidGetter) *runrunc.Execer, runcontainerd.Statser, lager.Logger, peas.Volumizer, runcontainerd.PeaHandlesGetter, *metrics.MetricsProvider) (*runcontainerd.RunContainerd, *runcontainerd.RunContainerPea, *runcontainerd.PidGetter, *containerdprivchecker.PrivilegeChecker, peas.BundleLoader, runcontainerd.RuntimePolicy, error)

	WireCPUCgrouper() (rundmc.CPUCgrouper, error)
	WireContainerNetworkMetricsProvider(containerizer gardener.Containerizer, propertyManager gardener.PropertyManager) gardener.ContainerNetworkMetricsProvider
}

type PidGetter interface {
	GetPid(logger lager.Logger, containerID string) (int, error)
	GetPeaPid(logger lager.Logger, _, peaID string) (int, error)
}

type GdnCommand struct {
	SetupCommand   *SetupCommand   `command:"setup"`
	ServerCommand  *ServerCommand  `command:"server"`
	CleanupCommand *CleanupCommand `command:"cleanup"`

	// This must be present to stop go-flags complaining, but it's not actually
	// used. We parse this flag outside of the go-flags framework.
	ConfigFilePath string `long:"config" description:"Config file path."`
}

type Service interface {
	Start()
	Stop()
}

type CommonCommand struct {
	Logger LagerFlag

	// wiredBackends is the outcome of wireExecutionBackends. createWiring sets
	// it before any factory wiring runs, so that factory methods whose
	// signature cannot carry it, such as WireContainerd, can read it.
	wiredBackends *executionBackends

	Server struct {
		BindIP   IPFlag `long:"bind-ip"   description:"Bind with TCP on the given IP."`
		BindPort uint16 `long:"bind-port" description:"Bind with TCP on the given port."`

		BindSocket string `long:"bind-socket" default:"/tmp/garden.sock" description:"Bind with Unix on the given socket path."`

		DebugBindIP   IPFlag `long:"debug-bind-ip"                   description:"Bind the debug server on the given IP."`
		DebugBindPort uint16 `long:"debug-bind-port" default:"17013" description:"Bind the debug server to the given port."`

		Tag       string `hidden:"true" long:"tag" description:"Optional 2-character identifier used for namespacing global configuration."`
		SkipSetup bool   `long:"skip-setup" description:"Skip the preparation part of the host that requires root privileges"`

		ReadHeaderTimeout time.Duration `long:"read-header-timeout" description:"The amount of time allowed to read request headers"`
	} `group:"Server Configuration"`

	Containers struct {
		Dir                        string                 `long:"depot" default:"/var/run/gdn/depot" description:"Directory in which to store container data."`
		PropertiesPath             string                 `long:"properties-path" description:"Path in which to store properties."`
		ConsoleSocketsPath         string                 `long:"console-sockets-path" description:"Path in which to store temporary sockets"`
		CleanupProcessDirsOnWait   bool                   `long:"cleanup-process-dirs-on-wait" description:"Clean up proccess dirs on first invocation of wait"`
		DisablePrivilgedContainers bool                   `long:"disable-privileged-containers" description:"Disable creation of privileged containers"`
		DeviceCgroupRules          []DeviceCgroupRuleFlag `long:"device-cgroup-rule" description:"Device cgroup rules that will be applied to privileged containers"`

		UIDMapStart  uint32 `long:"uid-map-start"  default:"1" description:"The lowest numerical subordinate user ID the user is allowed to map"`
		UIDMapLength uint32 `long:"uid-map-length" description:"The number of numerical subordinate user IDs the user is allowed to map"`
		GIDMapStart  uint32 `long:"gid-map-start"  default:"1" description:"The lowest numerical subordinate group ID the user is allowed to map"`
		GIDMapLength uint32 `long:"gid-map-length" description:"The number of numerical subordinate group IDs the user is allowed to map"`

		DefaultRootFS              string        `long:"default-rootfs"     description:"Default rootfs to use when not specified on container creation."`
		DefaultGraceTime           time.Duration `long:"default-grace-time" description:"Default time after which idle containers should expire."`
		DestroyContainersOnStartup bool          `long:"destroy-containers-on-startup" description:"Clean up all the existing containers on startup."`
		ApparmorProfile            string        `long:"apparmor" description:"Apparmor profile to use for unprivileged container processes"`
		NoNewPrivileges            bool          `long:"no-new-privileges" description:"Set NoNewPrivileges on unprivileged container processes"`
	} `group:"Container Lifecycle"`

	Bin struct {
		AssetsDir       string   `long:"assets-dir"     default:"/var/gdn/assets" description:"Directory in which to extract packaged assets"`
		Dadoo           FileFlag `long:"dadoo-bin"      description:"Path to the 'dadoo' binary."`
		NSTar           FileFlag `long:"nstar-bin"      description:"Path to the 'nstar' binary."`
		Tar             FileFlag `long:"tar-bin"        description:"Path to the 'tar' binary."`
		IPTables        FileFlag `long:"iptables-bin"  default:"/sbin/iptables" description:"path to the iptables binary"`
		IPTablesRestore FileFlag `long:"iptables-restore-bin"  default:"/sbin/iptables-restore" description:"path to the iptables-restore binary"`
		Init            FileFlag `long:"init-bin"       description:"Path execute as pid 1 inside each container."`
	} `group:"Binary Tools"`

	Runtime struct {
		Plugin          string   `long:"runtime-plugin"       default:"runc" description:"Path to the runtime plugin binary."`
		PluginExtraArgs []string `long:"runtime-plugin-extra-arg" description:"Extra argument to pass to the runtime plugin. Can be specified multiple times."`
	} `group:"Runtime"`

	Image struct {
		NoPlugin bool `long:"no-image-plugin" description:"Do not use the embedded 'grootfs' image plugin."`

		Plugin          FileFlag `long:"image-plugin"           description:"Path to image plugin binary."`
		PluginExtraArgs []string `long:"image-plugin-extra-arg" description:"Extra argument to pass to the image plugin to create unprivileged images. Can be specified multiple times."`

		PrivilegedPlugin          FileFlag `long:"privileged-image-plugin"           description:"Path to privileged image plugin binary."`
		PrivilegedPluginExtraArgs []string `long:"privileged-image-plugin-extra-arg" description:"Extra argument to pass to the image plugin to create privileged images. Can be specified multiple times."`
	} `group:"Image"`

	Docker struct {
		Registry           string   `long:"docker-registry" default:"registry-1.docker.io" description:"Docker registry API endpoint."`
		InsecureRegistries []string `long:"insecure-docker-registry" description:"Docker registry to allow connecting to even if not secure. Can be specified multiple times."`
	} `group:"Docker Image Fetching"`

	Network struct {
		Pool CIDRFlag `long:"network-pool" default:"10.254.0.0/22" description:"Network range to use for dynamically allocated container subnets."`

		AllowHostAccess bool       `long:"allow-host-access" description:"Allow network access to the host machine."`
		DenyNetworks    []CIDRFlag `long:"deny-network"      description:"Network ranges to which traffic from containers will be denied. Can be specified multiple times."`

		DNSServers           []IPFlag `long:"dns-server" description:"DNS server IP address to use instead of automatically determined servers. Can be specified multiple times."`
		AdditionalDNSServers []IPFlag `long:"additional-dns-server" description:"DNS server IP address to append to the automatically determined servers. Can be specified multiple times."`

		AdditionalHostEntries []string `long:"additional-host-entry" description:"Per line hosts entries. Can be specified multiple times and will be appended verbatim in order to /etc/hosts"`

		ExternalIP             IPFlag `long:"external-ip"                     description:"IP address to use to reach container's mapped ports. Autodetected if not specified."`
		PortPoolStart          uint32 `long:"port-pool-start" default:"61001" description:"Start of the ephemeral port range used for mapped container ports."`
		PortPoolSize           uint32 `long:"port-pool-size"  default:"4534"  description:"Size of the port pool used for mapped container ports."`
		PortPoolPropertiesPath string `long:"port-pool-properties-path" description:"Path in which to store port pool properties."`

		Mtu int `long:"mtu" description:"MTU size for container network interfaces. Defaults to the MTU of the interface used for outbound access by the host. Max allowed value is 1500."`

		Plugin          FileFlag `long:"network-plugin"           description:"Path to network plugin binary."`
		PluginExtraArgs []string `long:"network-plugin-extra-arg" description:"Extra argument to pass to the network plugin. Can be specified multiple times."`

		EnableMetrics bool `long:"enable-container-network-metrics" description:"Enable container network metrics. This feature is only available on Linux."`
	} `group:"Container Networking"`

	Limits struct {
		CPUQuotaPerShare        uint64 `long:"cpu-quota-per-share" default:"0" description:"Maximum number of microseconds each cpu share assigned to a container allows per quota period"`
		DefaultBlockIOWeight    uint16 `long:"default-container-blockio-weight" default:"0" description:"Default block IO weight assigned to a container"`
		ContainerIOMaxReadBps   uint64 `long:"container-io-max-read-bps" default:"0" description:"Per-container read bytes/s limit (cgroups v2 only, 0=unlimited)"`
		ContainerIOMaxWriteBps  uint64 `long:"container-io-max-write-bps" default:"0" description:"Per-container write bytes/s limit (cgroups v2 only, 0=unlimited)"`
		ContainerIOMaxReadIOPS  uint64 `long:"container-io-max-read-iops" default:"0" description:"Per-container read IOPS limit (cgroups v2 only, 0=unlimited)"`
		ContainerIOMaxWriteIOPS uint64 `long:"container-io-max-write-iops" default:"0" description:"Per-container write IOPS limit (cgroups v2 only, 0=unlimited)"`
		MaxContainers           uint64 `long:"max-containers" default:"0" description:"Maximum number of containers that can be created."`
		DisableSwapLimit        bool   `long:"disable-swap-limit" description:"Disable swap memory limit"`
	} `group:"Limits"`

	Metrics struct {
		EmissionInterval time.Duration `long:"metrics-emission-interval" default:"1m" description:"Interval on which to emit metrics."`

		DropsondeOrigin        string  `long:"dropsonde-origin"      default:"garden-linux"   description:"Origin identifier for Dropsonde-emitted metrics."`
		DropsondeDestination   string  `long:"dropsonde-destination" default:"127.0.0.1:3457" description:"Destination for Dropsonde-emitted metrics."`
		CPUEntitlementPerShare float64 `long:"cpu-entitlement-per-share" description:"CPU percentage entitled to a container for a single CPU share"`
	} `group:"Metrics"`

	Containerd struct {
		Socket                    string `long:"containerd-socket" description:"Path to a containerd socket."`
		UseContainerdForProcesses bool   `long:"use-containerd-for-processes" description:"Use containerd to run processes in containers."`
		RuntimeType               string `long:"containerd-runtime-type" description:"Containerd runtime type (e.g. io.containerd.runc.v2 or io.containerd.runsc.v1)."`
	} `group:"Containerd"`

	ExecutionBackends struct {
		Enabled        []string `long:"execution-backend" description:"Execution backend to enable: oci-gvisor, vm-qemu, or vm-firecracker. oci-runc is always enabled. Can be specified multiple times. Cannot be combined with an alternative --containerd-runtime-type."`
		VMArtifactsDir string   `long:"vm-artifacts-dir" default:"/var/vcap/data/vm-runtime/artifacts" description:"Host directory with the VM kernels and hypervisors, bound read-only into vm-* containers at /opt/garden-vm/artifacts."`
		VMLaunchBin    string   `long:"vm-launch-bin" description:"Host path of the static vm-launch binary, bound read-only into vm-* containers at /opt/garden-vm/vm-launch. Required when a vm-* backend is enabled."`
		VMKVMGid       uint32   `long:"vm-kvm-gid" description:"Host gid that owns /dev/kvm, added to the vm-launch process. Resolved from the host kvm group when not set."`
	} `group:"Execution Backends"`

	CPUThrottling struct {
		Enabled       bool   `long:"enable-cpu-throttling" description:"Enable CPU throttling."`
		CheckInterval uint32 `long:"cpu-throttling-check-interval" default:"15" description:"How often to check which apps need to get CPU throttled or not."`
	} `group:"CPU Throttling"`

	Sysctl struct {
		TCPKeepaliveTime     uint32 `long:"tcp-keepalive-time" description:"The net.ipv4.tcp_keepalive_time sysctl parameter that will be used inside containers"`
		TCPKeepaliveInterval uint32 `long:"tcp-keepalive-interval" description:"The net.ipv4.tcp_keepalive_intvl sysctl parameter that will be used inside containers"`
		TCPKeepaliveProbes   uint32 `long:"tcp-keepalive-probes" description:"The net.ipv4.tcp_keepalive_probes sysctl parameter that will be used inside containers"`
		TCPRetries1          uint32 `long:"tcp-retries1" description:"The net.ipv4.tcp_retries1 sysctl parameter that will be used inside containers"`
		TCPRetries2          uint32 `long:"tcp-retries2" description:"The net.ipv4.tcp_retries2 sysctl parameter that will be used inside containers"`
	} `group:"Sysctl"`
}

type commandWiring struct {
	Containerizer                   *rundmc.Containerizer
	PortPool                        *ports.PortPool
	Networker                       gardener.Networker
	Restorer                        gardener.Restorer
	Volumizer                       gardener.Volumizer
	Starter                         gardener.BulkStarter
	PeaCleaner                      gardener.PeaCleaner
	PropertiesManager               *properties.Manager
	UidGenerator                    gardener.UidGeneratorFunc
	SysInfoProvider                 gardener.SysInfoProvider
	Logger                          lager.Logger
	CpuEntitlementPerShare          float64
	ContainerNetworkMetricsProvider gardener.ContainerNetworkMetricsProvider
	Backends                        *backend.Registry
}

func (cmd *CommonCommand) createGardener(wiring *commandWiring) *gardener.Gardener {
	gdnr := gardener.New(wiring.UidGenerator,
		wiring.Starter,
		wiring.SysInfoProvider,
		wiring.Networker,
		wiring.Volumizer,
		wiring.Containerizer,
		wiring.PropertiesManager,
		wiring.Restorer,
		wiring.PeaCleaner,
		wiring.Logger,
		cmd.Limits.MaxContainers,
		!cmd.Containers.DisablePrivilgedContainers,
		wiring.ContainerNetworkMetricsProvider,
	)
	gdnr.Backends = wiring.Backends

	return gdnr
}

func (cmd *CommonCommand) createWiring(logger lager.Logger, metricsProvider *metrics.MetricsProvider) (*commandWiring, error) {
	backends, err := cmd.wireExecutionBackends(logger)
	if err != nil {
		logger.Error("invalid-execution-backend-flags", err)
		return nil, err
	}
	cmd.wiredBackends = backends

	factory := cmd.NewGardenFactory()

	propManager, err := cmd.loadProperties(logger, cmd.Containers.PropertiesPath)
	if err != nil {
		return nil, err
	}

	portPool, err := cmd.wirePortPool(logger)
	if err != nil {
		return nil, err
	}

	uidMappings, gidMappings := cmd.idMappings()
	networkDepot := depot.NewNetworkDepot(
		cmd.Containers.Dir,
		wireBindMountSourceCreator(uidMappings, gidMappings),
	)

	networker, iptablesStarter, err := cmd.wireNetworker(logger, factory, propManager, portPool, networkDepot, backends)
	if err != nil {
		logger.Error("failed-to-wire-networker", err)
		return nil, err
	}

	restorer := gardener.NewRestorer(networker)
	if cmd.Containers.DestroyContainersOnStartup {
		restorer = &gardener.NoopRestorer{}
	}

	volumizer := factory.WireVolumizer(logger)

	starters := []gardener.Starter{}
	if !cmd.Server.SkipSetup {
		starters = append(starters, factory.WireCgroupsStarter(logger))
	}
	if cmd.Network.Plugin.Path() == "" {
		starters = append(starters, iptablesStarter)
	}

	var bulkStarter gardener.BulkStarter = gardener.NewBulkStarter(starters)
	sysInfoProvider := sysinfo.NewResourcesProvider(cmd.Containers.Dir)

	cpuEntitlementPerShare := cmd.Metrics.CPUEntitlementPerShare
	if cpuEntitlementPerShare == 0 {
		cpuEntitlementCalculator := cpuentitlement.Calculator{SysInfoProvider: sysInfoProvider}
		cpuEntitlementPerShare, err = cpuEntitlementCalculator.CalculateDefaultEntitlementPerShare()
		if err != nil {
			logger.Error("failed-to-compute-default-cpu-entitlement-per-share", err)
			return nil, err
		}
	}

	containerizer, peaCleaner, err := cmd.wireContainerizer(logger, factory, propManager, volumizer, cpuEntitlementPerShare, networkDepot, metricsProvider, backends)
	if err != nil {
		logger.Error("failed-to-wire-containerizer", err)
		return nil, err
	}

	return &commandWiring{
		Containerizer:                   containerizer,
		Networker:                       networker,
		PortPool:                        portPool,
		Restorer:                        restorer,
		Volumizer:                       volumizer,
		Starter:                         bulkStarter,
		PeaCleaner:                      peaCleaner,
		PropertiesManager:               propManager,
		UidGenerator:                    wireUIDGenerator(),
		SysInfoProvider:                 sysInfoProvider,
		Logger:                          logger,
		CpuEntitlementPerShare:          cpuEntitlementPerShare,
		ContainerNetworkMetricsProvider: factory.WireContainerNetworkMetricsProvider(containerizer, propManager),
		Backends:                        backends.registry,
	}, nil
}

func (cmd *CommonCommand) wirePeaCleaner(factory GardenFactory, volumizer gardener.Volumizer, runtime rundmc.OCIRuntime, pidGetter peas.ProcessPidGetter, imageBackedPeas peas.ImageBackedPeas) gardener.PeaCleaner {
	if cmd.Containerd.UseContainerdForProcesses {
		nerdDeleter := runcontainerd.NewDeleter(runtime)
		cleaner := peas.NewPeaCleaner(deleter.NewDeleter(runtime, nerdDeleter), volumizer, runtime, pidGetter)
		cleaner.(*peas.PeaCleaner).ImageBackedPeas = imageBackedPeas
		return cleaner
	}

	cmdRunner := factory.CommandRunner()
	runcLogRunner := runrunc.NewLogRunner(cmdRunner, runrunc.LogDir(os.TempDir()).GenerateLogFile)
	runcBinary := goci.RuncBinary{Path: cmd.Runtime.Plugin, Root: cmd.computeRuncRoot()}

	runcStater := runrunc.NewStater(runcLogRunner, runcBinary)
	runcDeleter := runrunc.NewDeleter(runcLogRunner, runcBinary)
	return peas.NewPeaCleaner(deleter.NewDeleter(runcStater, runcDeleter), volumizer, runtime, pidGetter)
}

func (cmd *CommonCommand) loadProperties(logger lager.Logger, propertiesPath string) (*properties.Manager, error) {
	propManager, err := properties.Load(propertiesPath)
	if err != nil {
		logger.Error("failed-to-load-properties", err, lager.Data{"propertiesPath": propertiesPath})
		return &properties.Manager{}, err
	}

	return propManager, nil
}

func (cmd *CommonCommand) saveProperties(logger lager.Logger, propertiesPath string, propManager *properties.Manager) {
	if propertiesPath != "" {
		err := properties.Save(propertiesPath, propManager)
		if err != nil {
			logger.Error("failed-to-save-properties", err, lager.Data{"propertiesPath": propertiesPath})
		}
	}
}

func (cmd *CommonCommand) wirePortPool(logger lager.Logger) (*ports.PortPool, error) {
	portPoolState, err := ports.LoadState(cmd.Network.PortPoolPropertiesPath)
	if err != nil {
		if _, ok := err.(ports.StateFileNotFoundError); ok {
			logger.Info("no-port-pool-state-to-recover-starting-clean")
		} else {
			logger.Error("failed-to-parse-port-pool-properties", err)
		}
	}

	portPool, err := ports.NewPool(
		cmd.Network.PortPoolStart,
		cmd.Network.PortPoolSize,
		portPoolState,
	)
	if err != nil {
		return nil, fmt.Errorf("invalid pool range: %s", err)
	}
	return portPool, nil
}

func (cmd *CommonCommand) wireDepot(bundleSaver depot.BundleSaver, bundleLoader depot.BundleLoader) *depot.DirectoryDepot {
	return depot.New(cmd.Containers.Dir, bundleSaver, bundleLoader)
}

func extractIPs(ipflags []IPFlag) []net.IP {
	ips := make([]net.IP, len(ipflags))
	for i, ipflag := range ipflags {
		ips[i] = ipflag.IP()
	}
	return ips
}

func (cmd *CommonCommand) wireNetworker(log lager.Logger, factory GardenFactory, propManager kawasaki.ConfigStore, portPool *ports.PortPool, networkDepot depot.NetworkDepot, backends *executionBackends) (gardener.Networker, gardener.Starter, error) {
	externalIP, err := defaultExternalIP(cmd.Network.ExternalIP)
	if err != nil {
		return nil, nil, err
	}

	dnsServers := extractIPs(cmd.Network.DNSServers)
	additionalDNSServers := extractIPs(cmd.Network.AdditionalDNSServers)

	if cmd.Network.Plugin.Path() != "" {
		resolvConfigurer := factory.WireResolvConfigurer()
		var networkerOpts []netplugin.Option
		if cmd.Bin.IPTables.Path() != "" {
			networkerOpts = append(networkerOpts, netplugin.WithIPTablesBin(cmd.Bin.IPTables.Path()))
		}
		if gid, ok := backends.tapGroup(); ok {
			networkerOpts = append(networkerOpts, netplugin.WithTapGroup(gid))
		}
		if cmd.runscCell() {
			networkerOpts = append(networkerOpts, netplugin.WithLoopbackRequired())
		}
		externalNetworker := netplugin.New(
			factory.CommandRunner(),
			propManager,
			externalIP,
			dnsServers,
			additionalDNSServers,
			resolvConfigurer,
			cmd.Network.Plugin.Path(),
			cmd.Network.PluginExtraArgs,
			networkDepot,
			networkerOpts...,
		)
		return externalNetworker, externalNetworker, nil
	}

	interfacePrefix := fmt.Sprintf("w%s", cmd.Server.Tag)
	chainPrefix := fmt.Sprintf("w-%s-", cmd.Server.Tag)
	idGenerator := kawasaki.NewSequentialIDGenerator(time.Now().UnixNano())
	locksmith := &locksmithpkg.FileSystem{}

	iptRunner := &logging.Runner{CommandRunner: factory.CommandRunner(), Logger: log.Session("iptables-runner")}
	ipTables := iptables.New(cmd.Bin.IPTables.Path(), cmd.Bin.IPTablesRestore.Path(), iptRunner, locksmith, chainPrefix)

	containerMtu := cmd.Network.Mtu
	if containerMtu == 0 {
		containerMtu, err = mtu.MTU(externalIP.String())
		if err != nil {
			return nil, nil, err
		}
	}

	networker := kawasaki.New(
		kawasaki.SpecParserFunc(kawasaki.ParseSpec),
		subnets.NewPool(cmd.Network.Pool.CIDR()),
		kawasaki.NewConfigCreator(idGenerator, interfacePrefix, chainPrefix, externalIP, dnsServers, additionalDNSServers, cmd.Network.AdditionalHostEntries, containerMtu),
		propManager,
		kawasakifactory.NewDefaultConfigurer(ipTables, cmd.Containers.Dir),
		portPool,
		iptables.NewPortForwarder(ipTables),
		iptables.NewFirewallOpener(iptables.NewRuleTranslator(), ipTables),
		networkDepot,
	)

	var denyNetworksList []string
	for _, network := range cmd.Network.DenyNetworks {
		denyNetworksList = append(denyNetworksList, network.String())
	}
	nonLoggingIPTables := iptables.New(cmd.Bin.IPTables.Path(), cmd.Bin.IPTablesRestore.Path(), factory.CommandRunner(), locksmith, chainPrefix)
	ipTablesStarter := iptables.NewStarter(nonLoggingIPTables, cmd.Network.AllowHostAccess, interfacePrefix, denyNetworksList, cmd.Containers.DestroyContainersOnStartup, log)
	return networker, ipTablesStarter, nil
}

func (cmd *CommonCommand) wireImagePlugin(commandRunner commandrunner.CommandRunner, uid, gid int) gardener.Volumizer {
	var unprivilegedCommandCreator imageplugin.CommandCreator = &imageplugin.NotImplementedCommandCreator{
		Err: errors.New("no image_plugin provided"),
	}

	var privilegedCommandCreator imageplugin.CommandCreator = &imageplugin.NotImplementedCommandCreator{
		Err: errors.New("no privileged_image_plugin provided"),
	}

	if cmd.Image.Plugin.Path() != "" {
		unprivilegedCommandCreator = &imageplugin.DefaultCommandCreator{
			BinPath:   cmd.Image.Plugin.Path(),
			ExtraArgs: cmd.Image.PluginExtraArgs,
		}
	}

	if cmd.Image.PrivilegedPlugin.Path() != "" {
		privilegedCommandCreator = &imageplugin.DefaultCommandCreator{
			BinPath:   cmd.Image.PrivilegedPlugin.Path(),
			ExtraArgs: cmd.Image.PrivilegedPluginExtraArgs,
		}
	}

	imagePlugin := &imageplugin.ImagePlugin{
		UnprivilegedCommandCreator: unprivilegedCommandCreator,
		PrivilegedCommandCreator:   privilegedCommandCreator,
		ImageSpecCreator:           imageplugin.NewOCIImageSpecCreator(cmd.Containers.Dir),
		CommandRunner:              commandRunner,
		DefaultRootfs:              cmd.Containers.DefaultRootFS,
	}

	return gardener.NewVolumeProvider(imagePlugin, imagePlugin, commandRunner, uid, gid)
}

func (cmd *CommonCommand) wireContainerizer(
	log lager.Logger,
	factory GardenFactory,
	properties gardener.PropertyManager,
	volumizer gardener.Volumizer,
	cpuEntitlementPerShare float64,
	networkDepot depot.NetworkDepot,
	metricsProvider *metrics.MetricsProvider,
	backends *executionBackends,
) (*rundmc.Containerizer, gardener.PeaCleaner, error) {
	initMount, initPath := initBindMountAndPath(cmd.Bin.Init.Path())

	defaultMounts := append(defaultBindMounts(), initMount)
	privilegedMounts := append(defaultMounts, privilegedMounts()...)
	unprivilegedMounts := append(defaultMounts, unprivilegedMounts()...)

	// TODO centralize knowledge of garden -> runc capability schema translation
	baseProcess := specs.Process{
		Capabilities: &specs.LinuxCapabilities{
			Effective:   unprivilegedMaxCaps,
			Bounding:    unprivilegedMaxCaps,
			Inheritable: unprivilegedMaxCaps,
			Permitted:   unprivilegedMaxCaps,
		},
		Args:        []string{initPath},
		Cwd:         "/",
		ConsoleSize: &specs.Box{},
	}

	baseBundle := goci.Bundle().
		WithNamespaces(PrivilegedContainerNamespaces...).
		WithRootFS(cmd.Containers.DefaultRootFS).
		WithProcess(baseProcess).
		WithRootFSPropagation("private")

	uidMappings, gidMappings := cmd.idMappings()
	unprivilegedBundle := baseBundle.
		WithNamespace(goci.UserNamespace).
		WithUIDMappings(uidMappings...).
		WithGIDMappings(gidMappings...).
		WithMounts(unprivilegedMounts...).
		WithMaskedPaths(defaultMaskedPaths())

	seccomp, err := buildSeccomp()
	if err != nil {
		return nil, nil, err
	}
	unprivilegedBundle.Spec.Linux.Seccomp = seccomp

	if cmd.Containers.NoNewPrivileges {
		unprivilegedBundle = unprivilegedBundle.
			WithNoNewPrivileges().
			WithPingGroupRange()
	}

	if cmd.Containers.ApparmorProfile != "" {
		unprivilegedBundle = unprivilegedBundle.WithApparmorProfile(cmd.Containers.ApparmorProfile)
	}
	privilegedBundle := baseBundle.
		WithMounts(privilegedMounts...).
		WithDevices(getPrivilegedDevices()...).
		WithCapabilities(privilegedMaxCaps...).
		WithDeviceRestrictions(append(
			[]specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}},
			cmd.applyDeviceCgroupRules(allowedDevices)...,
		))

	log.Debug("base-bundles", lager.Data{
		"privileged":   privilegedBundle,
		"unprivileged": unprivilegedBundle,
	})

	cgroupRootPath := cmd.getCgroupRootPath()

	if cmd.Server.Tag != "" {
		cgroupRootPath = fmt.Sprintf("%s-%s", cgroupRootPath, cmd.Server.Tag)
	}

	if cmd.CPUThrottling.Enabled {
		cgroupRootPath = filepath.Join(cgroupRootPath, gardencgroups.GoodCgroupName)
	}

	bundleRules := []rundmc.BundlerRule{
		bundlerules.Base{
			PrivilegedBase:   privilegedBundle,
			UnprivilegedBase: unprivilegedBundle,
		},
		bundlerules.Namespaces{},
		bundlerules.CGroupPath{
			Path: cgroupRootPath,
		},
		wireMounts(log),
		bundlerules.Env{},
		bundlerules.Hostname{},
		bundlerules.Windows{},
		bundlerules.RootFS{},
		bundlerules.Limits{
			CpuQuotaPerShare: cmd.Limits.CPUQuotaPerShare,
			BlockIOWeight:    cmd.Limits.DefaultBlockIOWeight,
			IOMaxReadBps:     cmd.Limits.ContainerIOMaxReadBps,
			IOMaxWriteBps:    cmd.Limits.ContainerIOMaxWriteBps,
			IOMaxReadIOPS:    cmd.Limits.ContainerIOMaxReadIOPS,
			IOMaxWriteIOPS:   cmd.Limits.ContainerIOMaxWriteIOPS,
			DisableSwapLimit: cmd.Limits.DisableSwapLimit,
		},
	}

	bundleRules = append(bundleRules, cmd.wireKernelParams()...)

	// Registered last so that no earlier rule can undo its device and mount
	// additions, and only when a backend other than oci-runc is enabled so
	// that a cell without backend flags builds the same bundles as before.
	if backends.dispatch() {
		bundleRules = append(bundleRules, bundlerules.NewExecutionBackend(cmd.ExecutionBackends.VMArtifactsDir, cmd.ExecutionBackends.VMLaunchBin, backends.kvmGid))
	}

	template := &rundmc.BundleTemplate{Rules: bundleRules}

	bundleSaver := &goci.BundleSaver{}
	bndlLoader := &goci.BndlLoader{}
	depot := cmd.wireDepot(bundleSaver, bndlLoader)

	var processBuilderOpts []processes.Option
	if backends.kvmGid != 0 {
		processBuilderOpts = append(processBuilderOpts, processes.WithKVMGid(backends.kvmGid))
	}
	processBuilder := processes.NewBuilder(wireEnvFunc(), nonRootMaxCaps, processBuilderOpts...)

	cmdRunner := factory.CommandRunner()
	runcLogRunner := runrunc.NewLogRunner(cmdRunner, runrunc.LogDir(os.TempDir()).GenerateLogFile)
	runcRoot := cmd.computeRuncRoot()
	runcBinary := goci.RuncBinary{Path: cmd.Runtime.Plugin, Root: runcRoot}

	pidFileReader := wirePidfileReader()

	var ociRuntime rundmc.OCIRuntime
	var peaCreator *peas.PeaCreator
	var privilegeChecker peas.PrivilegedGetter
	var runtimeStopper rundmc.RuntimeStopper

	userLookupper := users.LookupFunc(users.LookupUser)

	processDepot := execrunner.NewProcessDirDepot(depot)

	// #nosec G115 - the uid/gidmappings lists are capped at maxint32 by idmapper, and should never be negative
	execRunner := factory.WireExecRunner(runcRoot, uint32(uidMappings.Map(0)), uint32(gidMappings.Map(0)), bundleSaver, depot, processDepot)
	wireExecerFunc := func(pidGetter runrunc.PidGetter) *runrunc.Execer {
		return runrunc.NewExecer(depot, processBuilder, factory.WireMkdirer(), userLookupper, execRunner, pidGetter)
	}

	statser := runrunc.NewStatser(runcLogRunner, runcBinary, depot, processDepot)
	bundleManager := runrunc.NewBundleManager(depot, processDepot)

	var peasExecRunner peas.ExecRunner = execRunner
	var peasBundleLoader peas.BundleLoader = depot

	var depotPidGetter PidGetter = &pid.ContainerPidGetter{Depot: depot, PidFileReader: pidFileReader}
	containersPidGetter := depotPidGetter
	peaPidGetter := depotPidGetter
	runtimeStopper = stopper.NewNoopStopper()

	// runtimePolicy tracks the resolved runtime type. It defaults to stock
	// and is set to the actual policy when containerd is active. All
	// downstream decisions (streamer, image-backed peas) branch on this single
	// value instead of re-resolving from the config string.
	runtimePolicy := runcontainerd.StockRuntime
	var imageBackedPeas peas.ImageBackedPeas
	var containerizerOpts []rundmc.Option

	if cmd.useContainerd() {
		var err error
		var peaRunner *runcontainerd.RunContainerPea
		var peaBundleLoader peas.BundleLoader
		var peaHandlesGetter runcontainerd.PeaHandlesGetter

		if !cmd.Containerd.UseContainerdForProcesses {
			peaHandlesGetter = bundleManager
		}

		var nerdPidGetter PidGetter
		var runContainerd *runcontainerd.RunContainerd
		runContainerd, peaRunner, nerdPidGetter, privilegeChecker, peaBundleLoader, runtimePolicy, err = factory.WireContainerd(processBuilder, userLookupper, wireExecerFunc, statser, log, volumizer, peaHandlesGetter, metricsProvider)
		if err != nil {
			return nil, nil, err
		}
		ociRuntime = runContainerd
		peasBundleLoader = peaBundleLoader
		containersPidGetter = nerdPidGetter
		runtimeStopper = runContainerd
		containerizerOpts = append(containerizerOpts, rundmc.WithTaskKiller(runContainerd, retrier.New(retrier.ConstantBackoff(10, 1*time.Second), nil)))
		if lister, ok := factory.(taskPidListerFactory); ok {
			if taskPids := lister.WireTaskPidLister(); taskPids != nil {
				containerizerOpts = append(containerizerOpts, rundmc.WithTaskPidLister(taskPids))
			}
		}

		if cmd.Containerd.UseContainerdForProcesses {
			peaPidGetter = nerdPidGetter
			peasExecRunner = peaRunner
		}
		if runtimePolicy.IsAlternative() {
			imageBackedPeas = runContainerd
			// The cgroup stopper reads runc state, which runsc does not write.
			containerizerOpts = append(containerizerOpts, rundmc.WithTaskStop())
		}

	} else {
		oomWatcher := runrunc.NewOomWatcher(cmdRunner, runcBinary)
		runcStater := runrunc.NewStater(runcLogRunner, runcBinary)
		containerRuntimeDeleter := runrunc.NewDeleter(runcLogRunner, runcBinary)
		containerDeleter := deleter.NewDeleter(runcStater, containerRuntimeDeleter)
		ociRuntime = runrunc.New(
			runrunc.NewCreator(runcBinary, cmd.Runtime.PluginExtraArgs, cmdRunner, oomWatcher, depot),
			wireExecerFunc(depotPidGetter),
			oomWatcher,
			statser,
			runcStater,
			containerDeleter,
			bundleManager,
		)
		privilegeChecker = &runcprivchecker.PrivilegeChecker{BundleLoader: depot, Log: log}
	}

	log.Info("runtime-policy-resolved", lager.Data{
		"policy":       runtimePolicy.String(),
		"containerd":   cmd.useContainerd(),
		"runtime_type": cmd.Containerd.RuntimeType,
	})

	eventStore := rundmc.NewEventStore(properties)
	stateStore := rundmc.NewStateStore(properties)

	peaCleaner := cmd.wirePeaCleaner(factory, volumizer, ociRuntime, peaPidGetter, imageBackedPeas)
	peaCreator = &peas.PeaCreator{
		Volumizer:        volumizer,
		PidGetter:        containersPidGetter,
		PrivilegedGetter: privilegeChecker,
		NetworkDepot:     networkDepot,
		BundleGenerator:  template,
		ProcessBuilder:   processBuilder,
		BundleSaver:      bundleSaver,
		ExecRunner:       peasExecRunner,
		PeaCleaner:       peaCleaner,
		GroupedRunsc:     runtimePolicy.IsAlternative(),
	}

	peaUsernameResolver := &peas.PeaUsernameResolver{
		PidGetter:     peaPidGetter,
		PeaCreator:    peaCreator,
		BundleLoader:  peasBundleLoader,
		UserLookupper: users.LookupFunc(users.LookupUser),
	}

	nstar := rundmc.NewNstarRunner(cmd.Bin.NSTar.Path(), cmd.Bin.Tar.Path(), cmdRunner)
	processesStopper := stopper.New(stopper.NewRuncStateCgroupPathResolver(runcRoot), nil, retrier.New(retrier.ConstantBackoff(10, 1*time.Second), nil))

	cpuCgrouper, err := factory.WireCPUCgrouper()
	if err != nil {
		return nil, nil, err
	}

	var streamer rundmc.Streamer
	if runtimePolicy.IsAlternative() {
		streamer = rundmc.NewExecStreamer(ociRuntime)
	} else {
		streamer = rundmc.NewNstarStreamer(ociRuntime, nstar)
	}

	containerizerOpts = append(containerizerOpts, backends.containerizerOptions(ociRuntime)...)

	containerizer := rundmc.New(depot, template, ociRuntime, streamer, processesStopper, eventStore, stateStore, peaCreator, peaUsernameResolver, cpuEntitlementPerShare, runtimeStopper, cpuCgrouper, runtimePolicy.IsAlternative(), containerizerOpts...)
	return containerizer, peaCleaner, nil
}

// executionBackends is the outcome of validating the execution backend flags.
type executionBackends struct {
	// registry holds the enabled backends. It is nil when none beyond oci-runc
	// is enabled, which keeps the Gardener on its runc-only behaviour.
	registry *backend.Registry

	// kvmGid is the host gid to add to vm-launch processes, or 0 when no vm-*
	// backend is enabled.
	kvmGid uint32
}

// taskPidListerFactory is implemented by factories that can list the processes
// of a containerd task. WireTaskPidLister returns nil until WireContainerd has
// run.
type taskPidListerFactory interface {
	WireTaskPidLister() rundmc.TaskPidLister
}

// dispatch reports whether any backend other than oci-runc is enabled. Only
// then do the containerizer and the containerd runtime look up a container's
// backend; otherwise both keep their stock code paths.
func (b *executionBackends) dispatch() bool {
	return b != nil && b.registry != nil
}

// containerizerOptions returns the Containerizer options the enabled backends
// need. gVisor containers stream files through runtime exec.
func (b *executionBackends) containerizerOptions(runtime rundmc.OCIRuntime) []rundmc.Option {
	if !b.dispatch() {
		return nil
	}
	return []rundmc.Option{rundmc.WithBackendDispatch(rundmc.NewExecStreamer(runtime))}
}

// runContainerdOptions returns the RunContainerd options the enabled backends
// need. It must enable dispatch exactly when containerizerOptions does, so
// that a gVisor container streams, executes, and reports metrics through
// containerd on both layers. gVisor metrics come from gvisorStatser.
func (b *executionBackends) runContainerdOptions(gvisorStatser runcontainerd.Statser) []runcontainerd.Option {
	if !b.dispatch() {
		return nil
	}
	return []runcontainerd.Option{runcontainerd.WithBackendDispatch(gvisorStatser)}
}

// tapGroup returns the gid that owns the tap device of a vm-firecracker
// container, which is the kvm gid that vm-launch carries. It reports false when
// vm-firecracker is not enabled.
func (b *executionBackends) tapGroup() (uint32, bool) {
	if !b.dispatch() || !b.registry.Allowed(backend.VMFirecracker) || b.kvmGid == 0 {
		return 0, false
	}
	return b.kvmGid, true
}

// lookupKVMGroup resolves the host group that owns /dev/kvm. Tests replace it.
var lookupKVMGroup = user.LookupGroup

// kvmGroupName is the host group that owns /dev/kvm.
const kvmGroupName = "kvm"

// wireExecutionBackends validates the execution backend flags and builds the
// backend registry from them. It returns an error, which stops gdn, when a
// backend name is unknown, when a backend is enabled on a cell whose
// containerd runtime type is runsc, when oci-gvisor is enabled without
// containerd, or when a vm-* backend is enabled and the vm-launch binary is
// not executable.
// A vm-* backend whose kvm gid cannot be determined is left out of the
// registry and logged, and gdn keeps serving the remaining backends. The
// artifacts directory is not inspected, because a missing artifact fails the
// container create instead.
func (cmd *CommonCommand) wireExecutionBackends(log lager.Logger) (*executionBackends, error) {
	log = log.Session("execution-backends")

	kinds := make([]backend.Kind, 0, len(cmd.ExecutionBackends.Enabled))
	for _, name := range cmd.ExecutionBackends.Enabled {
		kind := backend.Kind(name)
		if !backend.IsKnown(kind) {
			return nil, fmt.Errorf("%w: %q for --execution-backend", backend.ErrUnknownBackend, name)
		}
		if kind != backend.OCIRunc {
			kinds = append(kinds, kind)
		}
	}

	if len(kinds) == 0 {
		return &executionBackends{}, nil
	}

	// A runsc cell already runs every container under gVisor with its own
	// streaming, metrics, and pea paths, so per-container selection on top of
	// it is not supported.
	if cmd.runscCell() {
		return nil, fmt.Errorf("--execution-backend cannot be combined with --containerd-runtime-type %s", cmd.Containerd.RuntimeType)
	}

	vmEnabled := false
	for _, kind := range kinds {
		if backend.IsGvisor(kind) && !cmd.useContainerd() {
			return nil, fmt.Errorf("--execution-backend %s requires --containerd-socket: without containerd the container would run under runc instead of gVisor", kind)
		}
		if backend.IsVM(kind) {
			vmEnabled = true
		}
	}

	var kvmGid uint32
	if vmEnabled {
		if err := checkExecutable(cmd.ExecutionBackends.VMLaunchBin); err != nil {
			return nil, fmt.Errorf("--vm-launch-bin is required to be an executable file when a vm-* backend is enabled: %w", err)
		}

		var err error
		kvmGid, err = cmd.resolveKVMGid()
		if err != nil {
			log.Error("kvm-gid-unresolved-disabling-vm-backends", err)
			kinds = withoutVMBackends(kinds)
			kvmGid = 0
		}
	}

	if len(kinds) == 0 {
		return &executionBackends{}, nil
	}

	registry, err := backend.NewRegistry(kinds...)
	if err != nil {
		return nil, err
	}

	log.Info("enabled", lager.Data{"backends": kinds, "kvm-gid": kvmGid})

	return &executionBackends{registry: registry, kvmGid: kvmGid}, nil
}

func (cmd *CommonCommand) resolveKVMGid() (uint32, error) {
	if cmd.ExecutionBackends.VMKVMGid != 0 {
		return cmd.ExecutionBackends.VMKVMGid, nil
	}

	group, err := lookupKVMGroup(kvmGroupName)
	if err != nil {
		return 0, fmt.Errorf("--vm-kvm-gid not set and host group %q not found: %w", kvmGroupName, err)
	}

	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("host group %q has gid %q: %w", kvmGroupName, group.Gid, err)
	}
	if gid == 0 {
		return 0, fmt.Errorf("host group %q has gid 0, refusing to grant root group to vm-launch", kvmGroupName)
	}

	// #nosec G115 - ParseUint above bounds the value to 32 bits
	return uint32(gid), nil
}

func withoutVMBackends(kinds []backend.Kind) []backend.Kind {
	kept := make([]backend.Kind, 0, len(kinds))
	for _, kind := range kinds {
		if !backend.IsVM(kind) {
			kept = append(kept, kind)
		}
	}
	return kept
}

func checkExecutable(path string) error {
	if path == "" {
		return errors.New("no path given")
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}

	return nil
}

// runscCell reports whether containerd runs every container of the cell
// under runsc. An invalid runtime type reports false here and fails
// WireContainerd instead.
func (cmd *CommonCommand) runscCell() bool {
	if !cmd.useContainerd() {
		return false
	}
	policy, err := runcontainerd.ResolveRuntimePolicy(cmd.Containerd.RuntimeType)
	return err == nil && policy.IsAlternative()
}

func (cmd *CommonCommand) useContainerd() bool {
	return cmd.Containerd.Socket != ""
}

func wirePidfileReader() *pid.FileReader {
	return &pid.FileReader{
		Clock:         clock.NewClock(),
		Timeout:       10 * time.Second,
		SleepInterval: time.Millisecond * 100,
	}
}

func (cmd *CommonCommand) wireMetricsProvider(log lager.Logger) *metrics.MetricsProvider {
	return metrics.NewMetricsProvider(log, cmd.Containers.Dir)
}

func (cmd *CommonCommand) wireMetronNotifier(log lager.Logger, metricsProvider metrics.Metrics) *metrics.PeriodicMetronNotifier {
	return metrics.NewPeriodicMetronNotifier(
		log, metricsProvider, cmd.Metrics.EmissionInterval, clock.NewClock(),
	)
}

func (cmd *CommonCommand) idMappings() (idmapper.MappingList, idmapper.MappingList) {
	containerRootUID := mustGetMaxValidUID()
	containerRootGID := mustGetMaxValidUID()

	cmd.calculateDefaultMappingLengths(containerRootUID, containerRootGID)

	uidMappings := idmapper.MappingList{
		{
			ContainerID: 0,
			// #nosec G115 - containerRootUID uses idmapper's logic which caps the Uid at MaxInt32, and should not be negative.
			HostID: uint32(containerRootUID),
			Size:   1,
		},
		{
			ContainerID: 1,
			HostID:      cmd.Containers.UIDMapStart,
			Size:        cmd.Containers.UIDMapLength,
		},
	}
	gidMappings := idmapper.MappingList{
		{
			ContainerID: 0,
			// #nosec G115 - containerRootGID uses idmapper's logic which caps the Gid at MaxInt32, and should not be negative.
			HostID: uint32(containerRootGID),
			Size:   1,
		},
		{
			ContainerID: 1,
			HostID:      cmd.Containers.GIDMapStart,
			Size:        cmd.Containers.GIDMapLength,
		},
	}
	return uidMappings, gidMappings
}

func (cmd *CommonCommand) calculateDefaultMappingLengths(containerRootUID, containerRootGID int) {
	if cmd.Containers.UIDMapLength == 0 {
		// #nosec G115 - containerRootUID uses idmapper's logic which caps the Uid at MaxInt32, and should not be negative.
		cmd.Containers.UIDMapLength = uint32(containerRootUID) - cmd.Containers.UIDMapStart
	}

	if cmd.Containers.GIDMapLength == 0 {
		// #nosec G115 - containerRootUID uses idmapper's logic which caps the Uid at MaxInt32, and should not be negative.
		cmd.Containers.GIDMapLength = uint32(containerRootGID) - cmd.Containers.GIDMapStart
	}
}

func (cmd *CommonCommand) applyDeviceCgroupRules(defaultCgroupRules []specs.LinuxDeviceCgroup) []specs.LinuxDeviceCgroup {
	if len(cmd.Containers.DeviceCgroupRules) == 0 {
		return defaultCgroupRules
	}

	cgroupRules := []specs.LinuxDeviceCgroup{}
	for _, newCgroupRule := range cmd.Containers.DeviceCgroupRules {
		cgroupRules = append(cgroupRules, newCgroupRule.LinuxDeviceCgroup())
	}

	// Add default cgroup rules that don't match provided rules
	for _, defaultCgroupRule := range defaultCgroupRules {
		if !findMatchingCgroup(defaultCgroupRule, cmd.Containers.DeviceCgroupRules) {
			cgroupRules = append(cgroupRules, defaultCgroupRule)
		}
	}

	return cgroupRules
}

func wireUIDGenerator() gardener.UidGeneratorFunc {
	return gardener.UidGeneratorFunc(func() string { return mustStringify(uuid.NewV4()) })
}

func wireBindMountSourceCreator(uidMappings, gidMappings idmapper.MappingList) depot.BindMountSourceCreator {
	return &depot.DepotBindMountSourceCreator{
		BindMountPoints:      bindMountPoints(),
		Chowner:              &depot.OSChowner{},
		ContainerRootHostUID: uidMappings.Map(0),
		ContainerRootHostGID: gidMappings.Map(0),
	}
}

func defaultExternalIP(ip IPFlag) (net.IP, error) {
	if ip != nil {
		return ip.IP(), nil
	}

	localIP, err := localip.LocalIP()
	if err != nil {
		return nil, fmt.Errorf("Couldn't determine local IP to use for --external-ip parameter. You can use the --external-ip flag to pass an external IP explicitly.")
	}

	return net.ParseIP(localIP), nil
}

func defaultMaskedPaths() []string {
	return []string{
		"/proc/kcore",
		"/proc/latency_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/keys",
		"/sys/firmware",
	}
}

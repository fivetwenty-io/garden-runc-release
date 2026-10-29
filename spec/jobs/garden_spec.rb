require 'rspec'
require 'json'
require 'bosh/template/test'
require 'yaml'
require 'iniparse'
require 'ipaddr'

describe 'garden' do
  let(:release) { Bosh::Template::Test::ReleaseDir.new(File.join(File.dirname(__FILE__), '../..')) }
  let(:job) { release.job('garden') }
  let(:template) { job.template('config/config.ini') }
  let(:properties) {{}}

  describe 'alternative runtime configuration' do
    def render_runtime(properties)
      IniParse.parse(template.render({'garden' => properties}))['server']
    end

    it 'keeps stock runtime and process backend defaults' do
      server = render_runtime({})
      expect(server['containerd-socket']).to eql('/var/vcap/sys/run/containerd/containerd.sock')
      expect(server['containerd-runtime-type']).to be_nil
      expect(server['use-containerd-for-processes']).to be_nil
    end

    it 'renders an explicitly selected runtime without changing the process backend' do
      server = render_runtime({'containerd_runtime_type' => 'io.containerd.runsc.v1'})
      expect(server['containerd-runtime-type']).to eql('io.containerd.runsc.v1')
      expect(server['use-containerd-for-processes']).to be_nil
    end

    it 'renders an explicitly enabled process backend without selecting runsc' do
      server = render_runtime({'use_containerd_for_processes' => true})
      expect(server['containerd-runtime-type']).to be_nil
      expect(server['use-containerd-for-processes']).to eql(true)
    end

    it 'renders the complete explicit runsc opt-in' do
      server = render_runtime({'containerd_runtime_type' => 'io.containerd.runsc.v1', 'use_containerd_for_processes' => true})
      expect(server['containerd-runtime-type']).to eql('io.containerd.runsc.v1')
      expect(server['use-containerd-for-processes']).to eql(true)
      expect(server['containerd-socket']).to eql('/var/vcap/sys/run/containerd/containerd.sock')
    end

    it 'raises when a runtime type is selected with the backend disabled' do
      expect { render_runtime({'containerd_mode' => false, 'containerd_runtime_type' => 'io.containerd.runsc.v1'}) }.to raise_error(/require garden.containerd_mode/)
    end

    it 'raises when the process backend is enabled with the backend disabled' do
      expect { render_runtime({'containerd_mode' => false, 'use_containerd_for_processes' => true}) }.to raise_error(/require garden.containerd_mode/)
    end

    it 'omits containerd settings when the backend is disabled' do
      server = render_runtime({'containerd_mode' => false})
      expect(server['containerd-socket']).to be_nil
      expect(server['containerd-runtime-type']).to be_nil
      expect(server['use-containerd-for-processes']).to be_nil
    end
  end

  context 'config/config.ini' do
    context 'with defaults' do
      let(:rendered_template) { IniParse.parse(template.render(properties)) }

      it 'binds to a socket' do
        expect(rendered_template['server']['bind-socket']).to eql('/var/vcap/data/garden/garden.sock')
      end

      it 'sets the ip tables bin dir' do
        expect(rendered_template['server']['iptables-bin']).to eql('/sbin/iptables')
      end

      it 'sets the ip tables restore bin dir' do
        expect(rendered_template['server']['iptables-restore-bin']).to eql('/sbin/iptables-restore')
      end

      it 'sets the init bin dir' do
        expect(rendered_template['server']['init-bin']).to eql('/var/vcap/data/garden/bin/init')
      end

      it 'sets the default grace time' do
        expect(rendered_template['server']['default-grace-time']).to eql(0)
      end

      it 'sets the image-plugin' do
        expect(rendered_template['server']['image-plugin']).to eql('/var/vcap/packages/grootfs/bin/grootfs')
      end

      it 'sets the image-plugin-extra-arg' do
        expect(rendered_template['server']['image-plugin-extra-arg']).to eql(['"--config"', '/var/vcap/jobs/garden/config/grootfs_config.yml'])
      end

      it 'sets the privileged-image-plugin' do
        expect(rendered_template['server']['privileged-image-plugin']).to eql('/var/vcap/packages/grootfs/bin/grootfs')
      end

      it 'sets the privileged-image-plugin-extra-arg extra arg' do
        expect(rendered_template['server']['privileged-image-plugin-extra-arg']).to eql(['"--config"', '/var/vcap/jobs/garden/config/privileged_grootfs_config.yml'])
      end

      it 'sets the mtu to 0' do
        expect(rendered_template['server']['mtu']).to eql(0)
      end

      it 'sets the apparmor to garden-default' do
        expect(rendered_template['server']['apparmor']).to eql('garden-default')
      end

      it 'sets the log level to info' do
        expect(rendered_template['server']['log-level']).to eql('info')
      end

      it 'sets the default grace time to 0' do
        expect(rendered_template['server']['default-grace-time']).to eql(0)
      end

      it 'sets the default container blockio weight to 0' do
        expect(rendered_template['server']['default-container-blockio-weight']).to eql(0)
      end

      it 'does not render io-max properties when defaults are 0' do
        expect(rendered_template['server']['container-io-max-read-bps']).to eql(nil)
        expect(rendered_template['server']['container-io-max-write-bps']).to eql(nil)
        expect(rendered_template['server']['container-io-max-read-iops']).to eql(nil)
        expect(rendered_template['server']['container-io-max-write-iops']).to eql(nil)
      end

      it 'sets the default container rootfs to busybox' do
        expect(rendered_template['server']['default-rootfs']).to eq('/var/vcap/packages/busybox/busybox-1.37.0.tar')
      end

      it 'sets the runtime plugin to 0' do
        expect(rendered_template['server']['runtime-plugin']).to eql('/var/vcap/packages/runc/bin/runc')
      end

      it 'sets the read header timeout to 30s' do
        expect(rendered_template['server']['read-header-timeout']).to eql('30s')
      end

      it 'sets the max containers to 250' do
        expect(rendered_template['server']['max-containers']).to eql(250)
      end

      it 'sets the cpu quota per share to 0' do
        expect(rendered_template['server']['cpu-quota-per-share']).to eql(0)
      end

      it 'sets the experimental cpu entitlement per share in percent per share to 0' do
        expect(rendered_template['server']['cpu-entitlement-per-share']).to eql(0)
      end

      it 'sets the default device cgroup rules' do
        expect(rendered_template['server']['device-cgroup-rule']).to eql(['"b 7:* rwm"', '"c 10:237 rwm"'])
      end

      context 'cpu throttling' do
        context 'by default' do
          it 'sets the enable cpu throttling per share to false' do
            expect(rendered_template['server']['enable-cpu-throttling']).to eql(false)
          end

          it 'sets the experimental cpu throttling check interval to 15' do
            expect(rendered_template['server']['cpu-throttling-check-interval']).to eql(15)
          end
        end

        context 'when only experimental values are set' do
          let(:properties) {
            {
              'garden' => {
                'experimental_cpu_throttling' => ex_cpu_th,
                'experimental_cpu_throttling_check_interval' => ex_cpu_th_int
              }
            }
          }
          let(:ex_cpu_th) { true }
          let(:ex_cpu_th_int) { 20 }

          it 'uses the experimental values' do
            expect(rendered_template['server']['enable-cpu-throttling']).to eql(ex_cpu_th)
            expect(rendered_template['server']['cpu-throttling-check-interval']).to eql(ex_cpu_th_int)
          end
          context 'when the experimental interval value is invalid' do
            let(:ex_cpu_th_int) { 0 }
            it 'errors' do
              error_msg = 'garden.experimental_cpu_throttling_check_interval should be a positive integer'
              expect { rendered_template }.to raise_error(error_msg)
            end
          end
        end

        context 'when experimental and non-experimental values are set' do
          let(:properties) {
            {
              'garden' => {
                'experimental_cpu_throttling' => ex_cpu_th,
                'experimental_cpu_throttling_check_interval' => ex_cpu_th_int,
                'cpu_throttling' => cpu_th,
                'cpu_throttling_check_interval' => cpu_th_int
              }
            }
          }
          let(:ex_cpu_th) { true }
          let(:ex_cpu_th_int) { 20 }
          let(:cpu_th) { false }
          let(:cpu_th_int) { 30 }

          it 'uses the non-experimental values' do
            expect(rendered_template['server']['enable-cpu-throttling']).to eql(cpu_th)
            expect(rendered_template['server']['cpu-throttling-check-interval']).to eql(cpu_th_int)
          end

          context 'when the experimental interval value is invalid' do
            let(:ex_cpu_th_int) { 0 }
            it 'does not error' do
              expect { rendered_template }.to_not raise_error
            end
          end

          context 'when the non-experimental interval value is invalid' do
            let(:cpu_th_int) { 0 }
            it 'errors' do
              error_msg = 'garden.cpu_throttling_check_interval should be a positive integer'
              expect { rendered_template }.to raise_error(error_msg)
            end
          end
        end

        context 'when only non-experimental values are set' do
          let(:properties) {
            {
              'garden' => {
                'cpu_throttling' => cpu_th,
                'cpu_throttling_check_interval' => cpu_th_int
              }
            }
          }
          let(:cpu_th) { false }
          let(:cpu_th_int) { 30 }

          it 'uses the non-experimental values' do
            expect(rendered_template['server']['enable-cpu-throttling']).to eql(cpu_th)
            expect(rendered_template['server']['cpu-throttling-check-interval']).to eql(cpu_th_int)
          end

          context 'when the non-experimental interval value is invalid' do
            let(:cpu_th_int) { 0 }
            it 'errors' do
              error_msg = 'garden.cpu_throttling_check_interval should be a positive integer'
              expect { rendered_template }.to raise_error(error_msg)
            end
          end
        end
      end

      context 'container io.max throttling' do
        context 'when all io_max properties are set' do
          let(:properties) {
            {
              'garden' => {
                'container_io_max_read_bps' => 59768832,
                'container_io_max_write_bps' => 59768832,
                'container_io_max_read_iops' => 900,
                'container_io_max_write_iops' => 900
              }
            }
          }

          it 'renders container-io-max-read-bps' do
            expect(rendered_template['server']['container-io-max-read-bps']).to eql(59768832)
          end

          it 'renders container-io-max-write-bps' do
            expect(rendered_template['server']['container-io-max-write-bps']).to eql(59768832)
          end

          it 'renders container-io-max-read-iops' do
            expect(rendered_template['server']['container-io-max-read-iops']).to eql(900)
          end

          it 'renders container-io-max-write-iops' do
            expect(rendered_template['server']['container-io-max-write-iops']).to eql(900)
          end
        end

        context 'when only bps properties are set' do
          let(:properties) {
            {
              'garden' => {
                'container_io_max_read_bps' => 104857600,
                'container_io_max_write_bps' => 52428800
              }
            }
          }

          it 'renders bps values' do
            expect(rendered_template['server']['container-io-max-read-bps']).to eql(104857600)
            expect(rendered_template['server']['container-io-max-write-bps']).to eql(52428800)
          end

          it 'renders iops as 0' do
            expect(rendered_template['server']['container-io-max-read-iops']).to eql(0)
            expect(rendered_template['server']['container-io-max-write-iops']).to eql(0)
          end
        end
      end

      it 'sets the network-pool to 10.254.0.0/22' do
        expect(rendered_template['server']['network-pool']).to eql('10.254.0.0/22')
      end

      it 'sets the properties-path' do
        expect(rendered_template['server']['properties-path']).to eql('/var/vcap/data/garden/props.json')
      end

      it 'sets the port-pool-properties-path' do
        expect(rendered_template['server']['port-pool-properties-path']).to eql('/var/vcap/data/garden/port-pool-props.json')
      end

      it 'does not enable the container network metrics' do
        expect(rendered_template['server']['enable-container-network-metrics']).to eql(nil)
      end

      context 'when container network metrics are enabled' do
        let(:properties) {
          {
            'garden' => {
              'enable_container_network_metrics' => true,
            }
          }
        }

        it 'sets the enable container network metrics to true' do
          expect(rendered_template['server']['enable-container-network-metrics']).to eql(true)
        end
      end
    end

    context 'with a listen address' do
      it 'switches to a listen address and port' do
        properties.merge!(
          'garden' => {
            'listen_network' => 'tcp',
            'listen_address' => '127.0.0.1:5555'
          }
        )
        rendered_template = IniParse.parse(template.render(properties))
        expect(rendered_template['server']['bind-ip']).to eql('127.0.0.1')
        expect(rendered_template['server']['bind-port']).to eql(5555)
      end

      # it 'throws an exception if the ip is invalid' do
      #   properties.merge!({
      #     'garden' => {
      #       'listen_network' => 'tcp',
      #       'listen_address' => '0.0.0.1:5555'
      #     }
      #   })
        
      #   expect {template.render(properties)}.to raise_error(IPAddr::InvalidAddressError)
      # end
    end

    context 'execution backends' do
      let(:garden_properties) { {} }
      let(:properties) { { 'garden' => garden_properties } }
      let(:raw_template) { template.render(properties) }
      let(:server) { IniParse.parse(raw_template)['server'] }
      let(:vm_keys) { %w[execution-backend vm-artifacts-dir vm-launch-bin vm-kvm-gid gvisor-runtime-config] }

      context 'by default' do
        it 'renders none of the execution backend keys' do
          vm_keys.each do |key|
            expect(server[key]).to be_nil, "expected #{key} to be absent"
          end
          expect(raw_template).not_to include('execution backends')
          expect(raw_template).not_to include('vm-')
        end
      end

      context 'when the list is explicitly empty' do
        let(:garden_properties) { { 'execution_backends' => [] } }

        it 'renders none of the execution backend keys' do
          vm_keys.each do |key|
            expect(server[key]).to be_nil, "expected #{key} to be absent"
          end
        end

        it 'renders the same as when the property is unset' do
          expect(raw_template).to eql(template.render({ 'garden' => {} }))
        end
      end

      context 'when vm backends are listed' do
        let(:garden_properties) { { 'execution_backends' => %w[vm-qemu vm-firecracker] } }

        it 'renders one execution-backend key per entry' do
          expect(server['execution-backend']).to eql(%w[vm-qemu vm-firecracker])
        end

        it 'renders the default artifacts dir' do
          expect(server['vm-artifacts-dir']).to eql('/var/vcap/data/vm-runtime/artifacts')
        end

        it 'renders the packaged vm-launch binary' do
          expect(server['vm-launch-bin']).to eql('/var/vcap/packages/guardian/bin/vm-launch')
        end

        it 'leaves the kvm gid and gvisor runtime config to the gdn defaults' do
          expect(server['vm-kvm-gid']).to be_nil
          expect(server['gvisor-runtime-config']).to be_nil
        end

        context 'with a custom artifacts dir' do
          let(:garden_properties) { { 'execution_backends' => ['vm-qemu'], 'vm_artifacts_dir' => '/var/vcap/store/vm/artifacts' } }

          it 'renders the custom artifacts dir' do
            expect(server['vm-artifacts-dir']).to eql('/var/vcap/store/vm/artifacts')
          end
        end

        context 'with a relative artifacts dir' do
          let(:garden_properties) { { 'execution_backends' => ['vm-qemu'], 'vm_artifacts_dir' => 'artifacts' } }

          it 'raises' do
            expect { raw_template }.to raise_error(/vm_artifacts_dir must be an absolute path/)
          end
        end
      end

      context 'when a single vm backend is listed' do
        let(:garden_properties) { { 'execution_backends' => ['vm-firecracker'] } }

        it 'renders a single execution-backend value' do
          expect(server['execution-backend']).to eql('vm-firecracker')
          expect(server['vm-launch-bin']).to eql('/var/vcap/packages/guardian/bin/vm-launch')
        end
      end

      context 'when only oci-gvisor is listed' do
        let(:garden_properties) { { 'execution_backends' => ['oci-gvisor'] } }

        it 'renders the execution-backend key' do
          expect(server['execution-backend']).to eql('oci-gvisor')
        end

        it 'does not render the vm-only keys' do
          expect(server['vm-artifacts-dir']).to be_nil
          expect(server['vm-launch-bin']).to be_nil
        end

        it 'keeps the containerd socket that oci-gvisor needs' do
          expect(server['containerd-socket']).to eql('/var/vcap/sys/run/containerd/containerd.sock')
        end

        context 'when containerd mode is off' do
          let(:garden_properties) { { 'execution_backends' => ['oci-gvisor'], 'containerd_mode' => false } }

          it 'raises' do
            expect { raw_template }.to raise_error(/requires garden.containerd_mode/)
          end
        end
      end

      context 'when all backends are listed' do
        let(:garden_properties) { { 'execution_backends' => %w[oci-gvisor vm-qemu vm-firecracker] } }

        it 'renders every backend and the vm keys' do
          expect(server['execution-backend']).to eql(%w[oci-gvisor vm-qemu vm-firecracker])
          expect(server['vm-artifacts-dir']).to eql('/var/vcap/data/vm-runtime/artifacts')
          expect(server['vm-launch-bin']).to eql('/var/vcap/packages/guardian/bin/vm-launch')
        end
      end

      context 'when an entry is repeated' do
        let(:garden_properties) { { 'execution_backends' => %w[vm-qemu vm-qemu] } }

        it 'renders it once' do
          expect(server['execution-backend']).to eql('vm-qemu')
        end
      end

      context 'when vm backends are listed with containerd mode off' do
        let(:garden_properties) { { 'execution_backends' => ['vm-qemu'], 'containerd_mode' => false } }

        it 'renders (the vm backends do not need containerd)' do
          expect(server['execution-backend']).to eql('vm-qemu')
          expect(server['containerd-socket']).to be_nil
        end
      end

      context 'when an unknown backend is listed' do
        let(:garden_properties) { { 'execution_backends' => %w[vm-qemu vm-bochs] } }

        it 'raises naming the entry and the allowed set' do
          expect { raw_template }.to raise_error(/Invalid garden.execution_backends entry "vm-bochs".*oci-gvisor, vm-qemu, vm-firecracker/)
        end
      end

      context 'when oci-runc is listed' do
        let(:garden_properties) { { 'execution_backends' => ['oci-runc'] } }

        it 'raises because oci-runc is implicit' do
          expect { raw_template }.to raise_error(/must not list 'oci-runc'/)
        end
      end

      context 'when the property is not a list' do
        let(:garden_properties) { { 'execution_backends' => 'vm-qemu' } }

        it 'raises' do
          expect { raw_template }.to raise_error(/must be a list/)
        end
      end

      context 'when the cell runs every container under runsc' do
        let(:garden_properties) { { 'execution_backends' => ['oci-gvisor'], 'containerd_runtime_type' => 'io.containerd.runsc.v1' } }

        it 'raises' do
          expect { raw_template }.to raise_error(/cannot be combined with garden.containerd_runtime_type "io.containerd.runsc.v1"/)
        end
      end

      context 'when the cell names the stock runc runtime' do
        let(:garden_properties) { { 'execution_backends' => ['oci-gvisor'], 'containerd_runtime_type' => 'io.containerd.runc.v2' } }

        it 'renders the backends' do
          expect(server['execution-backend']).to eql('oci-gvisor')
          expect(server['containerd-runtime-type']).to eql('io.containerd.runc.v2')
        end
      end
    end
  end

  context 'bin/grootfs-utils' do
    let(:template) { job.template('bin/grootfs-utils') }

    context 'with defaults' do
      let(:rendered_template) { template.render(properties) }

      it 'passes the default reserved_space_for_other_jobs_in_mb to thresholder' do
        expect(rendered_template).to include('/var/vcap/packages/thresholder/bin/thresholder "15360"')
      end

      it 'passes routine_gc as false' do
        expect(rendered_template).to match(/thresholder "15360" "false"/)
      end

      it 'passes the default gc_threshold_factor of 1.0' do
        expect(rendered_template).to match(/"-1" "1.0"$/)
      end

      it 'invokes thresholder for both unprivileged and privileged configs' do
        expect(rendered_template).to include('$GARDEN_CONFIG_DIR/grootfs_config.yml')
        expect(rendered_template).to include('$GARDEN_CONFIG_DIR/privileged_grootfs_config.yml')
      end
    end

    context 'when grootfs.gc_threshold_factor is set' do
      let(:properties) do
        {
          'grootfs' => {
            'gc_threshold_factor' => 0.5
          }
        }
      end

      let(:rendered_template) { template.render(properties) }

      it 'passes the configured factor to thresholder' do
        expect(rendered_template).to match(/"-1" "0.5"$/)
      end
    end

    context 'when grootfs.routine_gc is true' do
      let(:properties) do
        {
          'grootfs' => {
            'routine_gc' => true
          }
        }
      end

      let(:rendered_template) { template.render(properties) }

      it 'passes routine_gc as true' do
        expect(rendered_template).to match(/thresholder "15360" "true"/)
      end

      it 'still passes the default gc_threshold_factor' do
        expect(rendered_template).to match(/"-1" "1.0"$/)
      end
    end

    context 'when grootfs.reserved_space_for_other_jobs_in_mb is customized' do
      let(:properties) do
        {
          'grootfs' => {
            'reserved_space_for_other_jobs_in_mb' => 5000,
            'gc_threshold_factor' => 0.75
          }
        }
      end

      let(:rendered_template) { template.render(properties) }

      it 'passes the custom reserved space and factor' do
        expect(rendered_template).to match(/thresholder "5000" "false" "\$DATA_DIR" "\$GARDEN_CONFIG_DIR\/grootfs_config.yml" "-1" "-1" "0.75"/)
      end
    end

    context 'when deprecated garden.graph_cleanup_threshold_in_mb is set' do
      let(:properties) do
        {
          'garden' => {
            'graph_cleanup_threshold_in_mb' => 2000
          }
        }
      end

      let(:rendered_template) { template.render(properties) }

      it 'passes the deprecated threshold alongside the factor' do
        expect(rendered_template).to match(/"2000" "-1" "1.0"$/)
      end
    end
  end
end

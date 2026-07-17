# Copyright 2026 SAP SE
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import io
import ipaddress
import logging
import os
import pathlib
import shutil
import signal
import socket

import netaddr
from neutron_lib.utils import file as file_utils
from oslo_utils import strutils

from neutron._i18n import _
from neutron.agent.linux.dhcp import DhcpLocalProcess
from neutron.agent.linux.dhcp import Dnsmasq
from neutron.agent.linux.dhcp import SIGTERM_TIMEOUT
from neutron.agent.linux import external_process
from neutron.common import utils as common_utils

LOG = logging.getLogger(__name__)


class FixedProcessManager(external_process.ProcessManager):

    def disable(self, sig='9', get_stop_command=None, delete_pid_file=True):
        # TODO(mutax): this is a bug upstream and needs fixing:
        #               see https://bugs.launchpad.net/neutron/+bug/2163415
        # if get_stop_command is not None, it will always remove the pidfile
        # which totally breaks reloading of unbound, this triggers because we
        # are not sending a signal but using unbound-control
        if self.active and get_stop_command and sig == '9':
            sig = None
        super(FixedProcessManager, self).disable(
                sig=sig,
                get_stop_command=get_stop_command,
                delete_pid_file=delete_pid_file)

    # TODO(mutax): patch ProcessManager upstream to add support for a callback
    #  for direct  reloading here?
    # def reload_cfg(self):
    #     if self._cb_reload and self._cb_reload():
    #         return
    #


class ProcessWrapper:
    """Generic Wrapper for a process to be spawned in the network namespace
       of a neutron network. Subclass this for your specific use case.
    """

    _preflight_check_done = False

    @classmethod
    def _preflight_check(cls, conf) -> bool:
        """Validate if all required binaries and template/config files are
           available before starting. Could also be used to perform version
           checks on the installed software packages.
           returns False if called for the first time.
           Should raise on errors.

           We implement it with caching, because the driver will be
           instantiated for every call.

           child classed should implement this check as follows:

           ```
           @classmethod
           def _preflight_check(cls, conf):

            if cls._preflight_check():
                return True

            # check code here

            # False - checks have been executed.
            # need to return False here for potential subclasses
            return False

        """
        ret = cls._preflight_check_done
        cls._preflight_check_done = True
        return ret

    def __init__(self, conf, network, net_conf_dir,
                 process_monitor, process_uuid):

        # note: process_uuid is not always a uuid and refers
        # to the namespace/network apparently, not the process?
        # from upstream code:
        # "%s/%s" % (self.segment.segmentation_id, self.network.id)

        self.conf = conf
        self.network = network
        self._process_monitor = process_monitor
        self._process_uuid = process_uuid
        self._network_conf_dir = net_conf_dir
        self._pidfile: str | None = None
        self._preflight_check(conf)

    @property
    def service_name(self):
        """Return the name of the process in the processlist.
        Used by default to build pid filenames, do not use spaces, etc.
        """
        raise NotImplementedError()

    @property
    def pidfile(self) -> str:
        if not self._pidfile:
            self._pidfile = self.get_conf_file_name(f'{self.service_name}.pid')
        return self._pidfile

    def get_conf_file_name(self, kind):
        """Returns the file name for a given kind of config file specific for
           the network namespace. Copied from upstream.
        """
        return str(pathlib.Path(self._network_conf_dir) / kind)

    def _get_process_manager(self, cmd_callback=None,
                             cmd_reload_callback=None):
        # need to return the fixed version, also we need to set
        # the service name and pidfile, etc.
        return FixedProcessManager(
                conf=self.conf,
                uuid=self._process_uuid,
                namespace=self.network.namespace,
                service=self.service_name,
                default_cmd_callback=cmd_callback,
                custom_reload_callback=cmd_reload_callback,
                pid_file=self.pidfile,
                run_as_root=True)

    def _spawn_or_reload(self, reload_with_HUP):
        """Spawns or reloads a process for the network.
        """
        pm = self._get_process_manager(
                cmd_callback=self._build_cmdline_callback,
                cmd_reload_callback=self._reload_callback,
        )

        # We only reload if we are active, else we spawn via upstream code.
        # If a reload callback is set, first try to reload via this
        # callback first, instead of spawning a process in the namespace or
        # sending a signal. We fall back to the upstream code if this is
        # not successful.
        if pm.active and self.reload():
            # do the ensure_active as pm does in enable():
            common_utils.wait_until_true(lambda: pm.active)
        else:
            pm.enable(reload_cfg=reload_with_HUP, ensure_active=True)

        self._process_monitor.register(uuid=pm.uuid,
                                       service_name=self.service_name,
                                       monitored_process=pm)

    def disable(self, block=False):
        pm = self._get_process_manager()
        self._process_monitor.unregister(pm.uuid, self.service_name)
        pm.disable(sig=str(int(signal.SIGTERM)))
        if block:
            try:
                common_utils.wait_until_true(lambda: not pm.active,
                                             timeout=SIGTERM_TIMEOUT)
            except common_utils.WaitTimeout:
                LOG.warning('%s process %s did not finish after SIGTERM '
                            'signal in %s seconds, sending SIGKILL signal',
                            self.service_name, pm.pid, SIGTERM_TIMEOUT)
                pm.disable(sig=str(int(signal.SIGKILL)))
                common_utils.wait_until_true(lambda: not self.active)

    @property
    def active(self):
        return self._get_process_manager().active

    def _build_cmdline_callback(self, pid_file) -> list[str]:
        raise NotImplementedError()

    def _reload_callback(self) -> list[str] | None:
        """return a shell command to be run in the namespace to make the
        service reload its config. Uses a signal if None is returned.
        Only called if self.reload() returns False.
        """
        return None

    def _output_config_files(self):
        pass

    def reload(self) -> bool:
        """Called when the process should reload its configuration.
           This is directly executed, and can be used instead of
           calling a binary in the namespace or sending a signal.
           When False is returned, we fallback to upstream code.
           Can be used to retry via SIGHUP, etc.
        """
        return False


class WrapUnbound(ProcessWrapper):

    def __init__(self, conf, network,
                 net_conf_dir, process_monitor, process_uuid,
                 ):

        super().__init__(conf, network,
                         net_conf_dir, process_monitor, process_uuid)

        self._control_socket_path = self.get_conf_file_name('unbound.socket')

    @classmethod
    def _preflight_check(cls, conf) -> bool:
        """Validate if all required binaries and template/config file are
           available before starting. Could also be used to perform version
           checks on the installed software packages.
        """
        if super()._preflight_check(conf):
            # only check once, not each time a new instance is created
            return True

        # It would be nice (and a litte more secure) to not rely on the PATH
        # to find unbound and unbound-control, but then the rootwrap config
        # has to match the path as well, or our preflight would be happy but
        # the execution would fail later. Lets do what upstream is doing.

        unbound_cmd = shutil.which('unbound')
        unbound_ctl = shutil.which('unbound-control')

        if not unbound_cmd:
            raise RuntimeError(_('unbound binary not found in PATH'))

        if not unbound_ctl:
            raise RuntimeError(_('unbound-control binary not found in PATH'))

        base_cfg_path = conf.SCI.unbound_config_file
        if not os.path.exists(base_cfg_path):
            msg = _("Base unbound config not found: '%s'") % base_cfg_path
            raise RuntimeError(msg)

        return False

    @property
    def service_name(self):
        return "unbound"

    def _build_cmdline_callback(self, pid_file):
        cmd = [
               'unbound',
               '-c', str(self.get_conf_file_name('unbound.conf'))
              ]
        return cmd

    def _reload_callback(self):
        """Returns a (shell) command to execute when unbound should reload.
           This is _not_ doing the actual reloading.
        """
        cmd = [
               'unbound-control',
               '-c', str(self.get_conf_file_name('unbound.conf')),
               'reload'
              ]
        return cmd

    def _output_config_files(self, iter_hosts_cb=None):
        self._output_unbound_rpz_file(iter_hosts_cb)
        self._output_unbound_config_file()

    def reload(self):
        """Reload unbound, newer unbound versions also support fast_reload.
           Unfortunately not the one currently packaged.
           Uses the control socket to communicate with unbound directly,
           instead of spawning unbound-control in the namespace.
        """
        try:
            ret = self._send_unbound_ctrl('reload')
            if ret:
                ret = ret.decode().strip()
            if ret == 'ok':
                return True
            LOG.info("reloading unbound via control socket failed. "
                     "Answer: '%s'", ret[:128])
        except OSError as e:
            LOG.info("reloading unbound via control socket failed. "
                     "Exception: %s", e)
        return False

    def _get_net_dns_upstreams(self):
        """returns the (custom) dns servers for this network"""
        # TODO(mutax): move to some more global class/helper and also
        #  use it in dnsmasq. e.g. some network config object/parser thing
        #  maybe add another callback that returns network-config from the
        #  calling class?

        if hasattr(self.network, 'dns_custom_upstreams'):
            # Do some input validation on the data we got via rpc call, to
            # avoid unbound not starting - worst case is we have no dns
            # if all servers are wrong. Should not happen as we are doing
            # validation on the server side as well.
            dns_servers = []
            for server in self.network.dns_custom_upstreams:
                try:
                    dns_servers.append(ipaddress.ip_address(server).compressed)
                except ValueError:
                    LOG.error('Invalid DNS server "%s" for network %s',
                              server, self.network.id)
        else:
            dns_servers = self.conf.dnsmasq_dns_servers

        return dns_servers

    def _send_unbound_ctrl(self, cmd, limit=1024, timeout=30,
                           limit_fatal=False
                           ) -> bytes:
        """Send a command to unbound via control socket and read up to
           `limit` bytes of response with timeout.
           If limit is 0, no limit will be enforced.
           Raises ValueError if limit_fatal is True and more data is received.
           Raises OSError on failure with communication.
        """

        buf = b""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            try:
                spath = str(self._control_socket_path)
                client.connect(spath)
                command = f"UBCT1 {cmd}\n"
                client.send(command.encode())
                while x := client.recv(min(limit, 4096)):
                    buf += x
                    if limit and len(buf) > limit:
                        if limit_fatal:
                            msg = _("Limit exceeded reading from unbound "
                                    "(%s): %d > %d") % (spath, len(buf), limit)
                            raise ValueError(msg)
                        LOG.warning("Limit exceeded reading from "
                                    "unbound (%s): %d > %d",
                                    spath, len(buf), limit)
                        break
                return buf
            except (OSError, socket.timeout) as e:
                LOG.warning("Error accessing unbound control socket %s - %s",
                            self._control_socket_path, str(e))
                raise

    def unbound_metrics(self, columns=None, prefixlist=None, reset=False)\
            -> dict[str, int | float]:
        """Retrieve metrics from unbound control socket directly.
           We assume all values are either float or int.
           columns: name of metrics to return
           prefixlist: list of prefixes to match metrics against, e.g. 'total.'
           reset: if the counters in unbound should be reset to 0
        """
        if reset:
            cmd = 'stats'
        else:
            cmd = 'stats_noreset'

        try:
            buf = self._send_unbound_ctrl(cmd)
        except OSError as e:
            LOG.info("Error fetching metrics from unbound control socket:"
                     " %s", e)
            return {}

        if not buf:
            return {}

        ret = {}
        for line in buf.decode().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                if not k or not v:
                    continue
                if prefixlist:
                    if not any((k.startswith(x) for x in prefixlist)):
                        continue
                if columns and k not in columns:
                    # skip what we are not interested in
                    continue
                # we know all metrics are numeric,
                # but some are floats.
                try:
                    if '.' in v:
                        v = float(v)
                    else:
                        v = int(v)
                except ValueError:
                    LOG.info("Unsupported unbound metric '%s' in net %s",
                             line, self.network.id)
                    continue

                if k in ret:
                    LOG.info("Duplicate unbound metric value '%s' "
                             "for key '%s' in net %s",
                             v, k, self.network.id)

                ret[k] = v
        return ret

    def _rpz_name(self):
        # TODO(mutax): which value to use? We are free to choose, should
        #  not be visible anywhere.
        return f"{self.network.id}.rpz.cloud.sap."

    @staticmethod
    def _add_unbound_section(buf: io.StringIO, section_name: str,
                             settings: dict[str, str | list[str]]):
        """Write a section with key-value pairs to unbound config in buf.
           If value is a list, the key will be repeated for every item.
        """
        buf.write(f'\n{section_name}:\n')
        for key, value in settings.items():
            if isinstance(value, list):
                for item in value:
                    buf.write(f'    {key}: {item}\n')
            else:
                buf.write(f'    {key}: {value}\n')

    def _output_unbound_config_file(self):
        """Write the unbound config file for the network namespace.
        """

        buf = io.StringIO()

        # TODO(mutax): check if we need to move more stuff into
        #        dynamic/per domain settings, e.g. range of private networks

        # include our static base config
        buf.write('include-toplevel: '
                  f'"{self.conf.SCI.unbound_config_file}"\n\n')

        settings = {'pidfile': self.pidfile, }
        if self.conf.SCI.unbound_logdir:
            settings['logfile'] = (f'{self.conf.SCI.unbound_logdir}/'
                                   f'unbound-{self.network.id}.log')

        self._add_unbound_section(buf, 'server', settings)

        self._unbound_cfg_add_upstreams(buf)
        self._unbound_cfg_add_control(buf)
        self._unbound_cfg_add_rpzcfg(buf)
        self._unbound_cfg_add_dnstap(buf)

        unbound_cfg = self.get_conf_file_name('unbound.conf')
        file_utils.replace_file(unbound_cfg, buf.getvalue())
        return unbound_cfg

    def _unbound_cfg_add_control(self, buf):
        """Add control socket configuration to unbound to allow
           reloading and metrics collection
        """

        self._add_unbound_section(buf, 'remote-control', {
            'control-enable': 'yes',
            'control-interface': str(self._control_socket_path),
        })

    def _unbound_cfg_add_rpzcfg(self, buf):
        """Add RPZ config to provide all local DNS names and PTR from the
           network via unbound
        """

        zonefile = self.get_conf_file_name('unbound-rpz.zone')
        rpz_name = self._rpz_name()
        self._add_unbound_section(buf, 'rpz', {
            'name': rpz_name,
            'zonefile': str(zonefile),
        })

    def _unbound_cfg_add_dnstap(self, buf):
        """Add dnstap configuration to unbound if enabled
        """

        # enable if the old edns logging option is True
        # or if the new one is set.
        dnstap_enabled = self.conf.edns_client_fingerprint
        if self.conf.SCI.dnstap_enabled:
            dnstap_enabled = True

        # TODO(mutax): rename network setting to something
        #   more generic, e.g.: 'dns_query_logging'?
        if hasattr(self.network, 'dns_ednslogging_enabled'):
            dnstap_enabled = strutils.bool_from_string(
                    self.network.dns_ednslogging_enabled,
                    default=dnstap_enabled  # no change if None
            )

        # only add dnstap config if its enabled
        if dnstap_enabled:
            dnstap_socket = self.conf.SCI.dnstap_socket

            agent = socket.gethostname()
            suffix = self.conf.SCI.dnstap_suffix

            # be consistent, project_id has no dashes.
            # also shortens the string a bit.
            netid = self.network.id.replace("-", "")
            identity = f"{netid}.{self.network.project_id}" \
                       f".{agent}.{suffix}"

            self._add_unbound_section(buf, 'dnstap', {
                'dnstap-enable': 'yes',
                'dnstap-socket-path': dnstap_socket,
                'dnstap-send-identity': 'yes',
                'dnstap-identity': identity,
                'dnstap-send-version': 'no',
                'dnstap-log-client-query-messages': 'yes',
                'dnstap-log-client-response-messages': 'yes'
            })

    def _unbound_cfg_add_upstreams(self, buf):
        """If the network has custom upstreams set, we will use them instead
           of the defaults from the config
        """

        dns_servers = self._get_net_dns_upstreams()

        if not dns_servers:
            # No custom upstreams configured, rely on recursive resolution
            # via root-hints from base config
            LOG.warning('No valid DNS upstreams configured for network %s, '
                        'using recursive resolution', self.network.id)
            return

        self._add_unbound_section(buf, 'forward-zone', {
            'name': '.',
            'forward-addr': dns_servers,
        })

    def _output_unbound_rpz_file(self, iter_hosts_cb=None):
        """Write the RPZ file containing the local hostname to IP mappings and
           PTR records.
        """
        buf = io.StringIO()
        buf.write(f'$ORIGIN {self._rpz_name()}\n')

        if iter_hosts_cb:
            # if no iterator is given the file will be empty but still valid,
            # so unbound can start.
            ttl = self.conf.SCI.unbound_rpz_ttl
            for _port, alloc, _hostname, fqdn, _no_dhcp, _no_opts, _tag \
                    in iter_hosts_cb():
                if alloc:
                    addr = netaddr.IPAddress(alloc.ip_address)
                    # for RPZ we need to end in the ORIGIN, so remove '.'
                    fqdn = fqdn.rstrip('.')
                    if addr.version == 4:
                        buf.write(f'{fqdn} {ttl} A    {addr}\n')
                    elif addr.version == 6:
                        buf.write(f'{fqdn} {ttl} AAAA {addr}\n')
                    # for the PTR we need the dot back. note: this also ensures
                    # that always exactly one dot is here.
                    buf.write(f'{addr.reverse_dns.rstrip(".")} {ttl}'
                              f' PTR {fqdn}.\n')

        unbound_rpz = self.get_conf_file_name('unbound-rpz.zone')
        file_utils.replace_file(unbound_rpz, buf.getvalue())
        return unbound_rpz

    def spawn_process(self, iter_hosts_cb):
        self._output_config_files(iter_hosts_cb=iter_hosts_cb)
        self._spawn_or_reload(reload_with_HUP=False)

    def reload_allocations(self, iter_hosts_cb):
        self._output_config_files(iter_hosts_cb=iter_hosts_cb)
        self._spawn_or_reload(reload_with_HUP=True)


class DnsmasqWithoutDNS(Dnsmasq):
    """Modified Dnsmasq dhcp driver that does not provide DNS service
    """

    def iter_hosts(self, *args, **kwargs):
        """we require this to be public accessible, because we do not want
           to copy existing code over from Dnsmasq to the unbound wrapper
        """
        return self._iter_hosts(*args, **kwargs)

    def _output_addn_hosts_file(self):
        """We do not want to create an addn host file for dnsmasq.
        """

    def _build_cmdline_callback(self, pid_file):
        """Returns commandline to spawn dnsmasq, but removes DNS related
           arguments from the original arguments and disables DNS by setting
           the port to 0 as documented in the manpage.
        """
        cmd = super()._build_cmdline_callback(pid_file)
        new_cmd = [arg for arg in cmd if not arg.startswith('--addn-hosts=')]
        new_cmd.append('--port=0')
        return new_cmd


class UnboundDnsmasq(DhcpLocalProcess):
    """Custom dhcp driver that disables DNS in dnsmasq and instead configures
       unbound in each namespace.
    """
    _dnsmasq_cls = DnsmasqWithoutDNS

    def __init__(self, conf, network, process_monitor, version=None,
                 plugin=None, segment=None):

        # Note: This class gets instantiated for every driver call

        super().__init__(conf, network, process_monitor,
                         version, plugin, segment)

        self._dnsmasq = self._dnsmasq_cls(conf, network, process_monitor,
                                          version, plugin, segment)

        self._unbound = WrapUnbound(conf=self.conf,
                                    net_conf_dir=self.network_conf_dir,
                                    network=network,
                                    process_monitor=process_monitor,
                                    process_uuid=self._get_process_uuid()
                                    )

    @classmethod
    def check_version(cls):
        cls._dnsmasq_cls.check_version()

    @classmethod
    def existing_dhcp_networks(cls, conf):
        return cls._dnsmasq_cls.existing_dhcp_networks(conf)

    @classmethod
    def get_isolated_subnets(cls, network):
        return cls._dnsmasq_cls.get_isolated_subnets(network)

    @classmethod
    def should_enable_metadata(cls, conf, network):
        return cls._dnsmasq_cls.should_enable_metadata(conf, network)

    def spawn_process(self):
        self._dnsmasq.spawn_process()
        # we do not want to copy the logic from dnsmasq, so use the existing
        # method to get the hostnames and IPs:
        self._unbound.spawn_process(iter_hosts_cb=self._dnsmasq.iter_hosts)

    def reload_allocations(self):
        self._dnsmasq.reload_allocations()
        # we do not want to copy the logic from dnsmasq, so use the existing
        # method to get the hostnames and IPs:
        self._unbound.reload_allocations(
                iter_hosts_cb=self._dnsmasq.iter_hosts)

    def disable(self, retain_port=False, block=False, **kwargs):
        """Disable DHCP for this network by killing the local processes.
           We also need to stop unbound, not just dnsmasq.
        """
        self._unbound.disable(block=block)
        # now call the parent method, so the config gets removed...
        self._dnsmasq.disable(retain_port=retain_port,
                              block=block, **kwargs)

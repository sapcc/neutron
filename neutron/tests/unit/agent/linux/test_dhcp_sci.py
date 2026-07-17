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
from unittest import mock

from oslo_config import fixture as fixture_config

from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.linux.external_process import ProcessMonitor
from neutron.agent.linux import utils
from neutron.conf.agent import common as config
from neutron.tests import base
from neutron.tests.unit.agent.linux.test_dhcp import FakeDualNetwork
from neutron.tests.unit.agent.linux.test_dhcp import FakeV4Network
from neutron.tests.unit.agent.linux.test_dhcp import TestBase
from neutron.tests.unit.agent.linux.test_dhcp import TestConfBase

from neutron.agent.linux.dhcp_sci import DnsmasqWithoutDNS, FixedProcessManager
from neutron.agent.linux.dhcp_sci import ProcessWrapper
from neutron.agent.linux.dhcp_sci import WrapUnbound


class TestFixedProcessManager(TestConfBase):
    def setUp(self):
        super().setUp()
        self.config_parse(self.conf)
        self.makedirs = mock.patch('os.makedirs').start()
        self.rmtree = mock.patch('shutil.rmtree').start()

    def test_fix_still_required(self):

        def cb(pidfile):
            return ['mockcmd']

        with (mock.patch.object(external_process.ProcessManager,
                                'active',
                                new_callable=mock.PropertyMock,
                                return_value=True),
              mock.patch.object(external_process.ProcessManager,
                                'pid',
                                new_callable=mock.PropertyMock,
                                return_value=23),
              mock.patch.object(external_process.ProcessManager,
                                '_kill_process') as mock_kill,
              mock.patch.object(utils,
                                'delete_if_exists') as mock_delete):

            f = external_process.ProcessManager(self.conf, uuid="foo")
            f.disable('9', get_stop_command=cb, delete_pid_file=False)

            self.assertTrue(
                    mock_delete.called,
                    "If this test fails, FixedProcessManager can be replaced "
                    "with ProcessManager."
            )
            mock_kill.assert_called_once_with(['mockcmd', ], 23)

    def test_fix_reload_keep_pidfile(self):

        def cb():
            return []

        with mock.patch.object(FixedProcessManager, 'active',
                               new_callable=mock.PropertyMock,
                               return_value=True), \
                mock.patch.object(external_process.ProcessManager,
                                  'disable') as mock_super_disable:

            f = FixedProcessManager(self.conf, uuid="foo",
                                    custom_reload_callback=cb)
            f.reload_cfg()

            mock_super_disable.assert_called_once_with(
                    sig=None,  # <-- the fix: sig changed from '9' to None
                    get_stop_command=cb,
                    delete_pid_file=False
            )


class TestProcessWrapper(TestConfBase):

    def setUp(self):
        super().setUp()
        from neutron.conf.agent import common as agent_config
        agent_config.register_process_monitor_opts(self.conf)

    def get_wrapper(self):

        class Wrapper(ProcessWrapper):

            @property
            def service_name(self):
                return 'MockWrapper'

        pm = ProcessMonitor(self.conf, 'fake_rtype')
        return Wrapper(self.conf,
                       network=FakeDualNetwork(),
                       net_conf_dir='/tmp/conf/dir',
                       process_monitor=pm,
                       process_uuid='mock/uuid'
                       )

    def test_preflight_check_runs_once(self):
        """Verify preflight check only runs once per class"""

        # reset in case it was already set:
        ProcessWrapper._preflight_check_done = False
        self.assertFalse(ProcessWrapper._preflight_check(self.conf))
        self.assertTrue(ProcessWrapper._preflight_check(self.conf))

    def test_preflight_check_inheritance(self):
        """Each subclass has its own _preflight_check_done flag"""
        # Verify WrapUnbound._preflight_check_done is independent

        class WrapperA(ProcessWrapper):

            @property
            def service_name(self):
                return 'A'

        class WrapperB(ProcessWrapper):

            @property
            def service_name(self):
                return 'B'

        self.assertFalse(WrapperA._preflight_check(self.conf))
        self.assertTrue(WrapperA._preflight_check(self.conf))
        self.assertFalse(WrapperB._preflight_check(self.conf))
        self.assertTrue(WrapperB._preflight_check(self.conf))

    def test_get_process_manager_returns_fixed_process_manager(self):
        """Verify FixedProcessManager is returned, not upstream ProcessManager
        """
        wrapper = self.get_wrapper()
        pm = wrapper._get_process_manager()
        self.assertIsInstance(pm, FixedProcessManager)

    def test_spawn_or_reload_when_active_and_reload_succeeds(self):
        """When process is active and reload() returns True,
        don't call pm.enable()
        """
        wrapper = self.get_wrapper()
        with (mock.patch.object(wrapper, '_get_process_manager')
              as mock_get_pm,
              mock.patch.object(wrapper, 'reload', return_value=True)):

            mock_pm = mock_get_pm.return_value
            mock_pm.active = True

            wrapper._spawn_or_reload(reload_with_HUP=True)

            mock_pm.enable.assert_not_called()


class TestWrapUnbound(base.BaseTestCase):
    """Tests for WrapUnbound DNS server wrapper"""

    def setUp(self):
        super().setUp()
        from neutron.conf.agent import common as agent_config
        from neutron.conf.agent import dhcp as dhcp_config

        conf = config.setup_conf()
        agent_config.register_agent_state_opts_helper(conf)
        agent_config.register_process_monitor_opts(conf)
        agent_config.register_external_process_opts(conf)
        conf.register_opts(dhcp_config.DHCP_OPTS)
        conf.register_opts(dhcp_config.DHCP_AGENT_OPTS)
        conf.register_opts(dhcp_config.DNSMASQ_OPTS)
        conf.register_opts(dhcp_config.SCI_OPTS, 'SCI')
        self.conf = self.useFixture(fixture_config.Config(conf)).conf

        # Mock network object
        self.network = FakeV4Network()
        self.network.project_id = 'pppppppp-pppp-pppp-pppp-pppppppppppp'

        # Mock process monitor
        self.process_monitor = mock.MagicMock()

        # Mock os.makedirs to avoid filesystem operations
        self.makedirs = mock.patch('os.makedirs').start()

    def _create_instance(self, conf=None) -> WrapUnbound:
        """Helper to create WrapUnbound instance"""

        with mock.patch.object(WrapUnbound, '_preflight_check',
                               return_value=True):
            return self._create_instance_with_preflight(conf)

    def _create_instance_with_preflight(self, conf=None) -> WrapUnbound:
        """Helper to create WrapUnbound instance"""

        return WrapUnbound(
                conf=conf or self.conf,
                network=self.network,
                net_conf_dir='/var/lib/neutron/dhcp/net-uuid-1234',
                process_monitor=self.process_monitor,
                process_uuid='net-uuid-1234',
        )

    # ------------------------------------------------------------------------
    # preflight_check tests
    # ------------------------------------------------------------------------

    def test_preflight_check_raises_if_unbound_missing(self):
        """Verify RuntimeError if unbound binary not found"""

        WrapUnbound._preflight_check_done = False

        with mock.patch('shutil.which', return_value=None):
            self.assertRaises(RuntimeError,
                              self._create_instance_with_preflight)

    def test_preflight_check_raises_if_unbound_control_missing(self):
        """Verify RuntimeError if unbound-control binary not found"""

        WrapUnbound._preflight_check_done = False

        def which_side_effect(name):
            return '/usr/sbin/unbound' if name == 'unbound' else None

        with mock.patch('shutil.which', side_effect=which_side_effect):
            self.assertRaises(RuntimeError,
                              self._create_instance_with_preflight)

    def test_preflight_check_raises_if_base_config_missing(self):
        """Verify RuntimeError if base unbound config not found"""

        WrapUnbound._preflight_check_done = False

        with (mock.patch('shutil.which',
                         return_value='/usr/sbin/unbound'),
                mock.patch('os.path.exists', return_value=False)):
            self.assertRaises(RuntimeError,
                              self._create_instance_with_preflight)

    def test_preflight_check_runs_once(self):
        """Verify preflight check only runs once"""

        WrapUnbound._preflight_check_done = False
        with (mock.patch('shutil.which',
                         return_value='mocked_value'),
              mock.patch('os.path.exists', return_value=True)):

            self.assertFalse(WrapUnbound._preflight_check(self.conf))
            self.assertTrue(WrapUnbound._preflight_check(self.conf))

    # ------------------------------------------------------------------------
    # Basic property tests
    # ------------------------------------------------------------------------

    def test_service_name(self):
        """Verify service_name returns 'unbound'"""
        wrapper = self._create_instance()
        self.assertEqual(wrapper.service_name, 'unbound')

    def test_control_socket_path(self):
        """Verify control socket path is set correctly"""
        wrapper = self._create_instance()
        self.assertIn('unbound.socket', wrapper._control_socket_path)

    # ------------------------------------------------------------------------
    # build_cmdline_callback tests
    # ------------------------------------------------------------------------

    def test_build_cmdline_callback(self):
        """Verify command line for spawning unbound"""
        wrapper = self._create_instance()
        cmd = wrapper._build_cmdline_callback('/tmp/unbound.pid')

        self.assertEqual(cmd[0], 'unbound')
        self.assertIn('-c', cmd)
        self.assertTrue(any('unbound.conf' in arg for arg in cmd))

    # ------------------------------------------------------------------------
    # reload_callback tests
    # ------------------------------------------------------------------------

    def test_reload_callback(self):
        """Verify reload command uses unbound-control"""
        wrapper = self._create_instance()
        cmd = wrapper._reload_callback()

        self.assertEqual(cmd[0], 'unbound-control')
        self.assertIn('-c', cmd)
        self.assertIn('reload', cmd)

    # ------------------------------------------------------------------------
    # reload tests
    # ------------------------------------------------------------------------

    def test_reload_success(self):
        """Verify reload returns True on successful control socket response"""
        wrapper = self._create_instance()

        with mock.patch.object(wrapper, '_send_unbound_ctrl',
                               return_value=b'ok\n'):
            result = wrapper.reload()
            self.assertTrue(result)

    def test_reload_unexpected_response(self):
        """Verify reload returns False on unexpected response"""
        wrapper = self._create_instance()

        with mock.patch.object(wrapper, '_send_unbound_ctrl',
                               return_value=b'error\n'):
            result = wrapper.reload()
            self.assertFalse(result)

    # ------------------------------------------------------------------------
    # get_net_dns_upstreams tests
    # ------------------------------------------------------------------------

    def test_get_net_dns_upstreams_from_network(self):
        """Verify custom upstreams are read from network object"""
        wrapper = self._create_instance()
        wrapper.network.dns_custom_upstreams = ['8.8.8.8', '8.8.4.4']

        result = wrapper._get_net_dns_upstreams()
        self.assertEqual(result, ['8.8.8.8', '8.8.4.4'])

    def test_get_net_dns_upstreams_invalid_ip_filtered(self):
        """Verify invalid IPs are filtered out"""
        wrapper = self._create_instance()
        wrapper.network.dns_custom_upstreams = ['8.8.8.8',
                                                'invalid',
                                                '1.1.1.1']

        result = wrapper._get_net_dns_upstreams()
        self.assertEqual(result, ['8.8.8.8', '1.1.1.1'])

    def test_get_net_dns_upstreams_fallback_to_conf(self):
        """Verify fallback to config if network has no custom upstreams"""
        wrapper = self._create_instance()
        self.assertFalse(hasattr(wrapper.network, 'dns_custom_upstreams'))
        self.conf.set_override('dnsmasq_dns_servers', ['9.9.9.9'])

        result = wrapper._get_net_dns_upstreams()
        self.assertEqual(result, ['9.9.9.9'])

    # ------------------------------------------------------------------------
    # rpz_name tests
    # ------------------------------------------------------------------------

    def test_rpz_name(self):
        """Verify RPZ zone name format"""
        wrapper = self._create_instance()
        rpz = wrapper._rpz_name()

        self.assertIn(wrapper.network.id, rpz)
        self.assertTrue(rpz.endswith('.'))

    # ------------------------------------------------------------------------
    # add_unbound_section tests
    # ------------------------------------------------------------------------

    def test_add_unbound_section_simple(self):
        """Verify section with simple key-value pairs"""

        buf = io.StringIO()

        WrapUnbound._add_unbound_section(buf, 'server', {
            'key1': 'value1',
            'key2': 'value2',
        })

        output = buf.getvalue()
        self.assertIn('server:', output)
        self.assertIn('  key1: value1', output)
        self.assertIn('  key2: value2', output)

    def test_add_unbound_section_list_values(self):
        """Verify section with list values repeats keys"""

        buf = io.StringIO()

        settings = {'name': '.', 'forward-addr': ['8.8.8.8', '8.8.4.4'], }

        WrapUnbound._add_unbound_section(buf,
                                         'forward-zone',
                                         settings)

        output = buf.getvalue()
        self.assertEqual(output.count('forward-addr:'), 2)

    # ------------------------------------------------------------------------
    # output_unbound_config_file tests
    # ------------------------------------------------------------------------

    def test_output_unbound_config_file(self):
        """Verify config file is written with required sections"""
        wrapper = self._create_instance()
        wrapper.network.dns_custom_upstreams = ['8.8.8.8']

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_config_file()

            mock_replace.assert_called_once()
            config_path, config_content = mock_replace.call_args[0]

            self.assertIn('unbound.conf', config_path)
            self.assertIn('include-toplevel:', config_content)
            self.assertIn('server:', config_content)
            self.assertIn('remote-control:', config_content)
            self.assertIn('rpz:', config_content)

    # ------------------------------------------------------------------------
    # output_unbound_rpz_file tests
    # ------------------------------------------------------------------------

    def test_output_unbound_rpz_file_empty(self):
        """Verify RPZ file with no hosts is syntactically valid"""
        wrapper = self._create_instance()

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_rpz_file(iter_hosts_cb=None)

            mock_replace.assert_called_once()
            _, content = mock_replace.call_args[0]
            self.assertIn('$ORIGIN', content)

    def test_output_unbound_rpz_file_with_hosts(self):
        """Verify RPZ file contains A and PTR records"""
        wrapper = self._create_instance()

        # Mock allocation object
        alloc = mock.MagicMock()
        alloc.ip_address = '10.0.0.5'

        def iter_hosts():
            # (port, alloc, hostname, fqdn, no_dhcp, no_opts, tag)
            yield (None, alloc, 'myhost', 'myhost.example.com.',
                   False, False, None)

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_rpz_file(iter_hosts_cb=iter_hosts)

            _, content = mock_replace.call_args[0]
            self.assertIn('myhost.example.com', content)
            self.assertIn('A', content)
            self.assertIn('PTR', content)
            self.assertIn('10.0.0.5', content)

    def test_output_unbound_rpz_file_ipv6(self):
        """Verify RPZ file handles IPv6 addresses"""
        wrapper = self._create_instance()

        alloc = mock.MagicMock()
        alloc.ip_address = '2001:db8::1'

        def iter_hosts():
            yield (None, alloc, 'myhost', 'myhost.example.com.',
                   False, False, None)

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_rpz_file(iter_hosts_cb=iter_hosts)

            _, content = mock_replace.call_args[0]
            self.assertIn('AAAA', content)
            self.assertIn('2001:db8::1', content)
            self.assertIn('PTR', content)

    # ------------------------------------------------------------------------
    # output_config_files tests
    # ------------------------------------------------------------------------

    def test_output_config_files_calls_both(self):
        """Verify output_config_files writes both config and RPZ file
        and calls iterator callback to get hosts
        """
        wrapper = self._create_instance()

        with (mock.patch.object(wrapper, '_output_unbound_rpz_file')
              as mock_rpz,
              mock.patch.object(wrapper, '_output_unbound_config_file')
              as mock_cfg):
            cb = mock.MagicMock()
            wrapper._output_config_files(iter_hosts_cb=cb)

            mock_rpz.assert_called_once_with(cb)
            mock_cfg.assert_called_once()

    # ------------------------------------------------------------------------
    # send_unbound_ctrl tests
    # ------------------------------------------------------------------------

    def test_send_unbound_ctrl_success(self):
        """Verify control socket communication"""
        wrapper = self._create_instance()

        mock_socket = mock.MagicMock()
        mock_socket.recv.side_effect = [b'ok\n', b'']

        with mock.patch('socket.socket') as mock_socket_class:
            mock_inst = mock_socket_class.return_value
            mock_inst.__enter__.return_value = mock_socket

            result = wrapper._send_unbound_ctrl('reload')

            self.assertEqual(result, b'ok\n')
            mock_socket.connect.assert_called_once()
            mock_socket.send.assert_called_once()
            self.assertIn(b'UBCT1 reload', mock_socket.send.call_args[0][0])

    def test_send_unbound_ctrl_connection_error(self):
        """Verify OSError is raised on connection failure"""
        wrapper = self._create_instance()

        with mock.patch('socket.socket') as mock_socket:
            mock_inst = mock_socket.return_value.__enter__.return_value
            mock_inst.connect.side_effect = OSError

            self.assertRaises(OSError, wrapper._send_unbound_ctrl, 'reload')

    def test_reload_oserror_returns_false_and_logs(self):
        """Verify OSError on reload returns False and logs warning"""
        wrapper = self._create_instance()

        with (self.assertLogs('neutron.agent.linux.dhcp_sci', level='INFO')
              as log,
              mock.patch('socket.socket')
              as mock_socket):
            mock_inst = mock_socket.return_value.__enter__.return_value
            mock_inst.connect.side_effect = OSError

            result = wrapper.reload()

            self.assertFalse(result)
            self.assertIn('Error accessing unbound control socket',
                          log.output[0])

    def test_unbound_metrics_oserror_returns_empty_and_logs(self):
        """Verify OSError on metrics returns empty dict and logs warning"""
        wrapper = self._create_instance()

        with (self.assertLogs('neutron.agent.linux.dhcp_sci',
                              level='INFO') as log,
              mock.patch('socket.socket') as mock_socket):

            mock_inst = mock_socket.return_value.__enter__.return_value
            mock_inst.connect.side_effect = OSError

            result = wrapper.unbound_metrics()

            self.assertEqual({}, result)
            self.assertIn('Error fetching metrics', log.output[1])

    def test_send_unbound_ctrl_limit_exceeded(self):
        """Verify warning when response exceeds limit"""
        wrapper = self._create_instance()

        mock_socket = mock.MagicMock()
        mock_socket.recv.return_value = b'x' * 2048

        with (self.assertLogs('neutron.agent.linux.dhcp_sci',
                              level='INFO') as log,
              mock.patch('socket.socket') as mock_socket_class):

            mock_inst = mock_socket_class.return_value
            mock_inst.__enter__.return_value = mock_socket

            # Should not raise, just log warning and return truncated
            result = wrapper._send_unbound_ctrl('stats', limit=123)
            self.assertGreater(len(result), 123)
            self.assertIn('Limit exceeded', log.output[0])

    def test_send_unbound_ctrl_limit_fatal(self):
        """Verify ValueError when limit_fatal=True and limit exceeded"""
        wrapper = self._create_instance()

        mock_socket = mock.MagicMock()
        mock_socket.recv.return_value = b'x' * 2048

        with mock.patch('socket.socket') as mock_socket_class:
            mock_inst = mock_socket_class.return_value
            mock_inst.__enter__.return_value = mock_socket

            self.assertRaises(ValueError, wrapper._send_unbound_ctrl,
                              'stats', limit=1024, limit_fatal=True)

    # ------------------------------------------------------------------------
    # unbound_metrics tests
    # ------------------------------------------------------------------------

    def test_unbound_metrics_parses_response(self):
        """Verify metrics are parsed correctly"""
        wrapper = self._create_instance()

        response = b'total.num.abc=100\ntotal.num.cache=50\ntime.up=123.456\n'

        with mock.patch.object(wrapper, '_send_unbound_ctrl',
                               return_value=response):
            result = wrapper.unbound_metrics()

            self.assertEqual(result['total.num.abc'], 100)
            self.assertEqual(result['total.num.cache'], 50)
            self.assertAlmostEqual(result['time.up'], 123.456)

    def test_unbound_metrics_invalid_ignored(self):
        """Verify invalid metrics are ignored but errors logged"""
        wrapper = self._create_instance()

        response = b'total.num.queries=100\nfoo=invalid\ntime.up=123.456\n'

        with (self.assertLogs('neutron.agent.linux.dhcp_sci',
                              level='INFO') as log,
              mock.patch.object(wrapper, '_send_unbound_ctrl',
                                return_value=response)):
            result = wrapper.unbound_metrics()
            self.assertEqual(result['total.num.queries'], 100)
            self.assertAlmostEqual(result['time.up'], 123.456)
            self.assertIn('Unsupported unbound metric', log.output[0])

    def test_unbound_metrics_duplicates_logged(self):
        """Verify duplicate metrics are logged and the last one wins"""
        wrapper = self._create_instance()

        response = b'total.num.queries=100\ntotal.num.queries=23\n'

        with (self.assertLogs('neutron.agent.linux.dhcp_sci',
                              level='INFO') as log,
              mock.patch.object(wrapper, '_send_unbound_ctrl',
                                return_value=response)):
            result = wrapper.unbound_metrics()
            self.assertEqual(result['total.num.queries'], 23)
            self.assertIn('Duplicate unbound metric', log.output[0])
            self.assertIn('total.num.queries', log.output[0])

    def test_unbound_metrics_with_prefix_filter(self):
        """Verify prefix filtering works"""
        wrapper = self._create_instance()

        response = b'total.num.queries=100\nmem.cache=500\n'

        with mock.patch.object(wrapper, '_send_unbound_ctrl',
                               return_value=response):
            result = wrapper.unbound_metrics(prefixlist=['total.'])

            self.assertIn('total.num.queries', result)
            self.assertNotIn('mem.cache', result)

    def test_unbound_metrics_with_columns_filter(self):
        """Verify column filtering works"""
        wrapper = self._create_instance()

        response = b'total.num.queries=100\ntotal.num.cache=50\n'

        with mock.patch.object(wrapper, '_send_unbound_ctrl',
                               return_value=response):
            result = wrapper.unbound_metrics(columns=['total.num.queries'])

            self.assertIn('total.num.queries', result)
            self.assertNotIn('total.num.cache', result)

    def test_unbound_metrics_reset_flag(self):
        """Verify reset flag sends 'stats' instead of 'stats_noreset'"""
        wrapper = self._create_instance()

        with mock.patch.object(wrapper, '_send_unbound_ctrl',
                               return_value=b'') as mock_ctrl:
            wrapper.unbound_metrics(reset=True)
            mock_ctrl.assert_called_with('stats')

            wrapper.unbound_metrics(reset=False)
            mock_ctrl.assert_called_with('stats_noreset')

    # ------------------------------------------------------------------------
    # dnstap config tests
    # ------------------------------------------------------------------------

    def test_dnstap_config_disabled_by_default(self):
        """Verify dnstap section not added when disabled"""
        wrapper = self._create_instance()
        self.conf.set_override('edns_client_fingerprint', False)

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_config_file()

            _, content = mock_replace.call_args[0]
            self.assertNotIn('dnstap:', content)

    def test_dnstap_config_enabled(self):
        """Verify dnstap section added when enabled"""
        conf = self.conf
        conf.set_override('edns_client_fingerprint', True)
        wrapper = self._create_instance(conf=conf)
        self.assertTrue(wrapper.conf.edns_client_fingerprint)
        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_config_file()

            _, content = mock_replace.call_args[0]
            self.assertIn('dnstap:', content)
            self.assertIn('dnstap-enable: yes', content)

    def test_dnstap_config_network_override(self):
        """Verify network-level dnstap setting overrides global"""
        wrapper = self._create_instance()
        self.conf.set_override('edns_client_fingerprint', False)
        wrapper.network.dns_ednslogging_enabled = 'true'

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_config_file()

            _, content = mock_replace.call_args[0]
            self.assertIn('dnstap:', content)

    # ------------------------------------------------------------------------
    # unbound_config_file and unbound_logdir tests
    # ------------------------------------------------------------------------

    def test_unbound_config_file_included_in_output(self):
        """Verify unbound_config_file is used in include-toplevel directive"""
        self.conf.set_override('unbound_config_file',
                               '/custom/path/unbound.conf',
                               group='SCI')
        wrapper = self._create_instance()

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_config_file()

            _, content = mock_replace.call_args[0]
            self.assertIn('include-toplevel: "/custom/path/unbound.conf"',
                          content)

    def test_unbound_logdir_not_set_no_logfile(self):
        """Verify no logfile directive when unbound_logdir is empty"""
        self.conf.set_override('unbound_logdir', '', group='SCI')
        wrapper = self._create_instance()

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_config_file()

            _, content = mock_replace.call_args[0]
            self.assertNotIn('logfile:', content)

    def test_unbound_logdir_set_creates_logfile_path(self):
        """Verify logfile directive includes network id when logdir is set"""
        self.conf.set_override('unbound_logdir', '/var/log/unbound',
                               group='SCI')
        wrapper = self._create_instance()

        with mock.patch('neutron_lib.utils.file.replace_file') as mock_replace:
            wrapper._output_unbound_config_file()

            _, content = mock_replace.call_args[0]
            self.assertIn('logfile:', content)
            self.assertIn('/var/log/unbound/', content)
            self.assertIn(f'unbound-{wrapper.network.id}.log', content)


class TestDnsmasqWithoutDNS(TestBase):
    """Tests for DnsmasqWithoutDNS - the dnsmasq DHCP-only driver"""

    def setUp(self):
        super().setUp()
        from neutron.conf.agent import common as agent_config
        agent_config.register_process_monitor_opts(self.conf)

    def _create_instance(self, network=None):
        """Helper to create DnsmasqWithoutDNS with mocked dependencies"""
        return DnsmasqWithoutDNS(
            self.conf,
            network or FakeDualNetwork(),
            process_monitor=mock.Mock(),
        )

    # ----------------------------------------------------------------------
    # _output_addn_hosts_file tests
    # ----------------------------------------------------------------------

    def test_output_addn_hosts_file_does_nothing(self):
        """Verify addn-hosts file is not created (unbound handles DNS)"""
        instance = self._create_instance()

        # Should not raise and should not write anything
        result = instance._output_addn_hosts_file()
        self.assertIsNone(result)

    # ----------------------------------------------------------------------
    # _output_config_files tests
    # ----------------------------------------------------------------------

    def test_output_config_files_calls_parent(self):
        """Verify dnsmasq config files are written"""
        instance = self._create_instance()

        with (mock.patch.object(dhcp.Dnsmasq, '_output_config_files')
              as mock_parent,
              ):

            instance._output_config_files()

            mock_parent.assert_called_once()

    # ----------------------------------------------------------------------
    # _build_cmdline_callback tests
    # ----------------------------------------------------------------------

    def test_build_cmdline_removes_addn_hosts(self):
        """Verify --addn-hosts argument is removed from dnsmasq command"""
        instance = self._create_instance()

        cmd = instance._build_cmdline_callback('/tmp/dnsmasq.pid')

        addn_hosts_args = [arg for arg in cmd
                           if arg.startswith('--addn-hosts=')]
        self.assertEqual([], addn_hosts_args)

    def test_build_cmdline_adds_port_zero(self):
        """Verify --port=0 is added to disable DNS in dnsmasq"""
        instance = self._create_instance()

        cmd = instance._build_cmdline_callback('/tmp/dnsmasq.pid')

        self.assertIn('--port=0', cmd)

    def test_build_cmdline_preserves_other_args(self):
        """Verify other dnsmasq arguments are preserved"""
        instance = self._create_instance()

        cmd = instance._build_cmdline_callback('/tmp/dnsmasq.pid')

        # Should still have dnsmasq as the command
        self.assertEqual(cmd[0], 'dnsmasq')
        # Should have other standard arguments
        self.assertTrue(any('--dhcp-hostsfile' in arg for arg in cmd))


class TestUnboundDnsmasq(TestBase):
    """Tests for UnboundDnsmasq - the combined dnsmasq+unbound DHCP driver"""

    def setUp(self):
        super().setUp()
        from neutron.conf.agent import common as agent_config
        agent_config.register_process_monitor_opts(self.conf)

    def _create_instance(self, network=None):
        """Helper to create UnboundDnsmasq with mocked dependencies"""
        from neutron.agent.linux.dhcp_sci import UnboundDnsmasq
        from neutron.agent.linux.dhcp_sci import WrapUnbound

        with mock.patch.object(WrapUnbound, '_preflight_check',
                               return_value=True):
            return UnboundDnsmasq(
                self.conf,
                network or FakeDualNetwork(),
                process_monitor=mock.Mock(),
            )

    def test_init_creates_unbound_wrapper(self):
        """Verify UnboundDnsmasq creates a WrapUnbound instance"""
        from neutron.agent.linux.dhcp_sci import WrapUnbound

        instance = self._create_instance()

        self.assertIsInstance(instance._unbound, WrapUnbound)

    def test_correct_dnsmasq(self):
        """Verify WrapUnbound receives correct configuration"""
        instance = self._create_instance()
        self.assertEqual(instance._dnsmasq_cls, DnsmasqWithoutDNS)

    def test_init_passes_correct_args(self):
        """Verify WrapUnbound receives correct configuration"""
        instance = self._create_instance()

        self.assertEqual(instance._unbound.conf, instance.conf)
        self.assertEqual(instance._unbound.network, instance.network)
        self.assertEqual(instance._dnsmasq.conf, instance.conf)
        self.assertEqual(instance._dnsmasq.network, instance.network)

    def test_spawn_process_calls_dnsmasq_and_unbound(self):
        """Verify both dnsmasq and unbound are spawned"""
        instance = self._create_instance()

        with (mock.patch.object(dhcp.Dnsmasq, 'spawn_process')
              as mock_dnsmasq,
              mock.patch.object(instance._unbound, 'spawn_process')
              as mock_unbound):

            instance.spawn_process()

            mock_dnsmasq.assert_called_once()
            mock_unbound.assert_called_once()

    # ----------------------------------------------------------------------
    # disable tests
    # ----------------------------------------------------------------------

    def test_disable_stops_unbound_and_dnsmasq(self):
        """Verify both unbound and dnsmasq are disabled"""
        instance = self._create_instance()

        with (mock.patch.object(dhcp.Dnsmasq, 'disable') as mock_parent,
              mock.patch.object(instance._unbound, 'disable')
              as mock_unbound):

            instance.disable(retain_port=False, block=True)

            mock_unbound.assert_called_once_with(block=True)
            mock_parent.assert_called_once_with(
                retain_port=False,
                block=True
            )

    def test_disable_stops_unbound_before_dnsmasq(self):
        """Verify unbound is stopped before dnsmasq"""
        instance = self._create_instance()
        call_order = []

        def record_parent(*args, **kwargs):
            call_order.append('dnsmasq')

        def record_unbound(*args, **kwargs):
            call_order.append('unbound')

        with (mock.patch.object(dhcp.Dnsmasq, 'disable',
                                side_effect=record_parent),
              mock.patch.object(instance._unbound, 'disable',
                                side_effect=record_unbound)):

            instance.disable()

            self.assertEqual(call_order, ['unbound', 'dnsmasq'])

    def test_disable_passes_block_to_unbound(self):
        """Verify block parameter is passed to unbound.disable"""
        instance = self._create_instance()

        with (mock.patch.object(dhcp.Dnsmasq, 'disable'),
              mock.patch.object(instance._unbound, 'disable')
              as mock_unbound):

            instance.disable(block=True)
            mock_unbound.assert_called_with(block=True)

            mock_unbound.reset_mock()

            instance.disable(block=False)
            mock_unbound.assert_called_with(block=False)

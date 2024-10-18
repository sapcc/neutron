# Copyright 2012 VMware, Inc.
# All rights reserved.
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
#

import contextlib
from unittest import mock

import netaddr
from neutron_lib import constants as lib_constants
from neutron_lib import context
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.db import l3_db
from neutron.extensions import l3
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2
from webob import exc


_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


DEVICE_OWNER_COMPUTE = lib_constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class L3NatTestCaseMixin(object):

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up is not None:
            data['router']['admin_state_up'] = admin_state_up
        flavor_id = kwargs.get('flavor_id', None)
        if flavor_id:
            data['router']['flavor_id'] = flavor_id
        for arg in (('admin_state_up', 'tenant_id',
                     'availability_zone_hints') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs:
                data['router'][arg] = kwargs[arg]
        if 'distributed' in kwargs:
            data['router']['distributed'] = bool(kwargs['distributed'])
        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _make_router(self, fmt, tenant_id, name=None, admin_state_up=None,
                     external_gateway_info=None, set_context=False,
                     arg_list=None, **kwargs):
        if external_gateway_info:
            arg_list = ('external_gateway_info', ) + (arg_list or ())
        res = self._create_router(fmt, tenant_id, name,
                                  admin_state_up, set_context,
                                  arg_list=arg_list,
                                  external_gateway_info=external_gateway_info,
                                  **kwargs)
        return self.deserialize(fmt, res)

    def _add_external_gateway_to_router(self, router_id, network_id,
                                        expected_code=exc.HTTPOk.code,
                                        neutron_context=None, ext_ips=None,
                                        **kwargs):
        ext_ips = ext_ips or []
        body = {'router':
                {'external_gateway_info': {'network_id': network_id}}}
        if ext_ips:
            body['router']['external_gateway_info'][
                'external_fixed_ips'] = ext_ips
        if 'policy_id' in kwargs:
            body['router']['external_gateway_info'][
                'qos_policy_id'] = kwargs.get('policy_id')
        return self._update('routers', router_id, body,
                            expected_code=expected_code,
                            neutron_context=neutron_context)

    def _remove_external_gateway_from_router(self, router_id, network_id,
                                             expected_code=exc.HTTPOk.code,
                                             external_gw_info=None):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                        external_gw_info}},
                            expected_code=expected_code)

    def _router_interface_action(self, action, router_id, subnet_id, port_id,
                                 expected_code=exc.HTTPOk.code,
                                 expected_body=None,
                                 tenant_id=None,
                                 msg=None):
        interface_data = {}
        if subnet_id is not None:
            interface_data.update({'subnet_id': subnet_id})
        if port_id is not None:
            interface_data.update({'port_id': port_id})

        req = self.new_action_request('routers', interface_data, router_id,
                                      "%s_router_interface" % action)
        # if tenant_id was specified, create a tenant context for this request
        if tenant_id:
            req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int, msg)
        response = self.deserialize(self.fmt, res)
        if expected_body:
            self.assertEqual(expected_body, response, msg)
        return response

    @contextlib.contextmanager
    def router(self, name='router1', admin_state_up=True,
               fmt=None, tenant_id=None,
               external_gateway_info=None, set_context=False,
               **kwargs):
        router = self._make_router(fmt or self.fmt, tenant_id, name,
                                   admin_state_up, external_gateway_info,
                                   set_context, **kwargs)
        yield router

    def _set_net_external(self, net_id):
        self._update('networks', net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}})

    def _create_floatingip(self, fmt, network_id, port_id=None,
                           fixed_ip=None, set_context=False,
                           floating_ip=None, subnet_id=None,
                           tenant_id=None, **kwargs):
        tenant_id = tenant_id or self._tenant_id
        data = {'floatingip': {'floating_network_id': network_id,
                               'tenant_id': tenant_id}}
        if port_id:
            data['floatingip']['port_id'] = port_id
            if fixed_ip:
                data['floatingip']['fixed_ip_address'] = fixed_ip

        if floating_ip:
            data['floatingip']['floating_ip_address'] = floating_ip

        if subnet_id:
            data['floatingip']['subnet_id'] = subnet_id

        data['floatingip'].update(kwargs)

        floatingip_req = self.new_create_request('floatingips', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            floatingip_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return floatingip_req.get_response(self.ext_api)

    def _make_floatingip(self, fmt, network_id, port_id=None,
                         fixed_ip=None, set_context=False, tenant_id=None,
                         floating_ip=None, http_status=exc.HTTPCreated.code,
                         **kwargs):
        res = self._create_floatingip(fmt, network_id, port_id,
                                      fixed_ip, set_context, floating_ip,
                                      tenant_id=tenant_id, **kwargs)
        self.assertEqual(http_status, res.status_int)
        return self.deserialize(fmt, res)

    def _validate_floating_ip(self, fip):
        body = self._list('floatingips')
        self.assertEqual(1, len(body['floatingips']))
        self.assertEqual(body['floatingips'][0]['id'],
                         fip['floatingip']['id'])

        body = self._show('floatingips', fip['floatingip']['id'])
        self.assertEqual(body['floatingip']['id'],
                         fip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_with_assoc(self, port_id=None, fmt=None, fixed_ip=None,
                              public_cidr='11.0.0.0/24', set_context=False,
                              tenant_id=None, flavor_id=None, **kwargs):
        with self.subnet(cidr=public_cidr,
                         set_context=set_context,
                         tenant_id=tenant_id) as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            args_list = {'set_context': set_context,
                         'tenant_id': tenant_id}
            if flavor_id:
                args_list['flavor_id'] = flavor_id
            private_port = None
            if port_id:
                private_port = self._show('ports', port_id)
            with test_db_base_plugin_v2.optional_ctx(
                    private_port, self.port,
                    set_context=set_context,
                    tenant_id=tenant_id) as private_port:
                with self.router(**args_list) as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    floatingip = None

                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action(
                        'add', r['router']['id'],
                        private_sub['subnet']['id'], None)

                    floatingip = self._make_floatingip(
                        fmt or self.fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'],
                        fixed_ip=fixed_ip,
                        tenant_id=tenant_id,
                        set_context=set_context,
                        **kwargs)
                    yield floatingip

                    if floatingip:
                        self._delete('floatingips',
                                     floatingip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_no_assoc_with_public_sub(self, private_sub, fmt=None,
                                            set_context=False, public_sub=None,
                                            flavor_id=None, **kwargs):
        self._set_net_external(public_sub['subnet']['network_id'])
        args_list = {}
        if flavor_id:
            # NOTE(manjeets) Flavor id None is not accepted
            # and return Flavor None not found error. So for
            # neutron testing this argument should not be passed
            # at all to router.
            args_list['flavor_id'] = flavor_id
        with self.router(**args_list) as r:
            floatingip = None

            self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'])
            self._router_interface_action('add', r['router']['id'],
                                          private_sub['subnet']['id'],
                                          None)

            floatingip = self._make_floatingip(
                fmt or self.fmt,
                public_sub['subnet']['network_id'],
                set_context=set_context,
                **kwargs)
            yield floatingip, r

            if floatingip:
                self._delete('floatingips',
                             floatingip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_no_assoc(self, private_sub, fmt=None,
                            set_context=False, flavor_id=None, **kwargs):
        with self.subnet(cidr='12.0.0.0/24') as public_sub:
            with self.floatingip_no_assoc_with_public_sub(
                    private_sub, fmt, set_context, public_sub,
                    flavor_id, **kwargs) as (f, r):
                # Yield only the floating ip object
                yield f


class L3TestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3TestExtensionManagerWithDNS(L3TestExtensionManager):

    def get_resources(self):
        return l3.L3.get_resources()


class L3BaseForSepTests(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=None, ext_mgr=None):
        # the plugin without L3 support
        if not plugin:
            plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        if not ext_mgr:
            ext_mgr = L3TestExtensionManager()
        super(L3BaseForSepTests, self).setUp(plugin=plugin, ext_mgr=ext_mgr,
                                             service_plugins=service_plugins)

        self.setup_notification_driver()


class L3NatDBTestCaseMixin(object):
    """L3_NAT_dbonly_mixin specific test cases."""

    def setUp(self):
        super(L3NatDBTestCaseMixin, self).setUp()
        plugin = directory.get_plugin(plugin_constants.L3)
        if not isinstance(plugin, l3_db.L3_NAT_dbonly_mixin):
            self.skipTest("Plugin is not L3_NAT_dbonly_mixin")

    def test_create_router_gateway_fails(self):
        """Force _update_router_gw_info failure and see
        the exception is propagated.
        """

        plugin = directory.get_plugin(plugin_constants.L3)
        ctx = context.Context('', 'foo')

        class MyException(Exception):
            pass

        mock.patch.object(plugin, '_update_router_gw_info',
                          side_effect=MyException).start()
        with self.network() as n:
            data = {'router': {
                'name': 'router1', 'admin_state_up': True,
                'tenant_id': ctx.tenant_id,
                'external_gateway_info': {'network_id': n['network']['id']}}}

            self.assertRaises(MyException, plugin.create_router, ctx, data)
            # Verify router doesn't persist on failure
            routers = plugin.get_routers(ctx)
            self.assertEqual(0, len(routers))


class L3TestExtensionManagerWithDNS(L3TestExtensionManager):

    def get_resources(self):
        return l3.L3.get_resources()


class L3NatDBFloatingIpTestCaseWithDNSCcloud(L3BaseForSepTests, L3NatTestCaseMixin):
    """Unit tests for floating ip with external DNS integration"""

    fmt = 'json'
    DNS_NAME = 'test'
    DNS_DOMAIN = 'test-domain.org.'
    PUBLIC_CIDR = '11.0.0.0/24'
    PRIVATE_CIDR = '10.0.0.0/24'
    mock_client = mock.MagicMock()
    mock_admin_client = mock.MagicMock()
    MOCK_PATH = ('neutron.services.externaldns.drivers.'
                 'designate.driver_ccloud.get_clients')
    mock_config = {'return_value': (mock_client, mock_admin_client)}
    _extension_drivers = ['dns']

    def setUp(self):
        ext_mgr = L3TestExtensionManagerWithDNS()
        plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(L3NatDBFloatingIpTestCaseWithDNSCcloud, self).setUp(plugin=plugin,
                                                            ext_mgr=ext_mgr)
        cfg.CONF.set_override('external_dns_driver', 'designate_ccloud')
        self.mock_client.reset_mock()
        self.mock_admin_client.reset_mock()

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, set_context=False, tenant_id=None,
                        **kwargs):
        new_arg_list = ('dns_domain',)
        if arg_list is not None:
            new_arg_list = arg_list + new_arg_list
        return super(L3NatDBFloatingIpTestCaseWithDNSCcloud,
                     self)._create_network(fmt, name, admin_state_up,
                                           arg_list=new_arg_list,
                                           set_context=set_context,
                                           tenant_id=tenant_id,
                                           **kwargs)

    def _create_port(self, fmt, name, admin_state_up,
                     arg_list=None, set_context=False, tenant_id=None,
                     **kwargs):
        new_arg_list = ('dns_name',)
        if arg_list is not None:
            new_arg_list = arg_list + new_arg_list
        return super(L3NatDBFloatingIpTestCaseWithDNSCcloud,
                     self)._create_port(fmt, name, admin_state_up,
                                        arg_list=new_arg_list,
                                        set_context=set_context,
                                        tenant_id=tenant_id,
                                        **kwargs)

    def _create_net_sub_port(self, dns_domain='', dns_name=''):
        with self.network(dns_domain=dns_domain) as n:
            with self.subnet(cidr=self.PRIVATE_CIDR, network=n) as private_sub:
                with self.port(private_sub, dns_name=dns_name) as p:
                    return n, private_sub, p

    @contextlib.contextmanager
    def _create_floatingip_with_dns(self, net_dns_domain='', port_dns_name='',
                                    flip_dns_domain='', flip_dns_name='',
                                    assoc_port=False, private_sub=None):

        if private_sub is None:
            n, private_sub, p = self._create_net_sub_port(
                    dns_domain=net_dns_domain, dns_name=port_dns_name)

        data = {'fmt': self.fmt}
        data['dns_domain'] = flip_dns_domain
        data['dns_name'] = flip_dns_name

        # Set ourselves up to call the right function with
        # the right arguments for the with block
        if assoc_port:
            data['tenant_id'] = n['network']['tenant_id']
            data['port_id'] = p['port']['id']
            create_floatingip = self.floatingip_with_assoc
        else:
            data['private_sub'] = private_sub
            create_floatingip = self.floatingip_no_assoc

        with create_floatingip(**data) as flip:
            yield flip['floatingip']

    @contextlib.contextmanager
    def _create_floatingip_with_dns_on_update(self, net_dns_domain='',
            port_dns_name='', flip_dns_domain='', flip_dns_name=''):
        n, private_sub, p = self._create_net_sub_port(
            dns_domain=net_dns_domain, dns_name=port_dns_name)
        with self._create_floatingip_with_dns(flip_dns_domain=flip_dns_domain,
                flip_dns_name=flip_dns_name, private_sub=private_sub) as flip:
            flip_id = flip['id']
            data = {'floatingip': {'port_id': p['port']['id']}}
            req = self.new_update_request('floatingips', data, flip_id)
            res = req.get_response(self._api_for_resource('floatingip'))
            self.assertEqual(200, res.status_code)

            floatingip = self.deserialize(self.fmt, res)['floatingip']
            self.assertEqual(p['port']['id'], floatingip['port_id'])

            yield flip

    def _get_in_addr_zone_name(self, in_addr_name):
        units = self._get_bytes_or_nybles_to_skip(in_addr_name)
        return '.'.join(in_addr_name.split('.')[int(units):])

    def _get_bytes_or_nybles_to_skip(self, in_addr_name):
        if 'in-addr.arpa' in in_addr_name:
            return ((
                32 - cfg.CONF.designate.ipv4_ptr_zone_prefix_size) / 8)
        return (128 - cfg.CONF.designate.ipv6_ptr_zone_prefix_size) / 4

    def _get_in_addr(self, record):
        in_addr_name = netaddr.IPAddress(record).reverse_dns
        in_addr_zone_name = self._get_in_addr_zone_name(in_addr_name)
        return in_addr_name, in_addr_zone_name

    def _assert_recordset_created(self, floating_ip_address, floating_ip_id):
        # The recordsets.create function should be called with:
        # dns_domain, dns_name, 'A', ip_address ('A' for IPv4, 'AAAA' for IPv6)
        self.mock_client.recordsets.create.assert_called_with(self.DNS_DOMAIN,
            self.DNS_NAME, 'A', [floating_ip_address])
        in_addr_name, in_addr_zone_name = self._get_in_addr(
            floating_ip_address)
        self.mock_admin_client.reverse.set.assert_called_with(
            floating_ip_id,
            in_addr_zone_name)

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create(self, mock_args):
        with self._create_floatingip_with_dns():
            pass
        self.mock_client.recordsets.create.assert_not_called()
        self.mock_client.reverse.set.assert_not_called()
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_admin_client.reverse.set.assert_not_called()

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_flip_dns(self, mock_args):
        with self._create_floatingip_with_dns(flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'], floatingip["id"])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_net_port_dns(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain=self.DNS_DOMAIN,
                port_dns_name=self.DNS_NAME, assoc_port=True) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_flip_and_net_port_dns(self, mock_args):
        # If both network+port and the floating ip have dns domain and
        # dns name, floating ip's information should take priority
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain='junkdomain.org.',
                port_dns_name='junk', flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME, assoc_port=True) as flip:
            floatingip = flip
        # External DNS service should have been called with floating ip's
        # dns information, not the network+port's dns information
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])

        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port(self, mock_args):
        with self._create_floatingip_with_dns_on_update():
            pass
        self.mock_client.recordsets.create.assert_not_called()
        self.mock_client.reverse.set.assert_not_called()
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_admin_client.reverse.set.assert_not_called()

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_flip_dns(self, mock_args):
        with self._create_floatingip_with_dns_on_update(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_net_port_dns(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns_on_update(
                net_dns_domain=self.DNS_DOMAIN,
                port_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_flip_and_net_port_dns(self,
                                                                  mock_args):
        # If both network+port and the floating ip have dns domain and
        # dns name, floating ip's information should take priority
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns_on_update(
                net_dns_domain='junkdomain.org.',
                port_dns_name='junk',
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_disassociate_port(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain=self.DNS_DOMAIN,
                port_dns_name=self.DNS_NAME, assoc_port=True) as flip:
            fake_recordset = {'id': '',
                    'records': [flip['floating_ip_address']]}
            # This method is called during recordset deletion, which
            # will fail unless the list function call returns something like
            # this fake value
            self.mock_client.recordsets.list.return_value = ([fake_recordset])
            # Port gets disassociated if port_id is not in the request body
            data = {'floatingip': {}}
            req = self.new_update_request('floatingips', data, flip['id'])
            res = req.get_response(self._api_for_resource('floatingip'))
        floatingip = self.deserialize(self.fmt, res)['floatingip']
        flip_port_id = floatingip['port_id']
        self.assertEqual(200, res.status_code)
        self.assertIsNone(flip_port_id)
        self.mock_client.recordsets.delete.assert_called_with(
            self.DNS_DOMAIN, '')
        self.mock_admin_client.reverse.unset.assert_called_with(flip_port_id)

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_delete(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(flip_dns_domain=self.DNS_DOMAIN,
                                              flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
            # This method is called during recordset deletion, which will
            # fail unless the list function call returns something like
            # this fake value
            fake_recordset = {'id': '',
                              'records': [floatingip['floating_ip_address']]}
            self.mock_client.recordsets.list.return_value = [fake_recordset]
        self.mock_client.recordsets.delete.assert_called_with(
                self.DNS_DOMAIN, '')
        self.mock_admin_client.reverse.unset.assert_called_with(flip["id"])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_no_PTR_record(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)

        # Disabling this option should stop the admin client from creating
        # PTR records. So set this option and make sure the admin client
        # wasn't called to create any records
        cfg.CONF.set_override('allow_reverse_dns_lookup', False,
                              group='designate')

        with self._create_floatingip_with_dns(flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip

        self.mock_client.recordsets.create.assert_called_with(self.DNS_DOMAIN,
                self.DNS_NAME, 'A', [floatingip['floating_ip_address']])
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_admin_client.reverse.set.assert_not_called()
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

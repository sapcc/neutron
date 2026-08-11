# Copyright 2025 SAP SE
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

from unittest import mock

from designateclient import exceptions as d_exc
from designateclient.v2.base import DesignateList
from oslo_config import cfg

from neutron.tests.unit.extensions.test_l3\
    import L3NatDBFloatingIpTestCaseWithDNS
from neutron.tests.unit.extensions.test_l3\
    import L3TestExtensionManagerWithDNS

from neutron.services.externaldns.drivers.designate import driver_ccloud

from .test_driver import TestDesignateDriver


class L3NatDBFloatingIpTestCaseWithDNSCcloud(L3NatDBFloatingIpTestCaseWithDNS):
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
        super(L3NatDBFloatingIpTestCaseWithDNS, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)
        cfg.CONF.set_override('external_dns_driver', 'designate_ccloud')
        self.mock_client.reset_mock()
        self.mock_admin_client.reset_mock()

    def _assert_recordset_created(self, floating_ip_address, floating_ip_id):
        # The recordsets.create function should be called with:
        # dns_domain, dns_name, 'A', ip_address ('A' for IPv4, 'AAAA' for IPv6)
        self.mock_client.recordsets.create.assert_called_with(
            self.DNS_DOMAIN,
            self.DNS_NAME,
            'A',
            [floating_ip_address]
        )
        self.mock_client.floatingips.set.assert_called_with(
            f"{None}:{floating_ip_id}",
            f"{self.DNS_NAME}.{self.DNS_DOMAIN}")

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create(self, mock_args):
        with self._create_floatingip_with_dns():
            pass
        self.mock_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_flip_dns(self, mock_args):
        with self._create_floatingip_with_dns(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_net_port_dns(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain=self.DNS_DOMAIN,
                                              port_dns_name=self.DNS_NAME,
                                              assoc_port=True) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_flip_and_net_port_dns(self, mock_args):
        # If both network+port and the floating ip have dns domain and
        # dns name, floating ip's information should take priority
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain='junkdomain.org.',
                                              port_dns_name='junk',
                                              flip_dns_domain=self.DNS_DOMAIN,
                                              flip_dns_name=self.DNS_NAME,
                                              assoc_port=True) as flip:
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
        self.mock_client.floatingips.set.assert_not_called()
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()

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
        in_addr_name, in_addr_zone_name = self._get_in_addr(
            floatingip['floating_ip_address'])
        self.mock_client.recordsets.delete.assert_called_with(
            self.DNS_DOMAIN, '')
        self.mock_admin_client.recordsets.delete.assert_called_with(
            in_addr_zone_name, in_addr_name)

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_delete(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
            # This method is called during recordset deletion, which will
            # fail unless the list function call returns something like
            # this fake value
            fake_recordset = {'id': '',
                              'records': [floatingip['floating_ip_address']]}
            self.mock_client.recordsets.list.return_value = [fake_recordset]
        in_addr_name, in_addr_zone_name = self._get_in_addr(
                floatingip['floating_ip_address'])
        self.mock_client.recordsets.delete.assert_called_with(
                self.DNS_DOMAIN, '')
        self.mock_admin_client.recordsets.delete.assert_called_with(
                in_addr_zone_name, in_addr_name)

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_no_PTR_record(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)

        # Disabling this option should stop the admin client from creating
        # PTR records. So set this option and make sure the admin client
        # wasn't called to create any records
        cfg.CONF.set_override('allow_reverse_dns_lookup', False,
                              group='designate')

        with self._create_floatingip_with_dns(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME
        ) as flip:
            floatingip = flip

        self.mock_client.recordsets.create.assert_called_with(
            self.DNS_DOMAIN, self.DNS_NAME, 'A',
            [floatingip['floating_ip_address']]
        )
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])


class _PaginatedList(DesignateList):
    """A DesignateList carrying a 'next' link, as the client returns it."""

    def __init__(self, items, next_page=False, next_link_criterion=None):
        super().__init__(items)
        self.next_page = next_page
        self.next_link_criterion = next_link_criterion or {}


class TestCCloudDesignateDriver(TestDesignateDriver):
    def setUp(self):
        # skip our parents setup and call its parent instead:
        super(TestDesignateDriver, self).setUp()
        self.context = mock.Mock()
        self.context.project_id = 'tenant-1'
        self.context.is_admin = False
        self.client = mock.Mock()
        self.admin_client = mock.Mock()
        self.all_projects_client = mock.Mock()
        self.fallback_client = mock.Mock()
        mock.patch.object(driver_ccloud, 'get_clients', return_value=(
            self.client, self.admin_client)).start()
        mock.patch.object(driver_ccloud, 'get_all_projects_client',
                          return_value=self.all_projects_client).start()
        mock.patch.object(
            driver_ccloud, 'get_all_projects_edit_managed_client',
            return_value=(self.client, self.fallback_client)).start()
        self.driver = driver_ccloud.DesignateCcloud()

    def test_create_record_set_duplicate_recordset(self):
        # The Ccloud driver updates on conflict instead of raising,
        # in contrast to the default driver.
        self.client.recordsets.create.side_effect = d_exc.Conflict
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.create_record_set(self.context, 'example.test.',
                                      'test', ['192.168.0.10'])

        self.client.recordsets.update.assert_called_once_with(
            'example.test.', 'test.example.test.',
            {'records': ['192.168.0.10']})

    def test_delete_record_set_owner_path(self):
        # User's own client sees the zone: delete via that client, no fallback.
        self.client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.client.recordsets.delete.assert_called_once_with(
            'example.test.', 123)
        self.fallback_client.recordsets.delete.assert_not_called()

    def test_delete_record_set_zone_not_found(self):
        # Neither the user nor the fallback can find the zone -> no-op, no
        # exception.
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.fallback_client.zones.list.return_value = []
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.fallback_client.recordsets.delete.assert_not_called()
        self.fallback_client.recordsets.update.assert_not_called()

    def test_delete_record_set_fallback_own_zone(self):
        # User can't see the zone via regular client (e.g. managed record),
        # but the zone belongs to their project -> fallback deletes it.
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.fallback_client.zones.list.return_value = [
            {'id': 'zone-1', 'name': 'example.test.',
             'project_id': 'tenant-1'},
        ]
        self.fallback_client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.fallback_client.recordsets.delete.assert_called_once_with(
            'zone-1', 123)

    def test_delete_record_set_fallback_admin_cross_project(self):
        # Privileged (admin) caller may clean a zone owned by another project
        # (admin-initiated cross-project FIP delete).
        self.context.is_admin = True
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.fallback_client.zones.list.return_value = [
            {'id': 'zone-other', 'name': 'example.test.',
             'project_id': 'tenant-2'},
        ]
        self.fallback_client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.fallback_client.recordsets.delete.assert_called_once_with(
            'zone-other', 123)

    def test_delete_record_set_fallback_rejects_foreign_zone(self):
        # SECURITY: a regular (non-admin) user must NOT be able to delete
        # records in a zone owned by another project, even when reusing the
        # same base domain and the same floating IP.
        self.context.is_admin = False
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.fallback_client.zones.list.return_value = [
            {'id': 'zone-victim', 'name': 'example.test.',
             'project_id': 'tenant-victim'},
        ]
        # Even if the recordset/IP would match, nothing must be deleted.
        self.fallback_client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.fallback_client.recordsets.delete.assert_not_called()
        self.fallback_client.recordsets.update.assert_not_called()

    def test_delete_record_set_fallback_shared_zone(self):
        # A zone owned by another project but shared with ours is usable by
        # us, so its records must still be cleaned up.
        self.context.is_admin = False
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.fallback_client.zones.list.return_value = [
            {'id': 'zone-shared', 'name': 'example.test.',
             'project_id': 'tenant-owner', 'shared': True},
        ]
        # the caller's own credentials can see the zone, which is only
        # possible if it has been shared with their project
        self.client.zones.list.return_value = [
            {'id': 'zone-shared', 'name': 'example.test.'},
        ]
        self.fallback_client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.fallback_client.recordsets.delete.assert_called_once_with(
            'zone-shared', 123)

    def test_delete_record_set_fallback_shared_with_other_project(self):
        # SECURITY: a zone shared with a *different* project must not be
        # cleaned by us.
        self.context.is_admin = False
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.fallback_client.zones.list.return_value = [
            {'id': 'zone-shared', 'name': 'example.test.',
             'project_id': 'tenant-owner', 'shared': True},
        ]
        # shared, but not with us: our own credentials cannot see the zone
        self.client.zones.list.return_value = []
        self.fallback_client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.fallback_client.recordsets.delete.assert_not_called()
        self.fallback_client.recordsets.update.assert_not_called()

    def test_delete_record_set_keeps_other_round_robin_records(self):
        # A hostname may carry several floating IPs (DNS round robin).
        # Removing one of them must only drop that address, not the whole
        # recordset.
        self.client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10', '192.168.0.11']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.client.recordsets.update.assert_called_once_with(
            'example.test.', 123, {'records': ['192.168.0.11']})
        self.client.recordsets.delete.assert_not_called()

    def test_delete_record_set_dual_stack(self):
        # A dual-stack port passes both addresses, while the A and AAAA
        # recordsets each hold only one of them; both must be deleted.
        self.client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
            {'id': 456, 'records': ['2001:db8:0:1::1']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10', '2001:db8:0:1::1'])

        self.client.recordsets.delete.assert_has_calls([
            mock.call('example.test.', 123),
            mock.call('example.test.', 456),
        ])

    def test_delete_record_set_normalizes_ipv6(self):
        # Designate may return an IPv6 address in a different textual form
        # than the one Neutron passes in.
        self.client.recordsets.list.return_value = [
            {'id': 456,
             'records': ['2001:0db8:0000:0001:0000:0000:0000:0001']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['2001:db8:0:1::1'])

        self.client.recordsets.delete.assert_called_once_with(
            'example.test.', 456)

    def test_delete_record_set_fallback_skips_non_matching_ip(self):
        # Within an owned zone, only the recordset whose records match the
        # IPs being removed is deleted.
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.fallback_client.zones.list.return_value = [
            {'id': 'zone-1', 'name': 'example.test.',
             'project_id': 'tenant-1'},
        ]
        self.fallback_client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
            {'id': 999, 'records': ['10.9.9.9']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.fallback_client.recordsets.delete.assert_called_once_with(
            'zone-1', 123)

    def test_delete_record_set_with_reverse_dns(self):
        self.client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
            {'id': 456, 'records': ['2001:db8:0:1::1']},
        ]

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10', '2001:db8:0:1::1'])

        # forward deletion via the owner client (zone found on first try)
        self.client.recordsets.delete.assert_has_calls([
            mock.call('example.test.', 123),
            mock.call('example.test.', 456),
        ])
        # PTR deletion via the all-projects/edit-managed client
        self.fallback_client.recordsets.delete.assert_has_calls([
            mock.call('0.168.192.in-addr.arpa.', '10.0.168.192.in-addr.arpa.'),
            mock.call(
                '0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.1.0.'
                '0.2.ip6.arpa.',
                '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.'
                '1.0.0.2.ip6.arpa.'),
        ])

    def test_delete_record_set_uses_max_limit(self):
        # Designate returns only default_limit_v2 (20) items unless a limit is
        # given; limit='max' raises that to max_limit_v2 (1000) so a single
        # request is normally enough.
        self.client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        self.assertEqual(1, self.client.recordsets.list.call_count)
        self.assertEqual(
            'max', self.client.recordsets.list.call_args[1]['limit'])

    def test_delete_record_set_follows_recordset_pagination(self):
        # Even with limit='max' a collection can exceed max_limit_v2, and the
        # client does not follow the 'next' link by itself, so the driver has
        # to do it or it would silently miss records.
        page1 = _PaginatedList(
            [{'id': 123, 'records': ['10.0.0.1']}],
            next_page=True, next_link_criterion={'marker': '123'})
        page2 = _PaginatedList([{'id': 456, 'records': ['192.168.0.10']}])
        self.client.recordsets.list.side_effect = [page1, page2]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        # the match only exists on the second page
        self.client.recordsets.delete.assert_called_once_with(
            'example.test.', 456)
        self.assertEqual(2, self.client.recordsets.list.call_count)
        # the marker from the 'next' link must be carried over
        self.assertEqual(
            {'name': 'test.example.test.', 'marker': '123'},
            self.client.recordsets.list.call_args_list[1][1]['criterion'])

    def test_delete_record_set_follows_zone_pagination(self):
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.fallback_client.zones.list.side_effect = [
            _PaginatedList(
                [{'id': 'zone-other', 'name': 'example.test.',
                  'project_id': 'tenant-2'}],
                next_page=True, next_link_criterion={'marker': 'zone-other'}),
            _PaginatedList(
                [{'id': 'zone-1', 'name': 'example.test.',
                  'project_id': 'tenant-1'}]),
        ]
        self.fallback_client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
        ]
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate')

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test', ['192.168.0.10'])

        # our zone is only on the second page; the foreign one is skipped
        self.fallback_client.recordsets.delete.assert_called_once_with(
            'zone-1', 123)

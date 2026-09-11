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

from pydantic import ValidationError

from neutron.objects.sci_objects import SCINetworkSettings
from neutron.tests import base


class TestSCINetworkSettings(base.BaseTestCase):
    """Tests for SCINetworkSettings pydantic model"""

    # ------------------------------------------------------------------------
    # model_validate tests
    # ------------------------------------------------------------------------

    def test_model_validate_with_none(self):
        """Verify model_validate with None returns default values"""
        settings = SCINetworkSettings.model_validate(None)

        self.assertIsNone(settings.dns_query_logging)
        self.assertIsNone(settings.dns_custom_upstreams)
        self.assertIsNone(settings.ntp_servers)

    def test_model_validate_with_empty_dict(self):
        """Verify model_validate with empty dict returns default values"""
        settings = SCINetworkSettings.model_validate({})

        self.assertIsNone(settings.dns_query_logging)
        self.assertIsNone(settings.dns_custom_upstreams)
        self.assertIsNone(settings.ntp_servers)

    def test_model_validate_with_valid_data(self):
        """Verify model_validate parses valid data correctly"""
        data = {
            'dns_query_logging': True,
            'dns_custom_upstreams': ['8.8.8.8', '8.8.4.4'],
            'ntp_servers': ['192.0.2.100', '2001:db8::1'],
        }
        settings = SCINetworkSettings.model_validate(data)

        self.assertTrue(settings.dns_query_logging)
        self.assertEqual(len(settings.dns_custom_upstreams), 2)
        self.assertEqual(len(settings.ntp_servers), 2)

    def test_model_validate_ignores_extra_fields(self):
        """Verify extra fields are ignored (for forward compatibility)"""
        data = {
            'dns_query_logging': False,
            'unknown_future_field': 'some_value',
            'another_unknown': 123,
        }
        settings = SCINetworkSettings.model_validate(data)

        self.assertFalse(settings.dns_query_logging)
        self.assertFalse(hasattr(settings, 'unknown_future_field'))
        self.assertFalse(hasattr(settings, 'another_unknown'))

    def test_model_validate_invalid_ip_raises_validation_error(self):
        """Verify invalid IP addresses raise ValidationError"""
        data = {
            'dns_custom_upstreams': ['not-an-ip-address'],
        }
        self.assertRaises(ValidationError,
                          SCINetworkSettings.model_validate, data)

    def test_model_validate_invalid_ntp_server_raises_validation_error(self):
        """Verify invalid NTP server IP raises ValidationError"""
        data = {
            'ntp_servers': ['192.0.2.1', 'invalid.hostname'],
        }
        self.assertRaises(ValidationError,
                          SCINetworkSettings.model_validate, data)

    # ------------------------------------------------------------------------
    # model_dump tests
    # ------------------------------------------------------------------------

    def test_model_dump_with_defaults(self):
        """Verify model_dump returns dict with None values for defaults"""
        settings = SCINetworkSettings()
        result = settings.model_dump()

        self.assertIsNone(result['dns_query_logging'])
        self.assertIsNone(result['dns_custom_upstreams'])
        self.assertIsNone(result['ntp_servers'])

    def test_model_dump_serializes_ips_to_strings(self):
        """Verify IP addresses are serialized to compressed strings"""
        settings = SCINetworkSettings(
            dns_custom_upstreams=['192.0.2.1', '2001:db8:0:0::1'],
            ntp_servers=['10.0.0.1'],
        )
        result = settings.model_dump()

        # Verify IPs are strings (not IP address objects)
        self.assertIsInstance(result['dns_custom_upstreams'][0], str)
        self.assertIsInstance(result['ntp_servers'][0], str)

        # Verify IPv6 is compressed
        self.assertEqual(result['dns_custom_upstreams'][0], '192.0.2.1')
        self.assertEqual(result['dns_custom_upstreams'][1], '2001:db8::1')
        self.assertEqual(result['ntp_servers'][0], '10.0.0.1')

    def test_model_dump_roundtrip(self):
        """Verify model_dump output can be parsed by model_validate"""
        original = SCINetworkSettings(
            dns_query_logging=True,
            dns_custom_upstreams=['8.8.8.8', '2001:4860:4860::8888'],
            ntp_servers=['192.0.2.100'],
        )
        dumped = original.model_dump()
        restored = SCINetworkSettings.model_validate(dumped)

        self.assertEqual(original.dns_query_logging,
                         restored.dns_query_logging)
        self.assertEqual(len(original.dns_custom_upstreams),
                         len(restored.dns_custom_upstreams))
        self.assertEqual(len(original.ntp_servers), len(restored.ntp_servers))

    # ------------------------------------------------------------------------
    # get_ntp_servers tests
    # ------------------------------------------------------------------------

    def test_get_ntp_servers_returns_default_when_none(self):
        """Verify get_ntp_servers returns default when ntp_servers is None"""
        settings = SCINetworkSettings()
        default = ['10.0.0.1', '10.0.0.2']

        result = settings.get_ntp_servers(default)

        self.assertEqual(default, result)

    def test_get_ntp_servers_returns_compressed_strings(self):
        """Verify get_ntp_servers returns compressed IP strings"""
        settings = SCINetworkSettings(
            ntp_servers=['192.0.2.100', '2001:db8:0000::0001']
        )

        result = settings.get_ntp_servers(default=[])

        self.assertEqual(result, ['192.0.2.100', '2001:db8::1'])

    def test_get_ntp_servers_returns_empty_list_when_set_empty(self):
        """Verify get_ntp_servers returns empty list (not default) when set"""
        settings = SCINetworkSettings(ntp_servers=[])

        result = settings.get_ntp_servers(default=['10.0.0.1'])

        self.assertEqual([], result)

    # ------------------------------------------------------------------------
    # get_dns_custom_upstreams tests
    # ------------------------------------------------------------------------

    def test_get_dns_custom_upstreams_returns_default_when_none(self):
        """Verify get_dns_custom_upstreams returns default when None"""
        settings = SCINetworkSettings()
        default = ['8.8.8.8']

        result = settings.get_dns_custom_upstreams(default)

        self.assertEqual(default, result)

    def test_get_dns_custom_upstreams_returns_compressed_strings(self):
        """Verify get_dns_custom_upstreams returns compressed IP strings"""
        settings = SCINetworkSettings(
            dns_custom_upstreams=['192.0.2.10', '2001:db8:0:0:0:0:0:1']
        )

        result = settings.get_dns_custom_upstreams(default=[])

        self.assertEqual(result, ['192.0.2.10', '2001:db8::1'])

    def test_get_dns_custom_upstreams_returns_empty_list_when_set_empty(self):
        """Verify empty list is returned (not default) when explicitly set"""
        settings = SCINetworkSettings(dns_custom_upstreams=[])

        result = settings.get_dns_custom_upstreams(default=['8.8.8.8'])

        self.assertEqual([], result)

    # ------------------------------------------------------------------------
    # get_dns_query_logging tests
    # ------------------------------------------------------------------------

    def test_get_dns_query_logging_returns_default_when_none(self):
        """Verify get_dns_query_logging returns default when None"""
        settings = SCINetworkSettings()

        self.assertTrue(settings.get_dns_query_logging(default=True))
        self.assertFalse(settings.get_dns_query_logging(default=False))

    def test_get_dns_query_logging_returns_value_when_set(self):
        """Verify get_dns_query_logging returns set value, not default"""
        settings_true = SCINetworkSettings(dns_query_logging=True)
        settings_false = SCINetworkSettings(dns_query_logging=False)

        # Value should override default
        self.assertTrue(settings_true.get_dns_query_logging(default=False))
        self.assertFalse(settings_false.get_dns_query_logging(default=True))

    # ------------------------------------------------------------------------
    # Direct construction tests
    # ------------------------------------------------------------------------

    def test_direct_construction_with_string_ips(self):
        """Verify IPs passed as strings are converted to IP objects"""
        settings = SCINetworkSettings(
            dns_custom_upstreams=['192.0.2.1'],
            ntp_servers=['10.0.0.1'],
        )

        # Internal representation should be IP address objects
        self.assertTrue(hasattr(settings.dns_custom_upstreams[0],
                                'compressed'))
        self.assertTrue(hasattr(settings.ntp_servers[0],
                                'compressed'))

    def test_direct_construction_validates_ips(self):
        """Verify invalid IPs raise ValidationError on construction"""
        self.assertRaises(
            ValidationError,
            SCINetworkSettings,
            dns_custom_upstreams=['not-an-ip']
        )

    def test_ipv4_and_ipv6_mixed(self):
        """Verify both IPv4 and IPv6 addresses work together"""
        settings = SCINetworkSettings(
            dns_custom_upstreams=['192.0.2.1', '2001:db8::1'],
            ntp_servers=['10.0.0.1', '::1'],
        )

        upstreams = settings.get_dns_custom_upstreams(default=[])
        ntp = settings.get_ntp_servers(default=[])

        self.assertIn('192.0.2.1', upstreams)
        self.assertIn('2001:db8::1', upstreams)
        self.assertIn('10.0.0.1', ntp)
        self.assertIn('::1', ntp)

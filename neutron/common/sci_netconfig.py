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

# pylint: disable=no-name-in-module
# required for:
# E0611: No name 'BaseModel' in module 'pydantic' (no-name-in-module)
# E0611: No name 'IPvAnyAddress' in module 'pydantic' (no-name-in-module)

from __future__ import annotations


from pydantic import BaseModel
from pydantic import IPvAnyAddress
from pydantic import field_serializer


class SCINetworkSettings(BaseModel):
    """Settings for a specific network to be sent via rpc

    No sets or non trivial datatypes should be used.
    Additional fields are ignored by default in pydantic 1.10 when
    deserializing. This allows easy migration, where the server side
    can be updated before the agents.
    """

    dns_query_logging: bool | None = None
    dns_custom_upstreams: list[IPvAnyAddress] | None = None
    ntp_servers: list[IPvAnyAddress] | None = None

    @field_serializer('ntp_servers', 'dns_custom_upstreams')
    def serialize_ips(self, ips: list[IPvAnyAddress]|None) -> list[str]|None:
        if ips is None:
            return None
        return [ip.compressed for ip in ips]

    @classmethod
    def model_validate(cls, data: dict | None, *args,
                       **kwargs) -> SCINetworkSettings:
        """Returns settings, all values are defaults when None is given.
        """
        if data is None:
            data = {}
        return super().model_validate(data, *args, **kwargs)

    def get_ntp_servers(self, default) -> list[str]:
        """Returns a list of NTP servers when set, or default."""
        if self.ntp_servers is None:
            return default
        return [ip.compressed for ip in self.ntp_servers]

    def get_dns_query_logging(self, default: bool) -> bool:
        """Returns if DNS query logging is enabled or default if not set."""
        if self.dns_query_logging is None:
            return default
        return self.dns_query_logging

    def get_dns_custom_upstreams(self, default) -> list[str]:
        """Returns DNS forwarders if set, or default."""
        if self.dns_custom_upstreams is None:
            return default
        return [ip.compressed for ip in self.dns_custom_upstreams]

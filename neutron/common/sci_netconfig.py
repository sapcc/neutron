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

from typing import Any

from pydantic import BaseModel
from pydantic import IPvAnyAddress


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

    def dict(self, *args, **kwargs) -> dict[str, Any]:
        """returns a dictionary ensuring IP adresses are strings
        """
        # for pydantic 2 we would use something like:
        # @field_serializer('ips')
        # def serialize_ips(self, ips: List[IPvAnyAddress]) -> List[str]:
        #     return [str(ip) for ip in ips]
        d = super().dict(*args, **kwargs)
        if values := d.get('dns_custom_upstreams'):
            d['dns_custom_upstreams'] = [ip.compressed for ip in values]
        if values := d.get('ntp_servers'):
            d['ntp_servers'] = [ip.compressed for ip in values]
        return d

    def model_dump(self) -> dict[str, Any]:
        """returns the object as a dictionary,
        make migration to pydantic 2 easier by providing this wrapper
        """
        return self.dict()

    @classmethod
    def model_validate(cls, data: dict | None) -> SCINetworkSettings:
        """return settings, all values are defaults when None is given.
        Extra fields are ignored by default in pydantic 1.10
        """
        if data is None:
            data = {}
        return cls.parse_obj(data)

    def get_ntp_servers(self, default) -> list[str]:
        """returns a list of NTP servers or default if not set
        """
        if self.ntp_servers is None:
            return default
        return [ip.compressed for ip in self.ntp_servers]

    def get_dns_query_logging(self, default: bool) -> bool:
        """returns if dns query logging is enabled or default if not set
        """
        if self.dns_query_logging is None:
            return default
        return self.dns_query_logging

    def get_dns_custom_upstreams(self, default) -> list[str]:
        """returns dns forwarders or default if not set
        """
        if self.dns_custom_upstreams is None:
            return default
        return [ip.compressed for ip in self.dns_custom_upstreams]

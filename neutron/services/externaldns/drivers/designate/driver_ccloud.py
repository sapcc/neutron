# Copyright (c) 2016 IBM
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

import netaddr

from designateclient import exceptions as d_exc
from designateclient.v2 import client as d_client
from keystoneauth1.identity.generic import password
from keystoneauth1 import loading
from keystoneauth1 import token_endpoint
from oslo_config import cfg
from oslo_log import log

from neutron.conf.services import extdns_designate_driver
from neutron.services.externaldns import driver

IPV4_PTR_ZONE_PREFIX_MIN_SIZE = 8
IPV4_PTR_ZONE_PREFIX_MAX_SIZE = 24
IPV6_PTR_ZONE_PREFIX_MIN_SIZE = 4
IPV6_PTR_ZONE_PREFIX_MAX_SIZE = 124

_SESSION = None

CONF = cfg.CONF
extdns_designate_driver.register_designate_opts()

LOG = log.getLogger(__name__)


def get_clients(context, all_projects=False, edit_managed=False):
    global _SESSION

    if not _SESSION:
        _SESSION = loading.load_session_from_conf_options(
            CONF, 'designate')

    auth = token_endpoint.Token(CONF.designate.url, context.auth_token)
    client = d_client.Client(session=_SESSION, auth=auth)
    if CONF.designate.auth_type:
        admin_auth = loading.load_auth_from_conf_options(
            CONF, 'designate')
    else:
        # TODO(tkajinam): Make this fail when admin_* parameters are removed.
        admin_auth = password.Password(
            auth_url=CONF.designate.admin_auth_url,
            username=CONF.designate.admin_username,
            password=CONF.designate.admin_password,
            tenant_name=CONF.designate.admin_tenant_name,
            tenant_id=CONF.designate.admin_tenant_id)
    admin_client = d_client.Client(session=_SESSION, auth=admin_auth,
                                   endpoint_override=CONF.designate.url,
                                   all_projects=all_projects,
                                   edit_managed=edit_managed)
    return client, admin_client


def get_all_projects_client(context):
    auth = token_endpoint.Token(CONF.designate.url, context.auth_token)
    return d_client.Client(session=_SESSION, auth=auth, all_projects=True)


def get_all_projects_edit_managed_client(context):
    return get_clients(context, all_projects=True, edit_managed=True)


class Designate(driver.ExternalDNSService):
    """Ccloud Driver for Designate."""

    def create_record_set(self):
        pass

    def delete_record_set(self):
        pass

    def create_ptr_record(self, context, dns_domain, fip_id):
        designate, designate_admin = get_clients(context)
        designate.reverse.set(fip_id, dns_domain)

    def delete_ptr_record(self, context, fip_id):
        client, admin_client = get_clients(context)
        admin_client.reverse.unset(fip_id)

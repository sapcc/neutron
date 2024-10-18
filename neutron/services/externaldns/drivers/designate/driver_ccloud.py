import netaddr

from designateclient import exceptions as d_exc
from designateclient.v2 import client as d_client
from keystoneauth1.identity.generic import password
from keystoneauth1 import loading
from keystoneauth1 import token_endpoint
from neutron_lib import constants
from neutron_lib.exceptions import dns as dns_exc
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


class DesignateCcloud(driver.ExternalDNSService):
    """Driver for Designate."""

    ccloud = True

    def __init__(self):
        ipv4_ptr_zone_size = CONF.designate.ipv4_ptr_zone_prefix_size
        ipv6_ptr_zone_size = CONF.designate.ipv6_ptr_zone_prefix_size

        if (ipv4_ptr_zone_size < IPV4_PTR_ZONE_PREFIX_MIN_SIZE or
                ipv4_ptr_zone_size > IPV4_PTR_ZONE_PREFIX_MAX_SIZE or
                (ipv4_ptr_zone_size % 8) != 0):
            raise dns_exc.InvalidPTRZoneConfiguration(
                parameter='ipv4_ptr_zone_size', number='8',
                maximum=str(IPV4_PTR_ZONE_PREFIX_MAX_SIZE),
                minimum=str(IPV4_PTR_ZONE_PREFIX_MIN_SIZE))

        if (ipv6_ptr_zone_size < IPV6_PTR_ZONE_PREFIX_MIN_SIZE or
                ipv6_ptr_zone_size > IPV6_PTR_ZONE_PREFIX_MAX_SIZE or
                (ipv6_ptr_zone_size % 4) != 0):
            raise dns_exc.InvalidPTRZoneConfiguration(
                parameter='ipv6_ptr_zone_size', number='4',
                maximum=str(IPV6_PTR_ZONE_PREFIX_MAX_SIZE),
                minimum=str(IPV6_PTR_ZONE_PREFIX_MIN_SIZE))

    def create_record_set(self, context, dns_domain, dns_name, floatingip_data):
        records = [str(r) for r in [floatingip_data['floating_ip_address']]]
        designate, designate_admin = get_clients(context)
        v4, v6 = self._classify_records(records)
        try:
            if v4:
                designate.recordsets.create(dns_domain, dns_name, 'A', v4)
            if v6:
                designate.recordsets.create(dns_domain, dns_name, 'AAAA', v6)
        except d_exc.NotFound:
            raise dns_exc.DNSDomainNotFound(dns_domain=dns_domain)
        except d_exc.Conflict:
            raise dns_exc.DuplicateRecordSet(dns_name=dns_name)
        except d_exc.OverQuota:
            raise dns_exc.ExternalDNSOverQuota(resource="recordset")

        if not CONF.designate.allow_reverse_dns_lookup:
            return
        # Set up the PTR records
        for record in records:
            in_addr_name = netaddr.IPAddress(record).reverse_dns
            in_addr_zone_name = self._get_in_addr_zone_name(in_addr_name)
            fip_id = floatingip_data["id"]
            designate_admin.reverse.set(fip_id, in_addr_zone_name)

    def _classify_records(self, records):
        v4 = []
        v6 = []
        for record in records:
            if netaddr.IPAddress(record).version == 4:
                v4.append(record)
            else:
                v6.append(record)
        return v4, v6

    def _get_in_addr_zone_name(self, in_addr_name):
        units = self._get_bytes_or_nybles_to_skip(in_addr_name)
        return '.'.join(in_addr_name.split('.')[units:])

    def _get_bytes_or_nybles_to_skip(self, in_addr_name):
        if 'in-addr.arpa' in in_addr_name:
            return int((constants.IPv4_BITS -
                        CONF.designate.ipv4_ptr_zone_prefix_size) / 8)
        return int((constants.IPv6_BITS -
                    CONF.designate.ipv6_ptr_zone_prefix_size) / 4)

    def delete_record_set(self, context, dns_domain, dns_name, floatingip_data):
        records = [str(r) for r in [floatingip_data['floating_ip_address']]]
        client, admin_client = get_clients(context)
        ids_to_delete = []
        try:
            # first try regular client:
            ids_to_delete = self._get_ids_ips_to_delete(
                dns_domain, '%s.%s' % (dns_name, dns_domain), records, client)
        except dns_exc.DNSDomainNotFound:
            # Try whether we have admin powers and can see all projects
            # and also handle managed records (to prevent leftover PTRs):
            client, admin_client = get_all_projects_edit_managed_client(
                context)
            try:
                ids_to_delete = self._get_ids_ips_to_delete(
                    dns_domain,
                    '%s.%s' % (dns_name, dns_domain),
                    records,
                    client)
            except dns_exc.DNSDomainNotFound:
                LOG.debug("The domain '%s' not found in Designate",
                          dns_domain)
        except d_exc.Forbidden:
            LOG.error("Cannot determine Designate record ids for "
                      "deletion of: '%(name)s.%(dom)s'",
                      {'name': dns_name, 'dom': dns_domain})

        for _id in ids_to_delete:
            try:
                client.recordsets.delete(dns_domain, _id)
            except (d_exc.Forbidden, d_exc.NotFound) as exc:
                LOG.error("Cannot delete Designate record with id %(recid)s in"
                          " domain: %(dom)s. Error: %(err)s",
                          {'recid': _id, 'dom': dns_domain, 'err': exc})

        if not CONF.designate.allow_reverse_dns_lookup:
            return

        # PTR records part
        client, admin_client = get_clients(context)
        admin_client.reverse.unset(floatingip_data["id"])

    def _get_ids_ips_to_delete(self, dns_domain, name, records,
                               designate_client):
        try:
            recordsets = designate_client.recordsets.list(
                dns_domain, criterion={"name": "%s" % name})
        except (d_exc.NotFound, d_exc.Forbidden):
            raise dns_exc.DNSDomainNotFound(dns_domain=dns_domain)
        ids = [rec['id'] for rec in recordsets]
        ips = [str(ip) for rec in recordsets for ip in rec['records']]
        if set(ips) != set(records):
            raise dns_exc.DuplicateRecordSet(dns_name=name)
        return ids

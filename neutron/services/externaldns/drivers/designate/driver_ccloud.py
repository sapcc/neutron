# Copyright (c) 2016 IBM
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


from designateclient import exceptions as d_exc
from designateclient.v2.base import DesignateList
from designateclient.v2 import client as d_client
from keystoneauth1 import loading
from keystoneauth1 import token_endpoint
import netaddr
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

PAGE_LIMIT = 'max'

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
    admin_auth = loading.load_auth_from_conf_options(CONF, 'designate')
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

    def __init__(self):
        super().__init__()
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

    def create_record_set(self, context, dns_domain, dns_name, records,
                          fip_id=None):
        """Create a record set in the specified zone.

        :param context: neutron api request context
        :type context: neutron_lib.context.Context
        :param dns_domain: the dns_domain where the record set will be created
        :type dns_domain: String
        :param dns_name: the name associated with the record set
        :type dns_name: String
        :param records: the records in the set
        :type records: List of Strings
        :param fip_id: Floating IP id
        :type fip_id: String
        :raises: neutron.extensions.dns.DNSDomainNotFound
                 neutron.extensions.dns.DuplicateRecordSet
        """
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
            fqdn = ".".join([dns_name, dns_domain])
            if v4:
                designate.recordsets.update(dns_domain, fqdn, {"records": v4})
            if v6:
                designate.recordsets.update(dns_domain, fqdn, {"records": v6})
        except d_exc.OverQuota:
            raise dns_exc.ExternalDNSOverQuota(resource="recordset")

        if not CONF.designate.allow_reverse_dns_lookup:
            return
        # Set up the PTR records
        if fip_id:
            designate.floatingips.set(
                f"{CONF.designate.region_name}:{fip_id}",
                f"{dns_name}.{dns_domain}"
            )
        else:
            # Set up the PTR records
            recordset_name = '%s.%s' % (dns_name, dns_domain)
            ptr_zone_email = 'admin@%s' % dns_domain[:-1]
            if CONF.designate.ptr_zone_email:
                ptr_zone_email = CONF.designate.ptr_zone_email
            for record in records:
                in_addr_name = netaddr.IPAddress(record).reverse_dns
                in_addr_zone_name = self._get_in_addr_zone_name(in_addr_name)
                in_addr_zone_description = (
                        'An %s zone for reverse lookups set up by Neutron.' %
                        '.'.join(in_addr_name.split('.')[-3:]))
                try:
                    # Since we don't delete in-addr zones, assume it already
                    # exists. If it doesn't, create it
                    designate_admin.recordsets.create(in_addr_zone_name,
                                                      in_addr_name, 'PTR',
                                                      [recordset_name])
                except d_exc.Conflict:
                    # It can happen that we have left-over or manually created
                    # PTR from before (e.g. by a project that was using same
                    # FIP). If PTR exists, update it even if it is 'managed'.
                    c_designate, c_designate_admin = get_clients(
                        context,
                        edit_managed=True
                    )
                    recordset_dict = {'records': [recordset_name]}
                    # Use own instance of admin client as a precaution
                    c_designate_admin.recordsets.update(in_addr_zone_name,
                                                        in_addr_name,
                                                        recordset_dict)
                except d_exc.NotFound:
                    # Note(jh): If multiple PTRs get created at the same time,
                    # the creation of the zone may fail with a conflict because
                    # it has already been created by a parallel job. So we
                    # ignore that error and try to create the recordset
                    # anyway. That call will still fail in the end if something
                    # is really broken. See bug 1891309.
                    try:
                        designate_admin.zones.create(
                            in_addr_zone_name, email=ptr_zone_email,
                            description=in_addr_zone_description)
                    except d_exc.Conflict:
                        LOG.debug('Conflict when trying to create PTR zone %s,'
                                  ' assuming it exists.',
                                  in_addr_zone_name)
                        pass
                    except d_exc.OverQuota:
                        raise dns_exc.ExternalDNSOverQuota(resource='zone')
                    designate_admin.recordsets.create(in_addr_zone_name,
                                                      in_addr_name, 'PTR',
                                                      [recordset_name])

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

    @staticmethod
    def _list_all_pages(function, criterion, args=None):
        """Fetch a full Designate collection, following pagination if needed.

        List responses are paginated: without a limit the API returns only
        [service:api] default_limit_v2 items (20 by default). Designate also
        accepts limit='max', which returns up to max_limit_v2 items (1000 by
        default) in a single response. The 'next' link is still
        followed as a correctness guard, because the client does not do it by
        itself -- it only exposes it on the returned DesignateList.
        """
        args = args or []
        criterion = dict(criterion)
        data = function(*args, criterion=dict(criterion), limit=PAGE_LIMIT)
        results = list(data)
        while isinstance(data, DesignateList) and data.next_page:
            criterion.update(data.next_link_criterion)
            data = function(*args, criterion=dict(criterion),
                            limit=PAGE_LIMIT)
            results.extend(data)
        return results

    def _list_recordsets(self, designate_client, zone_ref, fqdn):
        """List all recordsets with this name in a zone (by id or name)."""
        return self._list_all_pages(designate_client.recordsets.list,
                                    {'name': fqdn}, args=[zone_ref])

    @staticmethod
    def _normalize_ips(values):
        """Normalize record values so addresses compare independent of format.

        Designate may return an address in a different textual representation
        than the one Neutron passes in (most notably for IPv6, e.g.
        '2001:db8:0:1::1' vs its expanded form), so comparing raw strings
        would miss matches. Values that are not valid addresses are kept
        verbatim.
        """
        normalized = set()
        for value in values:
            try:
                normalized.add(netaddr.IPAddress(value))
            except (ValueError, netaddr.AddrFormatError):
                normalized.add(value)
        return normalized

    def _zone_usable_by_project(self, user_client, zone, context):
        """Whether the caller owns the zone, or it is shared with them.

        Designate can share a zone with another project, and records in such a
        zone legitimately belong to the target project, so an ownership check
        on project_id alone would refuse to clean them up and leave orphaned
        records behind.
        """
        if zone.get('project_id') == context.project_id:
            return True
        if not zone.get('shared'):
            return False
        try:
            visible = self._list_all_pages(user_client.zones.list,
                                           {'name': zone['name']})
        except (d_exc.NotFound, d_exc.Forbidden):
            return False
        return any(seen.get('id') == zone['id'] for seen in visible)

    def _prune_recordsets(self, designate_client, zone_ref, recordsets,
                          target_records):
        """Remove only the records that belong to the resource being deleted.

        SECURITY: a recordset is only touched when at least one of its records
        matches an address being removed. Together with the zone
        ownership/share check in _delete_in_scoped_zone this is what stops an
        unprivileged caller from removing an unrelated recordset that merely
        shares the same FQDN. It relies on a floating IP being globally unique
        on the platform at any point in time. For a privileged (admin) caller
        the address match is the only remaining guard, which is acceptable
        since that caller is trusted.

        A recordset may hold several addresses for the same hostname (DNS
        round robin). In that case only the matching addresses are removed and
        the recordset is updated; it is deleted only when every one of its
        records is being removed.
        """
        for rs in recordsets:
            rs_records = self._normalize_ips(rs['records'])
            ours = rs_records & target_records
            if not ours:
                continue
            try:
                if rs_records == ours:
                    designate_client.recordsets.delete(zone_ref, rs['id'])
                else:
                    remaining = sorted(str(ip) for ip in rs_records - ours)
                    designate_client.recordsets.update(
                        zone_ref, rs['id'], {'records': remaining})
            except (d_exc.Forbidden, d_exc.NotFound) as exc:
                LOG.error("Cannot delete Designate record %(recid)s in "
                          "%(zone)s: %(err)s",
                          {'recid': rs['id'], 'zone': zone_ref, 'err': exc})

    def delete_record_set(self, context, dns_domain, dns_name, records):
        client, admin_client = get_clients(context)
        fqdn = '%s.%s' % (dns_name, dns_domain)

        try:
            recordsets = self._list_recordsets(client, dns_domain, fqdn)
        except (d_exc.NotFound, d_exc.Forbidden):
            # The user's client cannot list the recordsets. This is reached
            # for the legitimate admin-initiated cross-project FIP delete, for
            # a regular user that has no DNS permission in their own project,
            # and for a malicious user trying to delete records in another
            # project's zone by reusing its base domain + floating IP. Do NOT
            # delete blindly; the scoped fallback enforces the zone
            # ownership/share and privilege rules.
            self._delete_in_scoped_zone(context, dns_domain, fqdn, records)
        else:
            # Owner path: the user's own client can see the zone, so the
            # lookup is scoped to their project. Prune with the same client.
            self._prune_recordsets(client, dns_domain, recordsets,
                                   self._normalize_ips(records))

        if not CONF.designate.allow_reverse_dns_lookup:
            return

        # PTR records part
        client, admin_client = get_all_projects_edit_managed_client(context)
        for record in records:
            in_addr_name = netaddr.IPAddress(record).reverse_dns
            in_addr_zone_name = self._get_in_addr_zone_name(in_addr_name)
            try:
                admin_client.recordsets.delete(in_addr_zone_name,
                                               in_addr_name)
            except (dns_exc.DNSDomainNotFound, d_exc.NotFound):
                LOG.debug("No '%s' PTR record was found in Designate.",
                          in_addr_name)
            except d_exc.Forbidden:
                LOG.error("Cannot delete '%s' PTR record.", in_addr_name)

    def _delete_in_scoped_zone(self, context, dns_domain, fqdn, records):
        """All-projects fallback with an authorization check.

        The all-projects client can see every project's zones, so deleting by
        name alone is unsafe: a regular user could remove records from another
        project's zone by reusing its base domain and floating IP (the IP
        match is attacker-controlled and is not sufficient on its own).

        Authorization rules:
          * a zone owned by, or shared with, the requesting project may be
            cleaned by that project (e.g. a managed record in your own zone
            the regular client could not edit, or a user without DNS
            permissions in their own project), or
          * a zone belonging to a different project may be cleaned only by a
            caller with cross-project access (admin) -- the admin-initiated
            cross-project floating IP delete.

        Deletion is performed by zone_id (not by name) to avoid ambiguous name
        resolution when the same zone name exists in multiple pools/projects
        (Designate zone uniqueness is (name, deleted, pool_id), excluding
        tenant_id).
        """
        user_client, admin_client = get_all_projects_edit_managed_client(
            context)
        target_records = self._normalize_ips(records)

        try:
            zones_to_clean = self._list_all_pages(admin_client.zones.list,
                                                  {'name': dns_domain})
        except (d_exc.NotFound, d_exc.Forbidden):
            zones_to_clean = []

        if not zones_to_clean:
            LOG.debug("Zone '%s' not found in Designate.", dns_domain)
            return

        if not context.is_admin:
            # Allow cleaning only in zones the requesting project owns or has
            # shared with it.
            zones_to_clean = [
                zone for zone in zones_to_clean
                if self._zone_usable_by_project(user_client, zone, context)]

            if not zones_to_clean:
                LOG.warning(
                    "Refusing cross-project DNS cleanup of '%(fqdn)s': zone "
                    "'%(dom)s' is neither owned by nor shared with project "
                    "%(proj)s (user %(user)s) and the caller has no "
                    "cross-project access.",
                    {'fqdn': fqdn, 'dom': dns_domain,
                     'proj': context.project_id,
                     'user': getattr(context, 'user_id', None)})
                return

        for zone in zones_to_clean:
            zone_id = zone['id']
            try:
                recordsets = self._list_recordsets(admin_client, zone_id,
                                                   fqdn)
            except (d_exc.NotFound, d_exc.Forbidden):
                continue
            self._prune_recordsets(admin_client, zone_id, recordsets,
                                   target_records)

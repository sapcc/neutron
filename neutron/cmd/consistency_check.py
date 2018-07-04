import sys

from mock import MagicMock
from oslo_config import cfg
from oslo_log import log as logging
from requests.packages import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from neutron import context as ncontext
from neutron._i18n import _
from neutron.common import config
from neutron.common import rpc
from neutron.db import model_base
from neutron.db import servicetype_db as st_db
from neutron.plugins.common import constants
from neutron.services import provider_configuration as pconf
from neutron.services import service_base
from neutron_lbaas.db.loadbalancer import loadbalancer_dbv2

urllib3.disable_warnings(InsecureRequestWarning)

MYSQL_ENGINE = None
target_metadata = model_base.BASEV2.metadata
LOG = logging.getLogger(__name__)


def setup_conf():
    """Setup the cfg for the clean up utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during clean-up.
    """
    opts = [
        cfg.BoolOpt('fix_provider',
                    default=False,
                    help=_('Try fixing missing provider')),
        cfg.BoolOpt('fix_agents',
                    default=False,
                    help=_('Try fixing missing agent by rescheduling the lbs'))
    ]

    conf = cfg.CONF
    conf.register_cli_opts(opts)
    return conf


def add_provider_configuration(type_manager, service_type):
    type_manager.add_provider_configuration(
        service_type,
        pconf.ProviderConfiguration('neutron_lbaas'))


class ConsistenyCheck(object):
    def __init__(self):
        self.conf = setup_conf()
        self.conf()
        config.setup_logging()
        rpc.init(self.conf)
        self.agent_notifiers = MagicMock()

        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        add_provider_configuration(
            self.service_type_manager, constants.LOADBALANCERV2)

        self.drivers, self.default_provider = service_base.load_drivers(
            constants.LOADBALANCERV2, self)

        self.db = loadbalancer_dbv2.LoadBalancerPluginDbv2()
        self.ctx = ncontext.get_admin_context()

    def _check_provider(self, loadbalancers):
        LOG.info("Default Provider is %s" % self.default_provider)
        providers = set(
            [lb for lb in loadbalancers
             if not lb.provider or lb.provider.provider_name != self.default_provider])
        # resources are left without provider - stop the service
        if providers:
            LOG.warn("%d LBs without or wrong provider: %s" %
                     (len(providers), ','.join(map(lambda x: x.id, providers))))

            if self.conf.fix_provider:
                LOG.warn("Running with --fix_it, trying to set providers to %s" % self.default_provider)
                for lb in providers:
                    LOG.warn("Setting default provider for lb %s", lb.id)
                    self.service_type_manager.add_resource_association(
                        self.ctx,
                        constants.LOADBALANCERV2,
                        self.default_provider, lb.id)
            else:
                LOG.warn("Errors detected, if you like I could try to fix it (rerun with --fix_provider)")

    def _check_agent(self, loadbalancers):
        agents = set(
            [lb for lb in loadbalancers
             if not self.db.get_agent_hosting_loadbalancer(self.ctx, lb.id)]
        )
        if agents:
            LOG.warn("%d LBs without agent: %s" %
                     (len(agents), ','.join(map(lambda x: x.id, agents))))
            if self.conf.fix_agents and self.default_provider == "f5networks":
                LOG.warn("Running with --fix_it, scheduling an agent from %s provider" % self.default_provider)
                scheduler = self.drivers[self.default_provider].f5.scheduler

                for lb in agents:
                    agent = scheduler.schedule(self, self.ctx, lb.id, 'Project')
                    LOG.info("LB %s scheduled to agent %s" % (lb.id, agent))
            else:
                LOG.warn("Errors detected, if you like I could try to fix it (rerun with --fix_agents)")

    def main(self):
        LOG.info("Getting all Loadbalancers from neutron")
        loadbalancers = self.db.get_loadbalancers(self.ctx)
        LOG.info("Got %d LBs" % len(loadbalancers))
        self._check_provider(loadbalancers)
        self._check_agent(loadbalancers)


def main():
    c = ConsistenyCheck()
    c.main()


if __name__ == "__main__":
    sys.exit(main())

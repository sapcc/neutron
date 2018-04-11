import oslo_messaging
import sys
import socket

from neutron.common import rpc as n_rpc
from neutron.common import config as common_config
from neutron.common import topics
from neutron import context



def main():
    common_config.init(sys.argv[1:])

    ready = DHCPReady()
    if ready.check_readyness():
        sys.exit(0)
    else:
        sys.exit(1)

class DHCPReady(object):
    def __init__(self):
        self.host = socket.gethostname()
        target = oslo_messaging.Target(topic=topics.DHCP_AGENT, version='1.0', server=self.host)
        n_rpc.TRANSPORT.conf.rpc_response_timeout = 5
        self.client = n_rpc.get_client(target)
        self.context = context.get_admin_context_without_session()

    def check_readyness(self):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'dhcp_agent_ready')

if __name__ == "__main__":
    sys.exit(main())

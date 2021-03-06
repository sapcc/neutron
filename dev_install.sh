#!/bin/sh

set -xe

apt update && apt install -y haproxy git
git init
python setup.py install
neutron-dhcp-agent --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/dhcp_agent.ini
# neutron-server --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/neutron_lbaas.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini  --config-file /etc/neutron/plugins/ml2/ml2_conf_f5.ini --config-file /etc/neutron/plugins/ml2/ml2-conf-aci.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_asr.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_manila.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_arista.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_asr1k.ini --config-file /etc/neutron/plugins/cisco/cisco_device_manager_plugin.ini --config-file /etc/neutron/plugins/cisco/cisco_router_plugin.ini
# Copyright 2018 OpenStack Foundation
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

"""sapcc: neutron postgres missing indices

Revision ID: e1dd4eb0d598
Revises: 0e66c5227a8a
Create Date: 2018-06-25 14:49:49.907235

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = 'e1dd4eb0d598'
down_revision = '0e66c5227a8a'


def upgrade():
    op.create_index('ipallocations_port_id_idx',
                    'ipallocations', ['port_id'],
                    unique=False)
    op.create_index('ports_device_id_idx',
                    'ports', ['device_id'],
                    unique=False)
    op.create_index('ports_network_id_idx',
                    'ports', ['network_id'],
                    unique=False)
    op.create_index('securitygrouprules_security_group_id_idx',
                    'securitygrouprules', ['security_group_id'],
                    unique=False)
    op.create_index('subnets_network_id_idx',
                    'subnets', ['network_id'],
                    unique=False)
    op.create_index('ml2_network_segments_network_id_idx',
                    'ml2_network_segments', ['network_id'],
                    unique=False)
    op.create_index('ipallocationpools_subnet_id_idx',
                    'ipallocationpools', ['subnet_id'],
                    unique=False)
    op.create_index('standardattributes_id_uindex',
                    'standardattributes', ['id'],
                    unique=True)
    op.create_index('ix_networkrbacs_object_id',
                    'networkrbacs', ['object_id'],
                    unique=False)
    op.create_index('ix_networkrbacs_target_tenant',
                    'networkrbacs', ['target_tenant'],
                    unique=False)
    op.create_index('ml2_port_bindings_port_id_idx',
                    'ml2_port_bindings', ['port_id'],
                    unique=False)
    op.create_index('securitygroupportbindings_port_id_index',
                    'securitygroupportbindings', ['port_id'],
                    unique=False)
    op.create_index('securitygroupportbindings_security_group_id_index',
                    'securitygroupportbindings', ['security_group_id'],
                    unique=False)


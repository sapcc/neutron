# Copyright 2024 OpenStack Foundation
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

from alembic import op


"""Add missing indexes on ports.name and ml2_port_binding_levels(host, driver)

Revision ID: b9f3a2c8d501
Revises: 0e6eff810791
Create Date: 2024-09-15 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'b9f3a2c8d501'
down_revision = '0e6eff810791'


def upgrade():
    op.create_index(
        'ix_ports_name',
        'ports',
        ['name'],
    )
    op.create_index(
        'ix_ml2_port_binding_levels_host_driver',
        'ml2_port_binding_levels',
        ['host', 'driver'],
    )

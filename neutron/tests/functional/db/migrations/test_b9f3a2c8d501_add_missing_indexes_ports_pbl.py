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

from oslo_db.sqlalchemy import utils as db_utils

from neutron.tests.functional.db import test_migrations


def _has_index(engine, table, columns):
    for idx in db_utils.get_indexes(engine, table):
        if idx['column_names'] == list(columns):
            return True
    return False


class TestAddMissingIndexesMixin(object):

    def _pre_upgrade_b9f3a2c8d501(self, engine):
        self.assertFalse(_has_index(engine, 'ports', ['name']))
        self.assertFalse(_has_index(engine, 'ml2_port_binding_levels',
                                    ['host', 'driver']))

    def _check_b9f3a2c8d501(self, engine, data):
        self.assertTrue(_has_index(engine, 'ports', ['name']))
        self.assertTrue(_has_index(engine, 'ml2_port_binding_levels',
                                   ['host', 'driver']))


class TestAddMissingIndexesMySQL(
        TestAddMissingIndexesMixin,
        test_migrations.TestWalkMigrationsMySQL):
    pass


class TestAddMissingIndexesPostgreSQL(
        TestAddMissingIndexesMixin,
        test_migrations.TestWalkMigrationsPostgreSQL):
    pass

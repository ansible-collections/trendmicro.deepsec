# Copyright (c) 2022 Red Hat
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import tempfile
import unittest

from ansible.playbook.task import Task
from ansible.template import Templar
from ansible_collections.ansible.utils.tests.unit.compat.mock import MagicMock, patch

from ansible_collections.trendmicro.deepsec.plugins.action.deepsec_integrity_monitoring_rules import (
    ActionModule,
)


RESPONSE_PAYLOAD = {
    "integrity_monitoring_rules": [
        {
            "alert_enabled": False,
            "description": "THIS IS TEST IMR DESCRIPTION - 1",
            "id": "328",
            "minimum_agent_version": "6.0.0.0",
            "minimum_manager_version": "6.0.0",
            "name": "THIS IS TEST IMR - 1",
            "real_time_monitoring_enabled": True,
            "registry_attributes": ["STANDARD"],
            "registry_excluded_values": [""],
            "registry_include_default_value": True,
            "registry_include_sub_keys": False,
            "registry_included_values": ["test_1", "test_2"],
            "registry_key_root": "HKEY_CLASSES_ROOT",
            "registry_key_value": "\\",
            "severity": "medium",
            "template": "registry",
        },
    ],
}

REQUEST_PAYLOAD = [
    {
        "name": "THIS IS TEST IMR - 1",
        "alert_enabled": False,
        "description": "THIS IS TEST IMR DESCRIPTION - 1",
        "real_time_monitoring_enabled": True,
        "registry_included_values": ["test_1", "test_2"],
        "severity": "medium",
        "template": "registry",
    },
    {
        "name": "THIS IS TEST IMR - 2",
        "alert_enabled": False,
        "description": "THIS IS TEST IMR DESCRIPTION - 2",
        "real_time_monitoring_enabled": True,
        "registry_included_values": ["test"],
        "severity": "low",
        "template": "registry",
    },
]


class TestDeepsecIntegrityMonitoringRules(unittest.TestCase):
    def setUp(self):
        task = MagicMock(Task)
        # Ansible > 2.13 looks for check_mode in task
        task.check_mode = False
        play_context = MagicMock()
        # Ansible <= 2.13 looks for check_mode in play_context
        play_context.check_mode = False
        connection = patch(
            "ansible_collections.trendmicro.deepsec.plugins.action.deepsec_integrity_monitoring_rules.Connection",
        )
        fake_loader = {}
        templar = Templar(loader=fake_loader)
        self._plugin = ActionModule(
            task=task,
            connection=connection,
            play_context=play_context,
            loader=fake_loader,
            templar=templar,
            shared_loader_obj=None,
        )
        self._plugin.api_return = "integrity_monitoring_rules"
        self._plugin._task.action = "deepsec_integrity_monitoring_rules"
        self._task_vars = {}

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_integrity_monitoring_rules_merged(self, connection):
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = {}
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin._task.args = {
            "state": "merged",
            "config": REQUEST_PAYLOAD,
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_integrity_monitoring_rules_merged_idempotent(
        self,
        connection,
    ):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "merged",
            "config": [
                {
                    "name": "THIS IS TEST IMR - 1",
                    "alert_enabled": False,
                    "description": "THIS IS TEST IMR DESCRIPTION - 1",
                    "real_time_monitoring_enabled": True,
                    "registry_included_values": ["test_1", "test_2"],
                    "severity": "medium",
                    "template": "registry",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_integrity_monitoring_rules_replaced(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "replaced",
            "config": [
                {
                    "name": "THIS IS TEST IMR - 1",
                    "alert_enabled": False,
                    "description": "THIS IS REPLACED TEST IMR DESCRIPTION - 1",
                    "real_time_monitoring_enabled": True,
                    "registry_included_values": ["test_3", "test_4"],
                    "severity": "low",
                    "template": "registry",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_integrity_monitoring_rules_replaced_idempotent(
        self,
        connection,
    ):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = {
            "integrity_monitoring_rules": [
                {
                    "alert_enabled": False,
                    "description": "THIS IS REPLACED TEST IMR DESCRIPTION - 1",
                    "id": "328",
                    "minimum_agent_version": "6.0.0.0",
                    "minimum_manager_version": "6.0.0",
                    "name": "THIS IS TEST IMR - 1",
                    "real_time_monitoring_enabled": True,
                    "registry_attributes": ["STANDARD"],
                    "registry_excluded_values": [""],
                    "registry_include_default_value": True,
                    "registry_include_sub_keys": False,
                    "registry_included_values": ["test_3", "test_4"],
                    "registry_key_root": "HKEY_CLASSES_ROOT",
                    "registry_key_value": "\\",
                    "severity": "low",
                    "template": "registry",
                },
            ],
        }
        self._plugin._task.args = {
            "state": "replaced",
            "config": [
                {
                    "name": "THIS IS TEST IMR - 1",
                    "alert_enabled": False,
                    "description": "THIS IS REPLACED TEST IMR DESCRIPTION - 1",
                    "real_time_monitoring_enabled": True,
                    "registry_included_values": ["test_3", "test_4"],
                    "severity": "low",
                    "template": "registry",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_integrity_monitoring_rules_deleted(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "deleted",
            "config": [
                {
                    "name": "test_firewallrule_1",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_integrity_monitoring_rules_deleted_idempotent(
        self,
        connection,
    ):
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = {}
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin._task.args = {
            "state": "deleted",
            "config": [
                {
                    "name": "THIS IS TEST IMR - 1",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_integrity_monitoring_rules_gathered(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "gathered",
            "config": [{"name": "THIS IS TEST IMR - 1"}],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

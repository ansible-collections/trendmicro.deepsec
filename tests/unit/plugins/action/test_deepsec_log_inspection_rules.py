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

from ansible_collections.trendmicro.deepsec.plugins.action.deepsec_log_inspection_rules import (
    ActionModule,
)


RESPONSE_PAYLOAD = {
    "log_inspection_rules": [
        {
            "alert_enabled": True,
            "alert_minimum_severity": 4,
            "dependency": "none",
            "description": "MYSQLD description",
            "groups": ["test"],
            "id": "179",
            "level": "0",
            "logFiles": {
                "logFiles": [
                    {"location": "/var/log/mysqld.log", "format": "mysql-log"},
                ],
            },
            "minimum_agent_version": "6.0.0.0",
            "minimum_manager_version": "6.0.0",
            "name": "custom log_rule for mysqld event",
            "pattern": "name",
            "pattern_type": "string",
            "rule_description": "sqld rule description",
            "rule_id": 100001,
            "sort_order": "15000",
            "template": "basic-rule",
        },
    ],
}

REQUEST_PAYLOAD = [
    {
        "name": "custom log_rule for mysqld event",
        "description": "MYSQLD description",
        "minimum_agent_version": "6.0.0.0",
        "type": "defined",
        "template": "basic-rule",
        "pattern": "name",
        "pattern_type": "string",
        "rule_id": 100001,
        "rule_description": "sqld rule description",
        "groups": ["test"],
        "alert_minimum_severity": 4,
        "alert_enabled": True,
        "log_files": {
            "log_files": [
                {"location": "/var/log/mysqld.log", "format": "mysql-log"},
            ],
        },
    },
    {
        "name": "custom log_rule for daemon event",
        "description": "DAEMON description",
        "minimum_agent_version": "6.0.0.0",
        "type": "defined",
        "template": "basic-rule",
        "pattern": "name",
        "pattern_type": "string",
        "rule_id": 100002,
        "rule_description": "deamon rule description",
        "groups": ["test"],
        "alert_minimum_severity": 3,
        "alert_enabled": True,
        "log_files": {
            "log_files": [
                {"location": "/var/log/daemon.log", "format": "eventlog"},
            ],
        },
    },
]


class TestDeepsecFirewallRules(unittest.TestCase):
    def setUp(self):
        task = MagicMock(Task)
        # Ansible > 2.13 looks for check_mode in task
        task.check_mode = False
        play_context = MagicMock()
        # Ansible <= 2.13 looks for check_mode in play_context
        play_context.check_mode = False
        connection = patch(
            "ansible_collections.trendmicro.deepsec.plugins.action.deepsec_log_inspection_rules.Connection",
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
        self._plugin._task.action = "deepsec_log_inspection_rules"
        self._plugin.api_return = "log_inspection_rules"
        self._task_vars = {}

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_log_inspection_rules_merged(self, connection):
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
    def test_deepsec_log_inspection_rules_merged_idempotent(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "merged",
            "config": [
                {
                    "name": "custom log_rule for mysqld event",
                    "description": "MYSQLD description",
                    "minimum_agent_version": "6.0.0.0",
                    "type": "defined",
                    "template": "basic-rule",
                    "pattern": "name",
                    "pattern_type": "string",
                    "rule_id": 100001,
                    "rule_description": "sqld rule description",
                    "groups": ["test"],
                    "alert_minimum_severity": 4,
                    "alert_enabled": True,
                    "log_files": {
                        "log_files": [
                            {
                                "location": "/var/log/mysqld.log",
                                "format": "mysql-log",
                            },
                        ],
                    },
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_log_inspection_rules_replaced(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "replaced",
            "config": [
                {
                    "name": "custom log_rule for mysqld event",
                    "description": "REPLACED log mysqld event",
                    "minimum_agent_version": "6.0.0.0",
                    "type": "defined",
                    "template": "basic-rule",
                    "pattern": "name",
                    "pattern_type": "string",
                    "rule_id": "100003",
                    "rule_description": "mysqld rule description",
                    "groups": ["test"],
                    "alert_minimum_severity": 5,
                    "alert_enabled": True,
                    "log_files": {
                        "log_files": [
                            {
                                "location": "/var/log/mysqld.log",
                                "format": "mysql-log",
                            },
                        ],
                    },
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_log_inspection_rules_replaced_idempotent(
        self,
        connection,
    ):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = {
            "log_inspection_rules": [
                {
                    "alert_enabled": True,
                    "alert_minimum_severity": 3,
                    "dependency": "none",
                    "description": "REPLACED log daemon event",
                    "groups": ["test"],
                    "id": "181",
                    "level": "0",
                    "logFiles": {
                        "logFiles": [
                            {
                                "location": "/var/log/daemon.log",
                                "format": "eventlog",
                            },
                        ],
                    },
                    "minimum_agent_version": "6.0.0.0",
                    "minimum_manager_version": "6.0.0",
                    "name": "custom log_rule for daemon event",
                    "pattern": "name",
                    "pattern_type": "string",
                    "rule_description": "daemon rule description",
                    "rule_id": 100002,
                    "sort_order": "15000",
                    "template": "basic-rule",
                },
            ],
        }
        self._plugin._task.args = {
            "state": "replaced",
            "config": [
                {
                    "name": "custom log_rule for daemon event",
                    "description": "REPLACED log daemon event",
                    "minimum_agent_version": "6.0.0.0",
                    "type": "defined",
                    "template": "basic-rule",
                    "pattern": "name",
                    "pattern_type": "string",
                    "rule_id": 100002,
                    "rule_description": "daemon rule description",
                    "groups": ["test"],
                    "alert_minimum_severity": 3,
                    "alert_enabled": True,
                    "log_files": {
                        "log_files": [
                            {
                                "location": "/var/log/daemon.log",
                                "format": "eventlog",
                            },
                        ],
                    },
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_log_inspection_rules_deleted(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "deleted",
            "config": [
                {
                    "name": "custom log_rule for mysqld event",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_log_inspection_rules_deleted_idempotent(self, connection):
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = {}
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin._task.args = {
            "state": "deleted",
            "config": [
                {
                    "name": "custom log_rule for mysqld event",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_log_inspection_rules_gathered(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "gathered",
            "config": [{"name": "custom log_rule for mysqld event"}],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

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

import unittest
import tempfile
from ansible.playbook.task import Task
from ansible.template import Templar
from ansible_collections.trendmicro.deepsec.plugins.action.deepsec_firewall_rules import (
    ActionModule,
)
from ansible_collections.ansible.utils.tests.unit.compat.mock import (
    MagicMock,
    patch,
)

RESPONSE_PAYLOAD = {
    "firewall_rules": [
        {
            "action": "deny",
            "priority": "0",
            "direction": "incoming",
            "description": "incoming firewall 1 rule description",
            "frameType": "ip",
            "frameNumber": 2048,
            "frameNot": False,
            "protocol": "tcp",
            "protocolNot": False,
            "sourceIPType": "any",
            "sourceIPNot": False,
            "sourceMACType": "any",
            "sourceMACNot": False,
            "sourcePortType": "any",
            "sourcePortNot": False,
            "destinationIPType": "any",
            "destinationIPNot": False,
            "destinationMACType": "any",
            "destinationMACNot": False,
            "destinationPortType": "any",
            "destinationPortNot": False,
            "anyFlags": True,
            "logDisabled": True,
            "includePacketData": False,
            "alertEnabled": False,
            "ID": 146,
            "name": "test_firewallrule_1",
        }
    ]
}

REQUEST_PAYLOAD = [
    {
        "name": "test_firewallrule_1",
        "description": "incoming firewall 1 rule description",
        "action": "deny",
        "priority": 0,
        "source_iptype": "any",
        "destination_iptype": "any",
        "direction": "incoming",
        "protocol": "tcp",
        "log_disabled": True,
    },
    {
        "name": "test_firewallrule_2",
        "description": "incoming firewall 2 rule description",
        "action": "deny",
        "priority": 0,
        "source_iptype": "any",
        "source_ipnot": False,
        "source_port_type": "any",
        "destination_iptype": "any",
        "direction": "incoming",
        "protocol": "tcp",
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
            "ansible_collections.trendmicro.deepsec.plugins.action.deepsec_firewall_rules.Connection"
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
        self._plugin._task.action = "deepsec_firewall_rules"
        self._plugin.api_return = "firewall_rules"
        self._task_vars = {}

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_firewall_rules_merged(self, connection):
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
    def test_deepsec_firewall_rules_merged_idempotent(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "merged",
            "config": [
                {
                    "name": "test_firewallrule_1",
                    "description": "incoming firewall 1 rule description",
                    "action": "deny",
                    "priority": 0,
                    "source_iptype": "any",
                    "destination_iptype": "any",
                    "direction": "incoming",
                    "protocol": "tcp",
                    "log_disabled": True,
                }
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        config_respose = {
            "id": 146,
            "frame_type": "ip",
            "frame_number": 2048,
            "frame_not": False,
            "protocol_not": False,
            "source_iptype": "any",
            "source_ipnot": False,
            "source_mactype": "any",
            "source_macnot": False,
            "source_port_type": "any",
            "source_port_not": False,
            "destination_iptype": "any",
            "destination_ipnot": False,
            "destination_mactype": "any",
            "destination_macnot": False,
            "destination_port_type": "any",
            "destination_port_not": False,
            "any_flags": True,
            "log_disabled": True,
            "include_packet_data": False,
            "alert_enabled": False,
            "action": "deny",
            "priority": "0",
            "direction": "incoming",
            "description": "incoming firewall 1 rule description",
            "protocol": "tcp",
            "name": "test_firewallrule_1",
        }

        self.assertEqual(result["firewall_rules"]["before"][0]["name"], config_respose["name"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_firewall_rules_replaced(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "replaced",
            "config": [
                {
                    "name": "test_firewallrule_1",
                    "description": "outgoing firewall 1 replaced rule",
                    "action": "deny",
                    "priority": 0,
                    "source_iptype": "any",
                    "destination_iptype": "any",
                    "direction": "outgoing",
                    "protocol": "tcp",
                    "log_disabled": True,
                }
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_firewall_rules_replaced_idempotent(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = {
            "firewall_rules": [
                {
                    "action": "deny",
                    "priority": "0",
                    "direction": "outgoing",
                    "description": "outgoing firewall 1 replaced rule",
                    "frameType": "ip",
                    "frameNumber": 2048,
                    "frameNot": False,
                    "protocol": "tcp",
                    "protocolNot": False,
                    "sourceIPType": "any",
                    "sourceIPNot": False,
                    "sourceMACType": "any",
                    "sourceMACNot": False,
                    "sourcePortType": "any",
                    "sourcePortNot": False,
                    "destinationIPType": "any",
                    "destinationIPNot": False,
                    "destinationMACType": "any",
                    "destinationMACNot": False,
                    "destinationPortType": "any",
                    "destinationPortNot": False,
                    "anyFlags": True,
                    "logDisabled": True,
                    "includePacketData": False,
                    "alertEnabled": False,
                    "ID": 147,
                    "name": "test_firewallrule_1",
                }
            ]
        }
        self._plugin._task.args = {
            "state": "replaced",
            "config": [
                {
                    "name": "test_firewallrule_1",
                    "description": "outgoing firewall 1 replaced rule",
                    "action": "deny",
                    "priority": 0,
                    "source_iptype": "any",
                    "destination_iptype": "any",
                    "direction": "outgoing",
                    "protocol": "tcp",
                    "log_disabled": True,
                }
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_firewall_rules_deleted(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "deleted",
            "config": [
                {
                    "name": "test_firewallrule_1",
                }
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_firewall_rules_deleted_idempotent(self, connection):
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = {}
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin._task.args = {
            "state": "deleted",
            "config": [
                {
                    "name": "test_firewallrule_1",
                }
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_firewall_rules_gathered(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_resource_name = MagicMock()
        self._plugin.search_for_resource_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "gathered",
            "config": [{"name": "test_firewallrule_1"}],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

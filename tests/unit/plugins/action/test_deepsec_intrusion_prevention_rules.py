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

from unittest.mock import MagicMock, patch

from ansible.playbook.task import Task
from ansible.template import Templar

from ansible_collections.trendmicro.deepsec.plugins.action.deepsec_intrusion_prevention_rules import (
    ActionModule,
)


RESPONSE_PAYLOAD = {
    "intrusion_prevention_rules": [
        {
            "action": "drop",
            "alert_enabled": False,
            "always_include_packet_data": False,
            "application_type_id": 300,
            "case_sensitive": False,
            "debug_mode_enabled": False,
            "description": "TEST IPR 1 DESCRIPTION",
            "detect_only": False,
            "event_logging_disabled": False,
            "generate_event_on_packet_drop": True,
            "id": "8657",
            "name": "TEST IPR 1",
            "priority": "normal",
            "severity": "medium",
            "signature": "test_new_signature_1",
            "template": "signature",
        },
    ],
}

REQUEST_PAYLOAD = [
    {
        "alert_enabled": False,
        "always_include_packet_data": False,
        "application_type_id": 300,
        "template": "signature",
        "signature": "test_new_signature_1",
        "debug_mode_enabled": False,
        "description": "TEST IPR 1 DESCRIPTION",
        "detect_only": False,
        "event_logging_disabled": False,
        "generate_event_on_packet_drop": True,
        "name": "TEST IPR 1",
        "priority": "normal",
        "severity": "medium",
    },
    {
        "alert_enabled": False,
        "always_include_packet_data": False,
        "application_type_id": 300,
        "template": "signature",
        "signature": "test_new_signature_2",
        "debug_mode_enabled": False,
        "description": "TEST IPR 2 DESCRIPTION",
        "detect_only": False,
        "event_logging_disabled": False,
        "generate_event_on_packet_drop": True,
        "name": "TEST IPR 2",
        "priority": "normal",
        "severity": "medium",
    },
]


class TestDeepsecIntrusionPreventionRules(unittest.TestCase):
    def setUp(self):
        task = MagicMock(Task)
        # Ansible > 2.13 looks for check_mode in task
        task.check_mode = False
        play_context = MagicMock()
        # Ansible <= 2.13 looks for check_mode in play_context
        play_context.check_mode = False
        connection = patch(
            "ansible_collections.trendmicro.deepsec.plugins.action.deepsec_intrusion_prevention_rules.Connection",
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
        self._plugin._task.action = "deepsec_intrusion_prevention_rules"
        self._plugin.api_return = "intrusion_prevention_rules"
        self._task_vars = {}

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_intrusion_prevention_rules_merged(self, connection):
        self._plugin.search_for_ipr_name = MagicMock()
        self._plugin.search_for_ipr_name.return_value = {}
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin._task.args = {
            "state": "merged",
            "config": REQUEST_PAYLOAD,
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_intrusion_prevention_rules_merged_idempotent(
        self,
        connection,
    ):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_ipr_name = MagicMock()
        self._plugin.search_for_ipr_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "merged",
            "config": [
                {
                    "alert_enabled": False,
                    "always_include_packet_data": False,
                    "application_type_id": 300,
                    "template": "signature",
                    "signature": "test_new_signature_1",
                    "debug_mode_enabled": False,
                    "description": "TEST IPR 1 DESCRIPTION",
                    "detect_only": False,
                    "event_logging_disabled": False,
                    "generate_event_on_packet_drop": True,
                    "name": "TEST IPR 1",
                    "priority": "normal",
                    "severity": "medium",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_intrusion_prevention_rules_replaced(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_ipr_name = MagicMock()
        self._plugin.search_for_ipr_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "replaced",
            "config": [
                {
                    "alert_enabled": False,
                    "always_include_packet_data": False,
                    "application_type_id": 300,
                    "template": "signature",
                    "signature": "test_new_signature_1",
                    "debug_mode_enabled": False,
                    "description": "TEST IPR 1 REPLACE DESCRIPTION",
                    "detect_only": False,
                    "event_logging_disabled": False,
                    "generate_event_on_packet_drop": True,
                    "name": "TEST IPR 1",
                    "priority": "normal",
                    "severity": "low",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_intrusion_prevention_rules_replaced_idempotent(
        self,
        connection,
    ):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_ipr_name = MagicMock()
        self._plugin.search_for_ipr_name.return_value = {
            "intrusion_prevention_rules": [
                {
                    "action": "drop",
                    "alert_enabled": False,
                    "always_include_packet_data": False,
                    "application_type_id": 300,
                    "case_sensitive": False,
                    "debug_mode_enabled": False,
                    "description": "TEST IPR 1 REPLACE DESCRIPTION",
                    "detect_only": False,
                    "event_logging_disabled": False,
                    "generate_event_on_packet_drop": True,
                    "id": "8657",
                    "name": "TEST IPR 1",
                    "priority": "normal",
                    "severity": "low",
                    "signature": "test_new_signature_1",
                    "template": "signature",
                },
            ],
        }
        self._plugin._task.args = {
            "state": "replaced",
            "config": [
                {
                    "alert_enabled": False,
                    "always_include_packet_data": False,
                    "application_type_id": 300,
                    "template": "signature",
                    "signature": "test_new_signature_1",
                    "debug_mode_enabled": False,
                    "description": "TEST IPR 1 REPLACE DESCRIPTION",
                    "detect_only": False,
                    "event_logging_disabled": False,
                    "generate_event_on_packet_drop": True,
                    "name": "TEST IPR 1",
                    "priority": "normal",
                    "severity": "low",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_intrusion_prevention_rules_deleted(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_ipr_name = MagicMock()
        self._plugin.search_for_ipr_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "deleted",
            "config": [
                {
                    "name": "TEST IPR 1",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertTrue(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_intrusion_prevention_rules_deleted_idempotent(
        self,
        connection,
    ):
        self._plugin.search_for_ipr_name = MagicMock()
        self._plugin.search_for_ipr_name.return_value = {}
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin._task.args = {
            "state": "deleted",
            "config": [
                {
                    "name": "TEST IPR 1",
                },
            ],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

    @patch("ansible.module_utils.connection.Connection.__rpc__")
    def test_deepsec_intrusion_prevention_rules_gathered(self, connection):
        self._plugin._connection.socket_path = tempfile.NamedTemporaryFile().name
        self._plugin._connection._shell = MagicMock()
        self._plugin.search_for_ipr_name = MagicMock()
        self._plugin.search_for_ipr_name.return_value = RESPONSE_PAYLOAD
        self._plugin._task.args = {
            "state": "gathered",
            "config": [{"name": "TEST IPR 1"}],
        }
        result = self._plugin.run(task_vars=self._task_vars)
        self.assertFalse(result["changed"])

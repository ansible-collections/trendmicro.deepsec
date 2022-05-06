# Copyright (c) 2018 Red Hat
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

import os
import pytest
from ansible.playbook.task import Task
from ansible.template import Templar
from ansible_collections.trendmicro.deepsec.plugins.action.deepsec_firewall_rules import (
    ActionModule,
)
from ansible_collections.trendmicro.deepsec.tests.unit.plugins.modules.utils import (
    set_module_args,
    exit_json,
    fail_json,
    AnsibleFailJson,
    AnsibleExitJson
)
from ansible_collections.trendmicro.deepsec.tests.unit.compat.mock import (
    MagicMock,
    patch,
)

from ansible_collections.trendmicro.deepsec.tests.unit.mock.loader import (
    DictDataLoader,
    patch,
)

from ansible.module_utils import basic
from ansible_collections.trendmicro.deepsec.plugins.modules import deepsec_firewall_rules

OBJECT = {'layer': 'foo', 'position': 'bar', 'name': 'baz',
          'source': [{'name': 'lol'}], 'destination': [{'name': 'Any'}],
          'action': {'name': 'drop'}, 'enabled': True}
PAYLOAD = {'layer': 'foo', 'position': 'bar', 'name': 'baz'}


class TestDeepsecFirewallRules(object):
    def setUp(self):
        task = MagicMock(Task)
        play_context = MagicMock()
        play_context.check_mode = False
        connection = MagicMock()
        fake_loader = DictDataLoader({})
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

    @staticmethod
    def _load_fixture(filename):
        """Load a fixture from the filesystem
        :param filename: The name of the file to load
        :type filename: str
        :return: The file contents
        :rtype: str
        """
        fixture_name = os.path.join(
            os.path.dirname(__file__), "fixtures", filename
        )
        with open(fixture_name) as fhand:
            return fhand.read()
    
    def test_asa_acls_merged(self):
        

    # @pytest.fixture(autouse=True)
    # def module_mock(self, mocker):
    #     return mocker.patch.multiple(basic.AnsibleModule, exit_json=exit_json, fail_json=fail_json)

    # @pytest.fixture
    # def connection_mock(self, mocker):
    #     connection_class_mock = mocker.patch('ansible_collections.check_point.mgmt.plugins.modules.checkpoint_access_rule.Connection')
    #     return connection_class_mock.return_value

    # @pytest.fixture
    # def get_access_rule_200(self, mocker):
    #     mock_function = mocker.patch('ansible_collections.check_point.mgmt.plugins.modules.checkpoint_access_rule.get_access_rule')
    #     mock_function.return_value = (200, OBJECT)
    #     return mock_function.return_value

    # @pytest.fixture
    # def get_access_rule_404(self, mocker):
    #     mock_function = mocker.patch('ansible_collections.check_point.mgmt.plugins.modules.checkpoint_access_rule.get_access_rule')
    #     mock_function.return_value = (404, 'Object not found')
    #     return mock_function.return_value

    # def test_create(self, get_access_rule_404, connection_mock):
    #     connection_mock.send_request.return_value = (200, OBJECT)
    #     result = self._run_module(PAYLOAD)

    #     assert result['changed']
    #     assert 'checkpoint_access_rules' in result

    # def test_create_idempotent(self, get_access_rule_200, connection_mock):
    #     connection_mock.send_request.return_value = (200, PAYLOAD)
    #     result = self._run_module(PAYLOAD)

    #     assert not result['changed']

    # def test_update(self, get_access_rule_200, connection_mock):
    #     payload_for_update = {'enabled': False}
    #     payload_for_update.update(PAYLOAD)
    #     connection_mock.send_request.return_value = (200, payload_for_update)
    #     result = self._run_module(payload_for_update)

    #     assert result['changed']
    #     assert not result['checkpoint_access_rules']['enabled']

    # def test_delete(self, get_access_rule_200, connection_mock):
    #     connection_mock.send_request.return_value = (200, OBJECT)
    #     payload_for_delete = {'state': 'absent'}
    #     payload_for_delete.update(PAYLOAD)
    #     result = self._run_module(payload_for_delete)

    #     assert result['changed']

    # def test_delete_idempotent(self, get_access_rule_404, connection_mock):
    #     payload = {'name': 'baz', 'state': 'absent'}
    #     connection_mock.send_request.return_value = (200, OBJECT)
    #     result = self._run_module(payload)

    #     assert not result['changed']

    # def _run_module(self, module_args):
    #     set_module_args(module_args)
    #     with pytest.raises(AnsibleExitJson) as ex:
    #         self.module.main()
    #     return ex.value.args[0]

    # def _run_module_with_fail_json(self, module_args):
    #     set_module_args(module_args)
    #     with pytest.raises(AnsibleFailJson) as exc:
    #         self.module.main()
    #     result = exc.value.args[0]
    #     return result

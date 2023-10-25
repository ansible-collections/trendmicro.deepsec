#
# Copyright 2021 Red Hat Inc.
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

from ansible.plugins.action import ActionBase
from ansible.errors import AnsibleActionFail
from ansible.module_utils.connection import Connection

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    map_obj_to_params,
    map_params_to_obj,
    remove_get_keys_from_payload_dict,
)
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.trendmicro.deepsec.plugins.modules.deepsec_intrusion_prevention_rules import (
    DOCUMENTATION,
)


class ActionModule(ActionBase):
    """action module"""

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = None
        self._supports_async = True
        self.api_object = "/api/intrusionpreventionrules"
        self.api_object_search = "/api/intrusionpreventionrules/search"
        self.api_return = "intrusionPreventionRules"
        self.module_return = "intrusion_prevention_rules"
        self.key_transform = {
            "id": "ID",
            "minimum_agent_version": "minimumAgentVersion",
            "application_type_id": "applicationTypeID",
            "detect_only": "detectOnly",
            "event_logging_disabled": "eventLoggingDisabled",
            "generate_event_on_packet_drop": "generateEventOnPacketDrop",
            "always_include_packet_data": "alwaysIncludePacketData",
            "debug_mode_enabled": "debugModeEnabled",
            "original_issue": "originalIssue",
            "last_updated": "lastUpdated",
            "can_be_assigned_alone": "canBeAssignedAlone",
            "case_sensitive": "caseSensitive",
            "custom_xml": "customXML",
            "alert_enabled": "alertEnabled",
            "schedule_id": "scheduleID",
            "context_id": "contextID",
            "recommendations_mode": "recommendationsMode",
            "depends_on_rule_ids": "dependsOnRuleIDs",
            "cvss_score": "CVSSScore",
            "cve": "CVE",
        }

    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=DOCUMENTATION,
            schema_format="doc",
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            self._result["failed"] = True
            self._result["msg"] = errors

    def _check_for_response_code(self, response_code, response):
        if response_code >= 400:
            if response.get("errors"):
                raise AnsibleActionFail(
                    "Request failed with HTTPerror code: {0}, and with a response: {1}".format(
                        response_code, response["errors"]
                    )
                )
            elif response.get("message"):
                raise AnsibleActionFail(
                    "Request failed with HTTPerror code: {0}, and with a response: {1}".format(
                        response_code, response["message"]
                    )
                )

    def search_for_intrusion_prevention_rules(
        self, deepsec_conn_request, search_payload=None
    ):
        code, ipr_response = deepsec_conn_request.post(
            self.api_object_search, data=search_payload
        )
        self._check_for_response_code(code, ipr_response)
        return ipr_response

    def search_for_ipr_name(self, deepsec_conn_request, search_ipr_by_names):
        search_result = []
        if isinstance(search_ipr_by_names, list):
            for each in search_ipr_by_names:
                search_payload = {
                    "maxItems": 1,
                    "searchCriteria": [
                        {
                            "fieldName": "name",
                            "stringTest": "equal",
                            "stringValue": each["name"],
                        }
                    ],
                }
                temp_search_response = (
                    self.search_for_intrusion_prevention_rules(
                        deepsec_conn_request, search_payload
                    )
                )
                if (
                    temp_search_response.get("intrusionPreventionRules")
                    and temp_search_response["intrusionPreventionRules"]
                ):
                    search_result.append(
                        map_obj_to_params(
                            temp_search_response["intrusionPreventionRules"][
                                0
                            ],
                            self.key_transform,
                            self.api_return,
                        )
                    )
        else:
            search_payload = {
                "maxItems": 1,
                "searchCriteria": [
                    {
                        "fieldName": "name",
                        "stringTest": "equal",
                        "stringValue": search_ipr_by_names,
                    }
                ],
            }
            search_result = self.search_for_intrusion_prevention_rules(
                deepsec_conn_request, search_payload
            )

        return search_result

    def delete_module_api_config(
        self, deepsec_conn_request, module_config_params
    ):
        config = {}
        before = []
        after = []
        changed = False
        for each in module_config_params:
            search_by_name = self.search_for_ipr_name(
                deepsec_conn_request, each["name"]
            )
            if search_by_name.get(self.api_return):
                every = map_obj_to_params(
                    search_by_name[self.api_return][0],
                    self.key_transform,
                    self.api_return,
                )
                before.append(every)
                response_code, api_response = deepsec_conn_request.delete(
                    "{0}/{1}".format(self.api_object, every["id"]), data=each
                )
                self._check_for_response_code(response_code, api_response)

                changed = True
                if api_response:
                    after.append(
                        map_obj_to_params(
                            api_response, self.key_transform, self.api_return
                        )
                    )
        if changed:
            config.update({"before": before, "after": after})
        else:
            config.update({"before": before})
        return config, changed

    def configure_module_api(self, deepsec_conn_request, module_config_params):
        get_supported_keys = ["id", "identifier", "can_be_assigned_alone"]
        config = {}
        before = []
        after = []
        changed = False
        remove_from_diff_compare = [
            "id",
            "cvss_score",
            "cve",
            "can_be_assigned_alone",
            "type",
        ]
        temp_name = []
        for each in module_config_params:
            search_by_name = self.search_for_ipr_name(
                deepsec_conn_request, each["name"]
            )
            if search_by_name and search_by_name.get(self.api_return):
                each_result = search_by_name[self.api_return]
                for every in each_result:
                    every = map_obj_to_params(
                        every, self.key_transform, self.api_return
                    )
                    if every["name"] == each["name"]:
                        each = utils.remove_empties(each)
                        diff = utils.dict_diff(every, each)
                if diff:
                    diff = remove_get_keys_from_payload_dict(
                        diff, remove_from_diff_compare
                    )
                    if diff:
                        before.append(every)
                        if self._task.args["state"] == "merged":
                            # Check for actual modification and if present fire
                            # the request over that IPR ID
                            each = utils.remove_empties(
                                utils.dict_merge(every, each)
                            )
                            each = remove_get_keys_from_payload_dict(
                                each, remove_from_diff_compare
                            )
                            changed = True
                            payload = map_params_to_obj(
                                each, self.key_transform
                            )
                            (
                                response_code,
                                api_response,
                            ) = deepsec_conn_request.post(
                                "{0}/{1}".format(self.api_object, every["id"]),
                                data=payload,
                            )
                            self._check_for_response_code(
                                response_code, api_response
                            )
                            after.append(
                                map_obj_to_params(
                                    api_response,
                                    self.key_transform,
                                    self.api_return,
                                )
                            )
                        elif self._task.args["state"] == "replaced":
                            (
                                response_code,
                                api_response,
                            ) = deepsec_conn_request.delete(
                                "{0}/{1}".format(self.api_object, every["id"]),
                                data=each,
                            )
                            self._check_for_response_code(
                                response_code, api_response
                            )
                            changed = True
                            payload = map_params_to_obj(
                                each, self.key_transform
                            )
                            (
                                response_code,
                                api_response,
                            ) = deepsec_conn_request.post(
                                "{0}".format(self.api_object), data=payload
                            )
                            self._check_for_response_code(
                                response_code, api_response
                            )
                            after.append(
                                map_obj_to_params(
                                    api_response,
                                    self.key_transform,
                                    self.api_return,
                                )
                            )
                    else:
                        before.append(every)
                        after.append(every)
                        temp_name.append(every["name"])
                else:
                    before.append(every)
                    after.append(every)
            else:
                changed = True
                each = utils.remove_empties(each)
                each = remove_get_keys_from_payload_dict(
                    each, get_supported_keys
                )
                payload = map_params_to_obj(each, self.key_transform)
                code, api_response = deepsec_conn_request.post(
                    "{0}".format(self.api_object), data=payload
                )
                self._check_for_response_code(code, api_response)
                after.extend(before)
                after.append(
                    map_obj_to_params(
                        api_response, self.key_transform, self.api_return
                    )
                )
        if not changed:
            after = []
        config.update({"before": before, "after": after})

        return config, changed

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._check_argspec()
        if self._result.get("failed"):
            return self._result
        conn = Connection(self._connection.socket_path)
        deepsec_conn_request = DeepSecurityRequest(
            connection=conn, task_vars=task_vars
        )
        if self._task.args["state"] == "gathered":
            if self._task.args.get("config"):
                self._result["gathered"] = self.search_for_ipr_name(
                    deepsec_conn_request, self._task.args["config"]
                )
            else:
                self._result["gathered"] = deepsec_conn_request.get(
                    self.api_object
                )
            self._result["changed"] = False
        elif (
            self._task.args["state"] == "merged"
            or self._task.args["state"] == "replaced"
        ):
            if self._task.args.get("config"):
                (
                    self._result[self.module_return],
                    self._result["changed"],
                ) = self.configure_module_api(
                    deepsec_conn_request, self._task.args["config"]
                )
        elif self._task.args["state"] == "deleted":
            if self._task.args.get("config"):
                (
                    self._result[self.module_return],
                    self._result["changed"],
                ) = self.delete_module_api_config(
                    deepsec_conn_request, self._task.args["config"]
                )

        return self._result

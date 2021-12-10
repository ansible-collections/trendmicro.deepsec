# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The module file for deepsec_firewall_rules
"""

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
from ansible_collections.trendmicro.deepsec.plugins.modules.deepsec_firewall_rules import (
    DOCUMENTATION,
)


class ActionModule(ActionBase):
    """ action module
    """

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = None
        self.api_object = "/api/firewallrules"
        self.api_object_search = "/api/firewallrules/search"
        self.api_return = "firewallRules"
        self.module_return = "firewall_rules"
        self.key_transform = {
            "id": "ID",
            "frame_type": "frameType",
            "frame_number": "frameNumber",
            "frame_not": "frameNot",
            "protocol_number": "protocolNumber",
            "protocol_not": "protocolNot",
            "source_iptype": "sourceIPType",
            "source_ipvalue": "sourceIPValue",
            "source_ipmask": "sourceIPMask",
            "source_iprange_from": "sourceIPRangeFrom",
            "source_iprange_to": "sourceIPRangeTo",
            "source_ipmultiple": "sourceIPMultiple",
            "source_iplist_id": "sourceIPListID",
            "source_ipnot": "sourceIPNot",
            "source_mactype": "sourceMACType",
            "source_macvalue": "sourceMACValue",
            "source_macmultiple": "sourceMACMultiple",
            "source_maclist_id": "sourceMACListID",
            "source_macnot": "sourceMACNot",
            "source_port_type": "sourcePortType",
            "source_port_multiple": "sourcePortMultiple",
            "source_port_list_id": "sourcePortListID",
            "source_port_not": "sourcePortNot",
            "destination_iptype": "destinationIPType",
            "destination_ipvalue": "destinationIPValue",
            "destination_ipmask": "destinationIPMask",
            "destinationIPRangeFrom": "destination_iprange_from",
            "destination_iprange_to": "destinationIPRangeTo",
            "destination_ipmultiple": "destinationIPMultiple",
            "destination_iplist_id": "destinationIPListID",
            "destination_ipnot": "destinationIPNot",
            "destination_mactype": "destinationMACType",
            "destination_macvalue": "destinationMACValue",
            "destination_macmultiple": "destinationMACMultiple",
            "destination_maclist_id": "destinationMACListID",
            "destination_macnot": "destinationMACNot",
            "destination_port_type": "destinationPortType",
            "destination_port_multiple": "destinationPortMultiple",
            "destination_port_list_id": "destinationPortListID",
            "destination_port_not": "destinationPortNot",
            "any_flags": "anyFlags",
            "log_disabled": "logDisabled",
            "include_packet_data": "includePacketData",
            "alert_enabled": "alertEnabled",
            "schedule_id": "scheduleID",
            "context_id": "contextID",
            "tcpnot": "TCPNot",
            "icmptype": "ICMPType",
            "icmpcode": "ICMPCode",
            "icmpnot": "ICMPNot",
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

    def search_for_existing_rules(self, conn_request, search_payload=None):
        code, resource_response = conn_request.post(
            self.api_object_search, data=search_payload
        )
        self._check_for_response_code(code, resource_response)
        return resource_response

    def search_for_resource_name(self, conn_request, search_resource_by_names):
        search_result = []
        if isinstance(search_resource_by_names, list):
            for each in search_resource_by_names:
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
                temp_search_response = self.search_for_existing_rules(
                    conn_request, search_payload
                )
                if (
                    temp_search_response.get("firewallRules")
                    and temp_search_response["firewallRules"]
                ):
                    search_result.append(
                        map_obj_to_params(
                            temp_search_response["firewallRules"][0],
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
                        "stringValue": search_resource_by_names,
                    }
                ],
            }
            search_result = self.search_for_existing_rules(
                conn_request, search_payload
            )

        return search_result

    def delete_module_api_config(self, conn_request, module_config_params):
        config = {}
        before = []
        after = []
        changed = False
        for each in module_config_params:
            search_by_name = self.search_for_resource_name(
                conn_request, each["name"]
            )
            if search_by_name.get(self.api_return):
                every = map_obj_to_params(
                    search_by_name[self.api_return][0],
                    self.key_transform,
                    self.api_return,
                )
                before.append(every)
                response_code, api_response = conn_request.delete(
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

    def configure_module_api(self, conn_request, module_config_params):
        get_supported_keys = ["id", "identifier", "can_be_assigned_alone"]
        config = {}
        before = []
        after = []
        changed = False
        # Add to the THIS list for the value which needs to be excluded
        # from HAVE params when compared to WANT param like 'ID' can be
        # part of HAVE param but may not be part of your WANT param
        remove_from_diff_compare = []
        temp_name = []
        for each in module_config_params:
            search_by_name = self.search_for_resource_name(
                conn_request, each["name"]
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
                            # the request over that integrity_monitoring_rules ID
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
                            response_code, api_response = conn_request.post(
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
                            response_code, api_response = conn_request.delete(
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
                            response_code, api_response = conn_request.post(
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
                code, api_response = conn_request.post(
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
        conn_request = DeepSecurityRequest(
            connection=conn, task_vars=task_vars
        )
        if self._task.args["state"] == "gathered":
            if self._task.args.get("config"):
                self._result["gathered"] = self.search_for_resource_name(
                    conn_request, self._task.args["config"]
                )
            else:
                self._result["gathered"] = conn_request.get(self.api_object)
        elif (
            self._task.args["state"] == "merged"
            or self._task.args["state"] == "replaced"
        ):
            if self._task.args.get("config"):
                self._result[self.module_return], self._result[
                    "changed"
                ] = self.configure_module_api(
                    conn_request, self._task.args["config"]
                )
        elif self._task.args["state"] == "deleted":
            if self._task.args.get("config"):
                self._result[self.module_return], self._result[
                    "changed"
                ] = self.delete_module_api_config(
                    conn_request, self._task.args["config"]
                )

        return self._result

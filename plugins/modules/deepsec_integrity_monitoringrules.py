#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
module: deepsec_integrity_monitoringrules
short_description: Create/Configure Integrity Monitoring Rules.
description:
  - This module creates and configure Integrity Monitoring Rules under TrendMicro Deep Security.
version_added: "1.2.0"
options:
  config:
    description: Integrity Monitoring Rules config
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the IntegrityMonitoringRule.
        type: str
      description:
        description:  Description of the IntegrityMonitoringRule.
        type: str
      severity:
        description: Severity level of the event is multiplied by the computer's asset value to
          determine ranking. Ranking can be used to sort events with more business impact.
        choices: ["low", "medium", "high", "critical"]
        type: str
      template:
        description: Template which the IntegrityMonitoringRule follows.
        choices: ["registry", "file", "custom"]
        type: str
      registry_key_root:
        description: Registry hive which is monitored by the IntegrityMonitoringRule.
          Empty if the IntegrityMonitoringRule does not monitor a registry key.
        type: str
      registry_key_value:
        description: Registry key which is monitored by the IntegrityMonitoringRule.
          Empty if the IntegrityMonitoringRule does not monitor a registry key. Ignored
          if the IntegrityMonitoringRule does not monitor a registry key.
        type: str
      registry_include_subkeys:
        description: Controls whether the IntegrityMonitoringRule should also include subkeys
          of the registry key it monitors. Ignored if the IntegrityMonitoringRule does not monitor
          a registry key.
        type: bool
      registry_included_values:
        description: Registry key values to be monitored by the IntegrityMonitoringRule.
          Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: list
        elements: str
      registry_include_default_value:
        description: Controls whether the rule should monitor default registry key values.
          Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: bool
      registry_excluded_values:
        description: Registry key values to be ignored by the IntegrityMonitoringRule.
          Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: list
        elements: str
      registry_attributes:
        description: Registry key attributes to be monitored by the IntegrityMonitoringRule.
          Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: list
        elements: str
      filebase_directory:
        description: Base of the file directory to be monitored by the IntegrityMonitoringRule.
          Ignored if the IntegrityMonitoringRule does not monitor a file directory.
        type: str
      fileinclude_subdirectories:
        description: Controls whether the IntegrityMonitoringRule should also monitor sub-directories of
            the base file directory that is associated with it. Ignored if the IntegrityMonitoringRule
            does not monitor a file directory.
        type: bool
      file_included_values:
        description: File name values to be monitored by the IntegrityMonitoringRule. Leaving this
          field blank when monitoring file directories will cause the IntegrityMonitoringRule to
          monitor all files in a directory. This can use significant system resources if the
          base directory contains numerous or large files. Ignored if the IntegrityMonitoringRule
          does not monitor a file directory.
        type: list
        elements: str
      file_excluded_values:
        description: File name values to be ignored by the IntegrityMonitoringRule. Ignored if
        the IntegrityMonitoringRule does not monitor a file directory.
        type: list
        elements: str
      file_attributes:
        description: File attributes to be monitored by the IntegrityMonitoringRule. Defaults
          to STANDARD which will monitor changes in file creation date, last modified date,
          permissions, owner, group, size, content, flags (Windows) and SymLinkPath (Linux).
          Ignored if the IntegrityMonitoringRule does not monitor a file directory.
        type: list
        elements: str
      custom_xml:
        description: Custom XML rules to be used by the IntegrityMonitoringRule. Custom
          XML rules must be encoded in the Base64 format. Ignored if the
          IntegrityMonitoringRule does not follow the custom template.
        type: str
      alert_enabled:
        description: Controls whether an alert should be made if an event related to the
          IntegrityMonitoringRule is logged. Defaults to false.
        type: bool
      real_time_monitoring_enabled:
        description: Controls whether the IntegrityMonitoringRule is monitored in real
          time or during every scan. Defaults to true which indicates that it is monitored
          in real time. A value of false indicates that it will only be checked during scans.
        type: bool
      recommendations_mode:
        description: Indicates whether recommendation scans consider the IntegrityMonitoringRule.
          Can be set to enabled or ignored. Custom rules cannot be recommended.
        choices: ["enabled", "ignored", "unknown", "disabled"]
        type: str
      minimum_agent_version:
        description: Minimum Deep Security Agent version that supports the IntegrityMonitoringRule.
          This value is provided in the X.X.X.X format. Defaults to 6.0.0.0. If an agent is not
          the minimum required version, the manager does not send the rule to the agent, and generates
          an alert. APPLICABLE ONLY with GET call. NOT APPLICABLE param with Create/Modify POST call.
        type: str
      minimum_manager_version:
        description: Minimum Deep Security Manager version that supports the IntegrityMonitoringRule.
          This value is provided in the X.X.X format. Defaults to 6.0.0. An alert will be raised
          if a manager that fails to meet the minimum manager version value tries to assign this
          rule to a host or profile. APPLICABLE ONLY with GET call. NOT APPLICABLE param with
          Create/Modify POST call.
        type: str
      identifier:
        description: Identifier of the IntegrityMonitoringRule from Trend Micro.
          Empty if the IntegrityMonitoringRule is user created. APPLICABLE ONLY with GET call.
          NOT APPLICABLE param with Create/Modify POST call.
        type: str
      type:
        description: Type of the IntegrityMonitoringRule. If the rule is predefined
        by Trend Micro, it is set to 2. If it is user created, it is set to 1.
        APPLICABLE ONLY with GET call. NOT APPLICABLE param with Create/Modify POST call.
        type: str
      original_issue:
        description: Timestamp when the IntegrityMonitoringRule was originally issued
          by Trend Micro, in milliseconds since epoch. Empty if the IntegrityMonitoringRule
          is user created. APPLICABLE ONLY with GET call. NOT APPLICABLE param with
          Create/Modify POST call.
        type: int
      last_updated:
        description: Timestamp when the IntegrityMonitoringRule was last updated,
          in milliseconds since epoch. APPLICABLE ONLY with GET call.
          NOT APPLICABLE param with Create/Modify POST call.
        type: int
      id:
        description: ID of the IntegrityMonitoringRule. APPLICABLE ONLY with GET call.
          NOT APPLICABLE param with Create/Modify POST call.
        type: int
  state:
    description:
      - The state the configuration should be left in
      - The state I(gathered) will get the module API configuration from the device and
        transform it into structured data in the format as per the module argspec and
        the value is returned in the I(gathered) key within the result.
    type: str
    choices:
      - present
      - absent
      - gathered
    default: present

author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
"""

EXAMPLES = """

# Using PRESENT state
# -------------------

- name: Create and Configure Integrity Monitoring Rules
  trendmicro.deepsec.deepsec_integrity_monitoringrules:
    state: present
    config:
      - name: THIS IS TEST IMR - 1
        alert_enabled: false
        description: THIS IS TEST IMR DESCRIPTION - 1
        real_time_monitoring_enabled: true
        registry_included_values:
          - test_1
          - test_2
        severity: medium
        template: registry
      - name: THIS IS TEST IMR - 2
        alert_enabled: false
        description: THIS IS TEST IMR DESCRIPTION - 2
        real_time_monitoring_enabled: true
        registry_attributes:
          - test
        severity: low
        template: registry

# Play Run:
# =========
#
# "integrity_monitoringrules": {
#     "after": [
#         {
#             "alert_enabled": false,
#             "description": "THIS IS TEST IMR DESCRIPTION - 1",
#             "id": 213,
#             "minimum_agent_version": "6.0.0.0",
#             "minimum_manager_version": "6.0.0",
#             "name": "THIS IS TEST IMR - 1",
#             "real_time_monitoring_enabled": true,
#             "registry_attributes": [
#                 "STANDARD"
#             ],
#             "registry_excluded_values": [
#                 ""
#             ],
#             "registry_include_default_value": true,
#             "registry_include_subkeys": false,
#             "registry_included_values": [
#                 "test_1",
#                 "test_2"
#             ],
#             "registry_key_root": "HKEY_CLASSES_ROOT",
#             "registry_key_value": "\\",
#             "severity": "medium",
#             "template": "registry"
#         },
#         {
#             "alert_enabled": false,
#             "description": "THIS IS TEST IMR DESCRIPTION - 2",
#             "id": 214,
#             "minimum_agent_version": "6.0.0.0",
#             "minimum_manager_version": "6.0.0",
#             "name": "THIS IS TEST IMR - 2",
#             "real_time_monitoring_enabled": true,
#             "registry_attributes": [
#                 "test"
#             ],
#             "registry_excluded_values": [
#                 ""
#             ],
#             "registry_include_default_value": true,
#             "registry_include_subkeys": false,
#             "registry_included_values": [
#                 ""
#             ],
#             "registry_key_root": "HKEY_CLASSES_ROOT",
#             "registry_key_value": "\\",
#             "severity": "low",
#             "template": "registry"
#         }
#     ],
#     "before": []
# }

- name: Modify the severity of Integrity Monitoring Rule by name
  trendmicro.deepsec.deepsec_integrity_monitoringrules:
    state: present
    config:
      - name: THIS IS TEST IMR - 2
        severity: medium

# Play Run:
# =========
#
# "integrity_monitoringrules": {
#     "after": [
#         {
#             "alert_enabled": false,
#             "description": "THIS IS TEST IMR DESCRIPTION - 2",
#             "id": 216,
#             "minimum_agent_version": "6.0.0.0",
#             "minimum_manager_version": "6.0.0",
#             "name": "THIS IS TEST IMR - 2",
#             "real_time_monitoring_enabled": true,
#             "registry_attributes": [
#                 "test"
#             ],
#             "registry_excluded_values": [
#                 ""
#             ],
#             "registry_include_default_value": true,
#             "registry_include_subkeys": false,
#             "registry_included_values": [
#                 ""
#             ],
#             "registry_key_root": "HKEY_CLASSES_ROOT",
#             "registry_key_value": "\\",
#             "severity": "medium",
#             "template": "registry"
#         }
#     ],
#     "before": [
#         {
#             "alert_enabled": false,
#             "description": "THIS IS TEST IMR DESCRIPTION - 2",
#             "id": 216,
#             "minimum_agent_version": "6.0.0.0",
#             "minimum_manager_version": "6.0.0",
#             "name": "THIS IS TEST IMR - 2",
#             "real_time_monitoring_enabled": true,
#             "registry_attributes": [
#                 "test"
#             ],
#             "registry_excluded_values": [
#                 ""
#             ],
#             "registry_include_default_value": true,
#             "registry_include_subkeys": false,
#             "registry_included_values": [
#                 ""
#             ],
#             "registry_key_root": "HKEY_CLASSES_ROOT",
#             "registry_key_value": "\\",
#             "severity": "low",
#             "template": "registry"
#         }
#     ]
# }

# Using GATHERED state
# --------------------

- name: Gather Integrity Monitoring Rules by IMR names
  trendmicro.deepsec.deepsec_integrity_monitoringrules:
    state: gathered
    config:
      - name: THIS IS TEST IMR - 1
      - name: THIS IS TEST IMR - 2

# Play Run:
# =========
#
# "gathered": [
#     {
#         "alert_enabled": false,
#         "description": "THIS IS TEST IMR DESCRIPTION - 1",
#         "id": 215,
#         "minimum_agent_version": "6.0.0.0",
#         "minimum_manager_version": "6.0.0",
#         "name": "THIS IS TEST IMR - 1",
#         "real_time_monitoring_enabled": true,
#         "registry_attributes": [
#             "STANDARD"
#         ],
#         "registry_excluded_values": [
#             ""
#         ],
#         "registry_include_default_value": true,
#         "registry_include_subkeys": false,
#         "registry_included_values": [
#             "test_1",
#             "test_2"
#         ],
#         "registry_key_root": "HKEY_CLASSES_ROOT",
#         "registry_key_value": "\\",
#         "severity": "medium",
#         "template": "registry"
#     },
#     {
#         "alert_enabled": false,
#         "description": "THIS IS TEST IMR DESCRIPTION - 2",
#         "id": 216,
#         "minimum_agent_version": "6.0.0.0",
#         "minimum_manager_version": "6.0.0",
#         "name": "THIS IS TEST IMR - 2",
#         "real_time_monitoring_enabled": true,
#         "registry_attributes": [
#             "test"
#         ],
#         "registry_excluded_values": [
#             ""
#         ],
#         "registry_include_default_value": true,
#         "registry_include_subkeys": false,
#         "registry_included_values": [
#             ""
#         ],
#         "registry_key_root": "HKEY_CLASSES_ROOT",
#         "registry_key_value": "\\",
#         "severity": "low",
#         "template": "registry"
#     }
# ]

- name: Gather ALL of the Integrity Monitoring Rules
  trendmicro.deepsec.deepsec_integrity_monitoringrules:
    state: gathered

# Using ABSENT state
# ------------------

- name: Delete existing Integrity Monitoring Rules
  trendmicro.deepsec.deepsec_integrity_monitoringrules:
    state: absent
    config:
      - name: THIS IS TEST IMR - 1
      - name: THIS IS TEST IMR - 2

# Play Run:
# =========
#
# "integrity_monitoringrules": {
#     "after": [],
#     "before": [
#         {
#             "alert_enabled": false,
#             "description": "THIS IS TEST IMR DESCRIPTION - 1",
#             "id": 213,
#             "minimum_agent_version": "6.0.0.0",
#             "minimum_manager_version": "6.0.0",
#             "name": "THIS IS TEST IMR - 1",
#             "real_time_monitoring_enabled": true,
#             "registry_attributes": [
#                 "STANDARD"
#             ],
#             "registry_excluded_values": [
#                 ""
#             ],
#             "registry_include_default_value": true,
#             "registry_include_subkeys": false,
#             "registry_included_values": [
#                 "test_1",
#                 "test_2"
#             ],
#             "registry_key_root": "HKEY_CLASSES_ROOT",
#             "registry_key_value": "\\",
#             "severity": "medium",
#             "template": "registry"
#         },
#         {
#             "alert_enabled": false,
#             "description": "THIS IS TEST IMR DESCRIPTION - 2",
#             "id": 214,
#             "minimum_agent_version": "6.0.0.0",
#             "minimum_manager_version": "6.0.0",
#             "name": "THIS IS TEST IMR - 2",
#             "real_time_monitoring_enabled": true,
#             "registry_attributes": [
#                 "test"
#             ],
#             "registry_excluded_values": [
#                 ""
#             ],
#             "registry_include_default_value": true,
#             "registry_include_subkeys": false,
#             "registry_included_values": [
#                 ""
#             ],
#             "registry_key_root": "HKEY_CLASSES_ROOT",
#             "registry_key_value": "\\",
#             "severity": "low",
#             "template": "registry"
#         }
#     ]
# }

"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    map_obj_to_params,
    map_params_to_obj,
    remove_get_keys_from_payload_dict,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)

key_transform = {
    "id": "ID",
    "registry_key_root": "registryKeyRoot",
    "registry_key_value": "registryKeyValue",
    "registry_include_subkeys": "registryIncludeSubKeys",
    "registry_included_values": "registryIncludedValues",
    "registry_include_default_value": "registryIncludeDefaultValue",
    "registry_excluded_values": "registryExcludedValues",
    "registry_attributes": "registryAttributes",
    "filebase_directory": "fileBaseDirectory",
    "fileinclude_subdirectories": "fileIncludeSubDirectories",
    "file_included_values": "fileIncludedValues",
    "file_excluded_values": "fileExcludedValues",
    "file_attributes": "fileAttributes",
    "custom_xml": "customXML",
    "alert_enabled": "alertEnabled",
    "real_time_monitoring_enabled": "realTimeMonitoringEnabled",
    "recommendations_mode": "recommendationsMode",
    "minimum_agent_version": "minimumAgentVersion",
    "minimum_manager_version": "minimumManagerVersion",
    "original_issue": "originalIssue",
    "last_updated": "lastUpdated",
}

get_supported_keys = [
    "minimum_agent_version",
    "minimum_manager_version",
    "identifier",
    "type",
    "original_issue",
    "last_updated",
    "id",
]

api_object = "/api/integritymonitoringrules"
api_object_search = "/api/integritymonitoringrules/search"
api_return = "integrityMonitoringRules"
module_return = "integrity_monitoringrules"


def search_for_imr_by_name(deepsec_request, name):
    search_payload = {
        "maxItems": 1,
        "searchCriteria": [
            {"fieldName": "name", "stringTest": "equal", "stringValue": name}
        ],
    }
    search_result = search_for_integrity_monitoring_rules(
        deepsec_request, search_payload
    )
    return search_result


def display_gathered_result(module, deepsec_request):
    return_config = {}
    if module.params.get("config"):
        return_config["config"] = []
        for each in module.params.get("config"):
            search_result = search_for_imr_by_name(
                deepsec_request, each["name"]
            )
            return_config["config"].extend(
                map_obj_to_params(search_result, key_transform, api_return)[
                    api_return
                ]
            )
    else:
        search_result = search_for_integrity_monitoring_rules(deepsec_request)
        return_config["config"] = map_obj_to_params(
            search_result, key_transform, api_return
        )[api_return]
    module.exit_json(gathered=return_config["config"], changed=False)


def search_for_integrity_monitoring_rules(
    deepsec_api_request, search_payload=None
):
    search_for_integrity_monitoring_rules = deepsec_api_request.post(
        api_object_search, data=search_payload
    )
    return search_for_integrity_monitoring_rules


def reset_module_api_config(module, deepsec_request):
    if module.params.get("config"):
        config = {}
        before = []
        after = []
        changed = False
        for each in module.params["config"]:
            search_by_name = search_for_imr_by_name(
                deepsec_request, each["name"]
            )
            if search_by_name.get(api_return):
                every = map_obj_to_params(
                    search_by_name[api_return][0], key_transform, api_return
                )
                before.append(every)
                api_request = deepsec_request.delete(
                    "{0}/{1}".format(api_object, every["id"]), data=each
                )
                if api_request.get("errors"):
                    module.fail_json(msg=api_request["errors"])
                elif api_request.get("message"):
                    module.fail_json(msg=api_request["message"])
                changed = True
                if api_request:
                    after.append(
                        map_obj_to_params(
                            api_request, key_transform, api_return
                        )
                    )
        if changed:
            config.update({"before": before, "after": after})
            module.exit_json(integrity_monitoringrules=config, changed=changed)
        else:
            config.update({"before": before})
            module.exit_json(integrity_monitoringrules=config, changed=changed)


def configure_module_api(argspec, module, deepsec_request):
    if module.params.get("config"):
        config = {}
        before = []
        after = []
        changed = False
        temp_name = []
        for each in module.params["config"]:
            search_by_name = search_for_imr_by_name(
                deepsec_request, each["name"]
            )
            if search_by_name.get(api_return):
                each_result = search_by_name[api_return]
                temp = copy.deepcopy(each_result)
                for every in temp:
                    every = map_obj_to_params(every, key_transform, api_return)
                    if every["name"] == each["name"]:
                        diff = utils.dict_diff(every, each)
                if diff:
                    diff = remove_get_keys_from_payload_dict(
                        diff, get_supported_keys
                    )
                    if diff:
                        if each["name"] not in temp_name:
                            after.extend(before)
                        before.append(every)
                        # Check for actual modification and if present fire
                        # the request over that IPR ID
                        each = utils.remove_empties(
                            utils.dict_merge(every, each)
                        )
                        each = remove_get_keys_from_payload_dict(
                            each, get_supported_keys
                        )
                        changed = True
                        utils.validate_config(argspec, {"config": [each]})
                        payload = map_params_to_obj(each, key_transform)
                        api_request = deepsec_request.post(
                            "{0}/{1}".format(api_object, every["id"]),
                            data=payload,
                        )
                        if api_request.get("errors"):
                            module.fail_json(msg=api_request["errors"])
                        elif api_request.get("message"):
                            module.fail_json(msg=api_request["message"])
                        after.append(
                            map_obj_to_params(
                                api_request, key_transform, api_return
                            )
                        )
                    else:
                        before.append(every)
                        temp_name.append(every["name"])
                else:
                    before.append(every)
            else:
                changed = True
                each = remove_get_keys_from_payload_dict(
                    each, get_supported_keys
                )
                utils.validate_config(argspec, {"config": [each]})
                payload = map_params_to_obj(each, key_transform)
                api_request = deepsec_request.post(
                    "{0}".format(api_object), data=payload
                )
                if api_request.get("errors"):
                    module.fail_json(msg=api_request["errors"])
                elif api_request.get("message"):
                    module.fail_json(msg=api_request["message"])
                after.append(
                    map_obj_to_params(api_request, key_transform, api_return)
                )
        config.update({"before": before, "after": after})
        module.exit_json(integrity_monitoringrules=config, changed=changed)


def main():

    imr_spec = {
        "name": dict(type="str"),
        "description": dict(type="str"),
        "severity": dict(
            type="str", choices=["low", "medium", "high", "critical"]
        ),
        "template": dict(type="str", choices=["registry", "file", "custom"]),
        "registry_key_root": dict(type="str", no_log=True),
        "registry_key_value": dict(type="str", no_log=True),
        "registry_include_subkeys": dict(type="bool"),
        "registry_included_values": dict(type="list", elements="str"),
        "registry_include_default_value": dict(type="bool"),
        "registry_excluded_values": dict(type="list", elements="str"),
        "registry_attributes": dict(type="list", elements="str"),
        "filebase_directory": dict(type="str"),
        "fileinclude_subdirectories": dict(type="bool"),
        "file_included_values": dict(type="list", elements="str"),
        "file_excluded_values": dict(type="list", elements="str"),
        "file_attributes": dict(type="list", elements="str"),
        "custom_xml": dict(type="str"),
        "alert_enabled": dict(type="bool"),
        "real_time_monitoring_enabled": dict(type="bool"),
        "recommendations_mode": dict(
            type="str", choices=["enabled", "ignored", "unknown", "disabled"]
        ),
        "minimum_agent_version": dict(type="str"),
        "minimum_manager_version": dict(type="str"),
        "original_issue": dict(type="int"),
        "last_updated": dict(type="int"),
        "type": dict(type="str"),
        "identifier": dict(type="str"),
        "id": dict(type="int"),
    }

    argspec = dict(
        state=dict(
            choices=["present", "absent", "gathered"], default="present"
        ),
        config=dict(type="list", elements="dict", options=imr_spec),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    module.params = utils.remove_empties(module.params)

    if module.params["state"] == "gathered":
        display_gathered_result(module=module, deepsec_request=deepsec_request)
    elif module.params["state"] == "absent":
        reset_module_api_config(module=module, deepsec_request=deepsec_request)
    elif module.params["state"] == "present":
        configure_module_api(
            argspec=argspec, module=module, deepsec_request=deepsec_request
        )


if __name__ == "__main__":
    main()

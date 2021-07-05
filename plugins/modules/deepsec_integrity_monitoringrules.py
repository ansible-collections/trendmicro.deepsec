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
module: deepsec_integrity_monitoring_rules
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
        description:
          - Name of the IntegrityMonitoringRule.
          - Searchable as String.
        type: str
      description:
        description:
          - Description of the IntegrityMonitoringRule.
          - Searchable as String.
        type: str
      severity:
        description:
          - Severity level of the event is multiplied by the computer's asset value to determine ranking.
          - Ranking can be used to sort events with more business impact.
          - Searchable as Choice.
        choices: ["low", "medium", "high", "critical"]
        type: str
      template:
        description: Template which the IntegrityMonitoringRule follows.
        choices: ["registry", "file", "custom"]
        type: str
      registry_key_root:
        description:
          - Registry hive which is monitored by the IntegrityMonitoringRule.
          - Empty if the IntegrityMonitoringRule does not monitor a registry key.
        type: str
      registry_key_value:
        description:
          - Registry key which is monitored by the IntegrityMonitoringRule.
          - Empty if the IntegrityMonitoringRule does not monitor a registry key.
          - Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: str
      registryinclude_subkeys:
        description:
          - Controls whether the IntegrityMonitoringRule should also include subkeys of the registry key it monitors.
          - Defaults to false.
          - Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: bool
      registry_included_values
        description:
          - Registry key values to be monitored by the IntegrityMonitoringRule.
          - JSON array or delimited by \n. ? matches a single character, while * matches zero or more characters.
          - Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: list
        elements: str
      registryinclude_default_value:
        description:
          - Controls whether the rule should monitor default registry key values.
          - Defaults to true.
          - Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        default: true
        type: bool
      registry_excluded_values:
        description:
          - Registry key values to be ignored by the IntegrityMonitoringRule.
          - JSON array or delimited by \n. ? matches a single character, while * matches zero or more characters.
          - Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: list
        elements: str
      registry_attributes:
        description:
          - Registry key attributes to be monitored by the IntegrityMonitoringRule.
          - JSON array or delimited by \n. Defaults to STANDARD which will monitor changes in registry size, content and type.
          - Ignored if the IntegrityMonitoringRule does not monitor a registry key.
        type: list
        elements: str
      filebase_directory:
        description:
          - Base of the file directory to be monitored by the IntegrityMonitoringRule.
          - Ignored if the IntegrityMonitoringRule does not monitor a file directory.
        type: str
      fileinclude_subdirectories:
        description:
          - Controls whether the IntegrityMonitoringRule should also monitor sub-directories of
            the base file directory that is associated with it.
          - Defaults to false.
          - Ignored if the IntegrityMonitoringRule does not monitor a file directory.
        default: false
        type: bool
      file_included_values:
        description:
          - File name values to be monitored by the IntegrityMonitoringRule.
          - JSON array or delimited by \n. ? matches a single character, while * matches zero or more characters.
          - Leaving this field blank when monitoring file directories will cause the IntegrityMonitoringRule
            to monitor all files in a directory.
          - This can use significant system resources if the base directory contains numerous or large files.
          - Ignored if the IntegrityMonitoringRule does not monitor a file directory.
        type: list
        elements: str
      file_excluded_values:
        description:
          - File name values to be ignored by the IntegrityMonitoringRule.
          - JSON array or delimited by \n. ? matches a single character, while * matches zero or more characters.
          - Ignored if the IntegrityMonitoringRule does not monitor a file directory.
        type: list
        elements: str
      file_attributes:
        description:
          - File attributes to be monitored by the IntegrityMonitoringRule.
          - JSON array or delimited by \n.
          - Defaults to STANDARD which will monitor changes in file creation date,
            last modified date, permissions, owner, group, size, content, flags (Windows) and SymLinkPath (Linux).
          - Ignored if the IntegrityMonitoringRule does not monitor a file directory.
        type: list
        elements: str
      custom_xml:
        description:
          - Custom XML rules to be used by the IntegrityMonitoringRule.
          - Custom XML rules must be encoded in the Base64 format.
          - Ignored if the IntegrityMonitoringRule does not follow the custom template.
        type: str
      alert_enabled:
        description:
          - Controls whether an alert should be made if an event related to the IntegrityMonitoringRule is logged.
          - Defaults to false.
          - Searchable as Boolean.
        default: false
        type: bool
      real_time_monitoring_enabled:
        description:
          - Controls whether the IntegrityMonitoringRule is monitored in real time or during every scan.
          - Defaults to true which indicates that it is monitored in real time.
          - A value of false indicates that it will only be checked during scans.
          - Searchable as Boolean.
        default: true
        type: bool
      recommendations_mode:
        description:
          - Indicates whether recommendation scans consider the IntegrityMonitoringRule.
          - Can be set to enabled or ignored.
          - Custom rules cannot be recommended.
          - Searchable as Choice.
        choices: ["enabled", "ignored", "unknown", "disabled"
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

- name: Create Integrity Monitoring Rules
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: present
    config:
      - alert_enabled: false
        always_include_packet_data: false
        application_type_id: 300
        can_be_assigned_alone: true
        template: signature
        signature: test_new_signature_1
        debug_mode_enabled: false
        description: TEST IPR 2 DESCRIPTION
        detect_only: false
        event_logging_disabled: false
        generate_event_on_packet_drop: true
        name: TEST IPR 1
        priority: normal
        severity: medium
      - alert_enabled: false
        always_include_packet_data: false
        application_type_id: 300
        can_be_assigned_alone: true
        template: signature
        signature: test_new_signature_2
        debug_mode_enabled: false
        description: TEST IPR 2 DESCRIPTION
        detect_only: false
        event_logging_disabled: false
        generate_event_on_packet_drop: true
        name: TEST IPR 2
        priority: normal
        severity: medium

# Play Run:
# =========
#
# "integrity_monitoring_rules": {
#     "after": [
#         {
#             "action": "drop",
#             "alert_enabled": false,
#             "always_include_packet_data": false,
#             "application_type_id": 300,
#             "case_sensitive": false,
#             "debug_mode_enabled": false,
#             "description": "TEST IPR 2 DESCRIPTION",
#             "detect_only": false,
#             "event_logging_disabled": false,
#             "generate_event_on_packet_drop": true,
#             "id": 7887,
#             "name": "TEST IPR 1",
#             "priority": "normal",
#             "severity": "medium",
#             "signature": "test_new_signature_1",
#             "template": "signature"
#         },
#         {
#             "action": "drop",
#             "alert_enabled": false,
#             "always_include_packet_data": false,
#             "application_type_id": 300,
#             "case_sensitive": false,
#             "debug_mode_enabled": false,
#             "description": "TEST IPR 2 DESCRIPTION",
#             "detect_only": false,
#             "event_logging_disabled": false,
#             "generate_event_on_packet_drop": true,
#             "id": 7888,
#             "name": "TEST IPR 2",
#             "priority": "normal",
#             "severity": "medium",
#             "signature": "test_new_signature_2",
#             "template": "signature"
#         }
#     ],
#     "before": []
# }

- name: Delete Integrity Monitoring Rules
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: absent
    config:
      - name: TEST IPR 1
      - name: TEST IPR 2

# Play Run:
# =========
#
# "integrity_monitoring_rules": {
#     "after": [],
#     "before": [
#         {
#             "action": "drop",
#             "alert_enabled": false,
#             "always_include_packet_data": false,
#             "application_type_id": 300,
#             "case_sensitive": false,
#             "debug_mode_enabled": false,
#             "description": "TEST IPR 2 DESCRIPTION",
#             "detect_only": false,
#             "event_logging_disabled": false,
#             "generate_event_on_packet_drop": true,
#             "id": 7887,
#             "name": "TEST IPR 1",
#             "priority": "normal",
#             "severity": "medium",
#             "signature": "test_new_signature_1",
#             "template": "signature"
#         },
#         {
#             "action": "drop",
#             "alert_enabled": false,
#             "always_include_packet_data": false,
#             "application_type_id": 300,
#             "case_sensitive": false,
#             "debug_mode_enabled": false,
#             "description": "TEST IPR 2 DESCRIPTION",
#             "detect_only": false,
#             "event_logging_disabled": false,
#             "generate_event_on_packet_drop": true,
#             "id": 7888,
#             "name": "TEST IPR 2",
#             "priority": "normal",
#             "severity": "medium",
#             "signature": "test_new_signature_2",
#             "template": "signature"
#         }
#     ]
# }

- name: Gather Integrity Monitoring Rules by IPR names
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: gathered
    config:
      - name: TEST IPR 1
      - name: TEST IPR 2

# Play Run:
# =========
#
# "gathered": [
#     {
#         "action": "drop",
#         "alert_enabled": false,
#         "always_include_packet_data": false,
#         "application_type_id": 300,
#         "case_sensitive": false,
#         "debug_mode_enabled": false,
#         "description": "TEST IPR 2 DESCRIPTION",
#         "detect_only": false,
#         "event_logging_disabled": false,
#         "generate_event_on_packet_drop": true,
#         "id": 7887,
#         "name": "TEST IPR 1",
#         "priority": "normal",
#         "severity": "medium",
#         "signature": "test_new_signature_1",
#         "template": "signature"
#     },
#     {
#         "action": "drop",
#         "alert_enabled": false,
#         "always_include_packet_data": false,
#         "application_type_id": 300,
#         "case_sensitive": false,
#         "debug_mode_enabled": false,
#         "description": "TEST IPR 2 DESCRIPTION",
#         "detect_only": false,
#         "event_logging_disabled": false,
#         "generate_event_on_packet_drop": true,
#         "id": 7888,
#         "name": "TEST IPR 2",
#         "priority": "normal",
#         "severity": "medium",
#         "signature": "test_new_signature_2",
#         "template": "signature"
#     }
# ]

- name: Gather ALL of the Integrity Monitoring Rules
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: gathered
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    map_obj_to_params,
    map_params_to_obj,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)

key_transform = {
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

api_object = "/api/integritymonitoringrules"
api_object_search = "/api/integritymonitoringrules/search"
api_return = "integrityMonitoringRules"
module_return = "integrity_monitoring_rules"


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
            module.exit_json(
                integrity_monitoring_rules=config, changed=changed
            )
        else:
            config.update({"before": before})
            module.exit_json(
                integrity_monitoring_rules=config, changed=changed
            )


def configure_module_api(argspec, module, deepsec_request):
    if module.params.get("config"):
        config = {}
        before = []
        after = []
        changed = False
        remove_from_diff_compare = [
            "cvss_score",
            "cve",
            "can_be_assigned_alone",
            "type",
        ]
        for each in module.params["config"]:
            search_by_name = search_for_imr_by_name(
                deepsec_request, each["name"]
            )
            if search_by_name.get(api_return):
                each_result = search_by_name[api_return]
                for every in each_result:
                    every = map_obj_to_params(every, key_transform, api_return)
                    if every["name"] == each["name"]:
                        diff = utils.dict_diff(every, each)
                if diff:
                    before.append(every)
                    for each_key in remove_from_diff_compare:
                        if each_key in diff:
                            diff.pop(each_key)
                    if diff:
                        # Check for actual modification and if present fire
                        # the request over that IPR ID
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
                    before.append(each_result)
            else:
                changed = True
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
        module.exit_json(integrity_monitoring_rules=config, changed=changed)


def main():

    ipr_spec = {
        "name": dict(type="str"),
        "description": dict(type="str"),
        "minimum_agent_version": dict(type="str"),
        "application_type_id": dict(type="int"),
        "priority": dict(
            type="str", choices=["lowest", "low", "normal", "high", "highest"]
        ),
        "severity": dict(
            type="str", choices=["low", "medium", "high", "critical"]
        ),
        "detect_only": dict(type="bool"),
        "event_logging_disabled": dict(type="bool"),
        "generate_event_on_packet_drop": dict(type="bool"),
        "always_include_packet_data": dict(type="bool"),
        "debug_mode_enabled": dict(type="bool"),
        "type": dict(
            type="str",
            choices=[
                "custom",
                "smart",
                "vulnerability",
                "exploit",
                "hidden",
                "policy",
                "info",
            ],
        ),
        "original_issue": dict(type="int"),
        "id": dict(type="int"),
        "identifier": dict(type="str"),
        "last_updated": dict(type="int"),
        "template": dict(
            type="str", choices=["signature", "start-end-patterns", "custom"]
        ),
        "signature": dict(type="str"),
        "start": dict(type="str"),
        "patterns": dict(type="list", elements="str"),
        "end": dict(type="str"),
        "can_be_assigned_alone": dict(type="bool"),
        "case_sensitive": dict(type="bool"),
        "condition": dict(type="str", choices=["all", "any", "none"]),
        "action": dict(type="str", choices=["drop", "log-only"]),
        "custom_xml": dict(type="str"),
        "alert_enabled": dict(type="bool"),
        "schedule_id": dict(type="int"),
        "context_id": dict(type="int"),
        "recommendations_mode": dict(type="str"),
        "depends_on_rule_ids": dict(type="list", elements="int"),
        "cvss_score": dict(type="str"),
        "cve": dict(type="list", elements="str"),
    }

    argspec = dict(
        state=dict(
            choices=["present", "absent", "gathered"], default="present"
        ),
        config=dict(type="list", elements="dict", options=ipr_spec),
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
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
module: deepsec_intrusion_preventionrules
short_description: Create a new intrusion prevention rule.
description:
  - This module creates a new intrusion preventin rul under TrendMicro Deep Security.
version_added: "1.2.0"
deprecated:
  alternative: deepsec_intrusion_prevention_rules
  why: Newer and updated modules released with more functionality
  removed_at_date: '2023-12-08'
options:
  config:
    description: Intrusion prevention rules config
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of the IntrusionPreventionRule.
          - Searchable as String.
        type: str
      description:
        description:
          - Description of the IntrusionPreventionRule.
          - Searchable as String.
        type: str
      minimum_agent_version:
        description:
          - Version of the Deep Security agent or appliance required to support the rule.
          - Searchable as String.
        type: str
      application_type_id:
        description:
          - ID of the application type for the IntrusionPreventionRule.
          - Searchable as Numeric.
        type: int
      priority:
        description:
          - Priority level of the rule. Higher priority rules are applied before lower priority rules.
          - Searchable as Choice.
        choices: ["lowest", "low", "normal", "high", "highest"]
        type: str
      severity:
        description:
          - Severity level of the rule. Severity levels can be used as sorting criteria and affect event rankings.
          - Searchable as Choice.
        choices: ["low", "medium", "high", "critical"]
        type: str
      detect_only:
        description: In detect mode, the rule creates an event log and does not interfere with traffic.
        type: bool
      event_logging_disabled:
        description:
          - Enable to prevent event logs from being created when the rule is triggered.
          - Not available if detect only is true.
          - Searchable as Boolean.
        type: bool
      generate_event_on_packet_drop:
        description:
          - Generate an event every time a packet is dropped for the rule.
          - Not available if event logging disabled is true.
          - Searchable as Boolean.
        type: bool
      always_include_packet_data:
        description:
          - Enabled to include package data in the event logs.
          - Not available if event logging disabled is true.
          - Searchable as Boolean.
        type: bool
      debug_mode_enabled:
        description:
          - Enable to log additional packets preceeding and following the packet that the rule detected.
          - Not available if event logging disabled is true.
          - Searchable as Boolean.
        type: bool
      type:
        description:
          - Type of IntrusionPreventionRule.
          - Searchable as Choice.
        choices: ["custom", "smart", "vulnerability", "exploit", "hidden", "policy", "info"]
        type: str
      original_issue:
        description:
          - Timestamp of the date the rule was released, in milliseconds since epoch.
          - Searchable as Date.
        type: int
      last_updated:
        description:
          - Timestamp of the last rule modification, in milliseconds since epoch.
          - Searchable as Date.
        type: int
      template:
        description: Type of template for the IntrusionPreventionRule. Applicable only to custom rules.
        choices: ["signature", "start-end-patterns", "custom"]
        type: str
      signature:
        description: Signature of the rule. Applicable to custom rules with template type signature.
        type: str
      start:
        description: Start pattern of the rule. Applicable to custom rules with template type start-end-patterns.
        type: str
      patterns:
        description:
          - Body patterns of the rule, which must be found between start and end patterns.
          - Applicable to custom rules with template type start-end-patterns.
        type: list
        elements: str
      end:
        description: End pattern of the rule. Applicable to custom rules with template type start-end-patterns.
        type: str
      case_sensitive:
        description:
          - Enable to make signatures and patterns case sensitive.
          - Applicable to custom rules with template type signature or start-end-patterns.
        type: bool
      condition:
        description:
          - Condition to determine if the rule is triggered.
          - Applicable to custom rules with template type start-end-patterns.
        choices: ["all", "any", "none"]
        type: str
      action:
        description:
          - Action to apply if the rule is triggered.
          - Applicable to custom rules with template type signature or start-end-patterns.
        choices: ["drop", "log-only"]
        type: str
      custom_xml:
        description:
          - The custom XML used to define the rule.
          - Applicable to custom rules with template type custom.
        type: str
      alert_enabled:
        description:
          - Enable to raise an alert when the rule logs an event.
          - Searchable as Boolean.
        type: bool
      schedule_id:
        description:
          - ID of the schedule which defines times during which the rule is active.
          - Searchable as Numeric.
        type: int
      context_id:
        description:
          - ID of the context in which the rule is applied.
          - Searchable as Numeric.
        type: int
      recommendations_mode:
        description:
          - Indicates whether recommendation scans consider the IntrusionPreventionRule.
          - Can be set to enabled or ignored. Custom rules cannot be recommended.
          - Searchable as Choice.
        choices: ["enabled", "ignored", "unknown", "disabled"]
        type: str
      depends_on_rule_ids:
        description:
          - IDs of intrusion prevention rules the rule depends on, which will be automatically assigned if this rule is assigned.
        type: list
        elements: int
      cvss_score:
        description:
          - A measure of the severity of the vulnerability according the National Vulnerability Database.
          - Searchable as String or as Numeric.
        type: str
      cve:
        description:
          - List of CVEs associated with the IntrusionPreventionRule.
          - Searchable as String.
        type: list
        elements: str
      id:
        description:
          - ID for the Intrusion prevention rule.
          - Applicaple only with GET call
          - Not applicaple param with Create/Modify POST call
        type: int
      identifier:
        description:
          - Identifier for the Intrusion prevention rule.
          - Applicaple only with GET call
          - Not applicaple param with Create/Modify POST call
        type: str
      can_be_assigned_alone:
        description:
          - Intrusion prevention rule can be assigned by self.
          - Applicaple only with GET call
          - Not applicaple param with Create/Modify POST call
        type: bool
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

- name: Create Intrusion Prevention Rules
  trendmicro.deepsec.deepsec_intrusion_preventionrules:
    state: present
    config:
      - alert_enabled: false
        always_include_packet_data: false
        application_type_id: 300
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
# "intrusion_preventionrules": {
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

- name: Modify the severity of Integrity Monitoring Rule by name
  trendmicro.deepsec.deepsec_intrusion_preventionrules:
    state: present
    config:
      - name: TEST IPR 2
        severity: low

# Play Run:
# =========
#
# "intrusion_preventionrules": {
#     "after": [
#         {
#            "action": "drop",
#             "alert_enabled": false,
#             "always_include_packet_data": false,
#             "application_type_id": 300,
#             "case_sensitive": false,
#             "debug_mode_enabled": false,
#             "description": "TEST IPR",
#             "detect_only": false,
#             "event_logging_disabled": false,
#             "generate_event_on_packet_drop": true,
#             "id": 7902,
#             "name": "TEST IPR 2",
#             "priority": "normal",
#             "severity": "low",
#             "signature": "test_new_signature",
#             "template": "signature"
#          }
#     ],
#     "before": [
#         {
#            "action": "drop",
#             "alert_enabled": false,
#             "always_include_packet_data": false,
#             "application_type_id": 300,
#             "case_sensitive": false,
#             "debug_mode_enabled": false,
#             "description": "TEST IPR",
#             "detect_only": false,
#             "event_logging_disabled": false,
#             "generate_event_on_packet_drop": true,
#             "id": 7902,
#             "name": "TEST IPR 2",
#             "priority": "normal",
#             "severity": "medium",
#             "signature": "test_new_signature",
#             "template": "signature"
#          }
#     ]
# }

# Using GATHERED state
# --------------------

- name: Gather Intrusion Prevention Rules by IPR names
  trendmicro.deepsec.deepsec_intrusion_preventionrules:
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

- name: Gather ALL of the Intrusion Prevention Rules
  trendmicro.deepsec.deepsec_intrusion_preventionrules:
    state: gathered

# Using ABSENT state
# ------------------

- name: Delete Intrusion Prevention Rules
  trendmicro.deepsec.deepsec_intrusion_preventionrules:
    state: absent
    config:
      - name: TEST IPR 1
      - name: TEST IPR 2

# Play Run:
# =========
#
# "intrusion_preventionrules": {
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

"""

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

get_supported_keys = ["id", "identifier", "can_be_assigned_alone"]

api_object = "/api/intrusionpreventionrules"
api_object_search = "/api/intrusionpreventionrules/search"
api_return = "intrusionPreventionRules"
module_return = "intrusion_preventionrules"


def search_for_ipr_by_name(deepsec_request, name):
    search_payload = {
        "maxItems": 1,
        "searchCriteria": [
            {"fieldName": "name", "stringTest": "equal", "stringValue": name}
        ],
    }
    search_result = search_for_intrusion_prevention_rules(
        deepsec_request, search_payload
    )
    return search_result


def display_gathered_result(module, deepsec_request):
    return_config = {}
    if module.params.get("config"):
        return_config["config"] = []
        for each in module.params.get("config"):
            search_result = search_for_ipr_by_name(
                deepsec_request, each["name"]
            )
            return_config["config"].extend(
                map_obj_to_params(search_result, key_transform, api_return)[
                    api_return
                ]
            )
    else:
        search_result = search_for_intrusion_prevention_rules(deepsec_request)
        return_config["config"] = map_obj_to_params(
            search_result, key_transform, api_return
        )[api_return]
    module.exit_json(gathered=return_config["config"], changed=False)


def search_for_intrusion_prevention_rules(
    deepsec_api_request, search_payload=None
):
    search_for_intrusion_prevention_rules = deepsec_api_request.post(
        api_object_search, data=search_payload
    )
    return search_for_intrusion_prevention_rules


def reset_module_api_config(module, deepsec_request):
    if module.params.get("config"):
        config = {}
        before = []
        after = []
        changed = False
        for each in module.params["config"]:
            search_by_name = search_for_ipr_by_name(
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
            module.exit_json(intrusion_preventionrules=config, changed=changed)
        else:
            config.update({"before": before})
            module.exit_json(intrusion_preventionrules=config, changed=changed)


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
        temp_name = []
        for each in module.params["config"]:
            search_by_name = search_for_ipr_by_name(
                deepsec_request, each["name"]
            )
            if search_by_name.get(api_return):
                each_result = search_by_name[api_return]
                for every in each_result:
                    every = map_obj_to_params(every, key_transform, api_return)
                    if every["name"] == each["name"]:
                        diff = utils.dict_diff(every, each)
                if diff:
                    diff = remove_get_keys_from_payload_dict(
                        diff, remove_from_diff_compare
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
                            each, remove_from_diff_compare
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
        module.exit_json(intrusion_preventionrules=config, changed=changed)


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
        "recommendations_mode": dict(
            type="str", choices=["enabled", "ignored", "unknown", "disabled"]
        ),
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

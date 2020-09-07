#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Sumit Jaiswal (sjaiswal@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: intrusion_prevention_rules
short_description: Create a new intrusion prevention rule. 
description:
  - This module creates a new intrusion preventin rul under TrendMicro Deep Security.
version_added: "1.0.0"
options:
  name:
    description: Name of the IntrusionPreventionRule. Searchable as String.
    required: true
    type: str
  description:
    description: Description of the IntrusionPreventionRule. Searchable as String.
    required: false
    type: str
  minimumAgentVersion:
    description: Version of the Deep Security agent or appliance required to support the rule.
    Searchable as String.
    required: false
    type: str
  applicationTypeID:
    description: ID of the application type for the IntrusionPreventionRule.
    Searchable as Numeric.
    required: false
    type: int
  priority:
    description: Priority level of the rule. Higher priority rules are applied before
    lower priority rules. Searchable as Choice.
    choices: ["lowest", "low", "normal", "high", "highest"]
    required: false
    type: str
  severity:
    description: Severity level of the rule. Severity levels can be used as sorting
    criteria and affect event rankings. Searchable as Choice.
    choices: ["low", "medium", "high", "critical"]
    required: false
    type: str
  detectOnly:
    description: In detect mode, the rule creates an event log and does not interfere
    with traffic.
    required: false
    type: bool
  eventLoggingDisabled:
    description: Enable to prevent event logs from being created when the rule is triggered.
    Not available if detectOnly is true. Searchable as Boolean.
    required: false
    type: bool
  generateEventOnPacketDrop:
    description: Generate an event every time a packet is dropped for the rule.
    Not available if eventLoggingDisabled is true. Searchable as Boolean.
    required: false
    type: bool
  alwaysIncludePacketData:
    description: Enabled to include package data in the event logs. Not available if
    eventLoggingDisabled is true. Searchable as Boolean.
    required: false
    type: bool
  debugModeEnabled:
    description: Enable to log additional packets preceeding and following the packet that
    the rule detected. Not available if eventLoggingDisabled is true. Searchable as Boolean.
    required: false
    type: bool
  type:
    description: Type of IntrusionPreventionRule. Searchable as Choice.
    choices: ["custom", "smart", "vulnerability", "exploit", "hidden", "policy", "info"]
    required: false
    type: str
  originalIssue:
    description: Timestamp of the date the rule was released, in milliseconds since epoch.
    Searchable as Date.
    required: false
    type: int
  lastUpdated:
    description: Timestamp of the last rule modification, in milliseconds since epoch.
    Searchable as Date.
    required: false
    type: int
  template:
    description: Type of template for the IntrusionPreventionRule. Applicable only to custom rules.
    choices: ["signature", "start-end-patterns", "custom"]
    required: false
    type: str
  signature:
    description: Signature of the rule. Applicable to custom rules with template type signature.
    required: false
    type: str
  start:
    description: Start pattern of the rule. Applicable to custom rules with template type
    start-end-patterns.
    required: false
    type: str
  patterns:
    description: Body patterns of the rule, which must be found between start and end patterns.
    Applicable to custom rules with template type start-end-patterns.
    required: false
    type: list
    elements: str
  end:
    description: End pattern of the rule. Applicable to custom rules with template type
    start-end-patterns.
    required: false
    type: str
  caseSensitive:
    description: Enable to make signatures and patterns case sensitive. Applicable to custom
    rules with template type signature or start-end-patterns.
    required: false
    type: bool
  condition:
    description: Condition to determine if the rule is triggered. Applicable to custom rules
    with template type start-end-patterns.
    required: false
    choices: ["all", "any", "none"]
    type: str
  action:
    description: Action to apply if the rule is triggered. Applicable to custom rules
    with template type signature or start-end-patterns.
    required: false
    choices: ["drop", "log-only"]
    type: str
  customXML:
    description: The custom XML used to define the rule. Applicable to custom rules
    with template type custom.
    required: false
    type: str
  alertEnabled:
    description: Enable to raise an alert when the rule logs an event. Searchable as Boolean.
    required: false
    type: bool
  scheduleID:
    description: ID of the schedule which defines times during which the rule is active.
    Searchable as Numeric.
    required: false
    type: int
  contextID:
    description: ID of the context in which the rule is applied. Searchable as Numeric.
    required: false
    type: int
  recommendationsMode:
    description: Indicates whether recommendation scans consider the IntrusionPreventionRule.
    Can be set to enabled or ignored. Custom rules cannot be recommended. Searchable as Choice.
    required: false
    choices: ["enabled", "ignored", "unknown", "disabled"]
    type: str
  dependsOnRuleIDs:
    description: IDs of intrusion prevention rules the rule depends on, which will be
    automatically assigned if this rule is assigned.
    required: false
    type: list
    elements: int
  CVSSScore:
    description: A measure of the severity of the vulnerability according the National
    Vulnerability Database. Searchable as String or as Numeric.
    required: false
    type: int
  CVE:
    description: List of CVEs associated with the IntrusionPreventionRule.
    Searchable as String.
    required: false
    type: list
    elements: str

author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
"""


# FIXME - provide correct example here
RETURN = """
"""

EXAMPLES = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text

from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
)
import copy
import json


def map_params_to_obj(module_params):
    obj = {}
    obj["name"] = module_params["name"]
    if module_params.get("description"):
        obj["description"] = module_params.get("description")
    if module_params.get("minimum_agent_version"):
        obj["minimumAgentVersion"] = module_params.get("minimum_agent_version")
    if module_params.get("application_type_id"):
        obj["applicationTypeID"] = module_params.get("application_type_id")
    if module_params.get("priority"):
        obj["priority"] = module_params.get("priority")
    if module_params.get("severity"):
        obj["severity"] = module_params.get("severity")
    if module_params.get("detect_only"):
        obj["detectOnly"] = module_params.get("detect_only")
    if module_params.get("event_logging_disabled"):
        obj["event_logging_disabled"] = module_params.get(
            "eventLoggingDisabled"
        )
    if module_params.get("generate_event_on_packet_drop"):
        obj["generate_event_on_packet_drop"] = module_params.get(
            "generateEventOnPacketDrop"
        )
    if module_params.get("always_include_packet_data"):
        obj["alwaysIncludePacketData"] = module_params.get(
            "always_include_packet_data"
        )
    if module_params.get("debug_mode_enabled"):
        obj["debugModeEnabled"] = module_params.get("debug_mode_enabled")
    if module_params.get("type"):
        obj["type"] = module_params.get("type")
    if module_params.get("original_issue"):
        obj["originalIssue"] = module_params.get("original_issue")
    if module_params.get("last_updated"):
        obj["lastUpdated"] = module_params.get("last_updated")
    if module_params.get("template"):
        obj["template"] = module_params.get("template")
    if module_params.get("signature"):
        obj["signature"] = module_params.get("signature")
    if module_params.get("start"):
        obj["start"] = module_params.get("start")
    if module_params.get("patterns"):
        obj["patterns"] = module_params.get("patterns")
    if module_params.get("end"):
        obj["end"] = module_params.get("end")
    if module_params.get("case_sensitive"):
        obj["caseSensitive"] = module_params.get("case_sensitive")
    if module_params.get("condition"):
        obj["condition"] = module_params.get("condition")
    if module_params.get("action"):
        obj["action"] = module_params.get("action")
    if module_params.get("custom_xml"):
        obj["customXML"] = module_params.get("custom_xml")
    if module_params.get("alert_enabled"):
        obj["alertEnabled"] = module_params.get("alert_enabled")
    if module_params.get("schedule_id"):
        obj["scheduleID"] = module_params.get("schedule_id")
    if module_params.get("context_id"):
        obj["contextID"] = module_params.get("context_id")
    if module_params.get("recommendations_mode"):
        obj["recommendationsMode"] = module_params.get("recommendations_mode")
    if module_params.get("dependsOnRuleIDs"):
        obj["depends_on_rule_ids"] = module_params.get("dependsOnRuleIDs")
    if module_params.get("cvss_score"):
        obj["CVSSScore"] = module_params.get("cvss_score")
    if module_params.get("cve"):
        obj["CVE"] = module_params.get("cve")

    return obj


def check_if_intrusion_prevention_rules_exists(
    deepsec_request, antimalware_name
):
    """ The fn check if the antimalware detect based on antimalware name
    :param deepsec_request: the objects from which the configuration should be read
    :param antimalware_name: antimalware name with which antimalware will be searched
    in existing antimalware configurations
    :rtype: A dict
    :returns: dict with search result value
    """
    search_dict = {}
    search_dict["searchCriteria"] = []
    temp_criteria = {}
    temp_criteria["fieldName"] = "name"
    temp_criteria["stringTest"] = "equal"
    temp_criteria["stringValue"] = antimalware_name
    search_dict["searchCriteria"].append(temp_criteria)

    search_result = deepsec_request.post(
        "/api/intrusionpreventionrules/search", data=search_dict
    )
    if search_result.get("intrusionPreventionRules"):
        return search_result["intrusionPreventionRules"][0]
    return search_result


def delete_intrusion_prevention_with_id(
    module, deepsec_request, antimalware_id
):
    """ The fn calls the delete API based on the antimalware id
    :param module: ansible module object
    :param deepsec_request: connection obj for TM
    :param antimalware_id: antimalware id for the antimalware that's supposed to be deleted
    value has dict as its value
    :rtype: A dict
    :returns: Based on API response this fn. exits with appropriate msg
    """
    deepsec_request.delete(
        "/api/intrusionpreventionrules/{0}".format(antimalware_id)
    )
    module.exit_json(
        msg="intrusionPreventionRules with id: {} deleted successfully!".format(
            antimalware_id
        ),
        changed=True,
    )


def main():

    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        name=dict(required=True, type="str"),
        description=dict(type="str", required=False),
        minimum_agent_version=dict(type="str", required=False),
        application_type_id=dict(type="int", required=False),
        priority=dict(
            type="str",
            choices=["lowest", "low", "normal", "high", "highest"],
            required=False,
        ),
        severity=dict(
            type="str",
            choices=["low", "medium", "high", "critical"],
            required=False,
        ),
        detect_only=dict(type="bool", required=False),
        event_logging_disabled=dict(type="bool", required=False),
        generate_event_on_packet_drop=dict(type="bool", required=False),
        always_include_packet_data=dict(type="bool", required=False),
        debug_mode_enabled=dict(type="bool", required=False),
        type=dict(
            type="str",
            choices=[
                "custom",
                "smart",
                "smart",
                "exploit",
                "hidden",
                "policy",
                "info",
            ],
            required=False,
        ),
        original_issue=dict(type="int", required=False),
        last_updated=dict(type="int", required=False),
        template=dict(
            type="str",
            choices=["signature", "start-end-patterns", "custom"],
            required=True,
        ),
        signature=dict(type="str", required=False),
        start=dict(type="str", required=False),
        patterns=dict(type="list", required=False),
        end=dict(type="str", required=False),
        case_sensitive=dict(type="bool", required=False),
        condition=dict(
            type="str", choices=["all", "any", "none"], required=False
        ),
        action=dict(type="str", choices=["drop", "log-only"], required=False),
        custom_xml=dict(type="str", required=False),
        alert_enabled=dict(type="bool", required=False),
        schedule_id=dict(type="int", required=False),
        context_id=dict(type="int", required=False),
        recommendations_mode=dict(type="str", required=False),
        depends_on_rule_ids=dict(type="list", elements="int", required=False),
        cvss_score=dict(type="bool", required=False),
        cve=dict(type="list", elements="str", required=False),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))

    search_existing_intrusion_prevention_rules = check_if_config_exists(
        deepsec_request,
        want["name"],
        "intrusionpreventionrules",
        "intrusionPreventionRules",
    )

    if (
        "ID" in search_existing_intrusion_prevention_rules
        and module.params["state"] == "absent"
    ):
        delete_config_with_id(
            module,
            deepsec_request,
            "intrusionpreventionrules",
            search_existing_intrusion_prevention_rules["ID"],
            "intrusionPreventionRules",
        )
    elif (
        "ID" not in search_existing_intrusion_prevention_rules
        and module.params["state"] == "absent"
    ):
        module.exit_json(changed=False)
    else:
        intrusion_prevention_rules = deepsec_request.post(
            "/api/intrusionpreventionrules", data=want
        )
        if "ID" in search_existing_intrusion_prevention_rules:
            module.exit_json(
                intrusion_prevention_rules=search_existing_intrusion_prevention_rules,
                changed=False,
            )
        elif intrusion_prevention_rules.get("message"):
            module.fail_json(msg=intrusion_prevention_rules["message"])
        else:
            module.exit_json(
                intrusion_prevention_rules=intrusion_prevention_rules,
                changed=True,
            )
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

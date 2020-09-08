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
module: log_inspection_rules
short_description: Create a new log inspection rule. 
description:
  - This module creates a new log inspection rule under TrendMicro Deep Security.
version_added: "1.0.0"
options:
  name:
    description: Name of the LogInspectionRule. Searchable as String.
    required: true
    type: str
  description:
    description: Description of the LogInspectionRule that appears in search results,
    and on the General tab in the Deep Security Manager user interface. Searchable as String.
    type: str
  minimum_agent_version:
    description: Minimum Deep Security Agent version required by the LogInspectionRule.
    Searchable as String.
    type: str
  minimum_manager_version:
    description: Minimumn Deep Security Manager version required by the LogInspectionRule.
    Searchable as String.
    type: str
  type:
    description: Type of the LogInspectionRule. The value 'Defined' is used for LogInspectionRules
    provided by Trend Micro. Searchable as String.
    type: str
  original_issue:
    description: Creation timestamp of the LogInspectionRule, measured in milliseconds since
    epoch. Searchable as Date.
    type: int
  last_updated:
    description: Update timestamp of the LogInspectionRule, measured in milliseconds since epoch.
    Searchable as Date.
    type: int
  identifier:
    description: Indentifier of the LogInspectionRule used in the Deep Security Manager user interface.
    Searchable as String.
    type: str
  template:
    description: Template used to create this rule.
    choices: ["basic-rule", "custom"]
    type: str
  rule_id:
    description: ID of the LogInspectionRule sent to the Deep Security Agent.
    The values 100000 - 109999 are reserved for user-definded rules.
    type: int
  level:
    description: Log level of the LogInspectionRule indicates severity of attack.
    Level 0 is the least severe and will not log an event. Level 15 is the most severe.
    type: int
  groups:
    description: Groups that the LogInspectionRule is assigned to, separated by commas.
    Useful when dependency is used as it's possible to create a LogInspectionRule that
    fires when another LogInspectionRule belonging to a specific group fires.
    type: list
    elements: str
  rule_description:
    description: Description of the LogInspectionRule that appears on events and the
    Content tab in the Deep Security Manager user interface.
    Alternatively, you can configure this by inserting a description in 'rule_xml'.
    type: str
  pattern:
    description: Regular expression pattern the LogInspectionRule will look for in the logs.
    The rule will be triggered on a match. Open Source HIDS SEcurity (OSSEC) regular expression
    syntax is supported, see http://www.ossec.net/docs/syntax/regex.html.
    type: str
  pattern_type:
    description: Pattern the LogInspectionRule will look for in the logs. The string matching
    pattern is faster than the regex pattern.
    choices: ["string", "regex"]
    type: str
  dependency:
    description: Indicates if a dependant rule or dependency group is set or not.
    If set, the LogInspectionRule will only log an event if the dependency is triggered.
    Available for user-defined rules.
    choices: ["none", "rule", "group"]
    type: str
  dependency_rule_id:
    description: If dependency is configured, the ID of the rule that this rule is dependant on.
    Ignored if the rule is from Trend Micro, which uses dependsOnRuleIDs instead.
    type: int
  dependency_group:
    description: If dependency is configured, the dependancy groups that this rule is dependant on.
    type: str
  frequency:
    description: Number of times the dependant rule has to match within a specific time frame before
    the rule is triggered.
    type: int
  time_frame:
    description: Time period for the frequency of LogInspectionRule triggers that will generate an event,
    in seconds.
    type: int
  rule_xml:
    description: LogInspectionRule in an XML format. For information on the XML format,
    see http://ossec-docs.readthedocs.io/en/latest/syntax/head_rules.html
    type: str
  log_files:
    description: Log file objects
    type: dict
    suboptions:
      log_files:
        description: Array of objects (logFile)
        type: list
        elements: dict
        suboptions:
          location:
            description: File path of the log file.
            type: str
          format:
            description: Structure of the data in the log file. The application that generates
            the log file defines the structure of the data.
            choices: ["syslog", "snort-full", "snort-fast", "apache", "iis", "squid", "nmapg",
                "mysql-log", "postgresql-log", "dbj-multilog", "eventlog", "single-line-text-log"]
            type: str
  alert_enabled:
    description: Controls whether to raise an alert when a LogInspectionRule logs an event.
    Use true to raise an alert. Searchable as Boolean.
    type: bool
  alert_minimum_severity:
    description: Severity level that will trigger an alert. Ignored unless ruleXML contains
    multiple rules with different severities, and so you must indicate which severity level to use.
    Searchable as Numeric.
    type: int
  recommendations_mode:
    description: Indicates whether recommendation scans consider the LogInspectionRule. Can be set to
    enabled or ignored. Custom rules cannot be recommended. Searchable as Choice.
    choices: ["enabled", "ignored", "unknown", "disabled"]
    type: bool
  sort_order:
    description: Order in which LogInspectionRules are sent to the Deep Security Agent. Log inspeciton
    rules are sent in ascending order. Valid values are between 10000 and 20000.
    type: int
state:
  description:
  - The state the configuration should be left in
  type: str
  choices:
  - present
  - absent
  default: present
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


def log_files_fn(module_params):
    temp_obj = {}
    temp_obj = {"logFiles": module_params.get("log_files")["log_files"]}

    return temp_obj


def map_params_to_obj(module_params):
    obj = {}
    obj["name"] = module_params["name"]
    if module_params.get("description"):
        obj["description"] = module_params.get("description")
    if module_params.get("minimum_agent_version"):
        obj["minimumAgentVersion"] = module_params.get("minimum_agent_version")
    if module_params.get("minimum_manager_version"):
        obj["minimumManagerVersion"] = module_params.get(
            "minimum_manager_version"
        )
    if module_params.get("type"):
        obj["type"] = module_params.get("type")
    if module_params.get("original_issue"):
        obj["originalIssue"] = module_params.get("original_issue")
    if module_params.get("last_updated"):
        obj["lastUpdated"] = module_params.get("last_updated")
    if module_params.get("identifier"):
        obj["identifier"] = module_params.get("identifier")
    if module_params.get("template"):
        obj["template"] = module_params.get("template")
    if module_params.get("rule_id"):
        obj["ruleID"] = module_params.get("rule_id")
    if module_params.get("level"):
        obj["level"] = module_params.get("level")
    if module_params.get("groups"):
        obj["groups"] = module_params.get("groups")
    if module_params.get("rule_description"):
        obj["ruleDescription"] = module_params.get("rule_description")
    if module_params.get("pattern"):
        obj["pattern"] = module_params.get("pattern")
    if module_params.get("pattern_type"):
        obj["patternType"] = module_params.get("pattern_type")
    if module_params.get("dependency"):
        obj["dependency"] = module_params.get("dependency")
    if module_params.get("dependency_rule_id"):
        obj["dependencyRuleID"] = module_params.get("dependency_rule_id")
    if module_params.get("dependency_group"):
        obj["dependencyGroup"] = module_params.get("dependency_group")
    if module_params.get("frequency"):
        obj["frequency"] = module_params.get("frequency")
    if module_params.get("time_frame"):
        obj["timeFrame"] = module_params.get("time_frame")
    if module_params.get("rule_xml"):
        obj["ruleXML"] = module_params.get("rule_xml")
    if module_params.get("log_files"):
        obj["logFiles"] = log_files_fn(module_params)
    if module_params.get("alert_enabled"):
        obj["alertEnabled"] = module_params.get("alert_enabled")
    if module_params.get("alert_minimum_severity"):
        obj["alertMinimumSeverity"] = module_params.get(
            "alert_minimum_severity"
        )
    if module_params.get("recommendations_mode"):
        obj["recommendationsMode"] = module_params.get("recommendations_mode")
    if module_params.get("sort_order"):
        obj["sortOrder"] = module_params.get("sort_order")

    return obj


def check_if_log_inspection_rules_exists(deepsec_request, log_inspection_name):
    """ The fn check if the log_inspection detect based on log_inspection name
    :param deepsec_request: the objects from which the configuration should be read
    :param log_inspection_name: log_inspection name with which log_inspection will be searched
    in existing log_inspection configurations
    :rtype: A dict
    :returns: dict with search result value
    """
    search_dict = {}
    search_dict["searchCriteria"] = []
    temp_criteria = {}
    temp_criteria["fieldName"] = "name"
    temp_criteria["stringTest"] = "equal"
    temp_criteria["stringValue"] = log_inspection_name
    search_dict["searchCriteria"].append(temp_criteria)

    search_result = deepsec_request.post(
        "/api/loginspectionrules/search", data=search_dict
    )
    if search_result.get("logInspectionRules"):
        return search_result[""][0]
    return search_result


def delete_log_inspection_with_id(module, deepsec_request, log_inspection_id):
    """ The fn calls the delete API based on the log_inspection id
    :param module: ansible module object
    :param deepsec_request: connection obj for TM
    :param log_inspection_id: log_inspection id for the log_inspection that's supposed to be deleted
    value has dict as its value
    :rtype: A dict
    :returns: Based on API response this fn. exits with appropriate msg
    """
    deepsec_request.delete(
        "/api/loginspectionrules/{0}".format(log_inspection_id)
    )
    module.exit_json(
        msg=" with id: {} deleted successfully!".format(log_inspection_id),
        changed=True,
    )


def main():

    log_files_spec_list = {
        "location": dict(type="str", required=True),
        "format": dict(
            type="str",
            choices=[
                "syslog",
                "snort-full",
                "snort-fast",
                "apache",
                "iis",
                "iis",
                "squid",
                "nmapg",
                "mysql-log",
                "postgresql-log",
                "dbj-multilog",
                "eventlog",
                "single-line-text-log",
            ],
            required=True,
        ),
    }

    log_files_spec = {
        "log_files": dict(
            type="list", elements="dict", options=log_files_spec_list
        )
    }

    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        name=dict(required=True, type="str"),
        description=dict(type="str", required=False),
        minimum_agent_version=dict(type="str", required=False),
        minimum_manager_version=dict(type="str", required=False),
        type=dict(type="str", required=False),
        original_issue=dict(type="int", required=False),
        last_updated=dict(type="int", required=False),
        identifier=dict(type="str", required=False),
        template=dict(
            type="str", choices=["basic-rule", "custom"], required=True
        ),
        rule_id=dict(type="int", required=False),
        level=dict(type="int", required=False),
        groups=dict(type="list", elements="str", required=False),
        rule_description=dict(type="str", required=False),
        pattern=dict(type="str", required=False),
        pattern_type=dict(
            type="str", choices=["string", "regex"], required=True
        ),
        dependency=dict(
            type="str", choices=["none", "rule", "group"], required=False
        ),
        dependency_rule_id=dict(type="int", required=False),
        dependency_group=dict(type="str", required=False),
        frequency=dict(type="int", required=False),
        time_frame=dict(type="int", required=False),
        rule_xml=dict(
            type="str", choices=["all", "any", "none"], required=False
        ),
        log_files=dict(type="dict", options=log_files_spec),
        alert_enabled=dict(type="bool", required=False),
        alert_minimum_severity=dict(type="int", required=False),
        recommendations_mode=dict(type="str", required=False),
        sort_order=dict(type="int", required=False),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))

    search_existing_log_inspection_rules = check_if_config_exists(
        deepsec_request,
        want["name"],
        "loginspectionrules",
        "logInspectionRules",
    )

    if (
        "ID" in search_existing_log_inspection_rules
        and module.params["state"] == "absent"
    ):
        delete_config_with_id(
            module,
            deepsec_request,
            "loginspectionrules",
            search_existing_log_inspection_rules["ID"],
            "logInspectionRules",
        )
    elif (
        "ID" not in search_existing_log_inspection_rules
        and module.params["state"] == "absent"
    ):
        module.exit_json(changed=False)
    else:
        log_inspection_rules = deepsec_request.post(
            "/api/loginspectionrules", data=want
        )
        if "ID" in search_existing_log_inspection_rules:
            module.exit_json(
                log_inspection_rules=search_existing_log_inspection_rules,
                changed=False,
            )
        elif log_inspection_rules.get("message"):
            module.fail_json(msg=log_inspection_rules["message"])
        else:
            module.exit_json(
                log_inspection_rules=log_inspection_rules, changed=True
            )
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

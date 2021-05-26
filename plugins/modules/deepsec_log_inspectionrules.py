#!/usr/bin/python
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


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: deepsec_log_inspectionrules
short_description: Create a new log inspection rule.
description:
  - This module creates a new log inspection rule under TrendMicro Deep Security.
version_added: 1.0.0
author: "Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
options:
  name:
    description: Name of the LogInspectionRule. Searchable as String.
    required: true
    type: str
  description:
    description:
      - Description of the LogInspectionRule that appears in search results,and on the General
        tab in the Deep Security Manager user interface.
      - Searchable as String.
    type: str
  minimum_agent_version:
    description:
      - Minimum Deep Security Agent version required by the LogInspectionRule.
      - Searchable as String.
    type: str
  minimum_manager_version:
    description:
      - Minimumn Deep Security Manager version required by the LogInspectionRule.
      - Searchable as String.
    type: str
  type:
    description:
      - Type of the LogInspectionRule. The value 'Defined' is used for LogInspectionRules
        provided by Trend Micro.
      - Searchable as String.
    type: str
  original_issue:
    description:
      - Creation timestamp of the LogInspectionRule, measured in milliseconds since
        epoch.
      - Searchable as Date.
    type: int
  last_updated:
    description:
      - Update timestamp of the LogInspectionRule, measured in milliseconds since epoch.
      - Searchable as Date.
    type: int
  identifier:
    description:
      - Indentifier of the LogInspectionRule used in the Deep Security Manager user interface.
      - Searchable as String.
    type: str
  template:
    description: Template used to create this rule.
    choices: ["basic-rule", "custom"]
    type: str
  rule_id:
    description:
      - ID of the LogInspectionRule sent to the Deep Security Agent.
        The values 100000 - 109999 are reserved for user-definded rules.
    type: int
  level:
    description:
      - Log level of the LogInspectionRule indicates severity of attack.
        Level 0 is the least severe and will not log an event. Level 15 is the most severe.
    type: int
  groups:
    description:
      - Groups that the LogInspectionRule is assigned to, separated by commas.
        Useful when dependency is used as it's possible to create a LogInspectionRule that
        fires when another LogInspectionRule belonging to a specific group fires.
    type: list
    elements: str
  rule_description:
    description:
      - Description of the LogInspectionRule that appears on events and the
        Content tab in the Deep Security Manager user interface.
      - Alternatively, you can configure this by inserting a description in 'rule_xml'.
    type: str
  pattern:
    description:
      - Regular expression pattern the LogInspectionRule will look for in the logs.
        The rule will be triggered on a match. Open Source HIDS SEcurity (OSSEC) regular expression
        syntax is supported, see http://www.ossec.net/docs/syntax/regex.html.
    type: str
  pattern_type:
    description:
      - Pattern the LogInspectionRule will look for in the logs. The string matching
        pattern is faster than the regex pattern.
    choices: ["string", "regex"]
    type: str
  dependency:
    description:
      - Indicates if a dependant rule or dependency group is set or not.
        If set, the LogInspectionRule will only log an event if the dependency is triggered.
      - Available for user-defined rules.
    choices: ["none", "rule", "group"]
    type: str
  dependency_rule_id:
    description:
      - If dependency is configured, the ID of the rule that this rule is dependant on.
        Ignored if the rule is from Trend Micro, which uses dependsOnRuleIDs instead.
    type: int
  dependency_group:
    description:
      - If dependency is configured, the dependancy groups that this rule is dependant on.
    type: str
  frequency:
    description:
      - Number of times the dependant rule has to match within a specific time frame before
        the rule is triggered.
    type: int
  time_frame:
    description:
      - Time period for the frequency of LogInspectionRule triggers that will generate an event,
        in seconds.
    type: int
  rule_xml:
    description:
      - LogInspectionRule in an XML format. For information on the XML format,
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
            description:
              - Structure of the data in the log file. The application that generates
                the log file defines the structure of the data.
            choices: ["syslog", "snort-full", "snort-fast", "apache", "iis", "squid", "nmapg",
                "mysql-log", "postgresql-log", "dbj-multilog", "eventlog", "single-line-text-log"]
            type: str
  alert_enabled:
    description:
      - Controls whether to raise an alert when a LogInspectionRule logs an event.
        Use true to raise an alert. Searchable as Boolean.
    type: bool
  alert_minimum_severity:
    description:
      - Severity level that will trigger an alert. Ignored unless ruleXML contains
        multiple rules with different severities, and so you must indicate which severity level to use.
      - Searchable as Numeric.
    type: int
  recommendations_mode:
    description:
      - Indicates whether recommendation scans consider the LogInspectionRule. Can be set to
        enabled or ignored. Custom rules cannot be recommended.
      - Searchable as Choice.
    choices: ["enabled", "ignored", "unknown", "disabled"]
    type: str
  sort_order:
    description:
      - Order in which LogInspectionRules are sent to the Deep Security Agent. Log inspeciton
        rules are sent in ascending order. Valid values are between 10000 and 20000.
    type: int
  can_be_assigned_alone:
    description:
      - Indicates whether this LogInspectionRule can be allocated without allocating any additional
        LogInspectionRules
      - Ignored if the rule is user-defined, which uses dependency instead.
    type: bool
  depends_onrule_id:
    description:
      - IDs of LogInspectionRules, separated by commas, that are required by this rule.
      - Ignored if the rule is user-defined which uses dependency_rule_id or dependency_group instead.
    type: list
    elements: str
  state:
    description:
      - The state the configuration should be left in
    type: str
    choices:
      - present
      - absent
    default: present
"""

EXAMPLES = """
- name: Create a new log inspection rule
  trendmicro.deepsec.deepsec_log_inspectionrules:
    state: present
    name: custom log_rule for mysqld event
    description: some description
    minimum_agent_version: 6.0.0.0
    type: defined
    template: basic-rule
    pattern: name
    pattern_type: string
    rule_id: 100001
    rule_description: test rule description
    groups:
      - test
    alert_minimum_severity: 4
    alert_enabled: true
    log_files:
      log_files:
        - location: /var/log/mysqld.log
          format: mysql-log

- name: Delete/Remove the existing log inspection rule
  trendmicro.deepsec.deepsec_log_inspectionrules:
    state: absent
    name: custom log_rule for mysqld event
"""

from ansible.module_utils.six import iteritems
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    check_if_config_exists,
    delete_config_with_id,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
)


key_transform = {
    "minimum_agent_version": "minimumAgentVersion",
    "minimum_manager_version": "minimumManagerVersion",
    "original_issue": "originalIssue",
    "last_updated": "lastUpdated",
    "rule_id": "ruleID",
    "rule_description": "ruleDescription",
    "pattern_type": "patternType",
    "dependency_rule_id": "dependencyRuleID",
    "dependency_group": "dependencyGroup",
    "time_frame": "timeFrame",
    "rule_xml": "ruleXML",
    "alert_enabled": "alertEnabled",
    "alert_minimum_severity": "alertMinimumSeverity",
    "recommendations_mode": "recommendationsMode",
    "sort_order": "sortOrder",
    "can_be_assigned_alone": "canBeAssignedAlone",
    "depends_onrule_id": "dependsOnRuleIDs",
}


def log_files_fn(module_params):
    temp_obj = {}
    temp_obj = {"logFiles": module_params.get("log_files")["log_files"]}

    return temp_obj


def map_params_to_obj(module_params):
    obj = {}
    obj["name"] = module_params["name"]
    if module_params.get("description"):
        obj["description"] = module_params.get("description")
    if module_params.get("type"):
        obj["type"] = module_params.get("type")
    if module_params.get("identifier"):
        obj["identifier"] = module_params.get("identifier")
    if module_params.get("template"):
        obj["template"] = module_params.get("template")
    if module_params.get("level"):
        obj["level"] = module_params.get("level")
    if module_params.get("groups"):
        obj["groups"] = module_params.get("groups")
    if module_params.get("pattern"):
        obj["pattern"] = module_params.get("pattern")
    if module_params.get("dependency"):
        obj["dependency"] = module_params.get("dependency")
    if module_params.get("frequency"):
        obj["frequency"] = module_params.get("frequency")
    if module_params.get("log_files"):
        obj["logFiles"] = log_files_fn(module_params)
    for k, v in iteritems(key_transform):
        if module_params.get(k):
            obj[v] = module_params.get(k)

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
        msg=" with id: {0} deleted successfully!".format(log_inspection_id),
        changed=True,
    )


def main():

    log_files_spec_list = {
        "location": dict(type="str"),
        "format": dict(
            type="str",
            choices=[
                "syslog",
                "snort-full",
                "snort-fast",
                "apache",
                "iis",
                "squid",
                "nmapg",
                "mysql-log",
                "postgresql-log",
                "dbj-multilog",
                "eventlog",
                "single-line-text-log",
            ],
        ),
    }

    log_files_spec = {
        "log_files": dict(
            type="list", elements="dict", options=log_files_spec_list
        )
    }

    argspec = dict(
        state=dict(choices=["present", "absent"], default="present"),
        name=dict(required=True, type="str"),
        description=dict(type="str"),
        minimum_agent_version=dict(type="str"),
        minimum_manager_version=dict(type="str"),
        type=dict(type="str"),
        original_issue=dict(type="int"),
        last_updated=dict(type="int"),
        identifier=dict(type="str"),
        template=dict(type="str", choices=["basic-rule", "custom"]),
        rule_id=dict(type="int"),
        level=dict(type="int"),
        groups=dict(type="list", elements="str"),
        rule_description=dict(type="str"),
        pattern=dict(type="str"),
        pattern_type=dict(type="str", choices=["string", "regex"]),
        dependency=dict(type="str", choices=["none", "rule", "group"]),
        dependency_rule_id=dict(type="int"),
        dependency_group=dict(type="str"),
        frequency=dict(type="int"),
        time_frame=dict(type="int"),
        rule_xml=dict(type="str"),
        log_files=dict(type="dict", options=log_files_spec),
        alert_enabled=dict(type="bool"),
        alert_minimum_severity=dict(type="int"),
        recommendations_mode=dict(
            type="str", choices=["enabled", "ignored", "unknown", "disabled"]
        ),
        sort_order=dict(type="int"),
        can_be_assigned_alone=dict(type="bool"),
        depends_onrule_id=dict(type="list", elements="str"),
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
            handle_return=True,
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

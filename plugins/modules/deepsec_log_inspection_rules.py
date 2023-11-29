#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: deepsec_log_inspection_rules
short_description: Manages Log Inspection Rule resource module
description:
  Contains string matching and threshold to trigger alerts as well as group
  information for LogInspectionRules.
version_added: 1.2.0
options:
  config:
    description: A dictionary of Log Inspection Rules options
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the LogInspectionRule. Searchable as String.
        type: str
      description:
        description:
          Description of the LogInspectionRule that appears in search results,
          and on the General tab in the Deep Security Manager user interface. Searchable
          as String.
        type: str
      minimum_agent_version:
        description:
          Minimum Deep Security Agent version required by the LogInspectionRule.
          Searchable as String.
        type: str
      minimum_manager_version:
        description:
          Minimumn Deep Security Manager version required by the LogInspectionRule.
          Searchable as String.
        type: str
      type:
        description:
          Type of the LogInspectionRule. The value 'Defined' is used for
          LogInspectionRules provided by Trend Micro. Searchable as String.
        type: str
      original_issue:
        description:
          Creation timestamp of the LogInspectionRule, measured in milliseconds
          since epoch. Searchable as Date.
        type: int
      last_updated:
        description:
          Update timestamp of the LogInspectionRule, measured in milliseconds
          since epoch. Searchable as Date.
        type: int
      identifier:
        description:
          Indentifier of the LogInspectionRule used in the Deep Security
          Manager user interface. Searchable as String.
        type: str
      template:
        description: Template used to create this rule.
        type: str
        choices:
          - basic-rule
          - custom
      rule_id:
        description:
          ID of the LogInspectionRule sent to the Deep Security Agent.
          The values 100000 - 109999 are reserved for user-definded rules.
        type: int
      level:
        description:
          Log level of the LogInspectionRule indicates severity of attack.
          Level 0 is the least severe and will not log an event. Level 15 is the most
          severe.
        type: int
      groups:
        description:
          Groups that the LogInspectionRule is assigned to, separated by
          commas. Useful when dependency is used as it's possible to create a LogInspectionRule
          that fires when another LogInspectionRule belonging to a specific group
          fires.
        type: list
        elements: str
      rule_description:
        description:
          Description of the LogInspectionRule that appears on events and
          the Content tab in the Deep Security Manager user interface. Alternatively,
          you can configure this by inserting a description in 'ruleXML'.
        type: str
      pattern:
        description:
          Regular expression pattern the LogInspectionRule will look for
          in the logs. The rule will be triggered on a match. Open Source HIDS SEcurity
          (OSSEC) regular expression syntax is supported, see http://www.ossec.net/docs/syntax/regex.html.
        type: str
      pattern_type:
        description:
          Pattern the LogInspectionRule will look for in the logs. The
          string matching pattern is faster than the regex pattern.
        type: str
        choices:
          - string
          - regex
      dependency:
        description:
          Indicates if a dependant rule or dependency group is set or not.
          If set, the LogInspectionRule will only log an event if the dependency is
          triggered. Available for user-defined rules.
        type: str
        choices:
          - none
          - rule
          - group
      dependency_rule_id:
        description:
          If dependency is configured, the ID of the rule that this rule
          is dependant on. Ignored if the rule is from Trend Micro, which uses 'dependsOnRuleIDs'
          instead.
        type: int
      dependency_group:
        description:
          If dependency is configured, the dependancy groups that this
          rule is dependant on.
        type: str
      frequency:
        description:
          Number of times the dependant rule has to match within a specific
          time frame before the rule is triggered.
        type: int
      time_frame:
        description:
          Time period for the frequency of LogInspectionRule triggers that
          will generate an event, in seconds.
        type: int
      rule_xml:
        description:
          LogInspectionRule in an XML format. For information on the XML
          format, see http://ossec-docs.readthedocs.io/en/latest/syntax/head_rules.html
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
                  Structure of the data in the log file. The application
                  that generates the log file defines the structure of the data.
                choices:
                  [
                    syslog,
                    snort-full,
                    snort-fast,
                    apache,
                    iis,
                    squid,
                    nmapg,
                    mysql-log,
                    postgresql-log,
                    dbj-multilog,
                    eventlog,
                    single-line-text-log,
                  ]
                type: str
      alert_enabled:
        description:
          Controls whether to raise an alert when a LogInspectionRule logs
          an event. Use true to raise an alert. Searchable as Boolean.
        type: bool
      alert_minimum_severity:
        description:
          Severity level that will trigger an alert. Ignored unless 'ruleXML'
          contains multiple rules with different severities, and so you must indicate
          which severity level to use. Searchable as Numeric.
        type: int
      recommendations_mode:
        description:
          Indicates whether recommendation scans consider the LogInspectionRule.
          Can be set to enabled or ignored. Custom rules cannot be recommended. Searchable
          as Choice.
        type: str
        choices:
          - enabled
          - ignored
          - unknown
          - disabled
      sort_order:
        description:
          Order in which LogInspectionRules are sent to the Deep Security
          Agent. Log inspeciton rules are sent in ascending order. Valid values are
          between 10000 and 20000.
        type: int
      can_be_assigned_alone:
        description:
          Indicates whether this LogInspectionRule can be allocated without
          allocating any additional LogInspectionRules. Ignored if the rule is user-defined,
          which uses 'dependency' instead.
        type: bool
      depends_on_rule_ids:
        description:
          IDs of LogInspectionRules, separated by commas, that are required
          by this rule. Ignored if the rule is user-defined, which uses 'dependencyRuleID'
          or 'dependencyGroup' instead.
        type: list
        elements: int
      id:
        description:
          ID of the LogInspectionRule. This number is set automatically.
          Searchable as ID.
        type: int
  state:
    description:
      - The state the configuration should be left in
      - The state I(gathered) will get the module API configuration from the device
        and transform it into structured data in the format as per the module argspec
        and the value is returned in the I(gathered) key within the result.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - gathered
      - deleted
author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>
"""

EXAMPLES = """
# Using MERGED state
# -------------------

- name: Create Log Inspection Rules
  trendmicro.deepsec.deepsec_log_inspection_rules:
    state: merged
    config:
      - name: custom log_rule for mysqld event
        description: MYSQLD description
        minimum_agent_version: 6.0.0.0
        type: defined
        template: basic-rule
        pattern: name
        pattern_type: string
        rule_id: 100001
        rule_description: sqld rule description
        groups:
          - test
        alert_minimum_severity: 4
        alert_enabled: true
        log_files:
          log_files:
            - location: /var/log/mysqld.log
              format: mysql-log
      - name: custom log_rule for daemon event
        description: DAEMON description
        minimum_agent_version: 6.0.0.0
        type: defined
        template: basic-rule
        pattern: name
        pattern_type: string
        rule_id: 100002
        rule_description: deamon rule description
        groups:
          - test
        alert_minimum_severity: 3
        alert_enabled: true
        log_files:
          log_files:
            - location: /var/log/daemon.log
              format: eventlog

# RUN output:
# -----------

#   log_inspection_rules:
#     after:
#     - alert_enabled: true
#       alert_minimum_severity: 4
#       dependency: none
#       description: MYSQLD description
#       groups:
#       - test
#       id: 179
#       level: 0
#       log_files:
#         log_files:
#         - format: mysql-log
#           location: /var/log/mysqld.log
#       minimum_agent_version: 6.0.0.0
#       minimum_manager_version: 6.0.0
#       name: custom log_rule for mysqld event
#       pattern: name
#       pattern_type: string
#       rule_description: sqld rule description
#       rule_id: 100001
#       sort_order: 15000
#       template: basic-rule
#     - alert_enabled: true
#       alert_minimum_severity: 3
#       dependency: none
#       description: DAEMON description
#       groups:
#       - test
#       id: 180
#       level: 0
#       log_files:
#         log_files:
#         - format: eventlog
#           location: /var/log/daemon.log
#       minimum_agent_version: 6.0.0.0
#       minimum_manager_version: 6.0.0
#       name: custom log_rule for daemon event
#       pattern: name
#       pattern_type: string
#       rule_description: deamon rule description
#       rule_id: 100002
#       sort_order: 15000
#       template: basic-rule
#     before: []

- name: Modify the Pattern type of Log Inspection Rule by name
  trendmicro.deepsec.deepsec_log_inspection_rules:
    state: merged
    config:
      - name: custom log_rule for mysqld event
        description: UPDATE pattern type for mysqld log event
        pattern: name
        pattern_type: regex
        log_files:
          log_files:
            - location: /var/log/messages
              format: syslog

# RUN output:
# -----------

#   log_inspection_rules:
#     after:
#     - alert_enabled: true
#       alert_minimum_severity: 4
#       dependency: none
#       description: UPDATE pattern type for mysqld log event
#       groups:
#       - test
#       id: 179
#       level: 0
#       log_files:
#         log_files:
#         - format: mysql-log
#           location: /var/log/mysqld.log
#         - format: syslog
#           location: /var/log/messages
#       minimum_agent_version: 6.0.0.0
#       minimum_manager_version: 6.0.0
#       name: custom log_rule for mysqld event
#       pattern: name
#       pattern_type: regex
#       rule_description: sqld rule description
#       rule_id: 100001
#       sort_order: 15000
#       template: basic-rule
#     before:
#     - alert_enabled: true
#       alert_minimum_severity: 4
#       dependency: none
#       description: MYSQLD description
#       groups:
#       - test
#       id: 179
#       level: 0
#       log_files:
#         log_files:
#         - format: mysql-log
#           location: /var/log/mysqld.log
#       minimum_agent_version: 6.0.0.0
#       minimum_manager_version: 6.0.0
#       name: custom log_rule for mysqld event
#       pattern: name
#       pattern_type: string
#       rule_description: sqld rule description
#       rule_id: 100001
#       sort_order: 15000
#       template: basic-rule

# Using REPLACED state
# --------------------

- name: Replace existing Log Inspection Rules
  trendmicro.deepsec.deepsec_log_inspection_rules:
    state: replaced
    config:
      - name: custom log_rule for daemon event
        description: REPLACED log daemon event
        minimum_agent_version: 6.0.0.0
        type: defined
        template: basic-rule
        pattern: name
        pattern_type: string
        rule_id: 100003
        rule_description: daemon rule description
        groups:
          - test
        alert_minimum_severity: 5
        alert_enabled: true
        log_files:
          log_files:
            - location: /var/log/messages
              format: syslog

# RUN output:
# -----------

#   log_inspection_rules:
#     after:
#     - alert_enabled: true
#       alert_minimum_severity: 5
#       dependency: none
#       description: REPLACED log daemon event
#       groups:
#       - test
#       id: 181
#       level: 0
#       log_files:
#         log_files:
#         - format: syslog
#           location: /var/log/messages
#       minimum_agent_version: 6.0.0.0
#       minimum_manager_version: 6.0.0
#       name: custom log_rule for daemon event
#       pattern: name
#       pattern_type: string
#       rule_description: daemon rule description
#       rule_id: 100003
#       sort_order: 15000
#       template: basic-rule
#     before:
#     - alert_enabled: true
#       alert_minimum_severity: 3
#       dependency: none
#       description: DAEMON description
#       groups:
#       - test
#       id: 180
#       level: 0
#       log_files:
#         log_files:
#         - format: eventlog
#           location: /var/log/daemon.log
#       minimum_agent_version: 6.0.0.0
#       minimum_manager_version: 6.0.0
#       name: custom log_rule for daemon event
#       pattern: name
#       pattern_type: string
#       rule_description: deamon rule description
#       rule_id: 100002
#       sort_order: 15000
#       template: basic-rule

# Using GATHERED state
# --------------------

- name: Gather Log Inspection Rules by IPR names
  trendmicro.deepsec.deepsec_log_inspection_rules:
    state: gathered
    config:
      - name: custom log_rule for mysqld event
      - name: custom log_rule for daemon event

# RUN output:
# -----------

# gathered:
#   - alert_enabled: true
#     alert_minimum_severity: 4
#     dependency: none
#     description: UPDATE pattern type for mysqld log event
#     groups:
#     - test
#     id: 179
#     level: 0
#     log_files:
#       log_files:
#       - format: mysql-log
#         location: /var/log/mysqld.log
#       - format: syslog
#         location: /var/log/messages
#     minimum_agent_version: 6.0.0.0
#     minimum_manager_version: 6.0.0
#     name: custom log_rule for mysqld event
#     pattern: name
#     pattern_type: regex
#     rule_description: sqld rule description
#     rule_id: 100001
#     sort_order: 15000
#     template: basic-rule
#   - alert_enabled: true
#     alert_minimum_severity: 5
#     dependency: none
#     description: REPLACED log daemon event
#     groups:
#     - test
#     id: 181
#     level: 0
#     log_files:
#       log_files:
#       - format: syslog
#         location: /var/log/messages
#     minimum_agent_version: 6.0.0.0
#     minimum_manager_version: 6.0.0
#     name: custom log_rule for daemon event
#     pattern: name
#     pattern_type: string
#     rule_description: daemon rule description
#     rule_id: 100003
#     sort_order: 15000
#     template: basic-rule

- name: Gather ALL of the Log Inspection Rules
  trendmicro.deepsec.deepsec_log_inspection_rules:
    state: gathered

# Using DELETED state
# -------------------

- name: Delete Log Inspection Rules
  trendmicro.deepsec.deepsec_log_inspection_rules:
    state: deleted
    config:
      - name: custom log_rule for mysqld event
      - name: custom log_rule for daemon event
# RUN output:
# -----------

#   log_inspection_rules:
#     after: []
#     before:
#     - alert_enabled: true
#       alert_minimum_severity: 4
#       dependency: none
#       description: UPDATE pattern type for mysqld log event
#       groups:
#       - test
#       id: 179
#       level: 0
#       log_files:
#         log_files:
#         - format: mysql-log
#           location: /var/log/mysqld.log
#         - format: syslog
#           location: /var/log/messages
#       minimum_agent_version: 6.0.0.0
#       minimum_manager_version: 6.0.0
#       name: custom log_rule for mysqld event
#       pattern: name
#       pattern_type: regex
#       rule_description: sqld rule description
#       rule_id: 100001
#       sort_order: 15000
#       template: basic-rule
#     - alert_enabled: true
#       alert_minimum_severity: 5
#       dependency: none
#       description: REPLACED log daemon event
#       groups:
#       - test
#       id: 181
#       level: 0
#       log_files:
#         log_files:
#         - format: syslog
#           location: /var/log/messages
#       minimum_agent_version: 6.0.0.0
#       minimum_manager_version: 6.0.0
#       name: custom log_rule for daemon event
#       pattern: name
#       pattern_type: string
#       rule_description: daemon rule description
#       rule_id: 100003
#       sort_order: 15000
#       template: basic-rule
"""


RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
"""

#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: deepsec_integrity_monitoring_rules
short_description: Manages Integrity Monitoring Rule resource module
description: Integrity monitoring rules describe how Deep Security Agents should scan
  for and detect changes to a computer's files, directories and registry keys and
  values as well as changes in installed software, processes, listening ports and
  running services. Integrity monitoring rules can be assigned directly to computers
  or can be made part of a policy.
version_added: 2.0.0
options:
  config:
    description: A dictionary of Integrity Monitoring Rules options
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the IntegrityMonitoringRule. Searchable as String.
        type: str
      description:
        description: Description of the IntegrityMonitoringRule. Searchable as String.
        type: str
      minimum_agent_version:
        description: Minimum Deep Security Agent version that supports the IntegrityMonitoringRule.
          This value is provided in the X.X.X.X format. Defaults to '6.0.0.0'. If
          an agent is not the minimum required version, the manager does not send
          the rule to the agent, and generates an alert. Searchable as String.
        type: str
      minimum_manager_version:
        description: Minimum Deep Security Manager version that supports the IntegrityMonitoringRule.
          This value is provided in the X.X.X format. Defaults to '6.0.0'. An alert
          will be raised if a manager that fails to meet the minimum manager version
          value tries to assign this rule to a host or profile. Searchable as String.
        type: str
      severity:
        description: Severity level of the event is multiplied by the computer's asset
          value to determine ranking. Ranking can be used to sort events with more
          business impact. Searchable as Choice.
        type: str
        choices:
        - low
        - medium
        - high
        - critical
      type:
        description: Type of the IntegrityMonitoringRule. If the rule is predefined
          by Trend Micro, it is set to '2'. If it is user created, it is set to '1'.
          Searchable as String.
        type: str
      original_issue:
        description: Timestamp when the IntegrityMonitoringRule was originally issued
          by Trend Micro, in milliseconds since epoch.  Empty if the IntegrityMonitoringRule
          is user created. Searchable as Date.
        type: int
      last_updated:
        description: Timestamp when the IntegrityMonitoringRule was last updated,
          in milliseconds since epoch. Searchable as Date.
        type: int
      identifier:
        description: Identifier of the IntegrityMonitoringRule from Trend Micro. Empty
          if the IntegrityMonitoringRule is user created. Searchable as String.
        type: str
      template:
        description: Template which the IntegrityMonitoringRule follows.
        type: str
        choices:
        - registry
        - file
        - custom
      registry_key_root:
        description: Registry hive which is monitored by the IntegrityMonitoringRule.
          Empty if the IntegrityMonitoringRule does not monitor a registry key.
        type: str
      registry_key_value:
        description: Registry key which is monitored by the IntegrityMonitoringRule.
          Empty if the IntegrityMonitoringRule does not monitor a registry key. Ignored
          if the IntegrityMonitoringRule does not monitor a registry key.
        type: str
      registry_include_sub_keys:
        description: Controls whether the IntegrityMonitoringRule should also include
          subkeys of the registry key it monitors. Defaults to 'false'. Ignored if
          the IntegrityMonitoringRule does not monitor a registry key.
        type: bool
      registry_included_values:
        description: Registry key values to be monitored by the IntegrityMonitoringRule.
          JSON array or delimited by new line. Question mark matches a single character,
          while '*' matches zero or more characters. Ignored if the IntegrityMonitoringRule
          does not monitor a registry key.
        type: list
        elements: str
      registry_include_default_value:
        description: Controls whether the rule should monitor default registry key
          values. Defaults to 'true'. Ignored if the IntegrityMonitoringRule does
          not monitor a registry key.
        type: bool
      registry_excluded_values:
        description: Registry key values to be ignored by the IntegrityMonitoringRule.
          JSON array or delimited by new line. Question mark matches a single character,
          while '*' matches zero or more characters. Ignored if the IntegrityMonitoringRule
          does not monitor a registry key.
        type: list
        elements: str
      registry_attributes:
        description: Registry key attributes to be monitored by the IntegrityMonitoringRule.
          JSON array or delimited by new line. Defaults to 'STANDARD' which will monitor
          changes in registry size, content and type. Ignored if the IntegrityMonitoringRule
          does not monitor a registry key.
        type: list
        elements: str
      file_base_directory:
        description: Base of the file directory to be monitored by the IntegrityMonitoringRule.
          Ignored if the IntegrityMonitoringRule does not monitor a file directory.
        type: str
      file_include_sub_directories:
        description: Controls whether the IntegrityMonitoringRule should also monitor
          sub-directories of the base file directory that is associated with it. Defaults
          to 'false'. Ignored if the IntegrityMonitoringRule does not monitor a file
          directory.
        type: bool
      file_included_values:
        description: File name values to be monitored by the IntegrityMonitoringRule.
          JSON array or delimited by new line. Question mark matches a single character,
          while '*' matches zero or more characters. Leaving this field blank when
          monitoring file directories will cause the IntegrityMonitoringRule to monitor
          all files in a directory. This can use significant system resources if the
          base directory contains numerous or large files. Ignored if the IntegrityMonitoringRule
          does not monitor a file directory.
        type: list
        elements: str
      file_excluded_values:
        description: File name values to be ignored by the IntegrityMonitoringRule.
          JSON array or delimited by new line. Question mark matches a single character,
          while '*' matches zero or more characters. Ignored if the IntegrityMonitoringRule
          does not monitor a file directory.
        type: list
        elements: str
      file_attributes:
        description: File attributes to be monitored by the IntegrityMonitoringRule.
          JSON array or delimited by new line. Defaults to 'STANDARD' which will monitor
          changes in file creation date, last modified date, permissions, owner, group,
          size, content, flags (Windows) and SymLinkPath (Linux). Ignored if the IntegrityMonitoringRule
          does not monitor a file directory.
        type: list
        elements: str
      custom_xml:
        description: Custom XML rules to be used by the IntegrityMonitoringRule. Custom
          XML rules must be encoded in the Base64 format. Ignored if the IntegrityMonitoringRule
          does not follow the 'custom' template.
        type: str
      alert_enabled:
        description: Controls whether an alert should be made if an event related
          to the IntegrityMonitoringRule is logged. Defaults to 'false'. Searchable
          as Boolean.
        type: bool
      real_time_monitoring_enabled:
        description: Controls whether the IntegrityMonitoringRule is monitored in
          real time or during every scan. Defaults to 'true' which indicates that
          it is monitored in real time. A value of 'false' indicates that it will
          only be checked during scans. Searchable as Boolean.
        type: bool
      recommendations_mode:
        description: Indicates whether recommendation scans consider the IntegrityMonitoringRule.
          Can be set to enabled or ignored. Custom rules cannot be recommended. Searchable
          as Choice.
        type: str
        choices:
        - enabled
        - ignored
        - unknown
        - disabled
      id:
        description: ID of the IntegrityMonitoringRule. Searchable as ID.
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

- name: Create Integrity Monitoring Rules
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: merged
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
- name: Modify the severity of Integrity Monitoring Rule by name
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: merged
    config:
    - name: THIS IS TEST IMR - 2
      severity: medium
- name: Replace existing Integrity Monitoring Rule
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: replaced
    config:
    - name: THIS IS TEST IMR - 1
      alert_enabled: false
      description: THIS IS REPLACED TEST IMR DESCRIPTION - 1
      real_time_monitoring_enabled: true
      registry_included_values:
      - test_3
      - test_4
      severity: low
      template: registry
- name: Gather Integrity Monitoring Rule by IMR names
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: gathered
    config:
    - name: THIS IS TEST IMR - 1
    - name: THIS IS TEST IMR - 2
- name: Gather ALL of the Integrity Monitoring Rule
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: gathered
- name: Delete Integrity Monitoring Rule
  trendmicro.deepsec.deepsec_integrity_monitoring_rules:
    state: deleted
    config:
    - name: THIS IS TEST IMR - 1
    - name: THIS IS TEST IMR - 2
"""

RETURN = r"""

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

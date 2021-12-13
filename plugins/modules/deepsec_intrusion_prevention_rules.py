#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: deepsec_intrusion_prevention_rules
short_description: Intrusion Prevention Rule resource module.
description:
- This module creates a new intrusion preventin rul under TrendMicro Deep Security.
version_added: 2.0.0
options:
  config:
    description: Intrusion prevention rules config
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the IntrusionPreventionRule.
        type: str
      description:
        description: Description of the IntrusionPreventionRule.
        type: str
      minimum_agent_version:
        description: Version of the Deep Security agent or appliance required to support
          the rule.
        type: str
      application_type_id:
        description: ID of the application type for the IntrusionPreventionRule.
        type: int
      priority:
        description: Priority level of the rule. Higher priority rules are applied
          before lower priority rules.
        choices: [lowest, low, normal, high, highest]
        type: str
      severity:
        description: Severity level of the rule. Severity levels can be used as sorting
          criteria and affect event rankings.
        choices: [low, medium, high, critical]
        type: str
      detect_only:
        description: In detect mode, the rule creates an event log and does not interfere
          with traffic.
        type: bool
      event_logging_disabled:
        description: Enable to prevent event logs from being created when the rule
          is triggered. Not available if detect only is true.
        type: bool
      generate_event_on_packet_drop:
        description: Generate an event every time a packet is dropped for the rule.
          Not available if event logging disabled is true.
        type: bool
      always_include_packet_data:
        description: Enabled to include package data in the event logs. Not available
          if event logging disabled is true.
        type: bool
      debug_mode_enabled:
        description: Enable to log additional packets preceeding and following the
          packet that the rule detected. Not available if event logging disabled is
          true.
        type: bool
      type:
        description: Type of IntrusionPreventionRule.
        choices: [custom, smart, vulnerability, exploit, hidden, policy, info]
        type: str
      original_issue:
        description: Timestamp of the date the rule was released, in milliseconds
          since epoch.
        type: int
      last_updated:
        description: Timestamp of the last rule modification, in milliseconds since
          epoch.
        type: int
      template:
        description: Type of template for the IntrusionPreventionRule. Applicable
          only to custom rules.
        choices: [signature, start-end-patterns, custom]
        type: str
      signature:
        description: Signature of the rule. Applicable to custom rules with template
          type signature.
        type: str
      start:
        description: Start pattern of the rule. Applicable to custom rules with template
          type start-end-patterns.
        type: str
      patterns:
        description: Body patterns of the rule, which must be found between start
          and end patterns. Applicable to custom rules with template type start-end-patterns.
        type: list
        elements: str
      end:
        description: End pattern of the rule. Applicable to custom rules with template
          type start-end-patterns.
        type: str
      case_sensitive:
        description: Enable to make signatures and patterns case sensitive. Applicable
          to custom rules with template type signature or start-end-patterns.
        type: bool
      condition:
        description: Condition to determine if the rule is triggered. Applicable to
          custom rules with template type start-end-patterns.
        choices: [all, any, none]
        type: str
      action:
        description: Action to apply if the rule is triggered. Applicable to custom
          rules with template type signature or start-end-patterns.
        choices: [drop, log-only]
        type: str
      custom_xml:
        description: The custom XML used to define the rule. Applicable to custom
          rules with template type custom.
        type: str
      alert_enabled:
        description: Enable to raise an alert when the rule logs an event.
        type: bool
      schedule_id:
        description: ID of the schedule which defines times during which the rule
          is active.
        type: int
      context_id:
        description: ID of the context in which the rule is applied.
        type: int
      recommendations_mode:
        description: Indicates whether recommendation scans consider the IntrusionPreventionRule.
          Can be set to enabled or ignored. Custom rules cannot be recommended.
        choices: [enabled, ignored, unknown, disabled]
        type: str
      depends_on_rule_ids:
        description: IDs of intrusion prevention rules the rule depends on, which
          will be automatically assigned if this rule is assigned.
        type: list
        elements: int
      cvss_score:
        description: A measure of the severity of the vulnerability according the
          National Vulnerability Database.
        type: str
      cve:
        description: List of CVEs associated with the IntrusionPreventionRule.
        type: list
        elements: str
      id:
        description: ID for the Intrusion prevention rule. Applicaple only with GET
          call Not applicaple param with Create/Modify POST call
        type: int
      identifier:
        description: Identifier for the Intrusion prevention rule. Applicaple only
          with GET call. Not applicaple param with Create/Modify POST call
        type: str
      can_be_assigned_alone:
        description: Intrusion prevention rule can be assigned by self. Applicaple
          only with GET call. Not applicaple param with Create/Modify POST call
        type: bool
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
    - deleted
    - gathered
    default: present
author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
"""

EXAMPLES = """

# Using MERGED state
# -------------------

- name: Create Intrusion Prevention Rules
  trendmicro.deepsec.deepsec_intrusion_prevention_rules:
    state: merged
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
- name: Modify the severity of Integrity Monitoring Rule by name
  trendmicro.deepsec.deepsec_intrusion_prevention_rules:
    state: merged
    config:
    - name: TEST IPR 2
      severity: low
- name: Replace existing Intrusion Prevention Rules
  trendmicro.deepsec.deepsec_intrusion_prevention_rules:
    state: replaced
    config:
    - alert_enabled: false
      always_include_packet_data: false
      application_type_id: 300
      template: signature
      signature: test_new_signature_1
      debug_mode_enabled: false
      description: TEST IPR 1 REPLACE DESCRIPTION
      detect_only: false
      event_logging_disabled: false
      generate_event_on_packet_drop: true
      name: TEST IPR 1
      priority: normal
      severity: low
    - alert_enabled: false
      always_include_packet_data: false
      application_type_id: 300
      template: signature
      signature: test_new_signature_1
      debug_mode_enabled: false
      description: TEST IPR 2 REPLACE DESCRIPTION
      detect_only: false
      event_logging_disabled: false
      generate_event_on_packet_drop: true
      name: TEST IPR 2
      priority: normal
      severity: low
- name: Gather Intrusion Prevention Rules by IPR names
  trendmicro.deepsec.deepsec_intrusion_prevention_rules:
    state: gathered
    config:
    - name: TEST IPR 1
    - name: TEST IPR 2
- name: Gather ALL of the Intrusion Prevention Rules
  trendmicro.deepsec.deepsec_intrusion_prevention_rules:
    state: gathered
- name: Delete Intrusion Prevention Rules
  trendmicro.deepsec.deepsec_intrusion_prevention_rules:
    state: deleted
    config:
    - name: TEST IPR 1
    - name: TEST IPR 2
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

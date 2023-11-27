#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: deepsec_firewall_rules
short_description: Manages Firewall Rule resource module
description: Firewall rule details.
version_added: 1.2.0
options:
  config:
    description: A dictionary of Firewall Rules options
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the firewall rule. Searchable as String.
        type: str
      description:
        description: Description of the firewall rule. Searchable as String.
        type: str
      action:
        description: Action of the packet filter. Searchable as Choice.
        type: str
        choices:
          - log-only
          - allow
          - deny
          - force-allow
          - bypass
      priority:
        description: Priority of the packet filter. Searchable as Choice.
        type: str
        choices:
          - "0"
          - "1"
          - "2"
          - "3"
          - "4"
      direction:
        description: Packet direction. Searchable as Choice.
        type: str
        choices:
          - incoming
          - outgoing
      frame_type:
        description: Supported frame types. Searchable as Choice.
        type: str
        choices:
          - any
          - ip
          - arp
          - revarp
          - ipv4
          - ipv6
          - other
      frame_number:
        description:
          Ethernet frame number. Only required for FrameType "other". Searchable
          as Numeric.
        type: int
      frame_not:
        description:
          Controls if the frame setting should be inverted. Set to true
          to invert. Searchable as Boolean.
        type: bool
      protocol:
        description: Protocol. Searchable as Choice.
        type: str
        choices:
          - any
          - icmp
          - igmp
          - ggp
          - tcp
          - pup
          - udp
          - idp
          - nd
          - raw
          - tcp-udp
          - icmpv6
          - other
      protocol_number:
        description: Two-byte protocol number. Searchable as Numeric.
        type: int
      protocol_not:
        description:
          Controls if the protocol setting should be inverted. Set to true
          to invert. Searchable as Boolean.
        type: bool
      source_iptype:
        description: Source IP type. Default is "any". Searchable as Choice.
        type: str
        choices:
          - any
          - masked-ip
          - range
          - ip-list
          - single
          - multiple
      source_ipvalue:
        description:
          Source IP. Only applies to source IP type "masked-ip" or "single".
          Searchable as String.
        type: str
      source_ipmask:
        description:
          Source IP mask. Only applies to source IP type "masked-ip". Searchable
          as String.
        type: str
      source_iprange_from:
        description:
          The first value for a range of source IP addresses. Only applies
          to source IP type "range". Searchable as String.
        type: str
      source_iprange_to:
        description:
          The last value for a range of source IP addresses. Only applies
          to source IP type "range". Searchable as String.
        type: str
      source_ipmultiple:
        description:
          List of source IP addresses. Only applies to source IP type "multiple".
          Searchable as String.
        type: list
        elements: str
      source_iplist_id:
        description:
          ID of source IP list. Only applies to source IP type "ip-list".
          Set to 0 to remove any assignment. Searchable as Numeric.
        type: int
      source_ipnot:
        description:
          Controls if the source IP setting should be inverted. Set to
          true to invert. Searchable as Boolean.
        type: bool
      source_mactype:
        description: Source MAC type. Default is "any". Searchable as Choice.
        type: str
        choices:
          - any
          - single
          - mac-list
          - multiple
      source_macvalue:
        description:
          Source MAC address. Only applies to MAC type "single". Searchable
          as String.
        type: str
      source_macmultiple:
        description:
          List of MAC addresses. Only applies to MAC type "multiple". Searchable
          as String.
        type: list
        elements: str
      source_maclist_id:
        description:
          ID of MAC address list. Only applies to MAC type "mac-list".
          Set to 0 to remove any assignment. Searchable as Numeric.
        type: int
      source_macnot:
        description:
          Controls if the source MAC setting should be inverted. Set to
          true to invert. Searchable as Boolean.
        type: bool
      source_port_type:
        description: The type of source port. Searchable as Choice.
        type: str
        choices:
          - any
          - multiple
          - port-list
      source_port_multiple:
        description:
          List of comma-delimited source ports. Only applies to source
          type "multiple". Searchable as String.
        type: list
        elements: str
      source_port_list_id:
        description:
          ID of source port list. Only applies to source type "port-list".
          Set to 0 to remove any assignment. Searchable as Numeric.
        type: int
      source_port_not:
        description:
          Controls if the source port setting should be inverted. Set to
          true to invert. Searchable as Boolean.
        type: bool
      destination_iptype:
        description: Destination IP type. Default is "any". Searchable as Choice.
        type: str
        choices:
          - any
          - masked-ip
          - range
          - ip-list
          - single
          - multiple
      destination_ipvalue:
        description:
          Destination IP. Only applies to destination IP type "masked-ip"
          or "single". Searchable as String.
        type: str
      destination_ipmask:
        description:
          Destination IP mask. Only applies to destination IP type "masked-ip".
          Searchable as String.
        type: str
      destination_iprange_from:
        description:
          The first value for a range of destination IP addresses. Only
          applies to estination IP type "range". Searchable as String.
        type: str
      destination_iprange_to:
        description:
          The last value for a range of destination IP addresses. Only
          applies to destination IP type "range". Searchable as String.
        type: str
      destination_ipmultiple:
        description:
          List of comma-delimited destination IP addresses. Only applies
          to destination IP type "multiple". Searchable as String.
        type: list
        elements: str
      destination_iplist_id:
        description:
          ID of destination IP list. Only applies to destination IP type
          "ip-list". Set to 0 to remove any assignment. Searchable as Numeric.
        type: int
      destination_ipnot:
        description:
          Controls if the destination IP setting should be inverted. Set
          to true to invert. Searchable as Boolean.
        type: bool
      destination_mactype:
        description: Destination MAC type. Default is "any". Searchable as Choice.
        type: str
        choices:
          - any
          - single
          - mac-list
          - multiple
      destination_macvalue:
        description:
          Destination MAC address. Only applies to MAC type "single". Searchable
          as String.
        type: str
      destination_macmultiple:
        description:
          List of comma-delimited MAC addresses. Only applies to MAC type
          "multiple". Searchable as String.
        type: list
        elements: str
      destination_maclist_id:
        description:
          ID of MAC address list. Only applies to MAC type "mac-list".
          Set to 0 to remove any assignment. Searchable as Numeric.
        type: int
      destination_macnot:
        description:
          Controls if the destination MAC setting should be inverted. Set
          to true to invert. Searchable as Boolean.
        type: bool
      destination_port_type:
        description: The type of destination port. Searchable as Choice.
        type: str
        choices:
          - any
          - multiple
          - port-list
      destination_port_multiple:
        description:
          List of comma-delimited destination ports. Only applies to destination
          type "multiple". Searchable as String.
        type: list
        elements: str
      destination_port_list_id:
        description:
          ID of destination port list. Only applies to destination type
          "port-list". Set to 0 to remove any assignment. Searchable as Numeric.
        type: int
      destination_port_not:
        description:
          Controls if the destination port setting should be inverted.
          Set to true to invert. Searchable as Boolean.
        type: bool
      any_flags:
        description: True if any flags are used. Searchable as Boolean.
        type: bool
      log_disabled:
        description:
          Controls if logging for this filter is disabled. Only applies
          to filter action "log-only" or "deny". Searchable as Boolean.
        type: bool
      include_packet_data:
        description:
          Controls if this filter should capture data for every log. Searchable
          as Boolean.
        type: bool
      alert_enabled:
        description: Controls if this filter should be alerted on. Searchable as Boolean.
        type: bool
      schedule_id:
        description:
          ID of the schedule to control when this filter is "on". Set to
          0 to remove any assignment. Searchable as Numeric.
        type: int
      context_id:
        description:
          RuleContext that is applied to this filter. Set to 0 to remove
          any assignment. Searchable as Numeric.
        type: int
      tcpflags:
        description: TCP flags
        type: list
        elements: str
      id:
        description: ID of the firewall rule. Searchable as ID.
        type: int
      tcpnot:
        description: TCP not
        type: bool
      icmptype:
        description: ICMP type
        type: int
      icmpcode:
        description: ICMP code
        type: int
      icmpnot:
        description: ICMP not
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
      - overridden
      - gathered
      - deleted
author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>
"""

EXAMPLES = """
# Using MERGED state
# -------------------

- name: Create Firewall Rules
  trendmicro.deepsec.deepsec_firewall_rules:
    state: merged
    config:
      - name: test_firewallrule_1
        description: incoming firewall 1 rule description
        action: deny
        priority: 0
        source_iptype: any
        destination_iptype: any
        direction: incoming
        protocol: tcp
        log_disabled: true
      - name: test_firewallrule_2
        description: incoming firewall 2 rule description
        action: deny
        priority: 0
        source_iptype: any
        source_ipnot: false
        source_port_type: any
        destination_iptype: any
        direction: incoming
        protocol: tcp

# RUN output:
# -----------

#   firewall_rules:
#     after:
#     - action: deny
#       alert_enabled: false
#       any_flags: true
#       description: incoming firewall 1 rule description
#       destination_ipnot: false
#       destination_iptype: any
#       destination_macnot: false
#       destination_mactype: any
#       destination_port_not: false
#       destination_port_type: any
#       direction: incoming
#       frame_not: false
#       frame_number: 2048
#       frame_type: ip
#       id: 148
#       include_packet_data: false
#       log_disabled: true
#       name: test_firewallrule_1
#       priority: '0'
#       protocol: tcp
#       protocol_not: false
#       source_ipnot: false
#       source_iptype: any
#       source_macnot: false
#       source_mactype: any
#       source_port_not: false
#       source_port_type: any
#     - action: deny
#       alert_enabled: false
#       any_flags: true
#       description: incoming firewall 2 rule description
#       destination_ipnot: false
#       destination_iptype: any
#       destination_macnot: false
#       destination_mactype: any
#       destination_port_not: false
#       destination_port_type: any
#       direction: incoming
#       frame_not: false
#       frame_number: 2048
#       frame_type: ip
#       id: 149
#       include_packet_data: false
#       log_disabled: false
#       name: test_firewallrule_2
#       priority: '0'
#       protocol: tcp
#       protocol_not: false
#       source_ipnot: false
#       source_iptype: any
#       source_macnot: false
#       source_mactype: any
#       source_port_not: false
#       source_port_type: any
#     before: []

- name: Modify the severity of Firewall Rule by name
  trendmicro.deepsec.deepsec_firewall_rules:
    state: merged
    config:
      - name: test_firewallrule_1
        action: allow

# RUN output:
# -----------

#   firewall_rules:
#     after:
#     - action: allow
#       alert_enabled: false
#       any_flags: true
#       description: incoming firewall 1 rule description
#       destination_ipnot: false
#       destination_iptype: any
#       destination_macnot: false
#       destination_mactype: any
#       destination_port_not: false
#       destination_port_type: any
#       direction: incoming
#       frame_not: false
#       frame_number: 2048
#       frame_type: ip
#       id: 148
#       include_packet_data: false
#       log_disabled: true
#       name: test_firewallrule_1
#       priority: '0'
#       protocol: tcp
#       protocol_not: false
#       source_ipnot: false
#       source_iptype: any
#       source_macnot: false
#       source_mactype: any
#       source_port_not: false
#       source_port_type: any
#     before:
#     - action: deny
#       alert_enabled: false
#       any_flags: true
#       description: incoming firewall 1 rule description
#       destination_ipnot: false
#       destination_iptype: any
#       destination_macnot: false
#       destination_mactype: any
#       destination_port_not: false
#       destination_port_type: any
#       direction: incoming
#       frame_not: false
#       frame_number: 2048
#       frame_type: ip
#       id: 148
#       include_packet_data: false
#       log_disabled: true
#       name: test_firewallrule_1
#       priority: '0'
#       protocol: tcp
#       protocol_not: false
#       source_ipnot: false
#       source_iptype: any
#       source_macnot: false
#       source_mactype: any
#       source_port_not: false
#       source_port_type: any

# Using REPLACED state
# --------------------

- name: Replace existing Firewall Rules
  trendmicro.deepsec.deepsec_intrusion_prevention_rules:
    state: replaced
    config:
      - name: test_firewallrule_1
        description: outgoing firewall 1 REPLACED rule
        action: deny
        priority: 0
        source_iptype: any
        destination_iptype: any
        direction: outgoing
        protocol: any
        log_disabled: true

# RUN output:
# -----------

#   firewall_rules:
#     after:
#     - action: deny
#       alert_enabled: false
#       any_flags: true
#       description: outgoing firewall 1 REPLACED rule
#       destination_ipnot: false
#       destination_iptype: any
#       destination_macnot: false
#       destination_mactype: any
#       destination_port_not: false
#       destination_port_type: any
#       direction: outgoing
#       frame_not: false
#       frame_number: 2048
#       frame_type: ip
#       id: 150
#       include_packet_data: false
#       log_disabled: true
#       name: test_firewallrule_1
#       priority: '0'
#       protocol: any
#       protocol_not: false
#       source_ipnot: false
#       source_iptype: any
#       source_macnot: false
#       source_mactype: any
#       source_port_not: false
#       source_port_type: any
#     before:
#     - action: allow
#       alert_enabled: false
#       any_flags: true
#       description: incoming firewall 1 rule description
#       destination_ipnot: false
#       destination_iptype: any
#       destination_macnot: false
#       destination_mactype: any
#       destination_port_not: false
#       destination_port_type: any
#       direction: incoming
#       frame_not: false
#       frame_number: 2048
#       frame_type: ip
#       id: 148
#       include_packet_data: false
#       log_disabled: true
#       name: test_firewallrule_1
#       priority: '0'
#       protocol: tcp
#       protocol_not: false
#       source_ipnot: false
#       source_iptype: any
#       source_macnot: false
#       source_mactype: any
#       source_port_not: false
#       source_port_type: any

# Using GATHERED state
# --------------------

- name: Gather Firewall Rules by FW names
  trendmicro.deepsec.deepsec_firewall_rules:
    state: gathered
    config:
      - name: test_firewallrule_1
      - name: test_firewallrule_2

# RUN output:
# -----------

# gathered:
#   - action: deny
#     alert_enabled: false
#     any_flags: true
#     description: incoming firewall 1 rule description
#     destination_ipnot: false
#     destination_iptype: any
#     destination_macnot: false
#     destination_mactype: any
#     destination_port_not: false
#     destination_port_type: any
#     direction: incoming
#     frame_not: false
#     frame_number: 2048
#     frame_type: ip
#     id: 150
#     include_packet_data: false
#     log_disabled: true
#     name: test_firewallrule_1
#     priority: '0'
#     protocol: tcp
#     protocol_not: false
#     source_ipnot: false
#     source_iptype: any
#     source_macnot: false
#     source_mactype: any
#     source_port_not: false
#     source_port_type: any
#   - action: deny
#     alert_enabled: false
#     any_flags: true
#     description: incoming firewall 2 rule description
#     destination_ipnot: false
#     destination_iptype: any
#     destination_macnot: false
#     destination_mactype: any
#     destination_port_not: false
#     destination_port_type: any
#     direction: incoming
#     frame_not: false
#     frame_number: 2048
#     frame_type: ip
#     id: 149
#     include_packet_data: false
#     log_disabled: false
#     name: test_firewallrule_2
#     priority: '0'
#     protocol: tcp
#     protocol_not: false
#     source_ipnot: false
#     source_iptype: any
#     source_macnot: false
#     source_mactype: any
#     source_port_not: false
#     source_port_type: any

- name: Gather ALL of the Firewall Rules
  trendmicro.deepsec.deepsec_firewall_rules:
    state: gathered

# Using DELETED state
# -------------------

- name: Delete Firewall Rules
  trendmicro.deepsec.deepsec_firewall_rules:
    state: deleted
    config:
      - name: test_firewallrule_1
      - name: test_firewallrule_2
# RUN output:
# -----------

#   firewall_rules:
#     after: []
#     before:
#     - action: deny
#       alert_enabled: false
#       any_flags: true
#       description: incoming firewall 1 rule description
#       destination_ipnot: false
#       destination_iptype: any
#       destination_macnot: false
#       destination_mactype: any
#       destination_port_not: false
#       destination_port_type: any
#       direction: incoming
#       frame_not: false
#       frame_number: 2048
#       frame_type: ip
#       id: 150
#       include_packet_data: false
#       log_disabled: true
#       name: test_firewallrule_1
#       priority: '0'
#       protocol: tcp
#       protocol_not: false
#       source_ipnot: false
#       source_iptype: any
#       source_macnot: false
#       source_mactype: any
#       source_port_not: false
#       source_port_type: any
#     - action: deny
#       alert_enabled: false
#       any_flags: true
#       description: incoming firewall 2 rule description
#       destination_ipnot: false
#       destination_iptype: any
#       destination_macnot: false
#       destination_mactype: any
#       destination_port_not: false
#       destination_port_type: any
#       direction: incoming
#       frame_not: false
#       frame_number: 2048
#       frame_type: ip
#       id: 149
#       include_packet_data: false
#       log_disabled: false
#       name: test_firewallrule_2
#       priority: '0'
#       protocol: tcp
#       protocol_not: false
#       source_ipnot: false
#       source_iptype: any
#       source_macnot: false
#       source_mactype: any
#       source_port_not: false
#       source_port_type: any
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

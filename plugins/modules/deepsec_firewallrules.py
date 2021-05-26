#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
module: deepsec_firewallrules
short_description: Create a new firewall rule.
description: This module creates a new firewall rule under TrendMicro Deep Security.
version_added: 1.0.0
author: "Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
options:
  name:
    description:
      - Name of the firewall rule
      - Searchable as String.
    required: true
    type: str
  description:
    description:
      - Description of the firewall rule
      - Searchable as String.
    type: str
  action:
    description:
      - Action of the packet filter. Searchable as Choice.
    type: str
    choices:
      - 'log-only'
      - 'allow'
      - 'deny'
      - 'force-allow'
      - 'bypass'
  priority:
    description: Priority of the packet filter. Searchable as Choice.
    choices: ['0', '1', '2', '3', '4']
    type: str
  direction:
    description: Packet direction. Searchable as Choice.
    choices: ['incoming', 'outgoing']
    type: str
  frame_type:
    description: Supported frame types. Searchable as Choice.
    choices: ['any', 'ip', 'arp', 'revarp', 'ipv4', 'ipv6', 'other']
    type: str
  frame_number:
    description: Ethernet frame number. Only required for FrameType 'other'. Searchable as Numeric.
    type: int
  frame_not:
    description: Controls if the frame setting should be inverted. Set to true to invert. Searchable as Boolean.
    type: bool
  protocol:
    description: Protocol. Searchable as Choice.
    choices: ['any', 'icmp', 'igmp', 'ggp', 'tcp', 'pup', 'udp', 'idp', 'nd', 'raw', 'tcp-udp', 'icmpv6', 'other']
    type: str
  protocol_number:
    description: Two-byte protocol number. Searchable as Numeric.
    type: int
  protocol_not:
    description: Controls if the protocol setting should be inverted. Set to true to invert. Searchable as Boolean.
    type: bool
  source_iptype:
    description: Source IP type. Default is 'any'. Searchable as Choice.
    choices: ['any', 'masked-ip', 'range', 'ip-list', 'single', 'multiple']
    type: str
  source_ipvalue:
    description:
      - Source IP.
      - Only applies to source IP type 'masked-ip' or 'single'.
      - Searchable as String.
    type: str
  source_ipmask:
    description:
      - Source IP mask. Only applies to source IP type 'masked-ip'.
      - Searchable as String.
    type: str
  source_iprange_from:
    description:
      - The first value for a range of source IP addresses. Only applies to source IP type 'range'.
      - Searchable as String.
    type: str
  source_iprange_to:
    description:
      - The last value for a range of source IP addresses. Only applies to source IP type 'range'.
      - Searchable as String.
    type: str
  source_ipmultiple:
    description:
      - List of source IP addresses. Only applies to source IP type 'multiple'.
      - Searchable as String.
    type: list
    elements: str
  source_iplist_id:
    description:
      - ID of source IP list. Only applies to source IP type 'ip-list'.
      - Searchable as Numeric.
    type: int
  source_ipnot:
    description: Controls if the source IP setting should be inverted. Set to true to invert.
      Searchable as Boolean.
    type: bool
  source_mactype:
    description:
      - Source MAC type. Default is 'any'.
      - Searchable as Choice.
    choices: ['any', 'single', 'mac-list', 'multiple']
    type: str
  source_macvalue:
    description:
      - Source MAC address. Only applies to MAC type 'single'.
      - Searchable as String.
    type: str
  source_macmultiple:
    description:
      - List of MAC addresses. Only applies to MAC type 'multiple'.
      - Searchable as String.
    type: list
    elements: str
  source_maclist_id:
    description:
      - ID of MAC address list. Only applies to MAC type 'mac-list'.
      - Searchable as Numeric.
    type: int
  source_macnot:
    description: Controls if the source MAC setting should be inverted. Set to true to invert.
      Searchable as Boolean.
    type: bool
  source_port_type:
    description:
      - The type of source port.
      - Searchable as Choice.
    choices: ['any', 'multiple', 'port-list']
    type: str
  source_port_multiple:
    description:
      - List of comma-delimited source ports. Only applies to source type 'multiple'.
      - Searchable as String.
    type: list
    elements: str
  source_port_list_id:
    description:
      - ID of source port list. Only applies to source type 'port-list'.
      - Searchable as Numeric.
    type: int
  source_port_not:
    description: Controls if the source MAC setting should be inverted. Set to true to invert.
      Searchable as Boolean.
    type: bool
  destination_iptype:
    description:
      - Destination IP type. Default is 'any'.
      - Searchable as Choice.
    choices: ['any', 'masked-ip', 'range', 'ip-list', 'single', 'multiple']
    type: str
  destination_ipvalue:
    description:
      - Destination IP. Only applies to destination IP type 'masked-ip' or 'single'.
      - Searchable as String.
    type: str
  destination_ipmask:
    description:
      - Destination IP mask. Only applies to destination IP type 'masked-ip'.
      - Searchable as String.
    type: str
  destination_iprange_from:
    description:
      - The first value for a range of destination IP addresses. Only applies to estination IP
        type 'range'.
      - Searchable as String.
    type: str
  destination_iprange_to:
    description:
      - The last value for a range of destination IP addresses. Only applies to destination IP
        type 'range'.
      - Searchable as String.
    type: str
  destination_ipmultiple:
    description:
      - List of comma-delimited destination IP addresses. Only applies to destination IP
        type 'multiple'.
      - Searchable as String.
    type: list
    elements: str
  destination_iplist_id:
    description: ID of destination IP list. Only applies to destination IP type 'ip-list'.
      Searchable as Numeric.
    type: int
  destination_ipnot:
    description: Controls if the destination IP setting should be inverted. Set to true to invert.
      Searchable as Boolean.
    type: bool
  destination_mactype:
    description: Destination MAC type. Default is 'any'. Searchable as Choice.
    choices: ['any', 'single', 'mac-list', 'multiple']
    type: str
  destination_macvalue:
    description: Destination MAC address. Only applies to MAC type 'single'. Searchable as String.
    type: str
  destination_macmultiple:
    description: List of comma-delimited MAC addresses. Only applies to MAC type 'multiple'.
      Searchable as String.
    type: list
    elements: str
  destination_maclist_id:
    description: ID of MAC address list. Only applies to MAC type 'mac-list'. Searchable as Numeric.
    type: int
  destination_macnot:
    description: Controls if the destination MAC setting should be inverted. Set to true to invert.
      Searchable as Boolean.
    type: bool
  destination_port_type:
    description: The type of destination port. Searchable as Choice.
    choices: ['any', 'multiple', 'port-list']
    type: str
  destination_port_multiple:
    description: List of comma-delimited destination ports. Only applies to destination type 'multiple'.
      Searchable as String.
    type: list
    elements: str
  destination_port_list_id:
    description: ID of destination port list. Only applies to destination type 'port-list'.
      Searchable as Numeric.
    type: int
  destination_port_not:
    description: Controls if the destination port setting should be inverted. Set to true to invert.
      Searchable as Boolean.
    type: bool
  any_flags:
    description: True if any flags are used. Searchable as Boolean.
    type: bool
  log_disabled:
    description: Controls if logging for this filter is disabled. Only applies to filter
      action 'log-only' or 'deny'. Searchable as Boolean.
    type: bool
  include_packet_data:
    description: Controls if this filter should capture data for every log. Searchable as Boolean.
    type: bool
  alert_enabled:
    description: Controls if this filter should be alerted on. Searchable as Boolean.
    type: bool
  context_id:
    description: ID of the schedule to control when this filter is 'on'. Searchable as Numeric.
    type: int
  tcpflags:
    description: TCP flags
    choices: ['fin', 'syn', 'rst', 'psh', 'ack', 'urg']
    type: list
    elements: str
  tcpnot:
    description: TCP Not
    type: bool
  icmptype:
    description: ICMP Type
    type: int
  icmpcode:
    description: ICMPCode
    type: int
  icmpnot:
    description: ICMP Not
    type: bool
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
- name: Create/Config a new Firewall Rule Config
  trendmicro.deepsec.deepsec_firewallrules:
    state: present
    name: test_firewallrule config
    description: test firewall description
    action: deny
    priority: 0
    source_iptype: any
    destination_iptype: any
    direction: incoming
    protocol: tcp
    tcpflags:
      - syn

- name: Delete/Remove the existing Firewall rule Config
  trendmicro.deepsec.deepsec_firewallrules:
    state: absent
    name: test_firewallrule config
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
    "id": "ID",
    "frame_type": "frameType",
    "frame_number": "frameNumber",
    "frame_not": "frameNot",
    "protocol_number": "protocolNumber",
    "protocol_not": "protocolNot",
    "source_iptype": "sourceIPType",
    "source_ipvalue": "sourceIPValue",
    "source_ipmask": "sourceIPMask",
    "source_iprange_from": "sourceIPRangeFrom",
    "source_iprange_to": "sourceIPRangeTo",
    "source_ipmultiple": "sourceIPMultiple",
    "source_iplist_id": "sourceIPListID",
    "source_ipnot": "sourceIPNot",
    "source_mactype": "sourceMACType",
    "source_macvalue": "sourceMACValue",
    "source_macmultiple": "sourceMACMultiple",
    "source_maclist_id": "sourceMACListID",
    "source_macnot": "sourceMACNot",
    "source_port_type": "sourcePortType",
    "source_port_multiple": "sourcePortMultiple",
    "source_port_list_id": "sourcePortListID",
    "source_port_not": "sourcePortNot",
    "destination_iptype": "destinationIPType",
    "destination_ipvalue": "destinationIPValue",
    "destination_ipmask": "destinationIPMask",
    "destinationIPRangeFrom": "destination_iprange_from",
    "destination_iprange_to": "destinationIPRangeTo",
    "destination_ipmultiple": "destinationIPMultiple",
    "destination_iplist_id": "destinationIPListID",
    "destination_ipnot": "destinationIPNot",
    "destination_mactype": "destinationMACType",
    "destination_macvalue": "destinationMACValue",
    "destination_macmultiple": "destinationMACMultiple",
    "destination_maclist_id": "destinationMACListID",
    "destination_macnot": "destinationMACNot",
    "destination_port_type": "destinationPortType",
    "destination_port_multiple": "destinationPortMultiple",
    "destination_port_list_id": "destinationPortListID",
    "destination_port_not": "destinationPortNot",
    "any_flags": "anyFlags",
    "log_disabled": "logDisabled",
    "include_packet_data": "includePacketData",
    "alert_enabled": "alertEnabled",
    "schedule_id": "scheduleID",
    "context_id": "contextID",
    "tcpnot": "TCPNot",
    "icmptype": "ICMPType",
    "icmpcode": "ICMPCode",
    "icmpnot": "ICMPNot",
}


def map_params_to_obj(module_params):
    # populate the firewall rules dict with actual api expected values
    obj = {}
    obj["name"] = module_params["name"]
    if module_params.get("description"):
        obj["description"] = module_params.get("description")
    if module_params.get("action"):
        obj["action"] = module_params.get("action")
    if module_params.get("priority"):
        obj["priority"] = module_params.get("priority")
    if module_params.get("direction"):
        obj["direction"] = module_params.get("direction")
    if module_params.get("protocol"):
        obj["protocol"] = module_params.get("protocol")
    if module_params.get("tcpflags"):
        obj["tcpflags"] = module_params.get("tcpflags")
    for k, v in iteritems(key_transform):
        if module_params.get(k):
            obj[v] = module_params.get(k)
    return obj


def main():
    argspec = dict(
        state=dict(choices=["present", "absent"], default="present"),
        name=dict(required=True, type="str"),
        description=dict(type="str"),
        action=dict(
            type="str",
            choices=["log-only", "allow", "deny", "force-allow", "bypass"],
        ),
        priority=dict(type="str", choices=["0", "1", "2", "3", "4"]),
        direction=dict(type="str", choices=["incoming", "outgoing"]),
        frame_type=dict(
            type="str",
            choices=["any", "ip", "arp", "revarp", "ipv4", "ipv6", "other"],
        ),
        frame_number=dict(type="int"),
        frame_not=dict(type="bool"),
        protocol=dict(
            type="str",
            choices=[
                "any",
                "icmp",
                "igmp",
                "ggp",
                "tcp",
                "pup",
                "udp",
                "idp",
                "nd",
                "raw",
                "tcp-udp",
                "icmpv6",
                "other",
            ],
        ),
        protocol_number=dict(type="int"),
        protocol_not=dict(type="bool"),
        source_iptype=dict(
            type="str",
            choices=[
                "any",
                "masked-ip",
                "range",
                "ip-list",
                "single",
                "multiple",
            ],
        ),
        source_ipvalue=dict(type="str"),
        source_ipmask=dict(type="str"),
        source_iprange_from=dict(type="str"),
        source_iprange_to=dict(type="str"),
        source_ipmultiple=dict(type="list", elements="str"),
        source_iplist_id=dict(type="int"),
        source_ipnot=dict(type="bool"),
        source_mactype=dict(
            type="str", choices=["any", "single", "mac-list", "multiple"]
        ),
        source_macvalue=dict(type="str"),
        source_macmultiple=dict(type="list", elements="str"),
        source_maclist_id=dict(type="int"),
        source_macnot=dict(type="bool"),
        source_port_type=dict(
            type="str", choices=["any", "multiple", "port-list"]
        ),
        source_port_multiple=dict(type="list", elements="str"),
        source_port_list_id=dict(type="int"),
        source_port_not=dict(type="bool"),
        destination_iptype=dict(
            type="str",
            choices=[
                "any",
                "masked-ip",
                "range",
                "ip-list",
                "single",
                "multiple",
            ],
        ),
        destination_ipvalue=dict(type="str"),
        destination_ipmask=dict(type="str"),
        destination_iprange_from=dict(type="str"),
        destination_iprange_to=dict(type="str"),
        destination_ipmultiple=dict(type="list", elements="str"),
        destination_iplist_id=dict(type="int"),
        destination_ipnot=dict(type="bool"),
        destination_mactype=dict(
            type="str", choices=["any", "single", "mac-list", "multiple"]
        ),
        destination_macvalue=dict(type="str"),
        destination_macmultiple=dict(type="list", elements="str"),
        destination_maclist_id=dict(type="int"),
        destination_macnot=dict(type="bool"),
        destination_port_type=dict(
            type="str", choices=["any", "multiple", "port-list"]
        ),
        destination_port_multiple=dict(type="list", elements="str"),
        destination_port_list_id=dict(type="int"),
        destination_port_not=dict(type="bool"),
        any_flags=dict(type="bool"),
        log_disabled=dict(type="bool"),
        include_packet_data=dict(type="bool"),
        alert_enabled=dict(type="bool"),
        context_id=dict(type="int"),
        tcpflags=dict(
            type="list",
            elements="str",
            choices=["fin", "syn", "rst", "psh", "ack", "urg"],
        ),
        tcpnot=dict(type="bool"),
        icmptype=dict(type="int"),
        icmpcode=dict(type="int"),
        icmpnot=dict(type="bool"),
    )

    api_object = "/api/firewallrules"
    api_return = "firewallRules"

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))
    # Search for existing firewall rules config via Get call
    search_existing_firewallrules = check_if_config_exists(
        deepsec_request, want["name"], api_object.split("/")[2], api_return
    )

    if (
        "ID" in search_existing_firewallrules
        and module.params["state"] == "absent"
    ):
        delete_config_with_id(
            module,
            deepsec_request,
            api_object.split("/")[2],
            search_existing_firewallrules["ID"],
            api_return,
            handle_return=True,
        )
    elif (
        "ID" not in search_existing_firewallrules
        and module.params["state"] == "absent"
    ):
        module.exit_json(changed=False)
    else:
        firewallrules = deepsec_request.post(
            "{0}".format(api_object), data=want
        )
        if "ID" in search_existing_firewallrules:
            module.exit_json(
                firewallrules=search_existing_firewallrules, changed=False
            )
        elif firewallrules.get("message"):
            module.fail_json(msg=firewallrules["message"])
        else:
            module.exit_json(firewallrules=firewallrules, changed=True)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

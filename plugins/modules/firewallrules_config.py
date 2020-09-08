#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
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
---
module: firewallrules_config
short_description: Create a new firewall rule. 
description:
  - This module creates a new firewall rule under TrendMicro Deep Security.
version_added: "1.0.0"
options:
  name:
    description: Name of the firewall rule. Searchable as String.
    required: true
    type: str
  description:
    description: Description of the firewall rule. Searchable as String.
    required: false
    type: str
  action:
    description: Action of the packet filter. Searchable as Choice.
    required: false
    choices: ["log-only", "allow", "deny", "force-allow", "bypass"]
    type: str
  priority:
    description: Priority of the packet filter. Searchable as Choice.
    required: false
    choices: ["0", "1", "2", "3", "4"]
    type: str
  direction:
    description: Packet direction. Searchable as Choice.
    required: false
    choices: ["incoming", "outgoing"]
    type: str
  frame_type:
    description: Supported frame types. Searchable as Choice.
    required: false
    choices: ["any", "ip", "arp", "revarp", "ipv4", "ipv6", "other"]
    type: str
  frame_number:
    description: Ethernet frame number. Only required for FrameType "other".
    Searchable as Numeric.
    required: false
    type: int
  frame_not:
    description: Controls if the frame setting should be inverted. Set to true to invert.
    Searchable as Boolean.
    required: false
    type: bool
  protocol:
    description: Protocol. Searchable as Choice.
    required: false
    choices: ["any", "icmp", "igmp", "ggp", "tcp", "pup", "udp", "idp", "nd", "raw", "tcp-udp", "icmpv6", "other"]
    type: str
  protocol_number:
    description: Two-byte protocol number. Searchable as Numeric.
    Searchable as Numeric.
    required: false
    type: int
  protocol_not:
    description: Controls if the protocol setting should be inverted. Set to true to invert.
    Searchable as Boolean.
    required: false
    type: bool
  source_iptype:
    description: Source IP type. Default is "any". Searchable as Choice.
    required: false
    choices: ["any", "masked-ip", "range", "ip-list", "single", "multiple"]
    type: str
  source_ipvalue:
    description: Source IP. Only applies to source IP type "masked-ip" or "single".
    Searchable as String.
    required: false
    type: str
  source_ipmask:
    description: Source IP mask. Only applies to source IP type "masked-ip". Searchable as String.
    Searchable as String.
    required: false
    type: str
  source_iprange_from:
    description: The first value for a range of source IP addresses. Only applies to source IP type "range".
    Searchable as String.
    required: false
    type: str
  source_iprange_to:
    description: The last value for a range of source IP addresses. Only applies to source IP type "range".
    Searchable as String.
    required: false
    type: str
  source_ipmultiple:
    description: List of source IP addresses. Only applies to source IP type "multiple". Searchable as String.
    Searchable as String.
    required: false
    type: list
    elements: str
  source_iplist_id:
    description: ID of source IP list. Only applies to source IP type "ip-list". Searchable as Numeric.
    required: false
    type: int
  source_ipnot:
    description: Controls if the source IP setting should be inverted. Set to true to invert.
    Searchable as Boolean.
    required: false
    type: bool
  source_mactype:
    description: Source MAC type. Default is "any". Searchable as Choice.
    required: false
    choices: ["any", "single", "mac-list", "multiple"]
    type: str
  source_macvalue:
    description: Source MAC address. Only applies to MAC type "single". Searchable as String.
    required: false
    type: str
  source_macmultiple:
    description: List of MAC addresses. Only applies to MAC type "multiple". Searchable as String.
    required: false
    type: list
    elements: str
  source_maclist_id:
    description: ID of MAC address list. Only applies to MAC type "mac-list". Searchable as Numeric.
    required: false
    type: int
  source_macnot:
    description: Controls if the source MAC setting should be inverted. Set to true to invert.
    Searchable as Boolean.
    required: false
    type: bool
  source_port_type:
    description: The type of source port. Searchable as Choice.
    required: false
    choices: ["any", "multiple", "port-list"]
    type: str
  source_port_multiple:
    description: List of comma-delimited source ports. Only applies to source type "multiple".
    Searchable as String.
    required: false
    type: list
    elements: str
  source_port_list_id	
    description: ID of source port list. Only applies to source type "port-list". Searchable as Numeric.
    required: false
    type: int
  source_port_not:
    description: Controls if the source MAC setting should be inverted. Set to true to invert.
    Searchable as Boolean.
    required: false
    type: bool
  destination_iptype:
    description: Destination IP type. Default is "any". Searchable as Choice.
    required: false
    choices: ["any", "masked-ip", "range", "ip-list", "single", "multiple"]
    type: str
  destination_ipvalue:	
    description: Destination IP. Only applies to destination IP type "masked-ip" or "single".
    Searchable as String.
    required: false
    type: str
  destination_ipmask:
    description: Destination IP mask. Only applies to destination IP type "masked-ip". Searchable as String.
    Searchable as String.
    required: false
    type: str
  destination_iprange_from:
    description: The first value for a range of destination IP addresses. Only applies to estination IP
    type "range". Searchable as String.
    required: false
    type: str
  destination_iprange_to:
    description: The last value for a range of destination IP addresses. Only applies to destination IP
    type "range". Searchable as String.
    required: false
    type: str
  destination_ipmultiple:	
    description: List of comma-delimited destination IP addresses. Only applies to destination IP
    type "multiple". Searchable as String.
    required: false
    type: list
    elements: str
  destination_iplist_id:
    description: ID of destination IP list. Only applies to destination IP type "ip-list".
    Searchable as Numeric.
    required: false
    type: int
  destination_ipnot:
    description: Controls if the destination IP setting should be inverted. Set to true to invert.
    Searchable as Boolean.
    required: false
    type: bool
  destination_mactype:	
    description: Destination MAC type. Default is "any". Searchable as Choice.
    required: false
    choices: ["any", "single", "mac-list", "multiple"]
    type: str
  destination_macvalue:
    description: Destination MAC address. Only applies to MAC type "single". Searchable as String.
    required: false
    type: str
  destination_macmultiple:
    description: List of comma-delimited MAC addresses. Only applies to MAC type "multiple".
    Searchable as String.
    required: false
    type: list
    elements: str
  destination_maclist_id:
    description: ID of MAC address list. Only applies to MAC type "mac-list". Searchable as Numeric.
    required: false
    type: int
  destination_macnot:
    description: Controls if the destination MAC setting should be inverted. Set to true to invert.
    Searchable as Boolean.
    required: false
    type: bool
  destination_port_type:
    description: The type of destination port. Searchable as Choice.
    required: false
    choices: ["any", "multiple", "port-list"]
    type: str
  destination_port_multiple:
    description: List of comma-delimited destination ports. Only applies to destination type "multiple".
    Searchable as String.
    required: false
    type: list
    elements: str
  destination_port_list_id:
    description: ID of destination port list. Only applies to destination type "port-list".
    Searchable as Numeric.
    required: false
    type: int
  destination_port_not:
    description: Controls if the destination port setting should be inverted. Set to true to invert.
    Searchable as Boolean.
    required: false
    type: bool
  any_flags:
    description: True if any flags are used. Searchable as Boolean.
    required: false
    type: bool
  log_disabled:
    description: Controls if logging for this filter is disabled. Only applies to filter
    action "log-only" or "deny". Searchable as Boolean.
    required: false
    type: bool
  include_packet_data:
    description: Controls if this filter should capture data for every log. Searchable as Boolean.
    required: false
    type: bool
  alert_enabled:
    description: Controls if this filter should be alerted on. Searchable as Boolean.
    required: false
    type: bool
  context_id:
    description: ID of the schedule to control when this filter is "on". Searchable as Numeric.
    required: false
    type: int
  contextID:
    description: RuleContext that is applied to this filter. Searchable as Numeric.
    required: false
    type: int
  tcpflags:
    description: TCP flags
    required: false
    choices: ["fin", "syn", "rst", "psh", "ack", "urg"]
    type: list
    elements: str
  tcpnot:
    description: TCP Not
    required: false
    type: bool
  icmptype:
    description: ICMP Type
    required: false
    type: int
  icmpcode:
    description: ICMPCode
    required: false
    type: int
  icmpnot:
    description: ICMP Not
    required: false
    type: bool
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
    check_if_config_exists,
    delete_config_with_id,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
)
import copy
import json


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
    if module_params.get("frame_type"):
        obj["frameType"] = module_params.get("frame_type")
    if module_params.get("frame_number"):
        obj["frameNumber"] = module_params.get("frame_number")
    if module_params.get("frame_not"):
        obj["frameNot"] = module_params.get("frame_not")
    if module_params.get("protocol"):
        obj["protocol"] = module_params.get("protocol")
    if module_params.get("protocol_number"):
        obj["protocolNumber"] = module_params.get("protocol_number")
    if module_params.get("protocol_not"):
        obj["protocolNot"] = module_params.get("protocol_not")
    if module_params.get("source_iptype"):
        obj["sourceIPType"] = module_params.get("source_iptype")
    if module_params.get("source_ipvalue"):
        obj["sourceIPValue"] = module_params.get("source_ipvalue")
    if module_params.get("source_ipmask"):
        obj["sourceIPMask"] = module_params.get("source_ipmask")
    if module_params.get("source_iprange_from"):
        obj["sourceIPRangeFrom"] = module_params.get("source_iprange_from")
    if module_params.get("source_iprange_to"):
        obj["sourceIPRangeTo"] = module_params.get("source_iprange_to")
    if module_params.get("source_ipmultiple"):
        obj["sourceIPMultiple"] = module_params.get("source_ipmultiple")
    if module_params.get("source_iplist_id"):
        obj["sourceIPListID"] = module_params.get("source_iplist_id")
    if module_params.get("source_ipnot"):
        obj["sourceIPNot"] = module_params.get("source_ipnot")
    if module_params.get("source_mactype"):
        obj["sourceMACType"] = module_params.get("source_mactype")
    if module_params.get("source_macvalue"):
        obj["sourceMACValue"] = module_params.get("source_macvalue")
    if module_params.get("source_macmultiple"):
        obj["sourceMACMultiple"] = module_params.get("source_macmultiple")
    if module_params.get("source_maclist_id"):
        obj["sourceMACListID"] = module_params.get("source_maclist_id")
    if module_params.get("source_macnot"):
        obj["sourceMACNot"] = module_params.get("source_macnot")
    if module_params.get("source_port_type"):
        obj["sourcePortType"] = module_params.get("source_port_type")
    if module_params.get("source_port_multiple"):
        obj["sourcePortMultiple"] = module_params.get("source_port_multiple")
    if module_params.get("source_port_list_id"):
        obj["sourcePortListID"] = module_params.get("source_port_list_id")
    if module_params.get("source_port_not"):
        obj["sourcePortNot"] = module_params.get("source_port_not")
    if module_params.get("destination_iptype"):
        obj["destinationIPType"] = module_params.get("destination_iptype")
    if module_params.get("destination_ipvalue"):
        obj["destinationIPValue"] = module_params.get("destination_ipvalue")
    if module_params.get("destination_ipmask"):
        obj["destinationIPMask"] = module_params.get("destination_ipmask")
    if module_params.get("destination_iprange_from"):
        obj["destinationIPRangeFrom"] = module_params.get(
            "destination_iprange_from"
        )
    if module_params.get("destination_iprange_to"):
        obj["destinationIPRangeTo"] = module_params.get(
            "destination_iprange_to"
        )
    if module_params.get("destination_ipmultiple"):
        obj["destinationIPMultiple"] = module_params.get(
            "destination_ipmultiple"
        )
    if module_params.get("destination_iplist_id"):
        obj["destinationIPListID"] = module_params.get("destination_iplist_id")
    if module_params.get("destination_ipnot"):
        obj["destinationIPNot"] = module_params.get("destination_ipnot")
    if module_params.get("destination_mactype"):
        obj["destinationMACType"] = module_params.get("destination_mactype")
    if module_params.get("destination_macvalue"):
        obj["destinationMACValue"] = module_params.get("destination_macvalue")
    if module_params.get("destination_macmultiple"):
        obj["destinationMACMultiple"] = module_params.get(
            "destination_macmultiple"
        )
    if module_params.get("destination_maclist_id"):
        obj["destinationMACListID"] = module_params.get(
            "destination_maclist_id"
        )
    if module_params.get("destination_macnot"):
        obj["destinationMACNot"] = module_params.get("destination_macnot")
    if module_params.get("destination_port_type"):
        obj["destinationPortType"] = module_params.get("destination_port_type")
    if module_params.get("destination_port_multiple"):
        obj["destinationPortMultiple"] = module_params.get(
            "destination_port_multiple"
        )
    if module_params.get("destination_port_list_id"):
        obj["destinationPortListID"] = module_params.get(
            "destination_port_list_id"
        )
    if module_params.get("destination_port_not"):
        obj["destinationPortNot"] = module_params.get("destination_port_not")
    if module_params.get("any_flags"):
        obj["anyFlags"] = module_params.get("any_flags")
    if module_params.get("log_disabled"):
        obj["logDisabled"] = module_params.get("log_disabled")
    if module_params.get("include_packet_data"):
        obj["includePacketData"] = module_params.get("include_packet_data")
    if module_params.get("alert_enabled"):
        obj["alertEnabled"] = module_params.get("alert_enabled")
    if module_params.get("schedule_id"):
        obj["scheduleID"] = module_params.get("schedule_id")
    if module_params.get("context_id"):
        obj["contextID"] = module_params.get("context_id")
    if module_params.get("tcpflags"):
        obj["tcpflags"] = module_params.get("tcpflags")
    if module_params.get("tcpnot"):
        obj["TCPNot"] = module_params.get("tcpnot")
    if module_params.get("icmptype"):
        obj["ICMPType"] = module_params.get("icmptype")
    if module_params.get("icmpcode"):
        obj["ICMPCode"] = module_params.get("icmpcode")
    if module_params.get("icmpnot"):
        obj["ICMPNot"] = module_params.get("icmpnot")

    return obj


def main():

    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        name=dict(required=True, type="str"),
        description=dict(type="str", required=False),
        action=dict(
            type="str",
            choices=["log-only", "allow", "deny", "force-allow", "bypass"],
            required=False,
        ),
        priority=dict(
            type="str", choices=["0", "1", "2", "3", "4"], required=False
        ),
        direction=dict(
            type="str", choices=["incoming", "outgoing"], required=False
        ),
        frame_type=dict(
            type="str",
            choices=["any", "ip", "arp", "revarp", "ipv4", "ipv6", "other"],
            required=False,
        ),
        frame_number=dict(type="int", required=False),
        frame_not=dict(type="bool", required=False),
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
                "icmp6",
                "other",
            ],
            required=False,
        ),
        protocol_number=dict(type="int", required=False),
        protocol_not=dict(type="bool", required=False),
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
            required=False,
        ),
        source_ipvalue=dict(type="str", required=False),
        source_ipmask=dict(type="str", required=False),
        source_iprange_from=dict(type="str", required=False),
        source_iprange_to=dict(type="str", required=False),
        source_ipmultiple=dict(type="list", elements="str", required=False),
        source_iplist_id=dict(type="int", required=False),
        source_ipnot=dict(type="bool", required=False),
        source_mactype=dict(
            type="str",
            choices=["any", "single", "mac-list", "multiple"],
            required=False,
        ),
        source_macvalue=dict(type="str", required=False),
        source_macmultiple=dict(type="list", elements="str", required=False),
        source_maclist_id=dict(type="int", required=False),
        source_macnot=dict(type="bool", required=False),
        source_port_type=dict(
            type="str",
            choices=["any", "multiple", "port-list"],
            required=False,
        ),
        source_port_multiple=dict(type="list", elements="str", required=False),
        source_port_list_id=dict(type="int", required=False),
        source_port_not=dict(type="bool", required=False),
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
            required=False,
        ),
        destination_ipvalue=dict(type="str", required=False),
        destination_ipmask=dict(type="str", required=False),
        destination_iprange_from=dict(type="str", required=False),
        destination_iprange_to=dict(type="str", required=False),
        destination_ipmultiple=dict(
            type="list", elements="str", required=False
        ),
        destination_iplist_id=dict(type="int", required=False),
        destination_ipnot=dict(type="bool", required=False),
        destination_mactype=dict(
            type="str",
            choices=["any", "single", "mac-list", "multiple"],
            required=False,
        ),
        destination_macvalue=dict(type="str", required=False),
        destination_macmultiple=dict(
            type="list", elements="str", required=False
        ),
        destination_maclist_id=dict(type="int", required=False),
        destination_macnot=dict(type="bool", required=False),
        destination_port_type=dict(
            type="str",
            choices=["any", "multiple", "port-list"],
            required=False,
        ),
        destination_port_multiple=dict(
            type="list", elements="str", required=False
        ),
        destination_port_list_id=dict(type="int", required=False),
        destination_port_not=dict(type="bool", elements="int", required=False),
        any_flags=dict(type="bool", required=False),
        log_disabled=dict(type="bool", required=False),
        include_packet_data=dict(type="bool", required=False),
        alert_enabled=dict(type="bool", required=False),
        context_id=dict(type="int", required=False),
        tcpflags=dict(
            type="list",
            elements="str",
            choices=["fin", "syn", "rst", "psh", "ack", "urg"],
            required=False,
        ),
        tcpnot=dict(type="bool", required=False),
        icmptype=dict(type="int", required=False),
        icmpcode=dict(type="int", required=False),
        icmpnot=dict(type="bool", required=False),
    )

    api_object = "/api/firewallrules"
    api_return = "firewallRules"

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))

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

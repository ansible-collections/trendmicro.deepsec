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
module: computers_config
short_description: Create a new firewall rule. 
description:
  - This module creates a new firewall rule under TrendMicro Deep Security.
version_added: "1.0.0"
options:
  
  
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

EXAMPLES = """
- name: Create/Config a new Computers Config
  trendmicro.deepsec.computers_config:
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
- name: Delete/Remove the existing Computers Config
  trendmicro.deepsec.computers_config:
    state: absent
    name: test_firewallrule config
"""

RETURN = """
updates:
  description: The set of commands that will be pushed to the remote device
  returned: always
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    check_if_config_exists,
    delete_config_with_id,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
)


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

    computer_settings_spec = {
        "log_inspection_setting_severity_clipping_agent_event_send_syslog_level_min" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connections_cleanup_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_verify_tcp_checksum_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_scan_cache_on_demand_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "application_control_setting_shared_ruleset_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_server_connection_lost_warning_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "application_control_setting_execution_enforcement_level" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_blocked_url_domains" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_syn_sent_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_self_protection_password" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_tcp_xmas_attack_duration" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_virtual_and_container_network_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "log_inspection_setting_syslog_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_debug_mode_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_virtual_and_container_network_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_file_hash_sha_256enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_fingerprint_probe_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_retain_num" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_paws_zero" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_connected_threat_defense_use_control_manager_suspicious_object_list_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_option_fragmented_ip_keep_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_6to_4bogons_addresses_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "log_inspection_setting_severity_clipping_agent_event_store_level_min" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_scan_cache_concurrency_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_syslog_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_tcp_paws_window_policy" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_tcp_xmas_attack_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "application_control_setting_ruleset_mode" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_global_server_use_proxy_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_local_server_allow_off_domain_global" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_combined_mode_protection_source" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_close_wait_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_scan_open_port_list_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_self_protection_password_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ack_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_cached_entries_stale_time" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_combined_mode_protection_source" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_events_send_interval" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_inactive_agent_cleanup_override_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_failure_response_engine_system" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_relay_state" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_evasive_retransmit_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "activity_monitoring_setting_indicator_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_option_fragmented_ip_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_zero_flags" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_global_server_use_proxy_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_nsx_security_tagging_prevent_mode_level" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_tcp_xmas_attack_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_udp_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_local_server_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_tcp_mss_limit" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_cold_start_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_established_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_identified_files_space_max_mbytes" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_allow_null_ip_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_notifications_suppress_popups_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_rst_fin_flags" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_disconnect_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_close_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_tunnel_depth_max_exceeded_action" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_tcp_null_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_smart_protection_anti_malware_global_server_proxy_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_filter_ipv_4tunnels" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_local_server_urls" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_one_packet_period" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_filter_ipv_6tunnels" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_congestion_flags" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_heartbeat_missed_alert_threshold" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_options_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connections_num_udp_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_auto_apply_recommendations_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_tunnel_depth_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_unknown_ssl_protocol_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_nsx_security_tagging_value" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_log_data_rule_first_match_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_logging_policy" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_troubleshooting_logging_level" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_virtual_appliance_on_demand_scan_cache_entries_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_combined_mode_protection_source" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_closing_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_paws" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_auto_apply_recommendations_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_fingerprint_probe_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_nsx_security_tagging_remove_on_clean_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_packet_length_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_teredo_anomalies_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_security_level" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv_6site_local_addresses_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "activity_monitoring_setting_activity_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_strict_terodo_port_check_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_blocked_url_keywords" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_syslog_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_failure_response_packet_sanity_check" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_network_engine_mode" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_size_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_malware_scan_multithreaded_processing_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_tcp_syn_fin_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ip_zero_payload_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_block_ipv_6agent_8and_earlier_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_option_fragmented_ip_packet_send_icmp_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_predictive_machine_learning_exceptions" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_events_per_second_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ssl_session_time" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_behavior_monitoring_scan_exclusion_list" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_global_server_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_one_packet_within_period_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_generate_connection_events_icmp_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_heartbeat_inactive_vm_offline_alert_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_web_reputation_global_server_proxy_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_nsx_security_tagging_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_fragmented_packets" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connections_num_icmp_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_split_handshake" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_combined_mode_protection_source" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_event_nodes_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_monitor_port_list_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "application_control_setting_syslog_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_out_no_connection" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_block_ipv_6agent_9and_later_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_virtual_appliance_optimization_scan_cache_entries_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_tcp_null_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ignore_status_code_1\n" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ignore_status_code_0\n" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ignore_status_code_2\n" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ssl_session_size" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_scan_cache_real_time_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_recommendation_ongoing_scans_interval" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_smart_protection_global_server_use_proxy_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_interface_limit_one_active_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_checksum" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv_6ext_type_0enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_scan_file_size_max_mbytes" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_generate_connection_events_tcp_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_file_hash_size_max_mbytes" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_cached_entries_life_time" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_smart_protection_global_server_proxy_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "log_inspection_setting_auto_apply_recommendations_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_connected_threat_defense_suspicious_file_ddan_submission_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_blocking_page_link" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_syslog_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_communications_direction" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_scan_cache_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_document_exploit_protection_rule_exceptions" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_syn_with_data" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_file_hash_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_fingerprint_probe_duration" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv_6bogons_addresses_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_boot_start_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connections_num_tcp_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_security_posture" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_interface_patterns" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_interface_isolation_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_virtual_appliance_real_time_scan_cache_entries_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_events_out_of_allowed_policy_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_evasive_retransmit" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_icmp_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_syslog_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connection_cleanup_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_local_server_allow_off_domain_global" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_tcp_syn_fin_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_error_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_allowed_urls" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_network_or_port_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_fin_wait_1timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_generate_connection_events_udp_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "activity_monitoring_setting_syslog_config_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_syn_rst_flags" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_spyware_approved_list" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_urgent_flags" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_nsx_security_tagging_detect_mode_level" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_option_fragmented_ip_unconcerned_mac_address_bypass_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_all_packet_data_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_syn_fin_flags" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_heartbeat_interval" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_fragment_size_min" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_server_connection_lost_warning_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_network_or_port_scan_duration" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_content_hash_algorithm" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_scan_state" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_config_package_exceeds_alert_max_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_environment_variable_overrides" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_fragment_offset_min" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_local_server_urls" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_syn_rcvd_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_cached_entries_num" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_force_allow_icmp_type_3code_4\n" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_tcp_null_scan_duration" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_smart_protection_global_server_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_realtime_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_last_ack_timeout" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_exclude_ip_list_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_self_protection_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv_6reserved_addresses_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_fin_no_connection" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_debug_packet_num_max" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_bypass_cisco_waas_connections_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_heartbeat_local_time_shift_alert_threshold" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_file_hash_md_5enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_network_or_port_scan_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_silent_tcp_connection_drop_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_block_same_src_dst_ip_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_force_allow_dhcp_dns" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_include_ip_list_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_options_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_tcp_syn_fin_scan_duration" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_security_block_untested_pages_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_allowed_url_domains" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_ignore_source_ip_list_id" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv_6fragments_lower_than_min_mtu_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_auto_assign_new_intrusion_prevention_rules_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_rst_no_connection" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_blocked_urls" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_combined_mode_network_group_protection_source" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_alerting_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_nsx_security_tagging_on_remediation_failure_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_cpu_usage_level" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_auto_update_anti_malware_engine_enabled" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_combined_mode_protection_source" : dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
    }

    interfaces_obj_spec = {
        "display_name": dict(type="str", required=False),
        "interface_type_id": dict(type="int", required=False),
    }

    interfaces_spec = {
        "interfaces": dict(type="list", elements="dict", options=interfaces_obj_spec)
    }

    azure_armvirtual_machine_summary_spec = {
        "cloud_provider": dict(type="str", required=False),
        "subscription_id": dict(type="str", required=False),
        "deployment_model": dict(type="str", required=False),
        "resource_group": dict(type="str", required=False),
        "state": dict(type="str", required=False),
        "location": dict(type="str", required=False),
        "type": dict(type="str", required=False),
        "operating_system": dict(type="str", required=False),
        "public_ipaddress": dict(type="str", required=False),
        "private_ipaddress": dict(type="str", required=False),
        "cloud_service": dict(type="str", required=False),
        "deployment_id": dict(type="str", required=False),
        "image_id": dict(type="str", required=False),
        "security_group": dict(type="str", required=False),
        "dnsname": dict(type="str", required=False)
    }

    azure_vmvirtual_machine_summary_spec = {
        "cloud_provider": dict(type="str", required=False),
        "subscription_id": dict(type="str", required=False),
        "operating_system": dict(type="str", required=False),
        "public_virtual_ipaddress": dict(type="str", required=False),
        "private_ipaddress": dict(type="str", required=False),
        "public_ipaddress": dict(type="str", required=False),
        "location": dict(type="str", required=False),
        "instance_id": dict(type="str", required=False),
        "image_id": dict(type="str", required=False),
        "cloud_service": dict(type="str", required=False),
        "deployment_id": dict(type="str", required=False),
        "type": dict(type="str", required=False),
        "state": dict(type="str", required=False),
        "dnsname": dict(type="str", required=False)
    }

    ec_2virtual_machine_summary_spec = {
        "cloud_provider": dict(type="str", required=False),
        "account_id": dict(type="str", required=False),
        "operating_system": dict(type="str", required=False),
        "private_ipaddress": dict(type="str", required=False),
        "public_ipaddress": dict(type="str", required=False),
        "availability_zone": dict(type="str", required=False),
        "instance_id": dict(type="str", required=False),
        "security_groups": dict(type="list", elements="str", required=False),
        "type": dict(type="str", required=False),
        "virtualization_type": dict(type="str", required=False),
        "state": dict(type="str", required=False),
        "metadata": dict(type="str", required=False),
        "dnsname": dict(type="str", required=False),
        "ami_id": dict(type="str", required=False),
    }

    no_connector_virtual_machine_summary_spec = {
        "account_id": dict(type="str", required=False),
        "directory_id": dict(type="str", required=False),
        "user_name": dict(type="str", required=False),
        "instance_id": dict(type="str", required=False),
        "region": dict(type="str", required=False),
    }

    vmware_vmvirtual_machine_summary_spec = {
        "operating_system": dict(type="str", required=False),
        "memory": dict(type="str", required=False),
        "vmware_tools": dict(type="str", required=False),
        "bios_uuid": dict(type="str", required=False),
        "state": dict(type="str", required=False),
        "notes": dict(type="list", elements="str", required=False),
        "cpu": dict(type="str", required=False),
        "ipaddress": dict(type="str", required=False),
        "dnsname": dict(type="str", required=False),
        "vcenter_uuid": dict(type="str", required=False),
        "nsxsecurity_groups": dict(type="list", elements="str", required=False)
    }

    vcloud_vmvirtual_machine_summary_spec = {
        "cloud_provider": dict(type="str", required=False),
        "operating_system": dict(type="str", required=False),
        "instance_id": dict(type="str", required=False),
        "type": dict(type="str", required=False),
        "state": dict(type="str", required=False),
        "ipaddress": dict(type="str", required=False),
        "dnsname": dict(type="str", required=False),
    }

    workspace_virtual_machine_summary_spec = {
        "cloud_provider": dict(type="str", required=False),
        "account_id": dict(type="str", required=False),
        "workspace_directory": dict(type="str", required=False),
        "user_name": dict(type="str", required=False),
        "workspace_id": dict(type="str", required=False),
        "bundle_id": dict(type="str", required=False),
        "workspace_hardware": dict(type="str", required=False),
        "state": dict(type="str", required=False),
        "metadata_ipaddress": dict(type="str", required=False),
    }

    gcp_virtual_machine_summary_spec = {
        "cloud_provider": dict(type="str", required=False),
        "state": dict(type="str", required=False),
        "operating_system": dict(type="str", required=False),
        "instance_id": dict(type="str", required=False),
        "private_ipaddress": dict(type="str", required=False),
        "public_ipaddress": dict(type="str", required=False),
        "zone": dict(type="str", required=False),
        "v_cpus": dict(type="int", required=False),
        "memory": dict(type="int", required=False),
        "network_tags": dict(type="list", elements="str", required=False),
    }

    anti_malware_spec = {
        "state": dict(type="str", choices=["inherited", "on", "off"], required=False),
        "module_status": dict(type="dict", required=False),
        "real_time_scan_configuration_id": dict(type="int", required=False),
        "real_time_scan_schedule_id": dict(type="int", required=False),
        "manual_scan_configuration_id": dict(type="int", required=False),
        "scheduled_scan_configuration_id": dict(type="int", required=False),
    }

    web_reputation_spec = {
        "state": dict(type="str", choices=["inherited", "on", "off"], required=False),
        "module_status": dict(type="dict", required=False)
    }

    activity_monitoring_spec = {
        "state": dict(type="str", choices=["inherited", "on", "off"], required=False),
        "module_status": dict(type="dict", required=False)
    }

    firewall_spec = {
        "state": dict(type="str", choices=["inherited", "on", "off"], required=False),
        "module_status": dict(type="dict", required=False),
        "global_stateful_configuration_id": dict(type="int", required=False),
        "stateful_configuration_assignments": dict(type="dict", required=False),
        "rule_ids": dict(type="list", elements="int", required=False),
    }

    intrusion_prevention_spec = {
        "state": dict(type="str", choices=["inherited", "prevent", "detect", "off"], required=False),
        "module_status": dict(type="dict", required=False),
        "rule_ids": dict(type="list", elements="int", required=False),
    }

    integrity_monitoring_spec = {
        "state": dict(type="str", choices=["inherited", "real-time", "on", "off"], required=False),
        "module_status": dict(type="dict", required=False),
        "rule_ids": dict(type="list", elements="int", required=False),
    }

    log_inspection_spec = {
        "state": dict(type="str", choices=["inherited", "on", "off"], required=False),
        "module_status": dict(type="dict", required=False),
        "rule_ids": dict(type="list", elements="int", required=False),
    }

    application_control_spec = {
        "state": dict(type="str", choices=["inherited", "on", "off"], required=False),
        "module_status": dict(type="dict", required=False),
        "block_unrecognized": : dict(type="bool", required=False),
        "ruleset_id": dict(type="int", required=False),
        "maintenance_mode_status": dict(type="str", choices=["start-requested", "on", "off", "stop-requested", "reset-duration-requested"], required=False),
        "maintenance_mode_duration": dict(type="int", required=False),
    }

    esxsummary_spec = {
        "tpmenabled": dict(type="bool", required=False),
        "tpmalerts_enabled": dict(type="bool", required=False),
        "tpmhas_data": dict(type="bool", required=False),
        "tpmlast_checked": dict(type="int", required=False),
    }

    sap_spec = {
        "state": dict(type="str", choices=["inherited", "on", "off"], required=False),
        "module_status": dict(type="dict", required=False)
    }


    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        host_name=dict(required=True, type="str"),
        display_name=dict(required=False, type="str"),
        description=dict(type="str", required=False),
        group_id=dict(type="int", required=False),
        policy_id=dict(type="int", required=False),
        asset_importance_id=dict(type="int", required=False),
        relay_list_id=dict(type="int", required=False),
        computer_status=dict(type="dict", required=False),
        tasks=dict(type="dict", required=False),
        security_updates=dict(type="dict", required=False),
        computer_settings=dict(type="dict", options=computer_settings_spec)
        interfaces=dict(type="dict", options=interfaces_spec)
        azure_armvirtual_machine_summary=dict(type="dict", options=azure_armvirtual_machine_summary_spec)
        azure_vmvirtual_machine_summary=dict(type="dict", options=azure_vmvirtual_machine_summary_spec)
        ec_2virtual_machine_summary=dict(type="dict", options=ec_2virtual_machine_summary_spec)
        no_connector_virtual_machine_summary=dict(type="dict", options=no_connector_virtual_machine_summary_spec)
        vmware_vmvirtual_machine_summary=dict(type="dict", options=vmware_vmvirtual_machine_summary_spec)
        vcloud_vmvirtual_machine_summary=dict(type="dict", options=vcloud_vmvirtual_machine_summary_spec)
        workspace_virtual_machine_summary=dict(type="dict", options=workspace_virtual_machine_summary_spec)
        gcp_virtual_machine_summary=dict(type="dict", options=gcp_virtual_machine_summary_spec)
        anti_malware=dict(type="dict", options=anti_malware_spec)
        web_reputation=dict(type="dict", options=web_reputation_spec)
        activity_monitoring=dict(type="dict", options=activity_monitoring_spec)
        firewall=dict(type="dict", options=firewall_spec)
        intrusion_prevention=dict(type="dict", options=intrusion_prevention_spec)
        integrity_monitoring=dict(type="dict", options=integrity_monitoring_spec)
        log_inspection=dict(type="dict", options=log_inspection_spec)
        application_control=dict(type="dict", options=application_control_spec)
        sap=dict(type="dict", options=sap_spec)
        esxsummary=dict(type="dict", options=esxsummary_spec)
    )

    api_object = "/api/computers"
    api_return = "computers"

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))

    search_existing_computers = check_if_config_exists(
        deepsec_request, want["name"], api_object.split("/")[2], api_return
    )

    if (
        "ID" in search_existing_computers
        and module.params["state"] == "absent"
    ):
        delete_config_with_id(
            module,
            deepsec_request,
            api_object.split("/")[2],
            search_existing_computers["ID"],
            api_return,
        )
    elif (
        "ID" not in search_existing_computers
        and module.params["state"] == "absent"
    ):
        module.exit_json(changed=False)
    else:
        computers = deepsec_request.post(
            "{0}".format(api_object), data=want
        )
        if "ID" in search_existing_computers:
            module.exit_json(
                computers=search_existing_computers, changed=False
            )
        elif computers.get("message"):
            module.fail_json(msg=computers["message"])
        else:
            module.exit_json(computers=computers, changed=True)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

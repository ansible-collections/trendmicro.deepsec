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
module: policies_config
short_description: Create a new policy under TrendMicro Deep Security Policy
description:
  - This module creates a new policy under TrendMicro Deep Security
version_added: "1.0.0"
options:
  id:
    description:
      - Obtain only information of the Rule with provided ID
    required: false
    type: int

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


def common_populate_logic(param_val, param_dict=None, list_param_dict=None):
    """ The fn computes and expand the param_val to it's actual val
    :param param_val: the objects from which the configuration should be read
    :param param_dict: the ansible specific param to actual val conversion dict
    :param param_dict: the ansible specific param to actual val conversion dict when
    value has dict as its value
    :rtype: A dict
    :returns: dict with actual keys what's expected form TM platform side for API request
    """
    temp_obj = {}
    if list_param_dict:
        for each in param_val:
            if param_dict.get(each):
                key = param_dict[each]
                if key == "statefulConfigurationAssignments":
                    temp_obj[key] = []
                    for every in param_val[each]:
                        temp_list_obj = {}
                        for every_list_obj in every:
                            if list_param_dict.get(every_list_obj):
                                stateful_key = list_param_dict[every_list_obj]
                            temp_list_obj[stateful_key] = every[every_list_obj]
                        temp_obj[key].append(temp_list_obj)
                else:
                    temp_obj[key] = param_val[each]
        temp_obj["state"] = param_val.get("state")
    elif param_val.get("state"):
        for each in param_val:
            if param_dict.get(each):
                key = param_dict[each]
                temp_obj[key] = param_val[each]
        temp_obj["state"] = param_val.get("state")
    else:
        for each in param_val.keys():
            temp_obj[param_dict[each]] = param_val[each]

    return temp_obj


def policy_settings_fn(module_params):
    policy_settings_dict = {
        "log_inspection_setting_severity_clipping_agent_event_send_syslog_level_min": "logInspectionSettingSeverityClippingAgentEventSendSyslogLevelMin",
        "firewall_setting_engine_option_connections_cleanup_max": "firewallSettingEngineOptionConnectionsCleanupMax",
        "firewall_setting_engine_option_verify_tcp_checksum_enabled": "firewallSettingEngineOptionVerifyTcpChecksumEnabled",
        "anti_malware_setting_scan_cache_on_demand_config_id": "antiMalwareSettingScanCacheOnDemandConfigId",
        "application_control_setting_shared_ruleset_id": "applicationControlSettingSharedRulesetId",
        "web_reputation_setting_smart_protection_server_connection_lost_warning_enabled": "webReputationSettingSmartProtectionServerConnectionLostWarningEnabled",
        "application_control_setting_execution_enforcement_level": "applicationControlSettingExecutionEnforcementLevel",
        "web_reputation_setting_blocked_url_domains": "webReputationSettingBlockedUrlDomains",
        "firewall_setting_engine_option_syn_sent_timeout": "firewallSettingEngineOptionSynSentTimeout",
        "platform_setting_agent_self_protection_password": "platformSettingAgentSelfProtectionPassword",
        "firewall_setting_reconnaissance_block_tcp_xmas_attack_duration": "firewallSettingReconnaissanceBlockTcpXmasAttackDuration",
        "intrusion_prevention_setting_virtual_and_container_network_scan_enabled": "intrusionPreventionSettingVirtualAndContainerNetworkScanEnabled",
        "log_inspection_setting_syslog_config_id": "logInspectionSettingSyslogConfigId",
        "firewall_setting_engine_option_debug_mode_enabled": "firewallSettingEngineOptionDebugModeEnabled",
        "firewall_setting_virtual_and_container_network_scan_enabled": "firewallSettingVirtualAndContainerNetworkScanEnabled",
        "anti_malware_setting_file_hash_sha256_enabled": "antiMalwareSettingFileHashSha256Enabled",
        "firewall_setting_reconnaissance_notify_fingerprint_probe_enabled": "firewallSettingReconnaissanceNotifyFingerprintProbeEnabled",
        "firewall_setting_event_log_file_retain_num": "firewallSettingEventLogFileRetainNum",
        "firewall_setting_anti_evasion_check_tcp_paws_zero": "firewallSettingAntiEvasionCheckTcpPawsZero",
        "anti_malware_setting_connected_threat_defense_use_control_manager_suspicious_object_list_enabled": "antiMalwareSettingConnectedThreatDefenseUseControlManagerSuspiciousObjectListEnabled",
        "intrusion_prevention_setting_engine_option_fragmented_ip_keep_max": "intrusionPreventionSettingEngineOptionFragmentedIpKeepMax",
        "firewall_setting_engine_option_drop6_to_4bogons_addresses_enabled": "firewallSettingEngineOptionDrop6To4BogonsAddressesEnabled",
        "log_inspection_setting_severity_clipping_agent_event_store_level_min": "logInspectionSettingSeverityClippingAgentEventStoreLevelMin",
        "platform_setting_scan_cache_concurrency_max": "platformSettingScanCacheConcurrencyMax",
        "anti_malware_setting_syslog_config_id": "antiMalwareSettingSyslogConfigId",
        "firewall_setting_anti_evasion_tcp_paws_window_policy": "firewallSettingAntiEvasionTcpPawsWindowPolicy",
        "firewall_setting_reconnaissance_detect_tcp_xmas_attack_enabled": "firewallSettingReconnaissanceDetectTcpXmasAttackEnabled",
        "application_control_setting_ruleset_mode": "applicationControlSettingRulesetMode",
        "anti_malware_setting_smart_protection_global_server_use_proxy_enabled": "antiMalwareSettingSmartProtectionGlobalServerUseProxyEnabled",
        "web_reputation_setting_smart_protection_local_server_allow_off_domain_global": "webReputationSettingSmartProtectionLocalServerAllowOffDomainGlobal",
        "integrity_monitoring_setting_combined_mode_protection_source": "integrityMonitoringSettingCombinedModeProtectionSource",
        "firewall_setting_engine_option_close_wait_timeout": "firewallSettingEngineOptionCloseWaitTimeout",
        "platform_setting_scan_open_port_list_id": "platformSettingScanOpenPortListId",
        "platform_setting_agent_self_protection_password_enabled": "platformSettingAgentSelfProtectionPasswordEnabled",
        "firewall_setting_engine_option_ack_timeout": "firewallSettingEngineOptionAckTimeout",
        "firewall_setting_event_log_file_cached_entries_stale_time": "firewallSettingEventLogFileCachedEntriesStaleTime",
        "firewall_setting_combined_mode_protection_source": "firewallSettingCombinedModeProtectionSource",
        "platform_setting_agent_events_send_interval": "platformSettingAgentEventsSendInterval",
        "platform_setting_inactive_agent_cleanup_override_enabled": "platformSettingInactiveAgentCleanupOverrideEnabled",
        "firewall_setting_failure_response_engine_system": "firewallSettingFailureResponseEngineSystem",
        "platform_setting_relay_state": "platformSettingRelayState",
        "firewall_setting_engine_option_drop_evasive_retransmit_enabled": "firewallSettingEngineOptionDropEvasiveRetransmitEnabled",
        "activity_monitoring_setting_indicator_enabled": "activityMonitoringSettingIndicatorEnabled",
        "intrusion_prevention_setting_engine_option_fragmented_ip_timeout": "intrusionPreventionSettingEngineOptionFragmentedIpTimeout",
        "firewall_setting_anti_evasion_check_tcp_zero_flags": "firewallSettingAntiEvasionCheckTcpZeroFlags",
        "web_reputation_setting_smart_protection_global_server_use_proxy_enabled": "webReputationSettingSmartProtectionGlobalServerUseProxyEnabled",
        "intrusion_prevention_setting_nsx_security_tagging_prevent_mode_level": "intrusionPreventionSettingNsxSecurityTaggingPreventModeLevel",
        "firewall_setting_reconnaissance_notify_tcp_xmas_attack_enabled": "firewallSettingReconnaissanceNotifyTcpXmasAttackEnabled",
        "firewall_setting_engine_option_udp_timeout": "firewallSettingEngineOptionUdpTimeout",
        "web_reputation_setting_smart_protection_local_server_enabled": "webReputationSettingSmartProtectionLocalServerEnabled",
        "firewall_setting_engine_option_tcp_mss_limit": "firewallSettingEngineOptionTcpMssLimit",
        "firewall_setting_engine_option_cold_start_timeout": "firewallSettingEngineOptionColdStartTimeout",
        "firewall_setting_engine_option_established_timeout": "firewallSettingEngineOptionEstablishedTimeout",
        "anti_malware_setting_identified_files_space_max_mbytes": "antiMalwareSettingIdentifiedFilesSpaceMaxMbytes",
        "firewall_setting_engine_option_allow_null_ip_enabled": "firewallSettingEngineOptionAllowNullIpEnabled",
        "platform_setting_notifications_suppress_popups_enabled": "platformSettingNotificationsSuppressPopupsEnabled",
        "firewall_setting_anti_evasion_check_tcp_rst_fin_flags": "firewallSettingAntiEvasionCheckTcpRstFinFlags",
        "firewall_setting_engine_option_disconnect_timeout": "firewallSettingEngineOptionDisconnectTimeout",
        "firewall_setting_engine_option_close_timeout": "firewallSettingEngineOptionCloseTimeout",
        "firewall_setting_engine_option_tunnel_depth_max_exceeded_action": "firewallSettingEngineOptionTunnelDepthMaxExceededAction",
        "firewall_setting_reconnaissance_detect_tcp_null_scan_enabled": "firewallSettingReconnaissanceDetectTcpNullScanEnabled",
        "platform_setting_smart_protection_anti_malware_global_server_proxy_id": "platformSettingSmartProtectionAntiMalwareGlobalServerProxyId",
        "firewall_setting_engine_option_filter_ipv4_tunnels": "firewallSettingEngineOptionFilterIpv4Tunnels",
        "web_reputation_setting_smart_protection_local_server_urls": "webReputationSettingSmartProtectionLocalServerUrls",
        "firewall_setting_engine_option_log_one_packet_period": "firewallSettingEngineOptionLogOnePacketPeriod",
        "firewall_setting_engine_option_filter_ipv6_tunnels": "firewallSettingEngineOptionFilterIpv6Tunnels",
        "firewall_setting_anti_evasion_check_tcp_congestion_flags": "firewallSettingAntiEvasionCheckTcpCongestionFlags",
        "platform_setting_heartbeat_missed_alert_threshold": "platformSettingHeartbeatMissedAlertThreshold",
        "intrusion_prevention_setting_engine_options_enabled": "intrusionPreventionSettingEngineOptionsEnabled",
        "firewall_setting_engine_option_connections_num_udp_max": "firewallSettingEngineOptionConnectionsNumUdpMax",
        "integrity_monitoring_setting_auto_apply_recommendations_enabled": "integrityMonitoringSettingAutoApplyRecommendationsEnabled",
        "firewall_setting_engine_option_tunnel_depth_max": "firewallSettingEngineOptionTunnelDepthMax",
        "firewall_setting_engine_option_drop_unknown_ssl_protocol_enabled": "firewallSettingEngineOptionDropUnknownSslProtocolEnabled",
        "anti_malware_setting_nsx_security_tagging_value": "antiMalwareSettingNsxSecurityTaggingValue",
        "intrusion_prevention_setting_log_data_rule_first_match_enabled": "intrusionPreventionSettingLogDataRuleFirstMatchEnabled",
        "firewall_setting_engine_option_logging_policy": "firewallSettingEngineOptionLoggingPolicy",
        "platform_setting_troubleshooting_logging_level": "platformSettingTroubleshootingLoggingLevel",
        "anti_malware_setting_virtual_appliance_on_demand_scan_cache_entries_max": "antiMalwareSettingVirtualApplianceOnDemandScanCacheEntriesMax",
        "web_reputation_setting_combined_mode_protection_source": "webReputationSettingCombinedModeProtectionSource",
        "firewall_setting_engine_option_closing_timeout": "firewallSettingEngineOptionClosingTimeout",
        "firewall_setting_anti_evasion_check_paws": "firewallSettingAntiEvasionCheckPaws",
        "intrusion_prevention_setting_auto_apply_recommendations_enabled": "intrusionPreventionSettingAutoApplyRecommendationsEnabled",
        "firewall_setting_reconnaissance_detect_fingerprint_probe_enabled": "firewallSettingReconnaissanceDetectFingerprintProbeEnabled",
        "anti_malware_setting_nsx_security_tagging_remove_on_clean_scan_enabled": "antiMalwareSettingNsxSecurityTaggingRemoveOnCleanScanEnabled",
        "firewall_setting_engine_option_log_packet_length_max": "firewallSettingEngineOptionLogPacketLengthMax",
        "firewall_setting_engine_option_drop_teredo_anomalies_enabled": "firewallSettingEngineOptionDropTeredoAnomaliesEnabled",
        "web_reputation_setting_security_level": "webReputationSettingSecurityLevel",
        "firewall_setting_engine_option_drop_ipv6_site_local_addresses_enabled": "firewallSettingEngineOptionDropIpv6SiteLocalAddressesEnabled",
        "activity_monitoring_setting_activity_enabled": "activityMonitoringSettingActivityEnabled",
        "firewall_setting_engine_option_strict_terodo_port_check_enabled": "firewallSettingEngineOptionStrictTerodoPortCheckEnabled",
        "web_reputation_setting_blocked_url_keywords": "webReputationSettingBlockedUrlKeywords",
        "web_reputation_setting_syslog_config_id": "webReputationSettingSyslogConfigId",
        "firewall_setting_failure_response_packet_sanity_check": "firewallSettingFailureResponsePacketSanityCheck",
        "firewall_setting_network_engine_mode": "firewallSettingNetworkEngineMode",
        "firewall_setting_event_log_file_size_max": "firewallSettingEventLogFileSizeMax",
        "anti_malware_setting_malware_scan_multithreaded_processing_enabled": "antiMalwareSettingMalwareScanMultithreadedProcessingEnabled",
        "firewall_setting_reconnaissance_detect_tcp_syn_fin_scan_enabled": "firewallSettingReconnaissanceDetectTcpSynFinScanEnabled",
        "firewall_setting_engine_option_drop_ip_zero_payload_enabled": "firewallSettingEngineOptionDropIpZeroPayloadEnabled",
        "firewall_setting_engine_option_block_ipv6_agent8_and_earlier_enabled": "firewallSettingEngineOptionBlockIpv6Agent8AndEarlierEnabled",
        "intrusion_prevention_setting_engine_option_fragmented_ip_packet_send_icmp_enabled": "intrusionPreventionSettingEngineOptionFragmentedIpPacketSendIcmpEnabled",
        "anti_malware_setting_predictive_machine_learning_exceptions": "antiMalwareSettingPredictiveMachineLearningExceptions",
        "firewall_setting_engine_option_log_events_per_second_max": "firewallSettingEngineOptionLogEventsPerSecondMax",
        "firewall_setting_engine_option_ssl_session_time": "firewallSettingEngineOptionSslSessionTime",
        "anti_malware_setting_behavior_monitoring_scan_exclusion_list": "antiMalwareSettingBehaviorMonitoringScanExclusionList",
        "anti_malware_setting_smart_protection_global_server_enabled": "antiMalwareSettingSmartProtectionGlobalServerEnabled",
        "firewall_setting_engine_option_log_one_packet_within_period_enabled": "firewallSettingEngineOptionLogOnePacketWithinPeriodEnabled",
        "firewall_setting_engine_option_generate_connection_events_icmp_enabled": "firewallSettingEngineOptionGenerateConnectionEventsIcmpEnabled",
        "platform_setting_heartbeat_inactive_vm_offline_alert_enabled": "platformSettingHeartbeatInactiveVmOfflineAlertEnabled",
        "web_reputation_setting_smart_protection_web_reputation_global_server_proxy_id": "webReputationSettingSmartProtectionWebReputationGlobalServerProxyId",
        "anti_malware_setting_nsx_security_tagging_enabled": "antiMalwareSettingNsxSecurityTaggingEnabled",
        "firewall_setting_anti_evasion_check_fragmented_packets": "firewallSettingAntiEvasionCheckFragmentedPackets",
        "firewall_setting_engine_option_connections_num_icmp_max": "firewallSettingEngineOptionConnectionsNumIcmpMax",
        "firewall_setting_anti_evasion_check_tcp_split_handshake": "firewallSettingAntiEvasionCheckTcpSplitHandshake",
        "anti_malware_setting_combined_mode_protection_source": "antiMalwareSettingCombinedModeProtectionSource",
        "firewall_setting_engine_option_event_nodes_max": "firewallSettingEngineOptionEventNodesMax",
        "web_reputation_setting_monitor_port_list_id": "webReputationSettingMonitorPortListId",
        "application_control_setting_syslog_config_id": "applicationControlSettingSyslogConfigId",
        "firewall_setting_anti_evasion_check_out_no_connection": "firewallSettingAntiEvasionCheckOutNoConnection",
        "firewall_setting_engine_option_block_ipv6_agent9_and_later_enabled": "firewallSettingEngineOptionBlockIpv6Agent9AndLaterEnabled",
        "integrity_monitoring_setting_virtual_appliance_optimization_scan_cache_entries_max": "integrityMonitoringSettingVirtualApplianceOptimizationScanCacheEntriesMax",
        "firewall_setting_reconnaissance_notify_tcp_null_scan_enabled": "firewallSettingReconnaissanceNotifyTcpNullScanEnabled",
        "firewall_setting_engine_option_ignore_status_code1": "firewallSettingEngineOptionIgnoreStatusCode1",
        "firewall_setting_engine_option_ignore_status_code0": "firewallSettingEngineOptionIgnoreStatusCode0",
        "firewall_setting_engine_option_ignore_status_code2": "firewallSettingEngineOptionIgnoreStatusCode2",
        "firewall_setting_engine_option_ssl_session_size": "firewallSettingEngineOptionSslSessionSize",
        "anti_malware_setting_scan_cache_real_time_config_id": "antiMalwareSettingScanCacheRealTimeConfigId",
        "platform_setting_recommendation_ongoing_scans_interval": "platformSettingRecommendationOngoingScansInterval",
        "platform_setting_smart_protection_global_server_use_proxy_enabled": "platformSettingSmartProtectionGlobalServerUseProxyEnabled",
        "firewall_setting_interface_limit_one_active_enabled": "firewallSettingInterfaceLimitOneActiveEnabled",
        "firewall_setting_anti_evasion_check_tcp_checksum": "firewallSettingAntiEvasionCheckTcpChecksum",
        "firewall_setting_engine_option_drop_ipv6_next_type0_enabled": "firewallSettingEngineOptionDropIpv6ExtType0Enabled",
        "anti_malware_setting_scan_file_size_max_mbytes": "antiMalwareSettingScanFileSizeMaxMbytes",
        "firewall_setting_engine_option_generate_connection_events_tcp_enabled": "firewallSettingEngineOptionGenerateConnectionEventsTcpEnabled",
        "anti_malware_setting_file_hash_size_max_mbytes": "antiMalwareSettingFileHashSizeMaxMbytes",
        "firewall_setting_event_log_file_cached_entries_life_time": "firewallSettingEventLogFileCachedEntriesLifeTime",
        "platform_setting_smart_protection_global_server_proxy_id": "platformSettingSmartProtectionGlobalServerProxyId",
        "log_inspection_setting_auto_apply_recommendations_enabled": "logInspectionSettingAutoApplyRecommendationsEnabled",
        "anti_malware_setting_connected_threat_defense_suspicious_file_ddan_submission_enabled": "antiMalwareSettingConnectedThreatDefenseSuspiciousFileDdanSubmissionEnabled",
        "web_reputation_setting_blocking_page_link": "webReputationSettingBlockingPageLink",
        "firewall_setting_syslog_config_id": "firewallSettingSyslogConfigId",
        "platform_setting_agent_communications_direction": "platformSettingAgentCommunicationsDirection",
        "integrity_monitoring_setting_scan_cache_config_id": "integrityMonitoringSettingScanCacheConfigId",
        "anti_malware_setting_document_exploit_protection_rule_exceptions": "antiMalwareSettingDocumentExploitProtectionRuleExceptions",
        "firewall_setting_anti_evasion_check_tcp_syn_with_data": "firewallSettingAntiEvasionCheckTcpSynWithData",
        "anti_malware_setting_file_hash_enabled": "antiMalwareSettingFileHashEnabled",
        "firewall_setting_reconnaissance_block_fingerprint_probe_duration": "firewallSettingReconnaissanceBlockFingerprintProbeDuration",
        "firewall_setting_engine_option_drop_ipv6_bogons_addresses_enabled": "firewallSettingEngineOptionDropIpv6BogonsAddressesEnabled",
        "firewall_setting_engine_option_boot_start_timeout": "firewallSettingEngineOptionBootStartTimeout",
        "firewall_setting_engine_option_connections_num_tcp_max": "firewallSettingEngineOptionConnectionsNumTcpMax",
        "firewall_setting_anti_evasion_security_posture": "firewallSettingAntiEvasionSecurityPosture",
        "firewall_setting_interface_patterns": "firewallSettingInterfacePatterns",
        "firewall_setting_interface_isolation_enabled": "firewallSettingInterfaceIsolationEnabled",
        "anti_malware_setting_virtual_appliance_real_time_scan_cache_entries_max": "antiMalwareSettingVirtualApplianceRealTimeScanCacheEntriesMax",
        "firewall_setting_events_out_of_allowed_policy_enabled": "firewallSettingEventsOutOfAllowedPolicyEnabled",
        "firewall_setting_anti_evasion_check_evasive_retransmit": "firewallSettingAntiEvasionCheckEvasiveRetransmit",
        "firewall_setting_engine_option_icmp_timeout": "firewallSettingEngineOptionIcmpTimeout",
        "integrity_monitoring_setting_syslog_config_id": "integrityMonitoringSettingSyslogConfigId",
        "firewall_setting_engine_option_connection_cleanup_timeout": "firewallSettingEngineOptionConnectionCleanupTimeout",
        "anti_malware_setting_smart_protection_local_server_allow_off_domain_global": "antiMalwareSettingSmartProtectionLocalServerAllowOffDomainGlobal",
        "firewall_setting_reconnaissance_notify_tcp_syn_fin_scan_enabled": "firewallSettingReconnaissanceNotifyTcpSynFinScanEnabled",
        "firewall_setting_engine_option_error_timeout": "firewallSettingEngineOptionErrorTimeout",
        "web_reputation_setting_allowed_urls": "webReputationSettingAllowedUrls",
        "firewall_setting_reconnaissance_notify_network_or_port_scan_enabled": "firewallSettingReconnaissanceNotifyNetworkOrPortScanEnabled",
        "firewall_setting_engine_option_fin_wait_1timeout": "firewallSettingEngineOptionFinWait1Timeout",
        "firewall_setting_engine_option_generate_connection_events_udp_enabled": "firewallSettingEngineOptionGenerateConnectionEventsUdpEnabled",
        "activity_monitoring_setting_syslog_config_id": "activityMonitoringSettingSyslogConfigId",
        "firewall_setting_anti_evasion_check_tcp_syn_rst_flags": "firewallSettingAntiEvasionCheckTcpSynRstFlags",
        "anti_malware_setting_spyware_approved_list": "antiMalwareSettingSpywareApprovedList",
        "firewall_setting_anti_evasion_check_tcp_urgent_flags": "firewallSettingAntiEvasionCheckTcpUrgentFlags",
        "intrusion_prevention_setting_nsx_security_tagging_detect_mode_level": "intrusionPreventionSettingNsxSecurityTaggingDetectModeLevel",
        "intrusion_prevention_setting_engine_option_fragmented_ip_unconcerned_mac_address_bypass_enabled": "intrusionPreventionSettingEngineOptionFragmentedIpUnconcernedMacAddressBypassEnabled",
        "firewall_setting_engine_option_log_all_packet_data_enabled": "firewallSettingEngineOptionLogAllPacketDataEnabled",
        "firewall_setting_anti_evasion_check_tcp_syn_fin_flags": "firewallSettingAntiEvasionCheckTcpSynFinFlags",
        "platform_setting_heartbeat_interval": "platformSettingHeartbeatInterval",
        "firewall_setting_engine_option_fragment_size_min": "firewallSettingEngineOptionFragmentSizeMin",
        "anti_malware_setting_smart_protection_server_connection_lost_warning_enabled": "antiMalwareSettingSmartProtectionServerConnectionLostWarningEnabled",
        "firewall_setting_reconnaissance_block_network_or_port_scan_duration": "firewallSettingReconnaissanceBlockNetworkOrPortScanDuration",
        "integrity_monitoring_setting_content_hash_algorithm": "integrityMonitoringSettingContentHashAlgorithm",
        "anti_malware_setting_smart_scan_state": "antiMalwareSettingSmartScanState",
        "firewall_setting_config_package_exceeds_alert_max_enabled": "firewallSettingConfigPackageExceedsAlertMaxEnabled",
        "platform_setting_environment_variable_overrides": "platformSettingEnvironmentVariableOverrides",
        "firewall_setting_engine_option_fragment_offset_min": "firewallSettingEngineOptionFragmentOffsetMin",
        "anti_malware_setting_smart_protection_local_server_urls": "antiMalwareSettingSmartProtectionLocalServerUrls",
        "firewall_setting_engine_option_syn_rcvd_timeout": "firewallSettingEngineOptionSynRcvdTimeout",
        "firewall_setting_event_log_file_cached_entries_num": "firewallSettingEventLogFileCachedEntriesNum",
        "firewall_setting_engine_option_force_allow_icmp_type3_code4": "firewallSettingEngineOptionForceAllowIcmpType3Code4",
        "firewall_setting_reconnaissance_block_tcp_null_scan_duration": "firewallSettingReconnaissanceBlockTcpNullScanDuration",
        "platform_setting_smart_protection_global_server_enabled": "platformSettingSmartProtectionGlobalServerEnabled",
        "integrity_monitoring_setting_realtime_enabled": "integrityMonitoringSettingRealtimeEnabled",
        "firewall_setting_engine_option_last_ack_timeout": "firewallSettingEngineOptionLastAckTimeout",
        "firewall_setting_reconnaissance_exclude_ip_list_id": "firewallSettingReconnaissanceExcludeIpListId",
        "platform_setting_agent_self_protection_enabled": "platformSettingAgentSelfProtectionEnabled",
        "firewall_setting_engine_option_drop_ipv6_reserved_addresses_enabled": "firewallSettingEngineOptionDropIpv6ReservedAddressesEnabled",
        "firewall_setting_anti_evasion_check_fin_no_connection": "firewallSettingAntiEvasionCheckFinNoConnection",
        "firewall_setting_engine_option_debug_packet_num_max": "firewallSettingEngineOptionDebugPacketNumMax",
        "firewall_setting_engine_option_bypass_cisco_waas_connections_enabled": "firewallSettingEngineOptionBypassCiscoWaasConnectionsEnabled",
        "firewall_setting_reconnaissance_enabled": "firewallSettingReconnaissanceEnabled",
        "platform_setting_heartbeat_local_time_shift_alert_threshold": "platformSettingHeartbeatLocalTimeShiftAlertThreshold",
        "anti_malware_setting_file_hash_md5_enabled": "antiMalwareSettingFileHashMd5Enabled",
        "firewall_setting_reconnaissance_detect_network_or_port_scan_enabled": "firewallSettingReconnaissanceDetectNetworkOrPortScanEnabled",
        "firewall_setting_engine_option_silent_tcp_connection_drop_enabled": "firewallSettingEngineOptionSilentTcpConnectionDropEnabled",
        "firewall_setting_engine_option_block_same_src_dst_ip_enabled": "firewallSettingEngineOptionBlockSameSrcDstIpEnabled",
        "firewall_setting_engine_option_force_allow_dhcp_dns": "firewallSettingEngineOptionForceAllowDhcpDns",
        "firewall_setting_reconnaissance_include_ip_list_id": "firewallSettingReconnaissanceIncludeIpListId",
        "firewall_setting_engine_options_enabled": "firewallSettingEngineOptionsEnabled",
        "firewall_setting_reconnaissance_block_tcp_syn_fin_scan_duration": "firewallSettingReconnaissanceBlockTcpSynFinScanDuration",
        "web_reputation_setting_security_block_untested_pages_enabled": "webReputationSettingSecurityBlockUntestedPagesEnabled",
        "web_reputation_setting_allowed_url_domains": "webReputationSettingAllowedUrlDomains",
        "firewall_setting_event_log_file_ignore_source_ip_list_id": "firewallSettingEventLogFileIgnoreSourceIpListId",
        "firewall_setting_engine_option_drop_ipv6_fragments_lower_than_min_mtu_enabled": "firewallSettingEngineOptionDropIpv6FragmentsLowerThanMinMtuEnabled",
        "platform_setting_auto_assign_new_intrusion_prevention_rules_enabled": "platformSettingAutoAssignNewIntrusionPreventionRulesEnabled",
        "firewall_setting_anti_evasion_check_rst_no_connection": "firewallSettingAntiEvasionCheckRstNoConnection",
        "web_reputation_setting_blocked_urls": "webReputationSettingBlockedUrls",
        "platform_setting_combined_mode_network_group_protection_source": "platformSettingCombinedModeNetworkGroupProtectionSource",
        "web_reputation_setting_alerting_enabled": "webReputationSettingAlertingEnabled",
        "anti_malware_setting_nsx_security_tagging_on_remediation_failure_enabled": "antiMalwareSettingNsxSecurityTaggingOnRemediationFailureEnabled",
        "integrity_monitoring_setting_cpu_usage_level": "integrityMonitoringSettingCpuUsageLevel",
        "platform_setting_auto_update_anti_malware_engine_enabled": "platformSettingAutoUpdateAntiMalwareEngineEnabled",
    }

    policy_settings_val = module_params["policy_settings"]
    return common_populate_logic(policy_settings_val, policy_settings_dict)


def interface_type_fn(module_params):
    interface_obj = {}
    interface_obj["interfaceTypes"] = []
    temp_interface_obj = module_params.get("interface_types")
    for each in temp_interface_obj:
        temp = {}
        temp["name"] = each.get("name")
        temp["description"] = each.get("description")
        temp["matches"] = each.get("matches")
        interface_obj["interfaceTypes"].append(temp)

    return interface_obj


def anti_malware_fn(module_params):
    anti_malware_dict = {
        "real_time_scan_configuration_id": "realTimeScanConfigurationID",
        "real_time_scan_schedule_id": "realTimeScanScheduleID",
        "manual_scan_configuration_id": "manualScanConfigurationID",
        "scheduled_scan_configuration_id": "scheduledScanConfigurationID",
    }
    anti_malware_val = module_params.get("anti_malware")
    return common_populate_logic(anti_malware_val, anti_malware_dict)


def web_reputation_fn(module_params):
    temp_obj = {}
    web_reputation_val = module_params.get("web_reputation")
    temp_obj["state"] = web_reputation_val.get("state")

    return temp_obj


def activity_monitoring_fn(module_params):
    temp_obj = {}
    activity_monitoring_val = module_params.get("activity_monitoring")
    temp_obj["state"] = activity_monitoring_val.get("state")

    return temp_obj


def firewall_fn(module_params):
    firewall_dict = {
        "global_stateful_configuration_id": "globalStatefulConfigurationID",
        "stateful_configuration_assignments": "statefulConfigurationAssignments",
        "rule_id": "ruleIDs",
        "scheduled_scan_configuration_id": "scheduledScanConfigurationID",
    }
    stateful_configuration_assignments_dict = {
        "interface_id": "interfaceID",
        "interface_type_id": "interfaceTypeID",
        "stateful_configuration_id": "statefulConfigurationID",
    }
    firewall_val = module_params.get("firewall")
    return common_populate_logic(
        firewall_val, firewall_dict, stateful_configuration_assignments_dict
    )


def intrusion_prevention_fn(module_params):
    intrusion_prevention_dict = {
        "rule_id": "ruleIDs",
        "application_type_id": "applicationTypeIDs",
    }
    intrusion_prevention_val = module_params.get("intrusion_prevention")
    return common_populate_logic(
        intrusion_prevention_val, intrusion_prevention_dict
    )


def integrity_monitoring_fn(module_params):
    integrity_monitoring_dict = {"rule_id": "ruleIDs"}
    integrity_monitoring_val = module_params.get("integrity_monitoring")
    return common_populate_logic(
        integrity_monitoring_val, integrity_monitoring_dict
    )


def log_inspection_fn(module_params):
    log_inspection_dict = {"rule_id": "ruleIDs"}
    log_inspection_val = module_params.get("log_inspection")
    return common_populate_logic(log_inspection_val, log_inspection_dict)


def application_control_fn(module_params):
    application_control_dict = {
        "ruleset_id": "rulesetID",
        "block_unrecognized": "blockUnrecognized",
    }
    application_control_val = module_params.get("application_control")
    return common_populate_logic(
        application_control_val, application_control_dict
    )


def sap_fn(module_params):
    temp_obj = {}
    sap_val = module_params.get("sap")
    temp_obj["state"] = sap_val.get("state")

    return temp_obj


def map_params_to_obj(module_params):
    obj = {}
    obj["name"] = module_params["name"]
    obj["description"] = module_params.get("description")
    if module_params.get("parent_id"):
        obj["parentID"] = module_params.get("parent_id")
    if module_params.get("policy_settings"):
        obj["policySettings"] = policy_settings_fn(module_params)
    if module_params.get("recommendation_scan_mode"):
        obj["recommendationScanMode"] = module_params.get(
            "recommendation_scan_mode"
        )
    if module_params.get("auto_requires_update"):
        obj["autoRequiresUpdate"] = module_params.get("auto_requires_update")
    if module_params.get("interface_types"):
        obj["interfaceTypes"] = interface_type_fn(module_params)
    if module_params.get("anti_malware"):
        obj["antiMalware"] = anti_malware_fn(module_params)
    if module_params.get("web_reputation"):
        obj["webReputation"] = web_reputation_fn(module_params)
    if module_params.get("activity_monitoring"):
        obj["activityMonitoring"] = activity_monitoring_fn(module_params)
    if module_params.get("firewall"):
        obj["firewall"] = firewall_fn(module_params)
    if module_params.get("intrusion_prevention"):
        obj["intrusionPrevention"] = intrusion_prevention_fn(module_params)
    if module_params.get("integrity_monitoring"):
        obj["integrityMonitoring"] = integrity_monitoring_fn(module_params)
    if module_params.get("log_inspection"):
        obj["logInspection"] = log_inspection_fn(module_params)
    if module_params.get("application_control"):
        obj["applicationControl"] = application_control_fn(module_params)
    if module_params.get("sap"):
        obj["SAP"] = sap_fn(module_params)
    return obj


def delete_policy_with_id(module, deepsec_request, policy_id):
    """ The fn calls the delete API based on the policy id
    :param module: ansible module object
    :param deepsec_request: connection obj for TM
    :param policy_id: policy id for the policy that's supposed to be deleted
    value has dict as its value
    :rtype: A dict
    :returns: Based on API response this fn. exits with appropriate msg
    """
    deepsec_request.delete("/api/policies/{0}".format(policy_id))
    module.exit_json(
        msg="Policy with id: {} deleted successfully!".format(policy_id),
        changed=True,
    )


def check_if_policy_exists(deepsec_request, policy_name):
    """ The fn check if the policy detect based on policy name
    :param deepsec_request: the objects from which the configuration should be read
    :param policy_name: policy name with which policy will be searched in existing policy
    :rtype: A dict
    :returns: dict with search result value
    """
    search_dict = {}
    search_dict["searchCriteria"] = []
    temp_criteria = {}
    temp_criteria["fieldName"] = "name"
    temp_criteria["stringTest"] = "equal"
    temp_criteria["stringValue"] = policy_name
    search_dict["searchCriteria"].append(temp_criteria)

    search_result = deepsec_request.post(
        "/api/policies/search", data=search_dict
    )
    if search_result.get("policies"):
        return search_result["policies"][0]
    return search_result


def main():
    policy_settings_spec = {
        "log_inspection_setting_severity_clipping_agent_event_send_syslog_level_min": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connections_cleanup_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_verify_tcp_checksum_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_scan_cache_on_demand_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "application_control_setting_shared_ruleset_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_server_connection_lost_warning_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "application_control_setting_execution_enforcement_level": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_blocked_url_domains": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_syn_sent_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_self_protection_password": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_tcp_xmas_attack_duration": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_virtual_and_container_network_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "log_inspection_setting_syslog_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_debug_mode_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_virtual_and_container_network_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_file_hash_sha256_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_fingerprint_probe_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_retain_num": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_paws_zero": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_connected_threat_defense_use_control_manager_suspicious_object_list_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_option_fragmented_ip_keep_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop6_to_4bogons_addresses_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "log_inspection_setting_severity_clipping_agent_event_store_level_min": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_scan_cache_concurrency_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_syslog_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_tcp_paws_window_policy": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_tcp_xmas_attack_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "application_control_setting_ruleset_mode": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_global_server_use_proxy_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_local_server_allow_off_domain_global": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_combined_mode_protection_source": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_close_wait_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_scan_open_port_list_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_self_protection_password_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ack_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_cached_entries_stale_time": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_combined_mode_protection_source": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_events_send_interval": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_inactive_agent_cleanup_override_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_failure_response_engine_system": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_relay_state": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_evasive_retransmit_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "activity_monitoring_setting_indicator_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_option_fragmented_ip_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_zero_flags": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_global_server_use_proxy_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_nsx_security_tagging_prevent_mode_level": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_tcp_xmas_attack_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_udp_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_local_server_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_tcp_mss_limit": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_cold_start_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_established_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_identified_files_space_max_mbytes": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_allow_null_ip_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_notifications_suppress_popups_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_rst_fin_flags": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_disconnect_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_close_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_tunnel_depth_max_exceeded_action": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_tcp_null_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_smart_protection_anti_malware_global_server_proxy_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_filter_ipv4_tunnels": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_local_server_urls": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_one_packet_period": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_filter_ipv6_tunnels": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_congestion_flags": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_heartbeat_missed_alert_threshold": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_options_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connections_num_udp_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_auto_apply_recommendations_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_tunnel_depth_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_unknown_ssl_protocol_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_nsx_security_tagging_value": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_log_data_rule_first_match_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_logging_policy": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_troubleshooting_logging_level": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_virtual_appliance_on_demand_scan_cache_entries_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_combined_mode_protection_source": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_closing_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_paws": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_auto_apply_recommendations_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_fingerprint_probe_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_nsx_security_tagging_remove_on_clean_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_packet_length_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_teredo_anomalies_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_security_level": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv6_site_local_addresses_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "activity_monitoring_setting_activity_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_strict_terodo_port_check_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_blocked_url_keywords": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_syslog_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_failure_response_packet_sanity_check": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_network_engine_mode": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_size_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_malware_scan_multithreaded_processing_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_tcp_syn_fin_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ip_zero_payload_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_block_ipv_6agent_8and_earlier_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_option_fragmented_ip_packet_send_icmp_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_predictive_machine_learning_exceptions": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_events_per_second_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ssl_session_time": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_behavior_monitoring_scan_exclusion_list": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_global_server_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_one_packet_within_period_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_generate_connection_events_icmp_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_heartbeat_inactive_vm_offline_alert_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_smart_protection_web_reputation_global_server_proxy_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_nsx_security_tagging_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_fragmented_packets": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connections_num_icmp_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_split_handshake": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_combined_mode_protection_source": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_event_nodes_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_monitor_port_list_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "application_control_setting_syslog_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_out_no_connection": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_block_ipv6_agent9_and_later_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_virtual_appliance_optimization_scan_cache_entries_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_tcp_null_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ignore_status_code1": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ignore_status_code0": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ignore_status_code2": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_ssl_session_size": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_scan_cache_real_time_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_recommendation_ongoing_scans_interval": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_smart_protection_global_server_use_proxy_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_interface_limit_one_active_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_checksum": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv6_next_type0_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_scan_file_size_max_mbytes": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_generate_connection_events_tcp_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_file_hash_size_max_mbytes": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_cached_entries_life_time": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_smart_protection_global_server_proxy_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "log_inspection_setting_auto_apply_recommendations_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_connected_threat_defense_suspicious_file_ddan_submission_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_blocking_page_link": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_syslog_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_communications_direction": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_scan_cache_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_document_exploit_protection_rule_exceptions": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_syn_with_data": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_file_hash_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_fingerprint_probe_duration": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv6_bogons_addresses_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_boot_start_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connections_num_tcp_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_security_posture": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_interface_patterns": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_interface_isolation_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_virtual_appliance_real_time_scan_cache_entries_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_events_out_of_allowed_policy_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_evasive_retransmit": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_icmp_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_syslog_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_connection_cleanup_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_local_server_allow_off_domain_global": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_tcp_syn_fin_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_error_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_allowed_urls": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_notify_network_or_port_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_fin_wait_1timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_generate_connection_events_udp_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "activity_monitoring_setting_syslog_config_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_syn_rst_flags": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_spyware_approved_list": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_urgent_flags": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_nsx_security_tagging_detect_mode_level": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "intrusion_prevention_setting_engine_option_fragmented_ip_unconcerned_mac_address_bypass_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_log_all_packet_data_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_tcp_syn_fin_flags": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_heartbeat_interval": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_fragment_size_min": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_server_connection_lost_warning_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_network_or_port_scan_duration": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_content_hash_algorithm": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_scan_state": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_config_package_exceeds_alert_max_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_environment_variable_overrides": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_fragment_offset_min": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_smart_protection_local_server_urls": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_syn_rcvd_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_cached_entries_num": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_force_allow_icmp_type3_code4": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_tcp_null_scan_duration": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_smart_protection_global_server_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_realtime_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_last_ack_timeout": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_exclude_ip_list_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_agent_self_protection_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv6_reserved_addresses_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_fin_no_connection": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_debug_packet_num_max": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_bypass_cisco_waas_connections_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_heartbeat_local_time_shift_alert_threshold": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_file_hash_md5_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_detect_network_or_port_scan_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_silent_tcp_connection_drop_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_block_same_src_dst_ip_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_force_allow_dhcp_dns": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_include_ip_list_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_options_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_reconnaissance_block_tcp_syn_fin_scan_duration": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_security_block_untested_pages_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_allowed_url_domains": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_event_log_file_ignore_source_ip_list_id": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_engine_option_drop_ipv6_fragments_lower_than_min_mtu_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_auto_assign_new_intrusion_prevention_rules_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "firewall_setting_anti_evasion_check_rst_no_connection": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_blocked_urls": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_combined_mode_network_group_protection_source": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "web_reputation_setting_alerting_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "anti_malware_setting_nsx_security_tagging_on_remediation_failure_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "integrity_monitoring_setting_cpu_usage_level": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
        "platform_setting_auto_update_anti_malware_engine_enabled": dict(
            type="dict", options=dict(value=dict(type="str", required=False))
        ),
    }

    interface_types_spec = {
        "name": dict(type="str", required=False),
        "description": dict(type="str", required=False),
        "matches": dict(type="list"),
    }

    anti_malware_spec = {
        "state": dict(type="str", required=False, choices=["off", "on"]),
        "real_time_scan_configuration_id": dict(type="int", required=False),
        "real_time_scan_schedule_id": dict(type="int"),
        "manual_scan_configuration_id": dict(type="int"),
        "scheduled_scan_configuration_id": dict(type="int"),
    }

    stateful_configuration_assignments_spec = {
        "interface_id": dict(type="int", required=False),
        "interface_type_id": dict(type="int", required=False),
        "stateful_configuration_id": dict(type="int", required=False),
    }

    firewall_spec = {
        "state": dict(
            type="str", required=False, choices=["inherited", "off", "on"]
        ),
        "global_stateful_configuration_id": dict(type="int", required=False),
        "stateful_configuration_assignments": dict(
            type="list",
            elements="dict",
            options=stateful_configuration_assignments_spec,
        ),
        "rule_id": dict(type="list", required=False),
    }

    intrusion_prevention_spec = {
        "state": dict(
            type="str",
            required=False,
            choices=["inherited", "prevent", "detect", "off"],
        ),
        "rule_id": dict(type="list", required=False),
        "application_type_id": dict(type="list", required=False),
    }

    integrity_monitoring_spec = {
        "state": dict(
            type="str",
            required=False,
            choices=["inherited", "real-time", "off", "on"],
        ),
        "rule_id": dict(type="list", required=False),
    }

    log_inspection_spec = {
        "state": dict(
            type="str", required=False, choices=["inherited", "off", "on"]
        ),
        "rule_id": dict(type="list", required=False),
    }

    application_control_spec = {
        "state": dict(
            type="int", required=False, choices=["inherited", "off", "on"]
        ),
        "ruleset_id": dict(type="str", required=False),
        "block_unrecognized": dict(type="bool", required=False),
    }

    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        parent_id=dict(required=False, type="int"),
        name=dict(required=True, type="str"),
        description=dict(type="str"),
        policy_settings=dict(type="dict", options=policy_settings_spec),
        recommendation_scan_mode=dict(type="str", choices=["off", "ongoing"]),
        auto_requires_update=dict(type="str", choices=["off", "on"]),
        interface_types=dict(
            type="list", elements="dict", options=interface_types_spec
        ),
        anti_malware=dict(type="dict", options=anti_malware_spec),
        web_reputation=dict(
            type="dict",
            options=dict(
                state=dict(
                    type="str",
                    required=False,
                    choices=["inherited", "off", "on"],
                )
            ),
        ),
        activity_monitoring=dict(
            type="dict",
            options=dict(
                state=dict(
                    type="str",
                    required=False,
                    choices=["inherited", "off", "on"],
                )
            ),
        ),
        firewall=dict(type="dict", options=firewall_spec),
        intrusion_prevention=dict(
            type="dict", options=intrusion_prevention_spec
        ),
        integrity_monitoring=dict(
            type="dict", options=integrity_monitoring_spec
        ),
        log_inspection=dict(type="dict", options=log_inspection_spec),
        application_control=dict(
            type="dict", options=application_control_spec
        ),
        sap=dict(
            type="dict",
            options=dict(
                state=dict(
                    type="str",
                    required=False,
                    choices=["inherited", "off", "on"],
                )
            ),
        ),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))

    search_existing_policies = check_if_config_exists(
        deepsec_request, want["name"], "policies", "policies"
    )

    if "ID" in search_existing_policies and module.params["state"] == "absent":
        delete_config_with_id(
            module,
            deepsec_request,
            "policies",
            search_existing_policies["ID"],
            "policies",
        )
    elif (
        "ID" not in search_existing_policies
        and module.params["state"] == "absent"
    ):
        module.exit_json(changed=False)
    else:
        policies_config = deepsec_request.post("/api/policies", data=want)
        if "ID" in search_existing_policies:
            module.exit_json(
                policies_config=search_existing_policies, changed=False
            )
        elif policies_config.get("message"):
            module.fail_json(msg=policies_config["message"])
        else:
            module.exit_json(policies_config=policies_config, changed=True)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

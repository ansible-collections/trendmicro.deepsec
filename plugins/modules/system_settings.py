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
module: system_settings
short_description: Modify the system settings for TrendMicro Deep Security.
description:
  - This module modifies system settings under TrendMicro Deep Security.
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
from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
)
import copy
import json
import q

def check_if_systemsettings_config_exists(deepsec_request, want_params, api):
  systemsettings = deepsec_request.get(api)
  for key, value in iteritems(want_params):
    temp = systemsettings.get(key)
    if temp.get('value') == value.get('value'):
      continue
    else:
      return False, systemsettings
  return True, systemsettings

def reset_systemsettings_config(module, deepsec_request, want_params, api):
  for key, value in iteritems(want_params):
    temp_api_object = api + '/' + key
    temp = deepsec_request.delete(temp_api_object)
  systemsettings = deepsec_request.get(api)
  module.exit_json(systemsettings=systemsettings, changed=True)


def map_params_to_obj(module_params):
    # populate the firewall rules dict with actual api expected values
  obj = {}
  if module_params.get("platform_setting_saml_identity_provider_certificate_expiry_warning_daysr"):
    obj["platformSettingSamlIdentityProviderCertificateExpiryWarningDays"] = module_params.get("platform_setting_saml_identity_provider_certificate_expiry_warning_daysr")
  if module_params.get("platform_setting_update_agent_security_on_missing_deep_security_manager_enabled"):
    obj["platformSettingUpdateAgentSecurityOnMissingDeepSecurityManagerEnabled"] = module_params.get("platform_setting_update_agent_security_on_missing_deep_security_manager_enabled")
  if module_params.get("platform_setting_ddan_manual_source_server_url"):
    obj["platformSettingDdanManualSourceServerUrl"] = module_params.get("platform_setting_ddan_manual_source_server_url")
  if module_params.get("platform_setting_load_balancer_manager_port"):
    obj["platformSettingLoadBalancerManagerPort"] = module_params.get("platform_setting_load_balancer_manager_port")
  if module_params.get("platform_setting_smart_protection_feedback_threat_detections_threshold"):
    obj["platformSettingSmartProtectionFeedbackThreatDetectionsThreshold"] = module_params.get("platform_setting_smart_protection_feedback_threat_detections_threshold")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_run_port_scan_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantRunPortScanEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_run_port_scan_enabled")
  if module_params.get("intrusion_prevention_setting_event_rank_severity_filter_medium"):
    obj["intrusionPreventionSettingEventRankSeverityFilterMedium"] = module_params.get("intrusion_prevention_setting_event_rank_severity_filter_medium")
  if module_params.get("firewall_setting_intranet_connectivity_test_expected_content_regex"):
    obj["firewallSettingIntranetConnectivityTestExpectedContentRegex"] = module_params.get("firewall_setting_intranet_connectivity_test_expected_content_regex")
  if module_params.get("platform_setting_event_forwarding_sns_enabled"):
    obj["platformSettingEventForwardingSnsEnabled"] = module_params.get("platform_setting_event_forwarding_sns_enabled")
  if module_params.get("platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_timeout"):
    obj["platformSettingTenantAutoRevokeImpersonationByPrimaryTenantTimeout"] = module_params.get("platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_timeout")
  if module_params.get("web_reputation_setting_event_rank_risk_blocked_by_administrator_rank"):
    obj["webReputationSettingEventRankRiskBlockedByAdministratorRank"] = module_params.get("web_reputation_setting_event_rank_risk_blocked_by_administrator_rank")
  if module_params.get("platform_setting_primary_tenant_lock_and_hide_tenant_storage_tab_enabled"):
    obj["platformSettingPrimaryTenantLockAndHideTenantStorageTabEnabled"] = module_params.get("platform_setting_primary_tenant_lock_and_hide_tenant_storage_tab_enabled")
  if module_params.get("anti_malware_setting_event_email_recipients"):
    obj["antiMalwareSettingEventEmailRecipients"] = module_params.get("anti_malware_setting_event_email_recipients")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_use_default_relay_group_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantUseDefaultRelayGroupEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_use_default_relay_group_enabled")
  if module_params.get("platform_setting_http_strict_transport_enabled"):
    obj["platformSettingHttpStrictTransportEnabled"] = module_params.get("platform_setting_http_strict_transport_enabled")
  if module_params.get("firewall_setting_intranet_connectivity_test_url"):
    obj["firewallSettingIntranetConnectivityTestUrl"] = module_params.get("firewall_setting_intranet_connectivity_test_url")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_configure_sns_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantConfigureSnsEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_configure_sns_enabled")
  if module_params.get("platform_setting_tenant_use_default_relay_group_from_primary_tenant_enabled"):
    obj["platformSettingTenantUseDefaultRelayGroupFromPrimaryTenantEnabled"] = module_params.get("platform_setting_tenant_use_default_relay_group_from_primary_tenant_enabled")
  if module_params.get("platform_setting_exported_diagnostic_package_locale"):
    obj["platformSettingExportedDiagnosticPackageLocale"] = module_params.get("platform_setting_exported_diagnostic_package_locale")
  if module_params.get("intrusion_prevention_setting_event_rank_severity_filter_critical"):
    obj["intrusionPreventionSettingEventRankSeverityFilterCritical"] = module_params.get("intrusion_prevention_setting_event_rank_severity_filter_critical")
  if module_params.get("platform_setting_update_imported_software_auto_download_enabled"):
    obj["platformSettingUpdateImportedSoftwareAutoDownloadEnabled"] = module_params.get("platform_setting_update_imported_software_auto_download_enabled")
  if module_params.get("platform_setting_demo_mode_enabled"):
    obj["platformSettingDemoModeEnabled"] = module_params.get("platform_setting_demo_mode_enabled")
  if module_params.get("platform_setting_user_enforce_terms_and_conditions_message"):
    obj["platformSettingUserEnforceTermsAndConditionsMessage"] = module_params.get("platform_setting_user_enforce_terms_and_conditions_message")
  if module_params.get("platform_setting_trend_micro_xdr_common_log_receiver_url"):
    obj["platformSettingTrendMicroXdrCommonLogReceiverUrl"] = module_params.get("platform_setting_trend_micro_xdr_common_log_receiver_url")
  if module_params.get("platform_setting_managed_detect_response_company_guid"):
    obj["platformSettingManagedDetectResponseCompanyGuid"] = module_params.get("platform_setting_managed_detect_response_company_guid")
  if module_params.get("platform_setting_alert_default_email_address"):
    obj["platformSettingAlertDefaultEmailAddress"] = module_params.get("platform_setting_alert_default_email_address")
  if module_params.get("platform_setting_agent_initiated_activation_reactivate_cloned_enabled"):
    obj["platformSettingAgentInitiatedActivationReactivateClonedEnabled"] = module_params.get("platform_setting_agent_initiated_activation_reactivate_cloned_enabled")
  if module_params.get("platform_setting_managed_detect_response_server_url"):
    obj["platformSettingManagedDetectResponseServerUrl"] = module_params.get("platform_setting_managed_detect_response_server_url")
  if module_params.get("platform_setting_primary_tenant_share_managed_detect_responses_enabled"):
    obj["platformSettingPrimaryTenantShareManagedDetectResponsesEnabled"] = module_params.get("platform_setting_primary_tenant_share_managed_detect_responses_enabled")
  if module_params.get("platform_setting_saml_service_provider_certificate"):
    obj["platformSettingSamlServiceProviderCertificate"] = module_params.get("platform_setting_saml_service_provider_certificate")
  if module_params.get("platform_setting_syslog_config_id"):
    obj["platformSettingSyslogConfigId"] = module_params.get("platform_setting_syslog_config_id")
  if module_params.get("platform_setting_smtp_start_tls_enabled"):
    obj["platformSettingSmtpStartTlsEnabled"] = module_params.get("platform_setting_smtp_start_tls_enabled")
  if module_params.get("platform_setting_user_password_require_letters_and_numbers_enabled"):
    obj["platformSettingUserPasswordRequireLettersAndNumbersEnabled"] = module_params.get("platform_setting_user_password_require_letters_and_numbers_enabled")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_synchronize_ldap_directories_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantSynchronizeLdapDirectoriesEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_synchronize_ldap_directories_enabled")
  if module_params.get("platform_setting_load_balancer_relay_port"):
    obj["platformSettingLoadBalancerRelayPort"] = module_params.get("platform_setting_load_balancer_relay_port")
  if module_params.get("platform_setting_managed_detect_response_enabled"):
    obj["platformSettingManagedDetectResponseEnabled"] = module_params.get("platform_setting_managed_detect_response_enabled")
  if module_params.get("platform_setting_update_rules_policy_auto_apply_enabled"):
    obj["platformSettingUpdateRulesPolicyAutoApplyEnabled"] = module_params.get("platform_setting_update_rules_policy_auto_apply_enabled")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_configure_forgot_password_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantConfigureForgotPasswordEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_configure_forgot_password_enabled")
  if module_params.get("platform_setting_user_password_require_not_same_as_username_enabled"):
    obj["platformSettingUserPasswordRequireNotSameAsUsernameEnabled"] = module_params.get("platform_setting_user_password_require_not_same_as_username_enabled")
  if module_params.get("log_inspection_setting_event_rank_severity_medium"):
    obj["logInspectionSettingEventRankSeverityMedium"] = module_params.get("log_inspection_setting_event_rank_severity_medium")
  if module_params.get("anti_malware_setting_retain_event_duration"):
    obj["antiMalwareSettingRetainEventDuration"] = module_params.get("anti_malware_setting_retain_event_duration")
  if module_params.get("platform_setting_update_agent_security_contact_primary_source_on_missing_relay_enabled"):
    obj["platformSettingUpdateAgentSecurityContactPrimarySourceOnMissingRelayEnabled"] = module_params.get("platform_setting_update_agent_security_contact_primary_source_on_missing_relay_enabled")
  if module_params.get("firewall_setting_event_rank_severity_log_only"):
    obj["firewallSettingEventRankSeverityLogOnly"] = module_params.get("firewall_setting_event_rank_severity_log_only")
  if module_params.get("platform_setting_primary_tenant_lock_and_hide_tenant_data_privacy_option_enabled"):
    obj["platformSettingPrimaryTenantLockAndHideTenantDataPrivacyOptionEnabled"] = module_params.get("platform_setting_primary_tenant_lock_and_hide_tenant_data_privacy_option_enabled")
  if module_params.get("application_control_setting_retain_event_duration"):
    obj["applicationControlSettingRetainEventDuration"] = module_params.get("application_control_setting_retain_event_duration")
  if module_params.get("platform_setting_api_soap_web_service_enabled"):
    obj["platformSettingApiSoapWebServiceEnabled"] = module_params.get("platform_setting_api_soap_web_service_enabled")
  if module_params.get("platform_setting_saml_service_provider_private_key"):
    obj["platformSettingSamlServiceProviderPrivateKey"] = module_params.get("platform_setting_saml_service_provider_private_key")
  if module_params.get("platform_setting_windows_upgrade_on_activation_enabled"):
    obj["platformSettingWindowsUpgradeOnActivationEnabled"] = module_params.get("platform_setting_windows_upgrade_on_activation_enabled")
  if module_params.get("platform_setting_system_event_forwarding_snmp_port"):
    obj["platformSettingSystemEventForwardingSnmpPort"] = module_params.get("platform_setting_system_event_forwarding_snmp_port")
  if module_params.get("firewall_setting_event_rank_severity_deny"):
    obj["firewallSettingEventRankSeverityDeny"] = module_params.get("firewall_setting_event_rank_severity_deny")
  if module_params.get("intrusion_prevention_setting_event_rank_severity_filter_low"):
    obj["intrusionPreventionSettingEventRankSeverityFilterLow"] = module_params.get("intrusion_prevention_setting_event_rank_severity_filter_low")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_control_impersonation_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantControlImpersonationEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_control_impersonation_enabled")
  if module_params.get("platform_setting_recommendation_cpu_usage_level"):
    obj["platformSettingRecommendationCpuUsageLevel"] = module_params.get("platform_setting_recommendation_cpu_usage_level")
  if module_params.get("platform_setting_managed_detect_response_service_token"):
    obj["platformSettingManagedDetectResponseServiceToken"] = module_params.get("platform_setting_managed_detect_response_service_token")
  if module_params.get("platform_setting_load_balancer_heartbeat_address"):
    obj["platformSettingLoadBalancerHeartbeatAddress"] = module_params.get("platform_setting_load_balancer_heartbeat_address")
  if module_params.get("platform_setting_trend_micro_xdr_api_user"):
    obj["platformSettingTrendMicroXdrApiUser"] = module_params.get("platform_setting_trend_micro_xdr_api_user")
  if module_params.get("platform_setting_content_security_policy_report_only_enabled"):
    obj["platformSettingContentSecurityPolicyReportOnlyEnabled"] = module_params.get("platform_setting_content_security_policy_report_only_enabled")
  if module_params.get("log_inspection_setting_retain_event_duration"):
    obj["logInspectionSettingRetainEventDuration"] = module_params.get("log_inspection_setting_retain_event_duration")
  if module_params.get("platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_enabled"):
    obj["platformSettingTenantAutoRevokeImpersonationByPrimaryTenantEnabled"] = module_params.get("platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_enabled")
  if module_params.get("anti_malware_setting_event_email_body_template"):
    obj["antiMalwareSettingEventEmailBodyTemplate"] = module_params.get("anti_malware_setting_event_email_body_template")
  if module_params.get("platform_setting_retain_security_updates_max"):
    obj["platformSettingRetainSecurityUpdatesMax"] = module_params.get("platform_setting_retain_security_updates_max")
  if module_params.get("platform_setting_connected_threat_defense_control_manager_source_option"):
    obj["platformSettingConnectedThreatDefenseControlManagerSourceOption"] = module_params.get("platform_setting_connected_threat_defense_control_manager_source_option")
  if module_params.get("anti_malware_setting_event_email_enabled"):
    obj["antiMalwareSettingEventEmailEnabled"] = module_params.get("anti_malware_setting_event_email_enabled")
  if module_params.get("platform_setting_update_agent_software_use_download_center_on_missing_deep_security_manager_enabled"):
    obj["platformSettingUpdateAgentSoftwareUseDownloadCenterOnMissingDeepSecurityManagerEnabled"] = module_params.get("platform_setting_update_agent_software_use_download_center_on_missing_deep_security_manager_enabled")
  if module_params.get("platform_setting_recommendation_ongoing_scans_enabled"):
    obj["platformSettingRecommendationOngoingScansEnabled"] = module_params.get("platform_setting_recommendation_ongoing_scans_enabled")
  if module_params.get("platform_setting_agent_initiated_activation_token"):
    obj["platformSettingAgentInitiatedActivationToken"] = module_params.get("platform_setting_agent_initiated_activation_token")
  if module_params.get("platform_setting_user_password_length_min"):
    obj["platformSettingUserPasswordLengthMin"] = module_params.get("platform_setting_user_password_length_min")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_database_state"):
    obj["platformSettingPrimaryTenantAllowTenantDatabaseState"] = module_params.get("platform_setting_primary_tenant_allow_tenant_database_state")
  if module_params.get("platform_setting_aws_manager_identity_use_instance_role_enabled"):
    obj["platformSettingAwsManagerIdentityUseInstanceRoleEnabled"] = module_params.get("platform_setting_aws_manager_identity_use_instance_role_enabled")
  if module_params.get("platform_setting_content_security_policy"):
    obj["platformSettingContentSecurityPolicy"] = module_params.get("platform_setting_content_security_policy")
  if module_params.get("platform_setting_product_usage_data_collection_enabled"):
    obj["platformSettingProductUsageDataCollectionEnabled"] = module_params.get("platform_setting_product_usage_data_collection_enabled")
  if module_params.get("platform_setting_alert_agent_update_pending_threshold"):
    obj["platformSettingAlertAgentUpdatePendingThreshold"] = module_params.get("platform_setting_alert_agent_update_pending_threshold")
  if module_params.get("platform_setting_user_password_require_special_characters_enabled"):
    obj["platformSettingUserPasswordRequireSpecialCharactersEnabled"] = module_params.get("platform_setting_user_password_require_special_characters_enabled")
  if module_params.get("platform_setting_update_appliance_default_agent_version"):
    obj["platformSettingUpdateApplianceDefaultAgentVersion"] = module_params.get("platform_setting_update_appliance_default_agent_version")
  if module_params.get("platform_setting_system_event_forwarding_snmp_enabled"):
    obj["platformSettingSystemEventForwardingSnmpEnabled"] = module_params.get("platform_setting_system_event_forwarding_snmp_enabled")
  if module_params.get("platform_setting_smtp_bounce_email_address"):
    obj["platformSettingSmtpBounceEmailAddress"] = module_params.get("platform_setting_smtp_bounce_email_address")
  if module_params.get("platform_setting_update_relay_security_support_agent_9and_earlier_enabled"):
    obj["platformSettingUpdateRelaySecuritySupportAgent9AndEarlierEnabled"] = module_params.get("platform_setting_update_relay_security_support_agent_9and_earlier_enabled")
  if module_params.get("platform_setting_managed_detect_response_proxy_id"):
    obj["platformSettingManagedDetectResponseProxyId"] = module_params.get("platform_setting_managed_detect_response_proxy_id ")
  if module_params.get("platform_setting_trend_micro_xdr_log_server_url"):
    obj["platformSettingTrendMicroXdrLogServerUrl"] = module_params.get("platform_setting_trend_micro_xdr_log_server_url")
  if module_params.get("platform_setting_inactive_agent_cleanup_enabled"):
    obj["platformSettingInactiveAgentCleanupEnabled"] = module_params.get("platform_setting_inactive_agent_cleanup_enabled")
  if module_params.get("platform_setting_load_balancer_relay_address"):
    obj["platformSettingLoadBalancerRelayAddress"] = module_params.get("platform_setting_load_balancer_relay_address")
  if module_params.get("platform_setting_http_public_key_pin_policy"):
    obj["platformSettingHttpPublicKeyPinPolicy"] = module_params.get("platform_setting_http_public_key_pin_policy")
  if module_params.get("platform_setting_user_session_idle_timeout"):
    obj["platformSettingUserSessionIdleTimeout"] = module_params.get("platform_setting_user_session_idle_timeout")
  if module_params.get("anti_malware_setting_event_email_subject"):
    obj["antiMalwareSettingEventEmailSubject"] = module_params.get("anti_malware_setting_event_email_subject")
  if module_params.get("platform_setting_connected_threat_defense_control_manager_use_proxy_enabled"):
    obj["platformSettingConnectedThreatDefenseControlManagerUseProxyEnabled"] = module_params.get("platform_setting_connected_threat_defense_control_manager_use_proxy_enabled")
  if module_params.get("platform_setting_user_enforce_terms_and_conditions_enabled"):
    obj["platformSettingUserEnforceTermsAndConditionsEnabled"] = module_params.get("platform_setting_user_enforce_terms_and_conditions_enabled")
  if module_params.get("platform_setting_aws_manager_identity_access_key"):
    obj["platformSettingAwsManagerIdentityAccessKey"] = module_params.get("platform_setting_aws_manager_identity_access_key")
  if module_params.get("platform_setting_connected_threat_defense_control_manager_proxy_id"):
    obj["platformSettingConnectedThreatDefenseControlManagerProxyId"] = module_params.get("platform_setting_connected_threat_defense_control_manager_proxy_id")
  if module_params.get("platform_setting_tenant_allow_impersonation_by_primary_tenant_enabled"):
    obj["platformSettingTenantAllowImpersonationByPrimaryTenantEnabled"] = module_params.get("platform_setting_tenant_allow_impersonation_by_primary_tenant_enabled")
  if module_params.get("platform_setting_connected_threat_defense_control_manager_manual_source_server_url"):
    obj["platformSettingConnectedThreatDefenseControlManagerManualSourceServerUrl"] = module_params.get("platform_setting_connected_threat_defense_control_manager_manual_source_server_url")
  if module_params.get("platform_setting_user_password_require_mixed_case_enabled"):
    obj["platformSettingUserPasswordRequireMixedCaseEnabled"] = module_params.get("platform_setting_user_password_require_mixed_case_enabled")
  if module_params.get("platform_setting_trend_micro_xdr_identity_provider_api_url"):
    obj["platformSettingTrendMicroXdrIdentityProviderApiUrl"] = module_params.get("platform_setting_trend_micro_xdr_identity_provider_api_url")
  if module_params.get("platform_setting_smart_protection_feedback_for_suspicious_file_enabled"):
    obj["platformSettingSmartProtectionFeedbackForSuspiciousFileEnabled"] = module_params.get("platform_setting_smart_protection_feedback_for_suspicious_file_enabled")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_configure_snmp_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantConfigureSnmpEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_configure_snmp_enabled")
  if module_params.get("platform_setting_smart_protection_feedback_industry_type"):
    obj["platformSettingSmartProtectionFeedbackIndustryType"] = module_params.get("platform_setting_smart_protection_feedback_industry_type")
  if module_params.get("web_reputation_setting_retain_event_duration"):
    obj["webReputationSettingRetainEventDuration"] = module_params.get("web_reputation_setting_retain_event_duration")
  if module_params.get("platform_setting_retain_server_log_duration"):
    obj["platformSettingRetainServerLogDuration"] = module_params.get("platform_setting_retain_server_log_duration")
  if module_params.get("integrity_monitoring_setting_event_rank_severity_medium"):
    obj["integrityMonitoringSettingEventRankSeverityMedium"] = module_params.get("integrity_monitoring_setting_event_rank_severity_medium")
  if module_params.get("platform_setting_proxy_manager_cloud_proxy_id"):
    obj["platformSettingProxyManagerCloudProxyId"] = module_params.get("platform_setting_proxy_manager_cloud_proxy_id")
  if module_params.get("platform_setting_update_relay_security_all_regions_patterns_download_enabled"):
    obj["platformSettingUpdateRelaySecurityAllRegionsPatternsDownloadEnabled"] = module_params.get("platform_setting_update_relay_security_all_regions_patterns_download_enabled")
  if module_params.get("platform_setting_ddan_submission_enabled"):
    obj["platformSettingDdanSubmissionEnabled"] = module_params.get("platform_setting_ddan_submission_enabled")
  if module_params.get("web_reputation_setting_event_rank_risk_suspicious"):
    obj["webReputationSettingEventRankRiskSuspicious"] = module_params.get("web_reputation_setting_event_rank_risk_suspicious")
  if module_params.get("integrity_monitoring_setting_event_rank_severity_critical"):
    obj["integrityMonitoringSettingEventRankSeverityCritical"] = module_params.get("integrity_monitoring_setting_event_rank_severity_critical")
  if module_params.get("platform_setting_smtp_from_email_address"):
    obj["platformSettingSmtpFromEmailAddress"] = module_params.get("platform_setting_smtp_from_email_address")
  if module_params.get("firewall_setting_global_stateful_config_id"):
    obj["firewallSettingGlobalStatefulConfigId"] = module_params.get("firewall_setting_global_stateful_config_id")
  if module_params.get("firewall_setting_global_stateful_config_id"):
    obj["platformSettingEventForwardingSnsTopicArn"] = module_params.get("firewall_setting_global_stateful_config_id")
  if module_params.get("firewall_setting_internet_connectivity_test_expected_content_regex"):
    obj["firewallSettingInternetConnectivityTestExpectedContentRegex"] = module_params.get("firewall_setting_internet_connectivity_test_expected_content_regex")
  if module_params.get("platform_setting_connected_threat_defense_control_manager_manual_source_api_key"):
    obj["platformSettingConnectedThreatDefenseControlManagerManualSourceApiKey"] = module_params.get("platform_setting_connected_threat_defense_control_manager_manual_source_api_key")
  if module_params.get("platform_setting_load_balancer_manager_address"):
    obj["platformSettingLoadBalancerManagerAddress"] = module_params.get("platform_setting_load_balancer_manager_address")
  if module_params.get("platform_setting_update_security_primary_source_mode"):
    obj["platformSettingUpdateSecurityPrimarySourceMode"] = module_params.get("platform_setting_update_security_primary_source_mode")
  if module_params.get("platform_setting_primary_tenant_share_connected_threat_defenses_enabled"):
    obj["platformSettingPrimaryTenantShareConnectedThreatDefensesEnabled"] = module_params.get("platform_setting_primary_tenant_share_connected_threat_defenses_enabled")
  if module_params.get("web_reputation_setting_event_rank_risk_dangerous"):
    obj["webReputationSettingEventRankRiskDangerous"] = module_params.get("web_reputation_setting_event_rank_risk_dangerous")
  if module_params.get("platform_setting_load_balancer_heartbeat_port"):
    obj["platformSettingLoadBalancerHeartbeatPort"] = module_params.get("platform_setting_load_balancer_heartbeat_port")
  if module_params.get("platform_setting_user_hide_unlicensed_modules_enabled"):
    obj["platformSettingUserHideUnlicensedModulesEnabled"] = module_params.get("platform_setting_user_hide_unlicensed_modules_enabled")
  if module_params.get("platform_setting_capture_encrypted_traffic_enabled"):
    obj["platformSettingCaptureEncryptedTrafficEnabled"] = module_params.get("platform_setting_capture_encrypted_traffic_enabled")
  if module_params.get("platform_setting_retain_system_event_duration"):
    obj["platformSettingRetainSystemEventDuration"] = module_params.get("platform_setting_retain_system_event_duration")
  if module_params.get("platform_setting_user_password_expiry"):
    obj["platformSettingUserPasswordExpiry"] = module_params.get("platform_setting_user_password_expiry")
  if module_params.get("platform_setting_smart_protection_feedback_enabled"):
    obj["platformSettingSmartProtectionFeedbackEnabled"] = module_params.get("platform_setting_smart_protection_feedback_enabled")
  if module_params.get("integrity_monitoring_setting_retain_event_duration"):
    obj["integrityMonitoringSettingRetainEventDuration"] = module_params.get("integrity_monitoring_setting_retain_event_duration")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_use_scheduled_run_script_task_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantUseScheduledRunScriptTaskEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_use_scheduled_run_script_task_enabled")
  if module_params.get("log_inspection_setting_event_rank_severity_critical"):
    obj["logInspectionSettingEventRankSeverityCritical"] = module_params.get("log_inspection_setting_event_rank_severity_critical")
  if module_params.get("platform_setting_primary_tenant_lock_and_hide_tenant_smtp_tab_enabled"):
    obj["platformSettingPrimaryTenantLockAndHideTenantSmtpTabEnabled"] = module_params.get("platform_setting_primary_tenant_lock_and_hide_tenant_smtp_tab_enabled")
  if module_params.get("platform_setting_ddan_proxy_id"):
    obj["platformSettingDdanProxyId"] = module_params.get("platform_setting_ddan_proxy_id")
  if module_params.get("platform_setting_agent_initiated_activation_within_ip_list_id"):
    obj["platformSettingAgentInitiatedActivationWithinIpListId"] = module_params.get("platform_setting_agent_initiated_activation_within_ip_list_id")
  if module_params.get("platform_setting_update_security_primary_source_url"):
    obj["platformSettingUpdateSecurityPrimarySourceUrl"] = module_params.get("platform_setting_update_security_primary_source_url")
  if module_params.get("platform_setting_agentless_vcloud_protection_enabled"):
    obj["platformSettingAgentlessVcloudProtectionEnabled"] = module_params.get("platform_setting_agentless_vcloud_protection_enabled")
  if module_params.get("platform_setting_linux_upgrade_on_activation_enabled"):
    obj["platformSettingLinuxUpgradeOnActivationEnabled"] = module_params.get("platform_setting_linux_upgrade_on_activation_enabled")
  if module_params.get("platform_setting_trend_micro_xdr_enabled"):
    obj["platformSettingTrendMicroXdrEnabled"] = module_params.get("platform_setting_trend_micro_xdr_enabled")
  if module_params.get("platform_setting_active_sessions_max_exceeded_action"):
    obj["platformSettingActiveSessionsMaxExceededAction"] = module_params.get("platform_setting_active_sessions_max_exceeded_action")
  if module_params.get("platform_setting_update_hostname_on_ip_change_enabled"):
    obj["platformSettingUpdateHostnameOnIpChangeEnabled"] = module_params.get("platform_setting_update_hostname_on_ip_change_enabled")
  if module_params.get("log_inspection_setting_event_rank_severity_high"):
    obj["logInspectionSettingEventRankSeverityHigh"] = module_params.get("log_inspection_setting_event_rank_severity_high")
  if module_params.get("platform_setting_smtp_requires_authentication_enabled"):
    obj["platformSettingSmtpRequiresAuthenticationEnabled"] = module_params.get("platform_setting_smtp_requires_authentication_enabled")
  if module_params.get("platform_setting_active_sessions_max"):
    obj["platformSettingActiveSessionsMax"] = module_params.get("platform_setting_active_sessions_max")
  if module_params.get("platform_setting_aws_external_id_retrieval_enabled"):
    obj["platformSettingAwsExternalIdRetrievalEnabled"] = module_params.get("platform_setting_aws_external_id_retrieval_enabled")
  if module_params.get("log_inspection_setting_event_rank_severity_low"):
    obj["logInspectionSettingEventRankSeverityLow"] = module_params.get("log_inspection_setting_event_rank_severity_low")
  if module_params.get("platform_setting_azure_sso_certificate"):
    obj["platformSettingAzureSsoCertificate"] = module_params.get("platform_setting_azure_sso_certificate")
  if module_params.get("platform_setting_smtp_username"):
    obj["platformSettingSmtpUsername"] = module_params.get("platform_setting_smtp_username")
  if module_params.get("platform_setting_event_forwarding_sns_advanced_config_enabled"):
    obj["platformSettingEventForwardingSnsAdvancedConfigEnabled"] = module_params.get("platform_setting_event_forwarding_sns_advanced_config_enabled")
  if module_params.get("firewall_setting_internet_connectivity_test_interval"):
    obj["firewallSettingInternetConnectivityTestInterval"] = module_params.get("firewall_setting_internet_connectivity_test_interval")
  if module_params.get("platform_setting_whois_url"):
    obj["platformSettingWhoisUrl"] = module_params.get("platform_setting_whois_url")
  if module_params.get("platform_setting_ddan_source_option"):
    obj["platformSettingDdanSourceOption"] = module_params.get("platform_setting_ddan_source_option")
  if module_params.get("platform_setting_connected_threat_defense_control_manager_suspicious_object_list_comparison_enabled"):
    obj["platformSettingConnectedThreatDefenseControlManagerSuspiciousObjectListComparisonEnabled"] = module_params.get("platform_setting_connected_threat_defense_control_manager_suspicious_object_list_comparison_enabled")
  if module_params.get("platform_setting_exported_file_character_encoding"):
    obj["platformSettingExportedFileCharacterEncoding"] = module_params.get("platform_setting_exported_file_character_encoding")
  if module_params.get("platform_setting_user_session_duration_max"):
    obj["platformSettingUserSessionDurationMax"] = module_params.get("platform_setting_user_session_duration_max")
  if module_params.get("platform_setting_update_software_alternate_update_server_urls"):
    obj["platformSettingUpdateSoftwareAlternateUpdateServerUrls"] = module_params.get("platform_setting_update_software_alternate_update_server_urls")
  if module_params.get("platform_setting_retain_counters_duration"):
    obj["platformSettingRetainCountersDuration"] = module_params.get("platform_setting_retain_counters_duration")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_run_computer_discovery_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantRunComputerDiscoveryEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_run_computer_discovery_enabled")
  if module_params.get("platform_setting_smart_protection_feedback_interval"):
    obj["platformSettingSmartProtectionFeedbackInterval"] = module_params.get("platform_setting_smart_protection_feedback_interval")
  if module_params.get("platform_setting_system_event_forwarding_snmp_address"):
    obj["platformSettingSystemEventForwardingSnmpAddress"] = module_params.get("platform_setting_system_event_forwarding_snmp_address")
  if module_params.get("platform_setting_smtp_server_address"):
    obj["platformSettingSmtpServerAddress"] = module_params.get("platform_setting_smtp_server_address")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_configure_siem_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantConfigureSiemEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_configure_siem_enabled")
  if module_params.get("platform_setting_smtp_password"):
    obj["platformSettingSmtpPassword"] = module_params.get("platform_setting_smtp_password")
  if module_params.get("platform_setting_event_forwarding_sns_config_json"):
    obj["platformSettingEventForwardingSnsConfigJson"] = module_params.get("platform_setting_event_forwarding_sns_config_json")
  if module_params.get("firewall_setting_retain_event_duration"):
    obj["firewallSettingRetainEventDuration"] = module_params.get("firewall_setting_retain_event_duration")
  if module_params.get("web_reputation_setting_event_rank_risk_untested"):
    obj["webReputationSettingEventRankRiskUntested"] = module_params.get("web_reputation_setting_event_rank_risk_untested")
  if module_params.get("platform_setting_managed_detect_response_use_proxy_enabled"):
    obj["platformSettingManagedDetectResponseUseProxyEnabled"] = module_params.get("platform_setting_managed_detect_response_use_proxy_enabled")
  if module_params.get("platform_setting_event_forwarding_sns_secret_key"):
    obj["platformSettingEventForwardingSnsSecretKey"] = module_params.get("platform_setting_event_forwarding_sns_secret_key")
  if module_params.get("platform_setting_logo_binary_image_img"):
    obj["platformSettingLogoBinaryImageImg"] = module_params.get("platform_setting_logo_binary_image_img")
  if module_params.get("platform_setting_aws_manager_identity_secret_key"):
    obj["platformSettingAwsManagerIdentitySecretKey"] = module_params.get("platform_setting_aws_manager_identity_secret_key")
  if module_params.get("web_reputation_setting_event_rank_risk_highly_suspicious"):
    obj["webReputationSettingEventRankRiskHighlySuspicious"] = module_params.get("web_reputation_setting_event_rank_risk_highly_suspicious")
  if module_params.get("platform_setting_api_status_monitoring_enabled"):
    obj["platformSettingApiStatusMonitoringEnabled"] = module_params.get("platform_setting_api_status_monitoring_enabled")
  if module_params.get("platform_setting_sign_in_page_message"):
    obj["platformSettingSignInPageMessage"] = module_params.get("platform_setting_sign_in_page_message")
  if module_params.get("platform_setting_user_password_expiry_send_email_enabled"):
    obj["platformSettingUserPasswordExpirySendEmailEnabled"] = module_params.get("platform_setting_user_password_expiry_send_email_enabled")
  if module_params.get("platform_setting_user_sign_in_attempts_allowed_number"):
    obj["platformSettingUserSignInAttemptsAllowedNumber"] = module_params.get("platform_setting_user_sign_in_attempts_allowed_number")
  if module_params.get("platform_setting_ddan_use_proxy_enabled"):
    obj["platformSettingDdanUseProxyEnabled"] = module_params.get("platform_setting_ddan_use_proxy_enabled")
  if module_params.get("platform_setting_agent_initiated_activation_enabled"):
    obj["platformSettingAgentInitiatedActivationEnabled"] = module_params.get("platform_setting_agent_initiated_activation_enabled")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_configure_remember_me_option_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantConfigureRememberMeOptionEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_configure_remember_me_option_enabled")
  if module_params.get("platform_setting_smart_protection_feedback_bandwidth_max_kbytes"):
    obj["platformSettingSmartProtectionFeedbackBandwidthMaxKbytes"] = module_params.get("platform_setting_smart_protection_feedback_bandwidth_max_kbytes")
  if module_params.get("firewall_setting_event_rank_severity_packet_rejection"):
    obj["firewallSettingEventRankSeverityPacketRejection"] = module_params.get("firewall_setting_event_rank_severity_packet_rejection")
  if module_params.get("platform_setting_proxy_manager_update_proxy_id"):
    obj["platformSettingProxyManagerUpdateProxyId"] = module_params.get("platform_setting_proxy_manager_update_proxy_id")
  if module_params.get("platform_setting_managed_detect_response_use_primary_tenant_settings_enabled"):
    obj["platformSettingManagedDetectResponseUsePrimaryTenantSettingsEnabled"] = module_params.get("platform_setting_managed_detect_response_use_primary_tenant_settings_enabled")
  if module_params.get("platform_setting_event_forwarding_sns_access_key"):
    obj["platformSettingEventForwardingSnsAccessKey"] = module_params.get("platform_setting_event_forwarding_sns_access_key")
  if module_params.get("platform_setting_agent_initiated_activation_specify_hostname_enabled"):
    obj["platformSettingAgentInitiatedActivationSpecifyHostnameEnabled"] = module_params.get("platform_setting_agent_initiated_activation_specify_hostname_enabled")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_sync_with_cloud_account_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantSyncWithCloudAccountEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_sync_with_cloud_account_enabled")
  if module_params.get("platform_setting_connected_threat_defenses_use_primary_tenant_server_settings_enabled"):
    obj["platformSettingConnectedThreatDefensesUsePrimaryTenantServerSettingsEnabled"] = module_params.get("platform_setting_connected_threat_defenses_use_primary_tenant_server_settings_enabled")
  if module_params.get("platform_setting_inactive_agent_cleanup_duration"):
    obj["platformSettingInactiveAgentCleanupDuration"] = module_params.get("platform_setting_inactive_agent_cleanup_duration")
  if module_params.get("platform_setting_agent_initiated_activation_duplicate_hostname_mode"):
    obj["platformSettingAgentInitiatedActivationDuplicateHostnameMode"] = module_params.get("platform_setting_agent_initiated_activation_duplicate_hostname_mode")
  if module_params.get("platform_setting_vmware_nsx_manager_node"):
    obj["platformSettingVmwareNsxManagerNode"] = module_params.get("platform_setting_vmware_nsx_manager_node")
  if module_params.get("platform_setting_user_enforce_terms_and_conditions_title"):
    obj["platformSettingUserEnforceTermsAndConditionsTitle"] = module_params.get("platform_setting_user_enforce_terms_and_conditions_title")
  if module_params.get("platform_setting_primary_tenant_allow_tenant_add_vmware_vcenter_enabled"):
    obj["platformSettingPrimaryTenantAllowTenantAddVmwareVcenterEnabled"] = module_params.get("platform_setting_primary_tenant_allow_tenant_add_vmware_vcenter_enabled")
  if module_params.get("platform_setting_new_tenant_download_security_update_enabled"):
    obj["platformSettingNewTenantDownloadSecurityUpdateEnabled"] = module_params.get("platform_setting_new_tenant_download_security_update_enabled")
  if module_params.get("platform_setting_tenant_protection_usage_monitoring_computer_id_3"):
    obj["platformSettingTenantProtectionUsageMonitoringComputerId3"] = module_params.get("platform_setting_tenant_protection_usage_monitoring_computer_id_3")
  if module_params.get("platform_setting_agent_initiated_activation_reactivate_unknown_enabled"):
    obj["platformSettingAgentInitiatedActivationReactivateUnknownEnabled"] = module_params.get("platform_setting_agent_initiated_activation_reactivate_unknown_enabled")
  if module_params.get("platform_setting_tenant_protection_usage_monitoring_computer_id_2"):
    obj["platformSettingTenantProtectionUsageMonitoringComputerId2"] = module_params.get("platform_setting_tenant_protection_usage_monitoring_computer_id_2")
  if module_params.get("platform_setting_agent_initiated_activation_policy_id"):
    obj["platformSettingAgentInitiatedActivationPolicyId"] = module_params.get("platform_setting_agent_initiated_activation_policy_id")
  if module_params.get("platform_setting_tenant_protection_usage_monitoring_computer_id_1"):
    obj["platformSettingTenantProtectionUsageMonitoringComputerId1"] = module_params.get("platform_setting_tenant_protection_usage_monitoring_computer_id_1")
  if module_params.get("platform_setting_trend_micro_xdr_api_server_url"):
    obj["platformSettingTrendMicroXdrApiServerUrl"] = module_params.get("platform_setting_trend_micro_xdr_api_server_url")
  if module_params.get("platform_setting_retain_agent_installers_per_platform_max"):
    obj["platformSettingRetainAgentInstallersPerPlatformMax"] = module_params.get("platform_setting_retain_agent_installers_per_platform_max")
  if module_params.get("application_control_setting_serve_rulesets_from_relays_enabled"):
    obj["applicationControlSettingServeRulesetsFromRelaysEnabled"] = module_params.get("application_control_setting_serve_rulesets_from_relays_enabled")
  if module_params.get("integrity_monitoring_setting_event_rank_severity_high"):
    obj["integrityMonitoringSettingEventRankSeverityHigh"] = module_params.get("integrity_monitoring_setting_event_rank_severity_high")
  if module_params.get("platform_setting_saml_retain_inactive_external_administrators_duration"):
    obj["platformSettingSamlRetainInactiveExternalAdministratorsDuration"] = module_params.get("platform_setting_saml_retain_inactive_external_administrators_duration")
  if module_params.get("intrusion_prevention_setting_retain_event_duration"):
    obj["intrusionPreventionSettingRetainEventDuration"] = module_params.get("intrusion_prevention_setting_retain_event_duration")
  if module_params.get("platform_setting_http_public_key_pin_policy_report_only_enabled"):
    obj["platformSettingHttpPublicKeyPinPolicyReportOnlyEnabled"] = module_params.get("platform_setting_http_public_key_pin_policy_report_only_enabled")
  if module_params.get("platform_setting_saml_service_provider_name"):
    obj["platformSettingSamlServiceProviderName"] = module_params.get("platform_setting_saml_service_provider_name")
  if module_params.get("firewall_setting_internet_connectivity_test_url"):
    obj["firewallSettingInternetConnectivityTestUrl"] = module_params.get("firewall_setting_internet_connectivity_test_url")
  if module_params.get("platform_setting_saml_service_provider_certificate_expiry_warning_days"):
    obj["platformSettingSamlServiceProviderCertificateExpiryWarningDays"] = module_params.get("platform_setting_saml_service_provider_certificate_expiry_warning_days")
  if module_params.get("platform_setting_proxy_agent_update_proxy_id"):
    obj["platformSettingProxyAgentUpdateProxyId"] = module_params.get("platform_setting_proxy_agent_update_proxy_id")
  if module_params.get("platform_setting_ddan_auto_submission_enabled"):
    obj["platformSettingDdanAutoSubmissionEnabled"] = module_params.get("platform_setting_ddan_auto_submission_enabled")
  if module_params.get("platform_setting_ddan_manual_source_api_key"):
    obj["platformSettingDdanManualSourceApiKey"] = module_params.get("platform_setting_ddan_manual_source_api_key")
  if module_params.get("platform_setting_saml_service_provider_entity_id"):
    obj["platformSettingSamlServiceProviderEntityId"] = module_params.get("platform_setting_saml_service_provider_entity_id")
  if module_params.get("intrusion_prevention_setting_event_rank_severity_filter_error"):
    obj["intrusionPreventionSettingEventRankSeverityFilterError"] = module_params.get("intrusion_prevention_setting_event_rank_severity_filter_error")
  if module_params.get("intrusion_prevention_setting_event_rank_severity_filter_high"):
    obj["intrusionPreventionSettingEventRankSeverityFilterHigh"] = module_params.get("intrusion_prevention_setting_event_rank_severity_filter_high")
  if module_params.get("platform_setting_trend_micro_xdr_api_key"):
    obj["platformSettingTrendMicroXdrApiKey"] = module_params.get("platform_setting_trend_micro_xdr_api_key")
  if module_params.get("integrity_monitoring_setting_event_rank_severity_low"):
    obj["integrityMonitoringSettingEventRankSeverityLow"] = module_params.get("integrity_monitoring_setting_event_rank_severity_low")
  if module_params.get("platform_setting_trend_micro_xdr_company_id"):
    obj["platformSettingTrendMicroXdrCompanyId"] = module_params.get("platform_setting_trend_micro_xdr_company_id")


  return obj


def main():

    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        platform_setting_saml_identity_provider_certificate_expiry_warning_daysr=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_agent_security_on_missing_deep_security_manager_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_ddan_manual_source_server_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_load_balancer_manager_port=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smart_protection_feedback_threat_detections_threshold=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_run_port_scan_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        intrusion_prevention_setting_event_rank_severity_filter_medium=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_intranet_connectivity_test_expected_content_regex=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_event_forwarding_sns_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_timeout=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        web_reputation_setting_event_rank_risk_blocked_by_administrator_rank=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_lock_and_hide_tenant_storage_tab_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        anti_malware_setting_event_email_recipients=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_use_default_relay_group_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_http_strict_transport_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_intranet_connectivity_test_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_configure_sns_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_tenant_use_default_relay_group_from_primary_tenant_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_exported_diagnostic_package_locale=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        intrusion_prevention_setting_event_rank_severity_filter_critical=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_imported_software_auto_download_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_demo_mode_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_enforce_terms_and_conditions_message=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_trend_micro_xdr_common_log_receiver_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_managed_detect_response_company_guid=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_alert_default_email_address=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agent_initiated_activation_reactivate_cloned_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_managed_detect_response_server_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_share_managed_detect_responses_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_saml_service_provider_certificate=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_syslog_config_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smtp_start_tls_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_password_require_letters_and_numbers_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_synchronize_ldap_directories_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_load_balancer_relay_port=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_managed_detect_response_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_rules_policy_auto_apply_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_configure_forgot_password_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_password_require_not_same_as_username_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        log_inspection_setting_event_rank_severity_medium=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        anti_malware_setting_retain_event_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_agent_security_contact_primary_source_on_missing_relay_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_event_rank_severity_log_only=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_lock_and_hide_tenant_data_privacy_option_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        application_control_setting_retain_event_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_api_soap_web_service_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_saml_service_provider_private_key=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_windows_upgrade_on_activation_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_system_event_forwarding_snmp_port=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_event_rank_severity_deny=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        intrusion_prevention_setting_event_rank_severity_filter_low=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_control_impersonation_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_recommendation_cpu_usage_level=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_managed_detect_response_service_token=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_load_balancer_heartbeat_address=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_trend_micro_xdr_api_user=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_content_security_policy_report_only_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        log_inspection_setting_retain_event_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        anti_malware_setting_event_email_body_template=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_retain_security_updates_max=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_connected_threat_defense_control_manager_source_option=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        anti_malware_setting_event_email_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_agent_software_use_download_center_on_missing_deep_security_manager_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_recommendation_ongoing_scans_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agent_initiated_activation_token=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_password_length_min=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_database_state=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_aws_manager_identity_use_instance_role_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_content_security_policy=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_product_usage_data_collection_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_alert_agent_update_pending_threshold=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_password_require_special_characters_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_appliance_default_agent_version=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_system_event_forwarding_snmp_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smtp_bounce_email_address=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_relay_security_support_agent_9and_earlier_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_managed_detect_response_proxy_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_trend_micro_xdr_log_server_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_inactive_agent_cleanup_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_load_balancer_relay_address=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_http_public_key_pin_policy=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_session_idle_timeout=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        anti_malware_setting_event_email_subject=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_connected_threat_defense_control_manager_use_proxy_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_enforce_terms_and_conditions_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_aws_manager_identity_access_key=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_connected_threat_defense_control_manager_proxy_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_tenant_allow_impersonation_by_primary_tenant_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_connected_threat_defense_control_manager_manual_source_server_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_password_require_mixed_case_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_trend_micro_xdr_identity_provider_api_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smart_protection_feedback_for_suspicious_file_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_configure_snmp_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smart_protection_feedback_industry_type=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        web_reputation_setting_retain_event_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_retain_server_log_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        integrity_monitoring_setting_event_rank_severity_medium=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_proxy_manager_cloud_proxy_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_relay_security_all_regions_patterns_download_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_ddan_submission_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        web_reputation_setting_event_rank_risk_suspicious=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        integrity_monitoring_setting_event_rank_severity_critical=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smtp_from_email_address=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_global_stateful_config_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_event_forwarding_sns_topic_arn=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_internet_connectivity_test_expected_content_regex=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_connected_threat_defense_control_manager_manual_source_api_key=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_load_balancer_manager_address=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_security_primary_source_mode=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_share_connected_threat_defenses_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        web_reputation_setting_event_rank_risk_dangerous=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_load_balancer_heartbeat_port=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_hide_unlicensed_modules_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_capture_encrypted_traffic_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_retain_system_event_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_password_expiry=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smart_protection_feedback_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        integrity_monitoring_setting_retain_event_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_use_scheduled_run_script_task_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        log_inspection_setting_event_rank_severity_critical=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_lock_and_hide_tenant_smtp_tab_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_ddan_proxy_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agent_initiated_activation_within_ip_list_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_security_primary_source_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agentless_vcloud_protection_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_linux_upgrade_on_activation_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_trend_micro_xdr_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_active_sessions_max_exceeded_action=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_hostname_on_ip_change_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        log_inspection_setting_event_rank_severity_high=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smtp_requires_authentication_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_active_sessions_max=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_aws_external_id_retrieval_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        log_inspection_setting_event_rank_severity_low=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_azure_sso_certificate=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smtp_username=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_event_forwarding_sns_advanced_config_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_internet_connectivity_test_interval=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_whois_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_ddan_source_option=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_connected_threat_defense_control_manager_suspicious_object_list_comparison_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_exported_file_character_encoding=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_session_duration_max=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_update_software_alternate_update_server_urls=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_retain_counters_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_run_computer_discovery_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smart_protection_feedback_interval=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_system_event_forwarding_snmp_address=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smtp_server_address=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_configure_siem_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smtp_password=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_event_forwarding_sns_config_json=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_retain_event_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        web_reputation_setting_event_rank_risk_untested=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_managed_detect_response_use_proxy_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_event_forwarding_sns_secret_key=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_logo_binary_image_img=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_aws_manager_identity_secret_key=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        web_reputation_setting_event_rank_risk_highly_suspicious=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_api_status_monitoring_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_sign_in_page_message=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_password_expiry_send_email_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_sign_in_attempts_allowed_number=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_ddan_use_proxy_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agent_initiated_activation_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_configure_remember_me_option_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_smart_protection_feedback_bandwidth_max_kbytes=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_event_rank_severity_packet_rejection=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_proxy_manager_update_proxy_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_managed_detect_response_use_primary_tenant_settings_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_event_forwarding_sns_access_key=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agent_initiated_activation_specify_hostname_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_sync_with_cloud_account_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_connected_threat_defenses_use_primary_tenant_server_settings_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_inactive_agent_cleanup_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agent_initiated_activation_duplicate_hostname_mode=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_vmware_nsx_manager_node=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_user_enforce_terms_and_conditions_title=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_primary_tenant_allow_tenant_add_vmware_vcenter_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_new_tenant_download_security_update_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_tenant_protection_usage_monitoring_computer_id_3=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agent_initiated_activation_reactivate_unknown_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_tenant_protection_usage_monitoring_computer_id_2=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_agent_initiated_activation_policy_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_tenant_protection_usage_monitoring_computer_id_1=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_trend_micro_xdr_api_server_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_retain_agent_installers_per_platform_max=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        application_control_setting_serve_rulesets_from_relays_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        integrity_monitoring_setting_event_rank_severity_high=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_saml_retain_inactive_external_administrators_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        intrusion_prevention_setting_retain_event_duration=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_http_public_key_pin_policy_report_only_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_saml_service_provider_name=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        firewall_setting_internet_connectivity_test_url=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_saml_service_provider_certificate_expiry_warning_days=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_proxy_agent_update_proxy_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_ddan_auto_submission_enabled=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_ddan_manual_source_api_key=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_saml_service_provider_entity_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        intrusion_prevention_setting_event_rank_severity_filter_error=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        intrusion_prevention_setting_event_rank_severity_filter_high=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_trend_micro_xdr_api_key=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        integrity_monitoring_setting_event_rank_severity_low=dict(type="dict", options=dict(value=dict(type="str", required=False))),
        platform_setting_trend_micro_xdr_company_id=dict(type="dict", options=dict(value=dict(type="str", required=False))),
    )

    api_object = '/api/systemsettings'
    api_return = 'systemsettings'

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))  
    search_existing_systemsettings, temp_systemsettings = check_if_systemsettings_config_exists(deepsec_request, want, api_object)
  
    if search_existing_systemsettings and module.params["state"] == "absent":
      reset_systemsettings_config(module, deepsec_request, want, api_object)
    elif not search_existing_systemsettings and module.params["state"] == "absent":
      module.exit_json(systemsettings=temp_systemsettings, changed=False)
    elif search_existing_systemsettings:
      module.exit_json(systemsettings=temp_systemsettings, changed=False)
    else:
      systemsettings = deepsec_request.post(api_object, data=want)
      module.exit_json(systemsettings=systemsettings, changed=True)

if __name__ == "__main__":
    main()

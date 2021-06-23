#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
module: deepsec_system_settings
short_description: Modify the system settings for TrendMicro Deep Security.
description:
  - This module modifies system settings under TrendMicro Deep Security.
version_added: "1.1.0"
options:
  config:
    description: System settings config
    type: dict
    suboptions:
      name:
        description: System Settings name
        type: list
        elements: str
      platform_setting_saml_identity_provider_certificate_expiry_warning_daysr:
        description: platform setting saml identity provider certificate expiry warning days
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "30"
      platform_setting_update_agent_security_on_missing_deep_security_manager_enabled:
        description: platform setting update agent security on missing deep security manager enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_ddan_manual_source_server_url:
        description: platform setting ddan manual source server url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_load_balancer_manager_port:
        description: platform setting load balancer manager port
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "4119"
      platform_setting_smart_protection_feedback_threat_detections_threshold:
        description: platform setting smart protection feedback threat detections threshold
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "10"
      platform_setting_primary_tenant_allow_tenant_run_port_scan_enabled:
        description: platform setting primary tenant allow tenant run port scan enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      intrusion_prevention_setting_event_rank_severity_filter_medium:
        description: intrusion prevention setting event rank severity filter medium
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "25"
      firewall_setting_intranet_connectivity_test_expected_content_regex:
        description: firewall setting intranet connectivity test expected content regex
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_event_forwarding_sns_enabled:
        description: platform setting event forwarding sns enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_timeout:
        description: platform setting tenant auto revoke impersonation by primary tenant timeout
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "4 Hours"
      web_reputation_setting_event_rank_risk_blocked_by_administrator_rank:
        description: web reputation setting event rank risk blocked by administrator rank
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "100"
      platform_setting_primary_tenant_lock_and_hide_tenant_storage_tab_enabled:
        description: platform setting primary tenant lock and hide tenant storage tab enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      anti_malware_setting_event_email_recipients:
        description: anti malware setting event email recipients
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_primary_tenant_allow_tenant_use_default_relay_group_enabled:
        description: platform setting primary tenant allow tenant use default relay group enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_http_strict_transport_enabled:
        description: platform setting http strict transport enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      firewall_setting_intranet_connectivity_test_url:
        description: firewall setting intranet connectivity test url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_primary_tenant_allow_tenant_configure_sns_enabled:
        description: platform setting primary tenant allow tenant configure sns enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_tenant_use_default_relay_group_from_primary_tenant_enabled:
        description: platform setting tenant use default relay group from primary tenant enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_exported_diagnostic_package_locale:
        description: platform setting exported diagnostic package locale
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "en_US"
      intrusion_prevention_setting_event_rank_severity_filter_critical:
        description: intrusion prevention setting event rank severity filter critical
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "100"
      platform_setting_update_imported_software_auto_download_enabled:
        description: platform setting update imported software auto download enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_demo_mode_enabled:
        description: platform setting demo mode enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_user_enforce_terms_and_conditions_message:
        description: platform setting user enforce terms and conditions message
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_trend_micro_xdr_common_log_receiver_url:
        description: platform setting trend micro xdr common log receiver url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_managed_detect_response_company_guid:
        description: platform setting managed detect response company guid
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_alert_default_email_address:
        description: platform setting alert default email address
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_agent_initiated_activation_reactivate_cloned_enabled:
        description: platform setting agent initiated activation reactivate cloned enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_managed_detect_response_server_url:
        description: platform setting managed detect response server url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_primary_tenant_share_managed_detect_responses_enabled:
        description: platform setting primary tenant share managed detect responses enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_saml_service_provider_certificate:
        description: platform setting saml service provider certificate
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_syslog_config_id:
        description: platform setting syslog config id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "0"
      platform_setting_smtp_start_tls_enabled:
        description: platform setting smtp start tls enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_user_password_require_letters_and_numbers_enabled:
        description: platform setting user password require letters and numbers enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_primary_tenant_allow_tenant_synchronize_ldap_directories_enabled:
        description: platform setting primary tenant allow tenant synchronize ldap directories enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_load_balancer_relay_port:
        description: platform setting load balancer relay port
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "4122"
      platform_setting_managed_detect_response_enabled:
        description: platform setting managed detect response enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_update_rules_policy_auto_apply_enabled:
        description: platform setting update rules policy auto apply enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_primary_tenant_allow_tenant_configure_forgot_password_enabled:
        description: platform setting primary tenant allow tenant configure forgot password enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_user_password_require_not_same_as_username_enabled:
        description: platform setting user password require not same as username enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      log_inspection_setting_event_rank_severity_medium:
        description: log inspection setting event rank severity medium
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "25"
      anti_malware_setting_retain_event_duration:
        description: anti malware setting retain event duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      platform_setting_update_agent_security_contact_primary_source_on_missing_relay_enabled:
        description: platform setting update agent security contact primary source on missing relay enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      firewall_setting_event_rank_severity_log_only:
        description: firewall setting event rank severity log only
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "1"
      platform_setting_primary_tenant_lock_and_hide_tenant_data_privacy_option_enabled:
        description: platform setting primary tenant lock and hide tenant data privacy option enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      application_control_setting_retain_event_duration:
        description: application control setting retain event duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      platform_setting_api_soap_web_service_enabled:
        description: platform setting api soap web service enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_saml_service_provider_private_key:
        description: platform setting saml service provider private key
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_windows_upgrade_on_activation_enabled:
        description: platform setting windows upgrade on activation enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_system_event_forwarding_snmp_port:
        description: platform setting system event forwarding snmp port
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "162"
      firewall_setting_event_rank_severity_deny:
        description: firewall setting event rank severity deny
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "100"
      intrusion_prevention_setting_event_rank_severity_filter_low:
        description: intrusion prevention setting event rank severity filter low
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "1"
      platform_setting_primary_tenant_allow_tenant_control_impersonation_enabled:
        description: platform setting primary tenant allow tenant control impersonation enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_recommendation_cpu_usage_level:
        description: platform setting recommendation cpu usage level
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "High"
      platform_setting_managed_detect_response_service_token:
        description: platform setting managed detect response service token
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_load_balancer_heartbeat_address:
        description: platform setting load balancer heartbeat address
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_trend_micro_xdr_api_user:
        description: platform setting trend micro xdr api user
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_content_security_policy_report_only_enabled:
        description: platform setting content security policy report only enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      log_inspection_setting_retain_event_duration:
        description: log inspection setting retain event duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_enabled:
        description: platform setting tenant auto revoke impersonation by primary tenant enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      anti_malware_setting_event_email_body_template:
        description: anti malware setting event email body template
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_retain_security_updates_max:
        description: platform setting retain security updates max
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "10"
      platform_setting_connected_threat_defense_control_manager_source_option:
        description: platform setting connected threat defense control manager source option
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Manually select an Apex Central server"
      anti_malware_setting_event_email_enabled:
        description: anti malware setting event email enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_update_agent_software_use_download_center_on_missing_deep_security_manager_enabled:
        description: platform setting update agent software use download center on missing deep security manager enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_recommendation_ongoing_scans_enabled:
        description: platform setting recommendation ongoing scans enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "No"
      platform_setting_agent_initiated_activation_token:
        description: platform setting agent initiated activation token
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_user_password_length_min:
        description: platform setting user password length min
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "8"
      platform_setting_primary_tenant_allow_tenant_database_state:
        description: platform setting primary tenant allow tenant database state
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "10"
      platform_setting_aws_manager_identity_use_instance_role_enabled:
        description: platform setting aws manager identity use instance role enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_content_security_policy:
        description: platform setting content security policy
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_product_usage_data_collection_enabled:
        description: platform setting product usage data collection enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_alert_agent_update_pending_threshold:
        description: platform setting alert agent update pending threshold
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      platform_setting_user_password_require_special_characters_enabled:
        description: platform setting user password require special characters enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_update_appliance_default_agent_version:
        description: platform setting update appliance default agent version
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_system_event_forwarding_snmp_enabled:
        description: platform setting system event forwarding snmp enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_smtp_bounce_email_address:
        description: platform setting smtp bounce email address
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_update_relay_security_support_agent_9and_earlier_enabled:
        description: platform setting update relay security support agent and earlier enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_managed_detect_response_proxy_id:
        description: platform setting managed detect response proxy id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_trend_micro_xdr_log_server_url:
        description: platform setting trend micro xdr log server url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_inactive_agent_cleanup_enabled:
        description: platform setting inactive agent cleanup enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_load_balancer_relay_address:
        description: platform setting load balancer relay address
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_http_public_key_pin_policy:
        description: platform setting http public key pin policy
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_user_session_idle_timeout:
        description: platform setting user session idle timeout
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "30 Minutes"
      anti_malware_setting_event_email_subject:
        description: anti malware setting event email subject
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_connected_threat_defense_control_manager_use_proxy_enabled:
        description: platform setting connected threat defense control manager use proxy enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_user_enforce_terms_and_conditions_enabled:
        description: platform setting user enforce terms and conditions enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_aws_manager_identity_access_key:
        description: platform setting aws manager identity access key
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_connected_threat_defense_control_manager_proxy_id:
        description: platform setting connected threat defense control manager proxy id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_tenant_allow_impersonation_by_primary_tenant_enabled:
        description: platform setting tenant allow impersonation by primary tenant enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_connected_threat_defense_control_manager_manual_source_server_url:
        description: platform setting connected threat defense control manager manual source server url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_user_password_require_mixed_case_enabled:
        description: platform setting user password require mixed case enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_trend_micro_xdr_identity_provider_api_url:
        description: platform setting trend micro xdr identity provider api url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_smart_protection_feedback_for_suspicious_file_enabled:
        description: platform setting smart protection feedback for suspicious file enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_primary_tenant_allow_tenant_configure_snmp_enabled:
        description: platform setting primary tenant allow tenant configure snmp enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_smart_protection_feedback_industry_type:
        description: platform setting smart protection feedback industry type
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Not specified"
      web_reputation_setting_retain_event_duration:
        description: web reputation setting retain event duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      platform_setting_retain_server_log_duration:
        description: platform setting retain server log duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      integrity_monitoring_setting_event_rank_severity_medium:
        description: integrity monitoring setting event rank severity medium
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "25"
      platform_setting_proxy_manager_cloud_proxy_id:
        description: platform setting proxy manager cloud proxy id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_update_relay_security_all_regions_patterns_download_enabled:
        description: platform setting update relay security all regions patterns download enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_ddan_submission_enabled:
        description: platform setting ddan submission enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      web_reputation_setting_event_rank_risk_suspicious:
        description: web reputation setting event rank risk suspicious
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "25"
      integrity_monitoring_setting_event_rank_severity_critical:
        description: integrity monitoring setting event rank severity critical
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "100"
      platform_setting_smtp_from_email_address:
        description: platform setting smtp from email address
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      firewall_setting_global_stateful_config_id:
        description: firewall setting global stateful config id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "0"
      platform_setting_event_forwarding_sns_topic_arn:
        description: platform setting event forwarding sns topic arn
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      firewall_setting_internet_connectivity_test_expected_content_regex:
        description: firewall setting internet connectivity test expected content regex
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_connected_threat_defense_control_manager_manual_source_api_key:
        description: platform setting connected threat defense control manager manual source api key
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_load_balancer_manager_address:
        description: platform setting load balancer manager address
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_update_security_primary_source_mode:
        description: platform setting update security primary source mode
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Trend Micro ActiveUpdate Server"
      platform_setting_primary_tenant_share_connected_threat_defenses_enabled:
        description: platform setting primary tenant share connected threat defenses enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      web_reputation_setting_event_rank_risk_dangerous:
        description: web reputation setting event rank risk dangerous
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "100"
      platform_setting_load_balancer_heartbeat_port:
        description: platform setting load balancer heartbeat port
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "4120"
      platform_setting_user_hide_unlicensed_modules_enabled:
        description: platform setting user hide unlicensed modules enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_capture_encrypted_traffic_enabled:
        description: platform setting capture encrypted traffic enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_retain_system_event_duration:
        description: platform setting retain system event duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "53 weeks"
      platform_setting_user_password_expiry:
        description: platform setting user password expiry
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Never"
      platform_setting_smart_protection_feedback_enabled:
        description: platform setting smart protection feedback enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      integrity_monitoring_setting_retain_event_duration:
        description: integrity monitoring setting retain event duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      platform_setting_primary_tenant_allow_tenant_use_scheduled_run_script_task_enabled:
        description: platform setting primary tenant allow tenant use scheduled run script task enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      log_inspection_setting_event_rank_severity_critical:
        description: log inspection setting event rank severity critical
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "100"
      platform_setting_primary_tenant_lock_and_hide_tenant_smtp_tab_enabled:
        description: platform setting primary tenant lock and hide tenant smtp tab enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_ddan_proxy_id:
        description: platform setting ddan proxy id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_agent_initiated_activation_within_ip_list_id:
        description: platform setting agent initiated activation within ip list id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_update_security_primary_source_url:
        description: platform setting update security primary source url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "http://"
      platform_setting_agentless_vcloud_protection_enabled:
        description: platform setting agentless vcloud protection enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_linux_upgrade_on_activation_enabled:
        description: platform setting linux upgrade on activation enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_trend_micro_xdr_enabled:
        description: platform setting trend micro xdr enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_active_sessions_max_exceeded_action:
        description: platform setting active sessions max exceeded action
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Block new sessions"
      platform_setting_update_hostname_on_ip_change_enabled:
        description: platform setting update hostname on ip change enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      log_inspection_setting_event_rank_severity_high:
        description: log inspection setting event rank severity high
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "50"
      platform_setting_smtp_requires_authentication_enabled:
        description: platform setting smtp requires authentication enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_active_sessions_max:
        description: platform setting active sessions max
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "10"
      platform_setting_aws_external_id_retrieval_enabled:
        description: platform setting aws external id retrieval enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      log_inspection_setting_event_rank_severity_low:
        description: log inspection setting event rank severity low
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "1"
      platform_setting_azure_sso_certificate:
        description: platform setting azure sso certificate
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_smtp_username:
        description: platform setting smtp username
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_event_forwarding_sns_advanced_config_enabled:
        description: platform setting event forwarding sns advanced config enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      firewall_setting_internet_connectivity_test_interval:
        description: firewall setting internet connectivity test interval
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "10 Seconds"
      platform_setting_whois_url:
        description: platform setting whois url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_ddan_source_option:
        description: platform setting ddan source option
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Manually select a Deep Discovery Analyzer server"
      platform_setting_connected_threat_defense_control_manager_suspicious_object_list_comparison_enabled:
        description: platform setting connected threat defense control manager suspicious object list comparison enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_exported_file_character_encoding:
        description: platform setting exported file character encoding
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "US-ASCII"
      platform_setting_user_session_duration_max:
        description: platform setting user session duration max
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "No Limit"
      platform_setting_update_software_alternate_update_server_urls:
        description: platform setting update software alternate update server urls
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_retain_counters_duration:
        description: platform setting retain counters duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "13 Weeks"
      platform_setting_primary_tenant_allow_tenant_run_computer_discovery_enabled:
        description: platform setting primary tenant allow tenant run computer discovery enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_smart_protection_feedback_interval:
        description: platform setting smart protection feedback interval
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "5"
      platform_setting_system_event_forwarding_snmp_address:
        description: platform setting system event forwarding snmp address
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_smtp_server_address:
        description: platform setting smtp server address
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_primary_tenant_allow_tenant_configure_siem_enabled:
        description: platform setting primary tenant allow tenant configure siem enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_smtp_password:
        description: platform setting smtp password
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_event_forwarding_sns_config_json:
        description: platform setting event forwarding sns config json
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      firewall_setting_retain_event_duration:
        description: firewall setting retain event duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      web_reputation_setting_event_rank_risk_untested:
        description: web reputation setting event rank risk untested
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "25"
      platform_setting_managed_detect_response_use_proxy_enabled:
        description: platform setting managed detect response use proxy enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_event_forwarding_sns_secret_key:
        description: platform setting event forwarding sns secret key
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_logo_binary_image_img:
        description: platform setting logo binary image img
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_aws_manager_identity_secret_key:
        description: platform setting aws manager identity secret key
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      web_reputation_setting_event_rank_risk_highly_suspicious:
        description: web reputation setting event rank risk highly suspicious
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "50"
      platform_setting_api_status_monitoring_enabled:
        description: platform setting api status monitoring enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_sign_in_page_message:
        description: platform setting sign in page message
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_user_password_expiry_send_email_enabled:
        description: platform setting user password expiry send email enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_user_sign_in_attempts_allowed_number:
        description: platform setting user sign in attempts allowed number
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "5"
      platform_setting_ddan_use_proxy_enabled:
        description: platform setting ddan use proxy enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_agent_initiated_activation_enabled:
        description: platform setting agent initiated activation enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "For any computers"
      platform_setting_primary_tenant_allow_tenant_configure_remember_me_option_enabled:
        description: platform setting primary tenant allow tenant configure remember me option enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_smart_protection_feedback_bandwidth_max_kbytes:
        description: platform setting smart protection feedback bandwidth max kbytes
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "32"
      firewall_setting_event_rank_severity_packet_rejection:
        description: firewall setting event rank severity packet rejection
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "50"
      platform_setting_proxy_manager_update_proxy_id:
        description: platform setting proxy manager update proxy id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_managed_detect_response_use_primary_tenant_settings_enabled:
        description: platform setting managed detect response use primary tenant settings enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_event_forwarding_sns_access_key:
        description: platform setting event forwarding sns access key
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_agent_initiated_activation_specify_hostname_enabled:
        description: platform setting agent initiated activation specify hostname enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_primary_tenant_allow_tenant_sync_with_cloud_account_enabled:
        description: platform setting primary tenant allow tenant sync with cloud account enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_connected_threat_defenses_use_primary_tenant_server_settings_enabled:
        description: platform setting connected threat defenses use primary tenant server settings enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_inactive_agent_cleanup_duration:
        description: platform setting inactive agent cleanup duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "1 Month"
      platform_setting_agent_initiated_activation_duplicate_hostname_mode:
        description: platform setting agent initiated activation duplicate hostname mode
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Re-activate the existing Computer"
      platform_setting_vmware_nsx_manager_node:
        description: platform setting vmware nsx manager node
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "1"
      platform_setting_user_enforce_terms_and_conditions_title:
        description: platform setting user enforce terms and conditions title
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_primary_tenant_allow_tenant_add_vmware_vcenter_enabled:
        description: platform setting primary tenant allow tenant add vmware vcenter enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_new_tenant_download_security_update_enabled:
        description: platform setting new tenant download security update enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_tenant_protection_usage_monitoring_computer_id_3:
        description: platform setting tenant protection usage monitoring computer id 3
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Platform"
      platform_setting_agent_initiated_activation_reactivate_unknown_enabled:
        description: platform setting agent initiated activation reactivate unknown enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_tenant_protection_usage_monitoring_computer_id_2:
        description: platform setting tenant protection usage monitoring computer id 2
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Last Used IP Address"
      platform_setting_agent_initiated_activation_policy_id:
        description: platform setting agent initiated activation policy id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_tenant_protection_usage_monitoring_computer_id_1:
        description: platform setting tenant protection usage monitoring computer id 1
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "Hostname"
      platform_setting_trend_micro_xdr_api_server_url:
        description: platform setting trend micro xdr api server url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_retain_agent_installers_per_platform_max:
        description: platform setting retain agent installers per platform max
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "5"
      application_control_setting_serve_rulesets_from_relays_enabled:
        description: application control setting serve rulesets from relays enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      integrity_monitoring_setting_event_rank_severity_high:
        description: integrity monitoring setting event rank severity high
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "50"
      platform_setting_saml_retain_inactive_external_administrators_duration:
        description: platform setting saml retain inactive external administrators duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "365"
      intrusion_prevention_setting_retain_event_duration:
        description: intrusion prevention setting retain event duration
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "7 Days"
      platform_setting_http_public_key_pin_policy_report_only_enabled:
        description: platform setting http public key pin policy report only enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "true"
      platform_setting_saml_service_provider_name:
        description: platform setting saml service provider name
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      firewall_setting_internet_connectivity_test_url:
        description: firewall setting internet connectivity test url
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_saml_service_provider_certificate_expiry_warning_days:
        description: platform setting saml service provider certificate expiry warning days
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "30"
      platform_setting_proxy_agent_update_proxy_id:
        description: platform setting proxy agent update proxy id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_ddan_auto_submission_enabled:
        description: platform setting ddan auto submission enabled
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "false"
      platform_setting_ddan_manual_source_api_key:
        description: platform setting ddan manual source api key
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      platform_setting_saml_service_provider_entity_id:
        description: platform setting saml service provider entity id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      intrusion_prevention_setting_event_rank_severity_filter_error:
        description: intrusion prevention setting event rank severity filter error
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "100"
      intrusion_prevention_setting_event_rank_severity_filter_high:
        description: intrusion prevention setting event rank severity filter high
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "50"
      platform_setting_trend_micro_xdr_api_key:
        description: platform setting trend micro xdr api key
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
      integrity_monitoring_setting_event_rank_severity_low:
        description: integrity monitoring setting event rank severity low
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
            default: "1"
      platform_setting_trend_micro_xdr_company_id:
        description: platform setting trend micro xdr company id
        type: dict
        suboptions:
          value:
            description: Value of a Setting.
            type: str
  state:
    description:
      - The state the configuration should be left in
      - The state I(gathered) will get the module API configuration from the device and
        transform it into structured data in the format as per the module argspec and
        the value is returned in the I(gathered) key within the result.
    type: str
    choices:
      - present
      - absent
      - gathered
    default: present
author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
"""

EXAMPLES = """

- name: Apply the input config to System Settings config
  trendmicro.deepsec.deepsec_system_settings:
    state: present
    config:
      platform_setting_syslog_config_id:
        value: 12
      platform_setting_http_strict_transport_enabled:
        value: true
      platform_setting_demo_mode_enabled:
        value: true

# Play Run:
# =========
#
# "system_settings": {
#         "after": {
#             "platform_setting_demo_mode_enabled": {
#                 "value": true
#             },
#             "platform_setting_http_strict_transport_enabled": {
#                 "value": true
#             },
#             "platform_setting_syslog_config_id": {
#                 "value": "12"
#             }
#         },
#         "before": {
#             "platform_setting_demo_mode_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_http_strict_transport_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_syslog_config_id": {
#                 "value": "0"
#             }
#         }
#     }

- name: Reset/Delete the input System Settings Config
  trendmicro.deepsec.deepsec_system_settings:
    state: absent
    config:
      name:
        - platform_setting_syslog_config_id
        - platform_setting_http_strict_transport_enabled
        - platform_setting_demo_mode_enabled

# Play Run:
# =========
#
# "system_settings": {
#         "after": {
#             "platform_setting_demo_mode_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_http_strict_transport_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_syslog_config_id": {
#                 "value": "0"
#             }
#         },
#         "before": {
#             "platform_setting_demo_mode_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_http_strict_transport_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_syslog_config_id": {
#                 "value": "12"
#             }
#         }
#     }

- name: Gather/Get System Settings by System Settings Name
  trendmicro.deepsec.deepsec_system_settings:
    state: gathered
    config:
      name:
        - platform_setting_syslog_config_id
        - platform_setting_http_strict_transport_enabled
        - platform_setting_demo_mode_enabled

# Play Run:
# =========
#
# "gathered": {
#         "config": {
#             "platform_setting_demo_mode_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_http_strict_transport_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_syslog_config_id": {
#                 "value": "0"
#             }
#         }
#     }

- name: Gather/Get the complete System Settings
  trendmicro.deepsec.deepsec_system_settings:
    state: gathered

# Play Run:
# =========
#
# "gathered": {
#         "config": {
#             "anti_malware_setting_event_email_body_template": {
#                 "value": ""
#             },
#             "anti_malware_setting_event_email_enabled": {
#                 "value": "false"
#             },
#             "anti_malware_setting_event_email_recipients": {
#                 "value": ""
#             },
#             "anti_malware_setting_event_email_subject": {
#                 "value": ""
#             },
#             "anti_malware_setting_retain_event_duration": {
#                 "value": "7 Days"
#             },
#             "application_control_setting_retain_event_duration": {
#                 "value": "7 Days"
#             },
#             "application_control_setting_serve_rulesets_from_relays_enabled": {
#                 "value": "false"
#             },
#             "firewall_setting_event_rank_severity_deny": {
#                 "value": "100"
#             },
#             "firewall_setting_event_rank_severity_log_only": {
#                 "value": "1"
#             },
#             "firewall_setting_event_rank_severity_packet_rejection": {
#                 "value": "50"
#             },
#             "firewall_setting_global_stateful_config_id": {
#                 "value": "0"
#             },
#             "firewall_setting_internet_connectivity_test_expected_content_regex": {
#                 "value": ""
#             },
#             "firewall_setting_internet_connectivity_test_interval": {
#                 "value": "10 Seconds"
#             },
#             "firewall_setting_internet_connectivity_test_url": {
#                 "value": ""
#             },
#             "firewall_setting_intranet_connectivity_test_expected_content_regex": {
#                 "value": ""
#             },
#             "firewall_setting_intranet_connectivity_test_url": {
#                 "value": ""
#             },
#             "firewall_setting_retain_event_duration": {
#                 "value": "7 Days"
#             },
#             "integrity_monitoring_setting_event_rank_severity_critical": {
#                 "value": "100"
#             },
#             "integrity_monitoring_setting_event_rank_severity_high": {
#                 "value": "50"
#             },
#             "integrity_monitoring_setting_event_rank_severity_low": {
#                 "value": "1"
#             },
#             "integrity_monitoring_setting_event_rank_severity_medium": {
#                 "value": "25"
#             },
#             "integrity_monitoring_setting_retain_event_duration": {
#                 "value": "7 Days"
#             },
#             "intrusion_prevention_setting_event_rank_severity_filter_critical": {
#                 "value": "100"
#             },
#             "intrusion_prevention_setting_event_rank_severity_filter_error": {
#                 "value": "100"
#             },
#             "intrusion_prevention_setting_event_rank_severity_filter_high": {
#                 "value": "50"
#             },
#             "intrusion_prevention_setting_event_rank_severity_filter_low": {
#                 "value": "1"
#             },
#             "intrusion_prevention_setting_event_rank_severity_filter_medium": {
#                 "value": "25"
#             },
#             "intrusion_prevention_setting_retain_event_duration": {
#                 "value": "7 Days"
#             },
#             "log_inspection_setting_event_rank_severity_critical": {
#                 "value": "100"
#             },
#             "log_inspection_setting_event_rank_severity_high": {
#                 "value": "50"
#             },
#             "log_inspection_setting_event_rank_severity_low": {
#                 "value": "1"
#             },
#             "log_inspection_setting_event_rank_severity_medium": {
#                 "value": "25"
#             },
#             "log_inspection_setting_retain_event_duration": {
#                 "value": "7 Days"
#             },
#             "platform_setting_active_sessions_max": {
#                 "value": "10"
#             },
#             "platform_setting_active_sessions_max_exceeded_action": {
#                 "value": "Block new sessions"
#             },
#             "platform_setting_agent_initiated_activation_duplicate_hostname_mode": {
#                 "value": "Re-activate the existing Computer"
#             },
#             "platform_setting_agent_initiated_activation_enabled": {
#                 "value": "For any computers"
#             },
#             "platform_setting_agent_initiated_activation_policy_id": {
#                 "value": ""
#             },
#             "platform_setting_agent_initiated_activation_reactivate_cloned_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_agent_initiated_activation_reactivate_unknown_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_agent_initiated_activation_specify_hostname_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_agent_initiated_activation_token": {
#                 "value": ""
#             },
#             "platform_setting_agent_initiated_activation_within_ip_list_id": {
#                 "value": ""
#             },
#             "platform_setting_agentless_vcloud_protection_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_alert_agent_update_pending_threshold": {
#                 "value": "7 Days"
#             },
#             "platform_setting_alert_default_email_address": {
#                 "value": ""
#             },
#             "platform_setting_api_soap_web_service_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_api_status_monitoring_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_aws_external_id_retrieval_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_aws_manager_identity_access_key": {
#                 "value": ""
#             },
#             "platform_setting_aws_manager_identity_secret_key": {
#                 "value": ""
#             },
#             "platform_setting_aws_manager_identity_use_instance_role_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_azure_sso_certificate": {
#                 "value": ""
#             },
#             "platform_setting_capture_encrypted_traffic_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_connected_threat_defense_control_manager_manual_source_api_key": {
#                 "value": ""
#             },
#             "platform_setting_connected_threat_defense_control_manager_manual_source_server_url": {
#                 "value": ""
#             },
#             "platform_setting_connected_threat_defense_control_manager_proxy_id": {
#                 "value": ""
#             },
#             "platform_setting_connected_threat_defense_control_manager_source_option": {
#                 "value": "Manually select an Apex Central server"
#             },
#             "platform_setting_connected_threat_defense_control_manager_suspicious_object_list_comparison_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_connected_threat_defense_control_manager_use_proxy_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_connected_threat_defenses_use_primary_tenant_server_settings_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_content_security_policy": {
#                 "value": ""
#             },
#             "platform_setting_content_security_policy_report_only_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_ddan_auto_submission_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_ddan_manual_source_api_key": {
#                 "value": ""
#             },
#             "platform_setting_ddan_manual_source_server_url": {
#                 "value": ""
#             },
#             "platform_setting_ddan_proxy_id": {
#                 "value": ""
#             },
#             "platform_setting_ddan_source_option": {
#                 "value": "Manually select a Deep Discovery Analyzer server"
#             },
#             "platform_setting_ddan_submission_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_ddan_use_proxy_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_demo_mode_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_event_forwarding_sns_access_key": {
#                 "value": ""
#             },
#             "platform_setting_event_forwarding_sns_advanced_config_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_event_forwarding_sns_config_json": {
#                 "value": ""
#             },
#             "platform_setting_event_forwarding_sns_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_event_forwarding_sns_secret_key": {
#                 "value": ""
#             },
#             "platform_setting_event_forwarding_sns_topic_arn": {
#                 "value": ""
#             },
#             "platform_setting_exported_diagnostic_package_locale": {
#                 "value": "en_US"
#             },
#             "platform_setting_exported_file_character_encoding": {
#                 "value": "US-ASCII"
#             },
#             "platform_setting_http_public_key_pin_policy": {
#                 "value": ""
#             },
#             "platform_setting_http_public_key_pin_policy_report_only_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_http_strict_transport_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_inactive_agent_cleanup_duration": {
#                 "value": "1 Month"
#             },
#             "platform_setting_inactive_agent_cleanup_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_linux_upgrade_on_activation_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_load_balancer_heartbeat_address": {
#                 "value": ""
#             },
#             "platform_setting_load_balancer_heartbeat_port": {
#                 "value": "4120"
#             },
#             "platform_setting_load_balancer_manager_address": {
#                 "value": ""
#             },
#             "platform_setting_load_balancer_manager_port": {
#                 "value": "4119"
#             },
#             "platform_setting_load_balancer_relay_address": {
#                 "value": ""
#             },
#             "platform_setting_load_balancer_relay_port": {
#                 "value": "4122"
#             },
#             "platform_setting_logo_binary_image_img": {
#                 "value": ""
#             },
#             "platform_setting_managed_detect_response_company_guid": {
#                 "value": ""
#             },
#             "platform_setting_managed_detect_response_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_managed_detect_response_proxy_id": {
#                 "value": ""
#             },
#             "platform_setting_managed_detect_response_server_url": {
#                 "value": ""
#             },
#             "platform_setting_managed_detect_response_service_token": {
#                 "value": ""
#             },
#             "platform_setting_managed_detect_response_use_primary_tenant_settings_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_managed_detect_response_use_proxy_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_new_tenant_download_security_update_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_primary_tenant_allow_tenant_add_vmware_vcenter_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_primary_tenant_allow_tenant_configure_forgot_password_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_allow_tenant_configure_remember_me_option_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_allow_tenant_configure_siem_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_allow_tenant_configure_snmp_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_allow_tenant_configure_sns_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_primary_tenant_allow_tenant_control_impersonation_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_allow_tenant_database_state": {
#                 "value": "10"
#             },
#             "platform_setting_primary_tenant_allow_tenant_run_computer_discovery_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_allow_tenant_run_port_scan_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_allow_tenant_sync_with_cloud_account_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_primary_tenant_allow_tenant_synchronize_ldap_directories_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_primary_tenant_allow_tenant_use_default_relay_group_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_allow_tenant_use_scheduled_run_script_task_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_lock_and_hide_tenant_data_privacy_option_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_lock_and_hide_tenant_smtp_tab_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_lock_and_hide_tenant_storage_tab_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_share_connected_threat_defenses_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_primary_tenant_share_managed_detect_responses_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_product_usage_data_collection_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_proxy_agent_update_proxy_id": {
#                 "value": ""
#             },
#             "platform_setting_proxy_manager_cloud_proxy_id": {
#                 "value": ""
#             },
#             "platform_setting_proxy_manager_update_proxy_id": {
#                 "value": ""
#             },
#             "platform_setting_recommendation_cpu_usage_level": {
#                 "value": "High"
#             },
#             "platform_setting_recommendation_ongoing_scans_enabled": {
#                 "value": "No"
#             },
#             "platform_setting_retain_agent_installers_per_platform_max": {
#                 "value": "5"
#             },
#             "platform_setting_retain_counters_duration": {
#                 "value": "13 Weeks"
#             },
#             "platform_setting_retain_security_updates_max": {
#                 "value": "10"
#             },
#             "platform_setting_retain_server_log_duration": {
#                 "value": "7 Days"
#             },
#             "platform_setting_retain_system_event_duration": {
#                 "value": "53 Weeks"
#             },
#             "platform_setting_saml_identity_provider_certificate_expiry_warning_daysr": {
#                 "value": "30"
#             },
#             "platform_setting_saml_retain_inactive_external_administrators_duration": {
#                 "value": "365"
#             },
#             "platform_setting_saml_service_provider_certificate": {
#                 "value": ""
#             },
#             "platform_setting_saml_service_provider_certificate_expiry_warning_days": {
#                 "value": "30"
#             },
#             "platform_setting_saml_service_provider_entity_id": {
#                 "value": ""
#             },
#             "platform_setting_saml_service_provider_name": {
#                 "value": ""
#             },
#             "platform_setting_saml_service_provider_private_key": {
#                 "value": ""
#             },
#             "platform_setting_sign_in_page_message": {
#                 "value": ""
#             },
#             "platform_setting_smart_protection_feedback_bandwidth_max_kbytes": {
#                 "value": "32"
#             },
#             "platform_setting_smart_protection_feedback_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_smart_protection_feedback_for_suspicious_file_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_smart_protection_feedback_industry_type": {
#                 "value": "Not specified"
#             },
#             "platform_setting_smart_protection_feedback_interval": {
#                 "value": "5"
#             },
#             "platform_setting_smart_protection_feedback_threat_detections_threshold": {
#                 "value": "10"
#             },
#             "platform_setting_smtp_bounce_email_address": {
#                 "value": ""
#             },
#             "platform_setting_smtp_from_email_address": {
#                 "value": ""
#             },
#             "platform_setting_smtp_password": {
#                 "value": ""
#             },
#             "platform_setting_smtp_requires_authentication_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_smtp_server_address": {
#                 "value": ""
#             },
#             "platform_setting_smtp_start_tls_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_smtp_username": {
#                 "value": ""
#             },
#             "platform_setting_syslog_config_id": {
#                 "value": "0"
#             },
#             "platform_setting_system_event_forwarding_snmp_address": {
#                 "value": ""
#             },
#             "platform_setting_system_event_forwarding_snmp_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_system_event_forwarding_snmp_port": {
#                 "value": "162"
#             },
#             "platform_setting_tenant_allow_impersonation_by_primary_tenant_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_timeout": {
#                 "value": "4 Hours"
#             },
#             "platform_setting_tenant_protection_usage_monitoring_computer_id_1": {
#                 "value": "Hostname"
#             },
#             "platform_setting_tenant_protection_usage_monitoring_computer_id_2": {
#                 "value": "Last Used IP Address"
#             },
#             "platform_setting_tenant_protection_usage_monitoring_computer_id_3": {
#                 "value": "Platform"
#             },
#             "platform_setting_tenant_use_default_relay_group_from_primary_tenant_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_trend_micro_xdr_api_key": {
#                 "value": ""
#             },
#             "platform_setting_trend_micro_xdr_api_server_url": {
#                 "value": ""
#             },
#             "platform_setting_trend_micro_xdr_api_user": {
#                 "value": ""
#             },
#             "platform_setting_trend_micro_xdr_common_log_receiver_url": {
#                 "value": ""
#             },
#             "platform_setting_trend_micro_xdr_company_id": {
#                 "value": ""
#             },
#             "platform_setting_trend_micro_xdr_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_trend_micro_xdr_identity_provider_api_url": {
#                 "value": ""
#             },
#             "platform_setting_trend_micro_xdr_log_server_url": {
#                 "value": ""
#             },
#             "platform_setting_update_agent_security_contact_primary_source_on_missing_relay_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_update_agent_security_on_missing_deep_security_manager_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_update_agent_software_use_download_center_on_missing_deep_security_manager_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_update_appliance_default_agent_version": {
#                 "value": ""
#             },
#             "platform_setting_update_hostname_on_ip_change_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_update_imported_software_auto_download_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_update_relay_security_all_regions_patterns_download_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_update_relay_security_support_agent_9and_earlier_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_update_rules_policy_auto_apply_enabled": {
#                 "value": "true"
#             },
#             "platform_setting_update_security_primary_source_mode": {
#                 "value": "Trend Micro ActiveUpdate Server"
#             },
#             "platform_setting_update_security_primary_source_url": {
#                 "value": "http://"
#             },
#             "platform_setting_update_software_alternate_update_server_urls": {
#                 "value": ""
#             },
#             "platform_setting_user_enforce_terms_and_conditions_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_user_enforce_terms_and_conditions_message": {
#                 "value": ""
#             },
#             "platform_setting_user_enforce_terms_and_conditions_title": {
#                 "value": ""
#             },
#             "platform_setting_user_hide_unlicensed_modules_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_user_password_expiry": {
#                 "value": "Never"
#             },
#             "platform_setting_user_password_expiry_send_email_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_user_password_length_min": {
#                 "value": "8"
#             },
#             "platform_setting_user_password_require_letters_and_numbers_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_user_password_require_mixed_case_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_user_password_require_not_same_as_username_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_user_password_require_special_characters_enabled": {
#                 "value": "false"
#             },
#             "platform_setting_user_session_duration_max": {
#                 "value": "No Limit"
#             },
#             "platform_setting_user_session_idle_timeout": {
#                 "value": "30 Minutes"
#             },
#             "platform_setting_user_sign_in_attempts_allowed_number": {
#                 "value": "5"
#             },
#             "platform_setting_vmware_nsx_manager_node": {
#                 "value": "1"
#             },
#             "platform_setting_whois_url": {
#                 "value": ""
#             },
#             "platform_setting_windows_upgrade_on_activation_enabled": {
#                 "value": "false"
#             },
#             "web_reputation_setting_event_rank_risk_blocked_by_administrator_rank": {
#                 "value": "100"
#             },
#             "web_reputation_setting_event_rank_risk_dangerous": {
#                 "value": "100"
#             },
#             "web_reputation_setting_event_rank_risk_highly_suspicious": {
#                 "value": "50"
#             },
#             "web_reputation_setting_event_rank_risk_suspicious": {
#                 "value": "25"
#             },
#             "web_reputation_setting_event_rank_risk_untested": {
#                 "value": "25"
#             },
#             "web_reputation_setting_retain_event_duration": {
#                 "value": "7 Days"
#             }
#         }
#       }

"""

from ansible.module_utils.six import iteritems
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    delete_config_with_id,
    map_obj_to_params,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)


key_transform = {
    "platform_setting_saml_identity_provider_certificate_expiry_warning_daysr": "platformSettingSamlIdentityProviderCertificateExpiryWarningDays",
    "platform_setting_update_agent_security_on_missing_deep_security_manager_enabled": "platformSettingUpdateAgentSecurityOnMissingDeepSecurityManagerEnabled",
    "platform_setting_ddan_manual_source_server_url": "platformSettingDdanManualSourceServerUrl",
    "platform_setting_load_balancer_manager_port": "platformSettingLoadBalancerManagerPort",
    "platform_setting_smart_protection_feedback_threat_detections_threshold": "platformSettingSmartProtectionFeedbackThreatDetectionsThreshold",
    "platform_setting_primary_tenant_allow_tenant_run_port_scan_enabled": "platformSettingPrimaryTenantAllowTenantRunPortScanEnabled",
    "intrusion_prevention_setting_event_rank_severity_filter_medium": "intrusionPreventionSettingEventRankSeverityFilterMedium",
    "firewall_setting_intranet_connectivity_test_expected_content_regex": "firewallSettingIntranetConnectivityTestExpectedContentRegex",
    "platform_setting_event_forwarding_sns_enabled": "platformSettingEventForwardingSnsEnabled",
    "platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_timeout": "platformSettingTenantAutoRevokeImpersonationByPrimaryTenantTimeout",
    "web_reputation_setting_event_rank_risk_blocked_by_administrator_rank": "webReputationSettingEventRankRiskBlockedByAdministratorRank",
    "platform_setting_primary_tenant_lock_and_hide_tenant_storage_tab_enabled": "platformSettingPrimaryTenantLockAndHideTenantStorageTabEnabled",
    "anti_malware_setting_event_email_recipients": "antiMalwareSettingEventEmailRecipients",
    "platform_setting_primary_tenant_allow_tenant_use_default_relay_group_enabled": "platformSettingPrimaryTenantAllowTenantUseDefaultRelayGroupEnabled",
    "platform_setting_http_strict_transport_enabled": "platformSettingHttpStrictTransportEnabled",
    "firewall_setting_intranet_connectivity_test_url": "firewallSettingIntranetConnectivityTestUrl",
    "platform_setting_primary_tenant_allow_tenant_configure_sns_enabled": "platformSettingPrimaryTenantAllowTenantConfigureSnsEnabled",
    "platform_setting_tenant_use_default_relay_group_from_primary_tenant_enabled": "platformSettingTenantUseDefaultRelayGroupFromPrimaryTenantEnabled",
    "platform_setting_exported_diagnostic_package_locale": "platformSettingExportedDiagnosticPackageLocale",
    "intrusion_prevention_setting_event_rank_severity_filter_critical": "intrusionPreventionSettingEventRankSeverityFilterCritical",
    "platform_setting_update_imported_software_auto_download_enabled": "platformSettingUpdateImportedSoftwareAutoDownloadEnabled",
    "platform_setting_demo_mode_enabled": "platformSettingDemoModeEnabled",
    "platform_setting_user_enforce_terms_and_conditions_message": "platformSettingUserEnforceTermsAndConditionsMessage",
    "platform_setting_trend_micro_xdr_common_log_receiver_url": "platformSettingTrendMicroXdrCommonLogReceiverUrl",
    "platform_setting_managed_detect_response_company_guid": "platformSettingManagedDetectResponseCompanyGuid",
    "platform_setting_alert_default_email_address": "platformSettingAlertDefaultEmailAddress",
    "platform_setting_agent_initiated_activation_reactivate_cloned_enabled": "platformSettingAgentInitiatedActivationReactivateClonedEnabled",
    "platform_setting_managed_detect_response_server_url": "platformSettingManagedDetectResponseServerUrl",
    "platform_setting_primary_tenant_share_managed_detect_responses_enabled": "platformSettingPrimaryTenantShareManagedDetectResponsesEnabled",
    "platform_setting_saml_service_provider_certificate": "platformSettingSamlServiceProviderCertificate",
    "platform_setting_syslog_config_id": "platformSettingSyslogConfigId",
    "platform_setting_smtp_start_tls_enabled": "platformSettingSmtpStartTlsEnabled",
    "platform_setting_user_password_require_letters_and_numbers_enabled": "platformSettingUserPasswordRequireLettersAndNumbersEnabled",
    "platform_setting_primary_tenant_allow_tenant_synchronize_ldap"
    + "_directories_enabled": "platformSettingPrimaryTenantAllowTenantSynchronizeLdapDirectoriesEnabled",
    "platform_setting_load_balancer_relay_port": "platformSettingLoadBalancerRelayPort",
    "platform_setting_managed_detect_response_enabled": "platformSettingManagedDetectResponseEnabled",
    "platform_setting_update_rules_policy_auto_apply_enabled": "platformSettingUpdateRulesPolicyAutoApplyEnabled",
    "platform_setting_primary_tenant_allow_tenant_configure_forgot_password_enabled": "platformSettingPrimaryTenantAllowTenantConfigureForgotPasswordEnabled",
    "platform_setting_user_password_require_not_same_as_username_enabled": "platformSettingUserPasswordRequireNotSameAsUsernameEnabled",
    "log_inspection_setting_event_rank_severity_medium": "logInspectionSettingEventRankSeverityMedium",
    "anti_malware_setting_retain_event_duration": "antiMalwareSettingRetainEventDuration",
    "platform_setting_update_agent_security_contact_primary_source_on_missing_relay"
    + "_enabled": "platformSettingUpdateAgentSecurityContactPrimarySourceOnMissingRelayEnabled",
    "firewall_setting_event_rank_severity_log_only": "firewallSettingEventRankSeverityLogOnly",
    "platform_setting_primary_tenant_lock_and_hide_tenant_data_privacy_option_enabled": "platformSettingPrimaryTenantLockAndHideTenantDataPrivacyOptionEnabled",
    "application_control_setting_retain_event_duration": "applicationControlSettingRetainEventDuration",
    "platform_setting_api_soap_web_service_enabled": "platformSettingApiSoapWebServiceEnabled",
    "platform_setting_saml_service_provider_private_key": "platformSettingSamlServiceProviderPrivateKey",
    "platform_setting_windows_upgrade_on_activation_enabled": "platformSettingWindowsUpgradeOnActivationEnabled",
    "platform_setting_system_event_forwarding_snmp_port": "platformSettingSystemEventForwardingSnmpPort",
    "firewall_setting_event_rank_severity_deny": "firewallSettingEventRankSeverityDeny",
    "intrusion_prevention_setting_event_rank_severity_filter_low": "intrusionPreventionSettingEventRankSeverityFilterLow",
    "platform_setting_primary_tenant_allow_tenant_control_impersonation_enabled": "platformSettingPrimaryTenantAllowTenantControlImpersonationEnabled",
    "platform_setting_recommendation_cpu_usage_level": "platformSettingRecommendationCpuUsageLevel",
    "platform_setting_managed_detect_response_service_token": "platformSettingManagedDetectResponseServiceToken",
    "platform_setting_load_balancer_heartbeat_address": "platformSettingLoadBalancerHeartbeatAddress",
    "platform_setting_trend_micro_xdr_api_user": "platformSettingTrendMicroXdrApiUser",
    "platform_setting_content_security_policy_report_only_enabled": "platformSettingContentSecurityPolicyReportOnlyEnabled",
    "log_inspection_setting_retain_event_duration": "logInspectionSettingRetainEventDuration",
    "platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_enabled": "platformSettingTenantAutoRevokeImpersonationByPrimaryTenantEnabled",
    "anti_malware_setting_event_email_body_template": "antiMalwareSettingEventEmailBodyTemplate",
    "platform_setting_retain_security_updates_max": "platformSettingRetainSecurityUpdatesMax",
    "platform_setting_connected_threat_defense_control_manager_source_option": "platformSettingConnectedThreatDefenseControlManagerSourceOption",
    "anti_malware_setting_event_email_enabled": "antiMalwareSettingEventEmailEnabled",
    "platform_setting_update_agent_software_use_download_center_on_missing_deep_security"
    + "_manager_enabled": "platformSettingUpdateAgentSoftwareUseDownloadCenterOnMissingDeepSecurityManagerEnabled",
    "platform_setting_recommendation_ongoing_scans_enabled": "platformSettingRecommendationOngoingScansEnabled",
    "platform_setting_agent_initiated_activation_token": "platformSettingAgentInitiatedActivationToken",
    "platform_setting_user_password_length_min": "platformSettingUserPasswordLengthMin",
    "platform_setting_primary_tenant_allow_tenant_database_state": "platformSettingPrimaryTenantAllowTenantDatabaseState",
    "platform_setting_aws_manager_identity_use_instance_role_enabled": "platformSettingAwsManagerIdentityUseInstanceRoleEnabled",
    "platform_setting_content_security_policy": "platformSettingContentSecurityPolicy",
    "platform_setting_product_usage_data_collection_enabled": "platformSettingProductUsageDataCollectionEnabled",
    "platform_setting_alert_agent_update_pending_threshold": "platformSettingAlertAgentUpdatePendingThreshold",
    "platform_setting_user_password_require_special_characters_enabled": "platformSettingUserPasswordRequireSpecialCharactersEnabled",
    "platform_setting_update_appliance_default_agent_version": "platformSettingUpdateApplianceDefaultAgentVersion",
    "platform_setting_system_event_forwarding_snmp_enabled": "platformSettingSystemEventForwardingSnmpEnabled",
    "platform_setting_smtp_bounce_email_address": "platformSettingSmtpBounceEmailAddress",
    "platform_setting_update_relay_security_support_agent_9and_earlier_enabled": "platformSettingUpdateRelaySecuritySupportAgent9AndEarlierEnabled",
    "platform_setting_managed_detect_response_proxy_id": "platformSettingManagedDetectResponseProxyId",
    "platform_setting_trend_micro_xdr_log_server_url": "platformSettingTrendMicroXdrLogServerUrl",
    "platform_setting_inactive_agent_cleanup_enabled": "platformSettingInactiveAgentCleanupEnabled",
    "platform_setting_load_balancer_relay_address": "platformSettingLoadBalancerRelayAddress",
    "platform_setting_http_public_key_pin_policy": "platformSettingHttpPublicKeyPinPolicy",
    "platform_setting_user_session_idle_timeout": "platformSettingUserSessionIdleTimeout",
    "anti_malware_setting_event_email_subject": "antiMalwareSettingEventEmailSubject",
    "platform_setting_connected_threat_defense_control_manager_use_proxy_enabled": "platformSettingConnectedThreatDefenseControlManagerUseProxyEnabled",
    "platform_setting_user_enforce_terms_and_conditions_enabled": "platformSettingUserEnforceTermsAndConditionsEnabled",
    "platform_setting_aws_manager_identity_access_key": "platformSettingAwsManagerIdentityAccessKey",
    "platform_setting_connected_threat_defense_control_manager_proxy_id": "platformSettingConnectedThreatDefenseControlManagerProxyId",
    "platform_setting_tenant_allow_impersonation_by_primary_tenant_enabled": "platformSettingTenantAllowImpersonationByPrimaryTenantEnabled",
    "platform_setting_connected_threat_defense_control_manager_manual_source"
    + "_server_url": "platformSettingConnectedThreatDefenseControlManagerManualSourceServerUrl",
    "platform_setting_user_password_require_mixed_case_enabled": "platformSettingUserPasswordRequireMixedCaseEnabled",
    "platform_setting_trend_micro_xdr_identity_provider_api_url": "platformSettingTrendMicroXdrIdentityProviderApiUrl",
    "platform_setting_smart_protection_feedback_for_suspicious_file_enabled": "platformSettingSmartProtectionFeedbackForSuspiciousFileEnabled",
    "platform_setting_primary_tenant_allow_tenant_configure_snmp_enabled": "platformSettingPrimaryTenantAllowTenantConfigureSnmpEnabled",
    "platform_setting_smart_protection_feedback_industry_type": "platformSettingSmartProtectionFeedbackIndustryType",
    "web_reputation_setting_retain_event_duration": "webReputationSettingRetainEventDuration",
    "platform_setting_retain_server_log_duration": "platformSettingRetainServerLogDuration",
    "integrity_monitoring_setting_event_rank_severity_medium": "integrityMonitoringSettingEventRankSeverityMedium",
    "platform_setting_proxy_manager_cloud_proxy_id": "platformSettingProxyManagerCloudProxyId",
    "platform_setting_update_relay_security_all_regions_patterns_download_enabled": "platformSettingUpdateRelaySecurityAllRegionsPatternsDownloadEnabled",
    "platform_setting_ddan_submission_enabled": "platformSettingDdanSubmissionEnabled",
    "web_reputation_setting_event_rank_risk_suspicious": "webReputationSettingEventRankRiskSuspicious",
    "integrity_monitoring_setting_event_rank_severity_critical": "integrityMonitoringSettingEventRankSeverityCritical",
    "platform_setting_smtp_from_email_address": "platformSettingSmtpFromEmailAddress",
    "firewall_setting_global_stateful_config_id": "firewallSettingGlobalStatefulConfigId",
    "platform_setting_event_forwarding_sns_topic_arn": "platformSettingEventForwardingSnsTopicArn",
    "firewall_setting_internet_connectivity_test_expected_content_regex": "firewallSettingInternetConnectivityTestExpectedContentRegex",
    "platform_setting_connected_threat_defense_control_manager_manual_source_api_key": "platformSettingConnectedThreatDefenseControlManagerManualSourceApiKey",
    "platform_setting_load_balancer_manager_address": "platformSettingLoadBalancerManagerAddress",
    "platform_setting_update_security_primary_source_mode": "platformSettingUpdateSecurityPrimarySourceMode",
    "platform_setting_primary_tenant_share_connected_threat_defenses_enabled": "platformSettingPrimaryTenantShareConnectedThreatDefensesEnabled",
    "web_reputation_setting_event_rank_risk_dangerous": "webReputationSettingEventRankRiskDangerous",
    "platform_setting_load_balancer_heartbeat_port": "platformSettingLoadBalancerHeartbeatPort",
    "platform_setting_user_hide_unlicensed_modules_enabled": "platformSettingUserHideUnlicensedModulesEnabled",
    "platform_setting_capture_encrypted_traffic_enabled": "platformSettingCaptureEncryptedTrafficEnabled",
    "platform_setting_retain_system_event_duration": "platformSettingRetainSystemEventDuration",
    "platform_setting_user_password_expiry": "platformSettingUserPasswordExpiry",
    "platform_setting_smart_protection_feedback_enabled": "platformSettingSmartProtectionFeedbackEnabled",
    "integrity_monitoring_setting_retain_event_duration": "integrityMonitoringSettingRetainEventDuration",
    "platform_setting_primary_tenant_allow_tenant_use_scheduled_run_script"
    + "_task_enabled": "platformSettingPrimaryTenantAllowTenantUseScheduledRunScriptTaskEnabled",
    "log_inspection_setting_event_rank_severity_critical": "logInspectionSettingEventRankSeverityCritical",
    "platform_setting_primary_tenant_lock_and_hide_tenant_smtp_tab_enabled": "platformSettingPrimaryTenantLockAndHideTenantSmtpTabEnabled",
    "platform_setting_ddan_proxy_id": "platformSettingDdanProxyId",
    "platform_setting_agent_initiated_activation_within_ip_list_id": "platformSettingAgentInitiatedActivationWithinIpListId",
    "platform_setting_update_security_primary_source_url": "platformSettingUpdateSecurityPrimarySourceUrl",
    "platform_setting_agentless_vcloud_protection_enabled": "platformSettingAgentlessVcloudProtectionEnabled",
    "platform_setting_linux_upgrade_on_activation_enabled": "platformSettingLinuxUpgradeOnActivationEnabled",
    "platform_setting_trend_micro_xdr_enabled": "platformSettingTrendMicroXdrEnabled",
    "platform_setting_active_sessions_max_exceeded_action": "platformSettingActiveSessionsMaxExceededAction",
    "platform_setting_update_hostname_on_ip_change_enabled": "platformSettingUpdateHostnameOnIpChangeEnabled",
    "log_inspection_setting_event_rank_severity_high": "logInspectionSettingEventRankSeverityHigh",
    "platform_setting_smtp_requires_authentication_enabled": "platformSettingSmtpRequiresAuthenticationEnabled",
    "platform_setting_active_sessions_max": "platformSettingActiveSessionsMax",
    "platform_setting_aws_external_id_retrieval_enabled": "platformSettingAwsExternalIdRetrievalEnabled",
    "log_inspection_setting_event_rank_severity_low": "logInspectionSettingEventRankSeverityLow",
    "platform_setting_azure_sso_certificate": "platformSettingAzureSsoCertificate",
    "platform_setting_smtp_username": "platformSettingSmtpUsername",
    "platform_setting_event_forwarding_sns_advanced_config_enabled": "platformSettingEventForwardingSnsAdvancedConfigEnabled",
    "firewall_setting_internet_connectivity_test_interval": "firewallSettingInternetConnectivityTestInterval",
    "platform_setting_whois_url": "platformSettingWhoisUrl",
    "platform_setting_ddan_source_option": "platformSettingDdanSourceOption",
    "platform_setting_connected_threat_defense_control_manager_suspicious_object"
    + "_list_comparison_enabled": "platformSettingConnectedThreatDefenseControlManagerSuspiciousObjectListComparisonEnabled",
    "platform_setting_exported_file_character_encoding": "platformSettingExportedFileCharacterEncoding",
    "platform_setting_user_session_duration_max": "platformSettingUserSessionDurationMax",
    "platform_setting_update_software_alternate_update_server_urls": "platformSettingUpdateSoftwareAlternateUpdateServerUrls",
    "platform_setting_retain_counters_duration": "platformSettingRetainCountersDuration",
    "platform_setting_primary_tenant_allow_tenant_run_computer_discovery_enabled": "platformSettingPrimaryTenantAllowTenantRunComputerDiscoveryEnabled",
    "platform_setting_smart_protection_feedback_interval": "platformSettingSmartProtectionFeedbackInterval",
    "platform_setting_system_event_forwarding_snmp_address": "platformSettingSystemEventForwardingSnmpAddress",
    "platform_setting_smtp_server_address": "platformSettingSmtpServerAddress",
    "platform_setting_primary_tenant_allow_tenant_configure_siem_enabled": "platformSettingPrimaryTenantAllowTenantConfigureSiemEnabled",
    "platform_setting_smtp_password": "platformSettingSmtpPassword",
    "platform_setting_event_forwarding_sns_config_json": "platformSettingEventForwardingSnsConfigJson",
    "firewall_setting_retain_event_duration": "firewallSettingRetainEventDuration",
    "web_reputation_setting_event_rank_risk_untested": "webReputationSettingEventRankRiskUntested",
    "platform_setting_managed_detect_response_use_proxy_enabled": "platformSettingManagedDetectResponseUseProxyEnabled",
    "platform_setting_event_forwarding_sns_secret_key": "platformSettingEventForwardingSnsSecretKey",
    "platform_setting_logo_binary_image_img": "platformSettingLogoBinaryImageImg",
    "platform_setting_aws_manager_identity_secret_key": "platformSettingAwsManagerIdentitySecretKey",
    "web_reputation_setting_event_rank_risk_highly_suspicious": "webReputationSettingEventRankRiskHighlySuspicious",
    "platform_setting_api_status_monitoring_enabled": "platformSettingApiStatusMonitoringEnabled",
    "platform_setting_sign_in_page_message": "platformSettingSignInPageMessage",
    "platform_setting_user_password_expiry_send_email_enabled": "platformSettingUserPasswordExpirySendEmailEnabled",
    "platform_setting_user_sign_in_attempts_allowed_number": "platformSettingUserSignInAttemptsAllowedNumber",
    "platform_setting_ddan_use_proxy_enabled": "platformSettingDdanUseProxyEnabled",
    "platform_setting_agent_initiated_activation_enabled": "platformSettingAgentInitiatedActivationEnabled",
    "platform_setting_primary_tenant_allow_tenant"
    + "_configure_remember_me_option_enabled": "platformSettingPrimaryTenantAllowTenantConfigureRememberMeOptionEnabled",
    "platform_setting_smart_protection_feedback_bandwidth_max_kbytes": "platformSettingSmartProtectionFeedbackBandwidthMaxKbytes",
    "firewall_setting_event_rank_severity_packet_rejection": "firewallSettingEventRankSeverityPacketRejection",
    "platform_setting_proxy_manager_update_proxy_id": "platformSettingProxyManagerUpdateProxyId",
    "platform_setting_managed_detect_response_use_primary_tenant_settings_enabled": "platformSettingManagedDetectResponseUsePrimaryTenantSettingsEnabled",
    "platform_setting_event_forwarding_sns_access_key": "platformSettingEventForwardingSnsAccessKey",
    "platform_setting_agent_initiated_activation_specify_hostname_enabled": "platformSettingAgentInitiatedActivationSpecifyHostnameEnabled",
    "platform_setting_primary_tenant_allow_tenant_sync_with_cloud_account_enabled": "platformSettingPrimaryTenantAllowTenantSyncWithCloudAccountEnabled",
    "platform_setting_connected_threat_defenses"
    + "_use_primary_tenant_server_settings_enabled": "platformSettingConnectedThreatDefensesUsePrimaryTenantServerSettingsEnabled",
    "platform_setting_inactive_agent_cleanup_duration": "platformSettingInactiveAgentCleanupDuration",
    "platform_setting_agent_initiated_activation_duplicate_hostname_mode": "platformSettingAgentInitiatedActivationDuplicateHostnameMode",
    "platform_setting_vmware_nsx_manager_node": "platformSettingVmwareNsxManagerNode",
    "platform_setting_user_enforce_terms_and_conditions_title": "platformSettingUserEnforceTermsAndConditionsTitle",
    "platform_setting_primary_tenant_allow_tenant_add_vmware_vcenter_enabled": "platformSettingPrimaryTenantAllowTenantAddVmwareVcenterEnabled",
    "platform_setting_new_tenant_download_security_update_enabled": "platformSettingNewTenantDownloadSecurityUpdateEnabled",
    "platform_setting_tenant_protection_usage_monitoring_computer_id_3": "platformSettingTenantProtectionUsageMonitoringComputerId3",
    "platform_setting_agent_initiated_activation_reactivate_unknown_enabled": "platformSettingAgentInitiatedActivationReactivateUnknownEnabled",
    "platform_setting_tenant_protection_usage_monitoring_computer_id_2": "platformSettingTenantProtectionUsageMonitoringComputerId2",
    "platform_setting_agent_initiated_activation_policy_id": "platformSettingAgentInitiatedActivationPolicyId",
    "platform_setting_tenant_protection_usage_monitoring_computer_id_1": "platformSettingTenantProtectionUsageMonitoringComputerId1",
    "platform_setting_trend_micro_xdr_api_server_url": "platformSettingTrendMicroXdrApiServerUrl",
    "platform_setting_retain_agent_installers_per_platform_max": "platformSettingRetainAgentInstallersPerPlatformMax",
    "application_control_setting_serve_rulesets_from_relays_enabled": "applicationControlSettingServeRulesetsFromRelaysEnabled",
    "integrity_monitoring_setting_event_rank_severity_high": "integrityMonitoringSettingEventRankSeverityHigh",
    "platform_setting_saml_retain_inactive_external_administrators_duration": "platformSettingSamlRetainInactiveExternalAdministratorsDuration",
    "intrusion_prevention_setting_retain_event_duration": "intrusionPreventionSettingRetainEventDuration",
    "platform_setting_http_public_key_pin_policy_report_only_enabled": "platformSettingHttpPublicKeyPinPolicyReportOnlyEnabled",
    "platform_setting_saml_service_provider_name": "platformSettingSamlServiceProviderName",
    "firewall_setting_internet_connectivity_test_url": "firewallSettingInternetConnectivityTestUrl",
    "platform_setting_saml_service_provider_certificate_expiry_warning_days": "platformSettingSamlServiceProviderCertificateExpiryWarningDays",
    "platform_setting_proxy_agent_update_proxy_id": "platformSettingProxyAgentUpdateProxyId",
    "platform_setting_ddan_auto_submission_enabled": "platformSettingDdanAutoSubmissionEnabled",
    "platform_setting_ddan_manual_source_api_key": "platformSettingDdanManualSourceApiKey",
    "platform_setting_saml_service_provider_entity_id": "platformSettingSamlServiceProviderEntityId",
    "intrusion_prevention_setting_event_rank_severity_filter_error": "intrusionPreventionSettingEventRankSeverityFilterError",
    "intrusion_prevention_setting_event_rank_severity_filter_high": "intrusionPreventionSettingEventRankSeverityFilterHigh",
    "platform_setting_trend_micro_xdr_api_key": "platformSettingTrendMicroXdrApiKey",
    "integrity_monitoring_setting_event_rank_severity_low": "integrityMonitoringSettingEventRankSeverityLow",
    "platform_setting_trend_micro_xdr_company_id": "platformSettingTrendMicroXdrCompanyId",
}

api_object = "/api/systemsettings"
api_return = "systemSettings"


def display_gathered_result(argspec, module, deepsec_request):
    return_config = {}
    if module.params.get("config") and module.params.get("config").get("name"):
        return_get = {}
        for each in module.params["config"]["name"]:
            return_val = deepsec_request.get(
                api_object + "/{0}".format(key_transform[each])
            )
            return_get.update({each: return_val})
        return_config["config"] = return_get
    else:
        return_get = deepsec_request.get(api_object)
        return_config["config"] = map_obj_to_params(
            return_get, key_transform, api_return
        )
    utils.validate_config(argspec, return_config)
    module.exit_json(gathered=return_config, changed=False)


def search_for_system_settings_default(deepsec_api_request):
    search_existing_system_setting = deepsec_api_request.get(api_object)
    return search_existing_system_setting


def reset_module_api_config(argspec, module, deepsec_request):
    if (
        module.params
        and not module.params["config"].get("name")
        and len(module.params["config"]) >= 1
    ):
        name = []
        for each in module.params["config"]:
            name.append(each)
        module.params["config"]["name"] = name
    if module.params and module.params["config"].get("name"):
        config = {}
        before = {}
        after = {}
        changed = False
        for each in module.params["config"]["name"]:
            system_setting_name = key_transform[each]
            search_result = search_for_system_settings_default(deepsec_request)
            before.update({each: search_result[system_setting_name]})
            if (
                search_result
                and search_result[system_setting_name]["value"]
                != argspec["config"]["options"][each]["options"]["value"][
                    "default"
                ]
            ):
                changed = True
                reset_return = delete_config_with_id(
                    module,
                    deepsec_request,
                    api_object.split("/")[2],
                    system_setting_name,
                    api_return,
                )
                after.update({each: reset_return})
            else:
                after.update({each: search_result[system_setting_name]})
        if changed:
            config.update({"before": before, "after": after})
            module.exit_json(system_settings=config, changed=True)
        else:
            config.update({"before": before})
            module.exit_json(system_settings=config, changed=False)


def configure_module_api(argspec, module, deepsec_request):
    if module.params:
        config = {}
        before = {}
        after = {}
        changed = False
        search_result = search_for_system_settings_default(deepsec_request)
        temp_config = {}
        for k, v in iteritems(module.params["config"]):
            system_setting_name = key_transform[k]
            before.update({k: search_result[system_setting_name]})
            if (
                system_setting_name in search_result
                and search_result[system_setting_name]["value"].lower()
                != str(v["value"]).lower()
            ):
                changed = True
                if v["value"] == "True" or v["value"] == "False":
                    temp_config.update(
                        {system_setting_name: {"value": v["value"].lower()}}
                    )
                else:
                    temp_config.update({system_setting_name: v})
                after.update({k: v})
        if len(temp_config) == 1:
            for k, v in iteritems(temp_config):
                api_key = deepsec_request.post(
                    "{0}/{1}".format(api_object, k), data=v
                )
                if api_key.get("errors"):
                    module.fail_json(msg=api_key["errors"])
                elif api_key.get("message"):
                    module.fail_json(msg=api_key["message"])
        elif len(temp_config) > 1:
            api_key = deepsec_request.post(
                "{0}".format(api_object), data=temp_config
            )
            if api_key.get("errors"):
                module.fail_json(msg=api_key["errors"])
            elif api_key.get("message"):
                module.fail_json(msg=api_key["message"])
        if changed:
            config.update({"before": before, "after": after})
            module.exit_json(system_settings=config, changed=True)
        else:
            config.update({"before": before})
            module.exit_json(system_settings=config, changed=False)


def main():
    argspec = dict(
        state=dict(
            choices=["present", "absent", "gathered"], default="present"
        ),
        config=dict(
            type="dict",
            options=dict(
                name=dict(type="list", elements="str"),
                platform_setting_saml_identity_provider_certificate_expiry_warning_daysr=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="30")),
                ),
                platform_setting_update_agent_security_on_missing_deep_security_manager_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_ddan_manual_source_server_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_load_balancer_manager_port=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="4119")),
                ),
                platform_setting_smart_protection_feedback_threat_detections_threshold=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="10")),
                ),
                platform_setting_primary_tenant_allow_tenant_run_port_scan_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                intrusion_prevention_setting_event_rank_severity_filter_medium=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="25")),
                ),
                firewall_setting_intranet_connectivity_test_expected_content_regex=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_event_forwarding_sns_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_timeout=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="4 Hours")),
                ),
                web_reputation_setting_event_rank_risk_blocked_by_administrator_rank=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="100")),
                ),
                platform_setting_primary_tenant_lock_and_hide_tenant_storage_tab_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                anti_malware_setting_event_email_recipients=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_primary_tenant_allow_tenant_use_default_relay_group_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_http_strict_transport_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                firewall_setting_intranet_connectivity_test_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_primary_tenant_allow_tenant_configure_sns_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_tenant_use_default_relay_group_from_primary_tenant_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_exported_diagnostic_package_locale=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="en_US")),
                ),
                intrusion_prevention_setting_event_rank_severity_filter_critical=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="100")),
                ),
                platform_setting_update_imported_software_auto_download_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_demo_mode_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_user_enforce_terms_and_conditions_message=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_trend_micro_xdr_common_log_receiver_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_managed_detect_response_company_guid=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_alert_default_email_address=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_agent_initiated_activation_reactivate_cloned_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_managed_detect_response_server_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_primary_tenant_share_managed_detect_responses_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_saml_service_provider_certificate=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_syslog_config_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="0")),
                ),
                platform_setting_smtp_start_tls_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_user_password_require_letters_and_numbers_enabled=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="false", no_log=False)
                    ),
                    no_log=False,
                ),
                platform_setting_primary_tenant_allow_tenant_synchronize_ldap_directories_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_load_balancer_relay_port=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="4122")),
                ),
                platform_setting_managed_detect_response_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_update_rules_policy_auto_apply_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_primary_tenant_allow_tenant_configure_forgot_password_enabled=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="false", no_log=False)
                    ),
                    no_log=False,
                ),
                platform_setting_user_password_require_not_same_as_username_enabled=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="false", no_log=False)
                    ),
                    no_log=False,
                ),
                log_inspection_setting_event_rank_severity_medium=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="25")),
                ),
                anti_malware_setting_retain_event_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                platform_setting_update_agent_security_contact_primary_source_on_missing_relay_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                firewall_setting_event_rank_severity_log_only=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="1")),
                ),
                platform_setting_primary_tenant_lock_and_hide_tenant_data_privacy_option_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                application_control_setting_retain_event_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                platform_setting_api_soap_web_service_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_saml_service_provider_private_key=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_windows_upgrade_on_activation_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_system_event_forwarding_snmp_port=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="162")),
                ),
                firewall_setting_event_rank_severity_deny=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="100")),
                ),
                intrusion_prevention_setting_event_rank_severity_filter_low=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="1")),
                ),
                platform_setting_primary_tenant_allow_tenant_control_impersonation_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_recommendation_cpu_usage_level=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="High")),
                ),
                platform_setting_managed_detect_response_service_token=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_load_balancer_heartbeat_address=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_trend_micro_xdr_api_user=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_content_security_policy_report_only_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                log_inspection_setting_retain_event_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                platform_setting_tenant_auto_revoke_impersonation_by_primary_tenant_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                anti_malware_setting_event_email_body_template=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_retain_security_updates_max=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="10")),
                ),
                platform_setting_connected_threat_defense_control_manager_source_option=dict(
                    type="dict",
                    options=dict(
                        value=dict(
                            type="str",
                            default="Manually select an Apex Central server",
                        )
                    ),
                ),
                anti_malware_setting_event_email_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_update_agent_software_use_download_center_on_missing_deep_security_manager_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_recommendation_ongoing_scans_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="No")),
                ),
                platform_setting_agent_initiated_activation_token=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_user_password_length_min=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="8", no_log=False)
                    ),
                    no_log=False,
                ),
                platform_setting_primary_tenant_allow_tenant_database_state=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="10")),
                ),
                platform_setting_aws_manager_identity_use_instance_role_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_content_security_policy=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_product_usage_data_collection_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_alert_agent_update_pending_threshold=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                platform_setting_user_password_require_special_characters_enabled=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="false", no_log=False)
                    ),
                    no_log=False,
                ),
                platform_setting_update_appliance_default_agent_version=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_system_event_forwarding_snmp_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_smtp_bounce_email_address=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_update_relay_security_support_agent_9and_earlier_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_managed_detect_response_proxy_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_trend_micro_xdr_log_server_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_inactive_agent_cleanup_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_load_balancer_relay_address=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_http_public_key_pin_policy=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_user_session_idle_timeout=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="30 Minutes")),
                ),
                anti_malware_setting_event_email_subject=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_connected_threat_defense_control_manager_use_proxy_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_user_enforce_terms_and_conditions_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_aws_manager_identity_access_key=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_connected_threat_defense_control_manager_proxy_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_tenant_allow_impersonation_by_primary_tenant_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_connected_threat_defense_control_manager_manual_source_server_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_user_password_require_mixed_case_enabled=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="false", no_log=False)
                    ),
                    no_log=False,
                ),
                platform_setting_trend_micro_xdr_identity_provider_api_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_smart_protection_feedback_for_suspicious_file_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_primary_tenant_allow_tenant_configure_snmp_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_smart_protection_feedback_industry_type=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="Not specified")
                    ),
                ),
                web_reputation_setting_retain_event_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                platform_setting_retain_server_log_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                integrity_monitoring_setting_event_rank_severity_medium=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="25")),
                ),
                platform_setting_proxy_manager_cloud_proxy_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_update_relay_security_all_regions_patterns_download_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_ddan_submission_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                web_reputation_setting_event_rank_risk_suspicious=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="25")),
                ),
                integrity_monitoring_setting_event_rank_severity_critical=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="100")),
                ),
                platform_setting_smtp_from_email_address=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_event_forwarding_sns_topic_arn=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                firewall_setting_global_stateful_config_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="0")),
                ),
                firewall_setting_internet_connectivity_test_expected_content_regex=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_connected_threat_defense_control_manager_manual_source_api_key=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_load_balancer_manager_address=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_update_security_primary_source_mode=dict(
                    type="dict",
                    options=dict(
                        value=dict(
                            type="str",
                            default="Trend Micro ActiveUpdate Server",
                        )
                    ),
                ),
                platform_setting_primary_tenant_share_connected_threat_defenses_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                web_reputation_setting_event_rank_risk_dangerous=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="100")),
                ),
                platform_setting_load_balancer_heartbeat_port=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="4120")),
                ),
                platform_setting_user_hide_unlicensed_modules_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_capture_encrypted_traffic_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_retain_system_event_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="53 weeks")),
                ),
                platform_setting_user_password_expiry=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="Never", no_log=False)
                    ),
                    no_log=False,
                ),
                platform_setting_smart_protection_feedback_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                integrity_monitoring_setting_retain_event_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                platform_setting_primary_tenant_allow_tenant_use_scheduled_run_script_task_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                log_inspection_setting_event_rank_severity_critical=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="100")),
                ),
                platform_setting_primary_tenant_lock_and_hide_tenant_smtp_tab_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_ddan_proxy_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_agent_initiated_activation_within_ip_list_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_update_security_primary_source_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="http://")),
                ),
                platform_setting_agentless_vcloud_protection_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_linux_upgrade_on_activation_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_trend_micro_xdr_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_active_sessions_max_exceeded_action=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="Block new sessions")
                    ),
                ),
                platform_setting_update_hostname_on_ip_change_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                log_inspection_setting_event_rank_severity_high=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="50")),
                ),
                platform_setting_smtp_requires_authentication_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_active_sessions_max=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="10")),
                ),
                platform_setting_aws_external_id_retrieval_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                log_inspection_setting_event_rank_severity_low=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="1")),
                ),
                platform_setting_azure_sso_certificate=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_smtp_username=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_event_forwarding_sns_advanced_config_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                firewall_setting_internet_connectivity_test_interval=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="10 Seconds")),
                ),
                platform_setting_whois_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_ddan_source_option=dict(
                    type="dict",
                    options=dict(
                        value=dict(
                            type="str",
                            default="Manually select a Deep Discovery Analyzer server",
                        )
                    ),
                ),
                platform_setting_connected_threat_defense_control_manager_suspicious_object_list_comparison_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_exported_file_character_encoding=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="US-ASCII")),
                ),
                platform_setting_user_session_duration_max=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="No Limit")),
                ),
                platform_setting_update_software_alternate_update_server_urls=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_retain_counters_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="13 Weeks")),
                ),
                platform_setting_primary_tenant_allow_tenant_run_computer_discovery_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_smart_protection_feedback_interval=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="5")),
                ),
                platform_setting_system_event_forwarding_snmp_address=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_smtp_server_address=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_primary_tenant_allow_tenant_configure_siem_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_smtp_password=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_event_forwarding_sns_config_json=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                firewall_setting_retain_event_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                web_reputation_setting_event_rank_risk_untested=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="25")),
                ),
                platform_setting_managed_detect_response_use_proxy_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_event_forwarding_sns_secret_key=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_logo_binary_image_img=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_aws_manager_identity_secret_key=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                web_reputation_setting_event_rank_risk_highly_suspicious=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="50")),
                ),
                platform_setting_api_status_monitoring_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_sign_in_page_message=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_user_password_expiry_send_email_enabled=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="false", no_log=False)
                    ),
                    no_log=False,
                ),
                platform_setting_user_sign_in_attempts_allowed_number=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="5")),
                ),
                platform_setting_ddan_use_proxy_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_agent_initiated_activation_enabled=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="For any computers")
                    ),
                ),
                platform_setting_primary_tenant_allow_tenant_configure_remember_me_option_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_smart_protection_feedback_bandwidth_max_kbytes=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="32")),
                ),
                firewall_setting_event_rank_severity_packet_rejection=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="50")),
                ),
                platform_setting_proxy_manager_update_proxy_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_managed_detect_response_use_primary_tenant_settings_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_event_forwarding_sns_access_key=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_agent_initiated_activation_specify_hostname_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_primary_tenant_allow_tenant_sync_with_cloud_account_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_connected_threat_defenses_use_primary_tenant_server_settings_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_inactive_agent_cleanup_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="1 Month")),
                ),
                platform_setting_agent_initiated_activation_duplicate_hostname_mode=dict(
                    type="dict",
                    options=dict(
                        value=dict(
                            type="str",
                            default="Re-activate the existing Computer",
                        )
                    ),
                ),
                platform_setting_vmware_nsx_manager_node=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="1")),
                ),
                platform_setting_user_enforce_terms_and_conditions_title=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_primary_tenant_allow_tenant_add_vmware_vcenter_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_new_tenant_download_security_update_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_tenant_protection_usage_monitoring_computer_id_3=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="Platform")),
                ),
                platform_setting_agent_initiated_activation_reactivate_unknown_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_tenant_protection_usage_monitoring_computer_id_2=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="Last Used IP Address")
                    ),
                ),
                platform_setting_agent_initiated_activation_policy_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_tenant_protection_usage_monitoring_computer_id_1=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="Hostname")),
                ),
                platform_setting_trend_micro_xdr_api_server_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_retain_agent_installers_per_platform_max=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="5")),
                ),
                application_control_setting_serve_rulesets_from_relays_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                integrity_monitoring_setting_event_rank_severity_high=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="50")),
                ),
                platform_setting_saml_retain_inactive_external_administrators_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="365")),
                ),
                intrusion_prevention_setting_retain_event_duration=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="7 Days")),
                ),
                platform_setting_http_public_key_pin_policy_report_only_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="true")),
                ),
                platform_setting_saml_service_provider_name=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                firewall_setting_internet_connectivity_test_url=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_saml_service_provider_certificate_expiry_warning_days=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="30")),
                ),
                platform_setting_proxy_agent_update_proxy_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                platform_setting_ddan_auto_submission_enabled=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="false")),
                ),
                platform_setting_ddan_manual_source_api_key=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                platform_setting_saml_service_provider_entity_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
                intrusion_prevention_setting_event_rank_severity_filter_error=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="100")),
                ),
                intrusion_prevention_setting_event_rank_severity_filter_high=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="50")),
                ),
                platform_setting_trend_micro_xdr_api_key=dict(
                    type="dict",
                    options=dict(
                        value=dict(type="str", default="", no_log=True)
                    ),
                    no_log=True,
                ),
                integrity_monitoring_setting_event_rank_severity_low=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="1")),
                ),
                platform_setting_trend_micro_xdr_company_id=dict(
                    type="dict",
                    options=dict(value=dict(type="str", default="")),
                ),
            ),
        ),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    module.params = utils.remove_empties(module.params)

    if module.params["state"] == "gathered":
        display_gathered_result(
            argspec=argspec, module=module, deepsec_request=deepsec_request
        )
    elif module.params["state"] == "absent":
        reset_module_api_config(
            argspec=argspec, module=module, deepsec_request=deepsec_request
        )
    elif module.params["state"] == "present":
        configure_module_api(
            argspec=argspec, module=module, deepsec_request=deepsec_request
        )


if __name__ == "__main__":
    main()

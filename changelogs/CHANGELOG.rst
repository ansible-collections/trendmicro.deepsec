================================================
TrendMicro DeepSecurity Collection Release Notes
================================================

.. contents:: Topics


v1.1.0
======

Minor Changes
-------------

- Add deepsec_apikey config module.
- Add deepsec_system_settings config module.

New Modules
-----------

- deepsec_apikey - Create a new and manage API Keys.
- deepsec_system_settings - Modify the system settings for TrendMicro Deep Security.

v1.0.0
======

Minor Changes
-------------

- Add deepsec_anti_malware config module.
- Add deepsec_firewallrules config module.
- Add deepsec_hosts_info config module.
- Add deepsec_log_inspectionrules module.
- Add deepsec_syslog module.

Bugfixes
--------

- Fix no log issues for private_key for deepsec_syslog_config module.

New Modules
-----------

- deepsec_anti_malware - Create a new antimalware under TrendMicro Deep Security Policy
- deepsec_firewallrules - Create a new firewall rule.
- deepsec_hosts_info - Obtain information about one or many Hosts defined by TrendMicro Deep Security
- deepsec_log_inspectionrules - Create a new log inspection rule.
- deepsec_syslog - Configure or create a syslog configuration for TrendMicro Deep Security

.. _trendmicro.deepsec.deepsec_integrity_monitoring_rules_module:


*****************************************************
trendmicro.deepsec.deepsec_integrity_monitoring_rules
*****************************************************

**Manages Integrity Monitoring Rule resource module**


Version added: 1.2.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Integrity monitoring rules describe how Deep Security Agents should scan for and detect changes to a computer's files, directories and registry keys and values as well as changes in installed software, processes, listening ports and running services. Integrity monitoring rules can be assigned directly to computers or can be made part of a policy.




Parameters
----------

.. raw:: html

    <table  border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="2">Parameter</th>
            <th>Choices/<font color="blue">Defaults</font></th>
            <th width="100%">Comments</th>
        </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>config</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=dictionary</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>A dictionary of Integrity Monitoring Rules options</div>
                </td>
            </tr>
                                <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>alert_enabled</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>no</li>
                                    <li>yes</li>
                        </ul>
                </td>
                <td>
                        <div>Controls whether an alert should be made if an event related to the IntegrityMonitoringRule is logged. Defaults to &#x27;false&#x27;. Searchable as Boolean.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>custom_xml</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Custom XML rules to be used by the IntegrityMonitoringRule. Custom XML rules must be encoded in the Base64 format. Ignored if the IntegrityMonitoringRule does not follow the &#x27;custom&#x27; template.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>description</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Description of the IntegrityMonitoringRule. Searchable as String.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>file_attributes</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>File attributes to be monitored by the IntegrityMonitoringRule. JSON array or delimited by new line. Defaults to &#x27;STANDARD&#x27; which will monitor changes in file creation date, last modified date, permissions, owner, group, size, content, flags (Windows) and SymLinkPath (Linux). Ignored if the IntegrityMonitoringRule does not monitor a file directory.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>file_base_directory</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Base of the file directory to be monitored by the IntegrityMonitoringRule. Ignored if the IntegrityMonitoringRule does not monitor a file directory.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>file_excluded_values</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>File name values to be ignored by the IntegrityMonitoringRule. JSON array or delimited by new line. Question mark matches a single character, while &#x27;*&#x27; matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a file directory.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>file_include_sub_directories</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>no</li>
                                    <li>yes</li>
                        </ul>
                </td>
                <td>
                        <div>Controls whether the IntegrityMonitoringRule should also monitor sub-directories of the base file directory that is associated with it. Defaults to &#x27;false&#x27;. Ignored if the IntegrityMonitoringRule does not monitor a file directory.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>file_included_values</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>File name values to be monitored by the IntegrityMonitoringRule. JSON array or delimited by new line. Question mark matches a single character, while &#x27;*&#x27; matches zero or more characters. Leaving this field blank when monitoring file directories will cause the IntegrityMonitoringRule to monitor all files in a directory. This can use significant system resources if the base directory contains numerous or large files. Ignored if the IntegrityMonitoringRule does not monitor a file directory.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>ID of the IntegrityMonitoringRule. Searchable as ID.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>identifier</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Identifier of the IntegrityMonitoringRule from Trend Micro. Empty if the IntegrityMonitoringRule is user created. Searchable as String.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>last_updated</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Timestamp when the IntegrityMonitoringRule was last updated, in milliseconds since epoch. Searchable as Date.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>minimum_agent_version</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Minimum Deep Security Agent version that supports the IntegrityMonitoringRule. This value is provided in the X.X.X.X format. Defaults to &#x27;6.0.0.0&#x27;. If an agent is not the minimum required version, the manager does not send the rule to the agent, and generates an alert. Searchable as String.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>minimum_manager_version</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Minimum Deep Security Manager version that supports the IntegrityMonitoringRule. This value is provided in the X.X.X format. Defaults to &#x27;6.0.0&#x27;. An alert will be raised if a manager that fails to meet the minimum manager version value tries to assign this rule to a host or profile. Searchable as String.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>name</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Name of the IntegrityMonitoringRule. Searchable as String.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>original_issue</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Timestamp when the IntegrityMonitoringRule was originally issued by Trend Micro, in milliseconds since epoch.  Empty if the IntegrityMonitoringRule is user created. Searchable as Date.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>real_time_monitoring_enabled</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>no</li>
                                    <li>yes</li>
                        </ul>
                </td>
                <td>
                        <div>Controls whether the IntegrityMonitoringRule is monitored in real time or during every scan. Defaults to &#x27;true&#x27; which indicates that it is monitored in real time. A value of &#x27;false&#x27; indicates that it will only be checked during scans. Searchable as Boolean.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>recommendations_mode</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>enabled</li>
                                    <li>ignored</li>
                                    <li>unknown</li>
                                    <li>disabled</li>
                        </ul>
                </td>
                <td>
                        <div>Indicates whether recommendation scans consider the IntegrityMonitoringRule. Can be set to enabled or ignored. Custom rules cannot be recommended. Searchable as Choice.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>registry_attributes</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Registry key attributes to be monitored by the IntegrityMonitoringRule. JSON array or delimited by new line. Defaults to &#x27;STANDARD&#x27; which will monitor changes in registry size, content and type. Ignored if the IntegrityMonitoringRule does not monitor a registry key.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>registry_excluded_values</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Registry key values to be ignored by the IntegrityMonitoringRule. JSON array or delimited by new line. Question mark matches a single character, while &#x27;*&#x27; matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a registry key.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>registry_include_default_value</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>no</li>
                                    <li>yes</li>
                        </ul>
                </td>
                <td>
                        <div>Controls whether the rule should monitor default registry key values. Defaults to &#x27;true&#x27;. Ignored if the IntegrityMonitoringRule does not monitor a registry key.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>registry_include_sub_keys</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>no</li>
                                    <li>yes</li>
                        </ul>
                </td>
                <td>
                        <div>Controls whether the IntegrityMonitoringRule should also include subkeys of the registry key it monitors. Defaults to &#x27;false&#x27;. Ignored if the IntegrityMonitoringRule does not monitor a registry key.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>registry_included_values</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Registry key values to be monitored by the IntegrityMonitoringRule. JSON array or delimited by new line. Question mark matches a single character, while &#x27;*&#x27; matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a registry key.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>registry_key_root</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Registry hive which is monitored by the IntegrityMonitoringRule. Empty if the IntegrityMonitoringRule does not monitor a registry key.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>registry_key_value</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Registry key which is monitored by the IntegrityMonitoringRule. Empty if the IntegrityMonitoringRule does not monitor a registry key. Ignored if the IntegrityMonitoringRule does not monitor a registry key.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>severity</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>low</li>
                                    <li>medium</li>
                                    <li>high</li>
                                    <li>critical</li>
                        </ul>
                </td>
                <td>
                        <div>Severity level of the event is multiplied by the computer&#x27;s asset value to determine ranking. Ranking can be used to sort events with more business impact. Searchable as Choice.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>template</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>registry</li>
                                    <li>file</li>
                                    <li>custom</li>
                        </ul>
                </td>
                <td>
                        <div>Template which the IntegrityMonitoringRule follows.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>type</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Type of the IntegrityMonitoringRule. If the rule is predefined by Trend Micro, it is set to &#x27;2&#x27;. If it is user created, it is set to &#x27;1&#x27;. Searchable as String.</div>
                </td>
            </tr>

            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>state</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>merged</li>
                                    <li>replaced</li>
                                    <li>overridden</li>
                                    <li>gathered</li>
                                    <li>deleted</li>
                        </ul>
                </td>
                <td>
                        <div>The state the configuration should be left in</div>
                        <div>The state <em>gathered</em> will get the module API configuration from the device and transform it into structured data in the format as per the module argspec and the value is returned in the <em>gathered</em> key within the result.</div>
                </td>
            </tr>
    </table>
    <br/>




Examples
--------

.. code-block:: yaml

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

    # RUN output:
    # -----------

    #   integrity_monitoring_rules:
    #     after:
    #     - alert_enabled: false
    #       description: THIS IS TEST IMR DESCRIPTION - 1
    #       id: 328
    #       minimum_agent_version: 6.0.0.0
    #       minimum_manager_version: 6.0.0
    #       name: THIS IS TEST IMR - 1
    #       real_time_monitoring_enabled: true
    #       registry_attributes:
    #       - STANDARD
    #       registry_excluded_values:
    #       - ''
    #       registry_include_default_value: true
    #       registry_include_sub_keys: false
    #       registry_included_values:
    #       - test_1
    #       - test_2
    #       registry_key_root: HKEY_CLASSES_ROOT
    #       registry_key_value: #       severity: medium
    #       template: registry
    #     - alert_enabled: false
    #       description: THIS IS TEST IMR DESCRIPTION - 2
    #       id: 329
    #       minimum_agent_version: 6.0.0.0
    #       minimum_manager_version: 6.0.0
    #       name: THIS IS TEST IMR - 2
    #       real_time_monitoring_enabled: true
    #       registry_attributes:
    #       - test
    #       registry_excluded_values:
    #       - ''
    #       registry_include_default_value: true
    #       registry_include_sub_keys: false
    #       registry_included_values:
    #       - ''
    #       registry_key_root: HKEY_CLASSES_ROOT
    #       registry_key_value: #       severity: low
    #       template: registry
    #     before: []

    - name: Modify the severity of Integrity Monitoring Rule by name
      trendmicro.deepsec.deepsec_integrity_monitoring_rules:
        state: merged
        config:
          - name: THIS IS TEST IMR - 2
            description: UPDATE TEST IMR DESCRIPTION - 2
            severity: medium

    # RUN output:
    # -----------

    #   integrity_monitoring_rules:
    #     after:
    #     - alert_enabled: false
    #       description: UPDATE TEST IMR DESCRIPTION - 2
    #       id: 329
    #       minimum_agent_version: 6.0.0.0
    #       minimum_manager_version: 6.0.0
    #       name: THIS IS TEST IMR - 2
    #       real_time_monitoring_enabled: true
    #       registry_attributes:
    #       - test
    #       registry_excluded_values:
    #       - ''
    #       registry_include_default_value: true
    #       registry_include_sub_keys: false
    #       registry_included_values:
    #       - ''
    #       registry_key_root: HKEY_CLASSES_ROOT
    #       registry_key_value: #       severity: medium
    #       template: registry
    #     before:
    #     - alert_enabled: false
    #       description: THIS IS TEST IMR DESCRIPTION - 2
    #       id: 329
    #       minimum_agent_version: 6.0.0.0
    #       minimum_manager_version: 6.0.0
    #       name: THIS IS TEST IMR - 2
    #       real_time_monitoring_enabled: true
    #       registry_attributes:
    #       - test
    #       registry_excluded_values:
    #       - ''
    #       registry_include_default_value: true
    #       registry_include_sub_keys: false
    #       registry_included_values:
    #       - ''
    #       registry_key_root: HKEY_CLASSES_ROOT
    #       registry_key_value: #       severity: low
    #       template: registry

    # Using REPLACED state
    # --------------------

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

    # RUN output:
    # -----------

    #   integrity_monitoring_rules:
    #     after:
    #     - alert_enabled: false
    #       description: THIS IS REPLACED TEST IMR DESCRIPTION - 1
    #       id: 330
    #       minimum_agent_version: 6.0.0.0
    #       minimum_manager_version: 6.0.0
    #       name: THIS IS TEST IMR - 1
    #       real_time_monitoring_enabled: true
    #       registry_attributes:
    #       - STANDARD
    #       registry_excluded_values:
    #       - ''
    #       registry_include_default_value: true
    #       registry_include_sub_keys: false
    #       registry_included_values:
    #       - test_3
    #       - test_4
    #       registry_key_root: HKEY_CLASSES_ROOT
    #       registry_key_value: #       severity: low
    #       template: registry
    #     before:
    #     - alert_enabled: false
    #       description: THIS IS TEST IMR DESCRIPTION - 1
    #       id: 328
    #       minimum_agent_version: 6.0.0.0
    #       minimum_manager_version: 6.0.0
    #       name: THIS IS TEST IMR - 1
    #       real_time_monitoring_enabled: true
    #       registry_attributes:
    #       - STANDARD
    #       registry_excluded_values:
    #       - ''
    #       registry_include_default_value: true
    #       registry_include_sub_keys: false
    #       registry_included_values:
    #       - test_1
    #       - test_2
    #       registry_key_root: HKEY_CLASSES_ROOT
    #       registry_key_value: #       severity: medium
    #       template: registry

    # Using GATHERED state
    # --------------------

    - name: Gather Integrity Monitoring Rule by IMR names
      trendmicro.deepsec.deepsec_integrity_monitoring_rules:
        state: gathered
        config:
          - name: THIS IS TEST IMR - 1
          - name: THIS IS TEST IMR - 2

    # RUN output:
    # -----------

    # gathered:
    #   - alert_enabled: false
    #     description: THIS IS TEST IMR DESCRIPTION - 1
    #     id: 330
    #     minimum_agent_version: 6.0.0.0
    #     minimum_manager_version: 6.0.0
    #     name: THIS IS TEST IMR - 1
    #     real_time_monitoring_enabled: true
    #     registry_attributes:
    #     - STANDARD
    #     registry_excluded_values:
    #     - ''
    #     registry_include_default_value: true
    #     registry_include_sub_keys: false
    #     registry_included_values:
    #     - test_1
    #     - test_3
    #     - test_4
    #     - test_2
    #     registry_key_root: HKEY_CLASSES_ROOT
    #     registry_key_value: #     severity: medium
    #     template: registry
    #   - alert_enabled: false
    #     description: THIS IS TEST IMR DESCRIPTION - 2
    #     id: 329
    #     minimum_agent_version: 6.0.0.0
    #     minimum_manager_version: 6.0.0
    #     name: THIS IS TEST IMR - 2
    #     real_time_monitoring_enabled: true
    #     registry_attributes:
    #     - test
    #     registry_excluded_values:
    #     - ''
    #     registry_include_default_value: true
    #     registry_include_sub_keys: false
    #     registry_included_values:
    #     - ''
    #     registry_key_root: HKEY_CLASSES_ROOT
    #     registry_key_value: #     severity: low
    #     template: registry

    - name: Gather ALL of the Integrity Monitoring Rule
      trendmicro.deepsec.deepsec_integrity_monitoring_rules:
        state: gathered

    # Using DELETED state
    # -------------------

    - name: Delete Integrity Monitoring Rule
      trendmicro.deepsec.deepsec_integrity_monitoring_rules:
        state: deleted
        config:
          - name: THIS IS TEST IMR - 1
          - name: THIS IS TEST IMR - 2
    # RUN output:
    # -----------

    #   integrity_monitoring_rules:
    #     after: []
    #     before:
    #     - alert_enabled: false
    #       description: THIS IS TEST IMR DESCRIPTION - 1
    #       id: 330
    #       minimum_agent_version: 6.0.0.0
    #       minimum_manager_version: 6.0.0
    #       name: THIS IS TEST IMR - 1
    #       real_time_monitoring_enabled: true
    #       registry_attributes:
    #       - STANDARD
    #       registry_excluded_values:
    #       - ''
    #       registry_include_default_value: true
    #       registry_include_sub_keys: false
    #       registry_included_values:
    #       - test_1
    #       - test_3
    #       - test_4
    #       - test_2
    #       registry_key_root: HKEY_CLASSES_ROOT
    #       registry_key_value: #       severity: medium
    #       template: registry
    #     - alert_enabled: false
    #       description: THIS IS TEST IMR DESCRIPTION - 2
    #       id: 329
    #       minimum_agent_version: 6.0.0.0
    #       minimum_manager_version: 6.0.0
    #       name: THIS IS TEST IMR - 2
    #       real_time_monitoring_enabled: true
    #       registry_attributes:
    #       - test
    #       registry_excluded_values:
    #       - ''
    #       registry_include_default_value: true
    #       registry_include_sub_keys: false
    #       registry_included_values:
    #       - ''
    #       registry_key_root: HKEY_CLASSES_ROOT
    #       registry_key_value: #       severity: low
    #       template: registry



Return Values
-------------
Common return values are documented `here <https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common-return-values>`_, the following are the fields unique to this module:

.. raw:: html

    <table border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Key</th>
            <th>Returned</th>
            <th width="100%">Description</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>after</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">list</span>
                    </div>
                </td>
                <td>when changed</td>
                <td>
                            <div>The configuration as structured data after module completion.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">The configuration returned will always be in the same format of the parameters above.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>before</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">list</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>The configuration as structured data prior to module invocation.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">The configuration returned will always be in the same format of the parameters above.</div>
                </td>
            </tr>
    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>

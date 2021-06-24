.. _trendmicro.deepsec.deepsec_apikey_module:


*********************************
trendmicro.deepsec.deepsec_apikey
*********************************

**Create a new and manage API Keys.**


Version added: 1.1.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- This module create and manages API key under TrendMicro Deep Security.




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
                    <b>api_keys</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=dictionary</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>List of API keys that needs to be configured</div>
                </td>
            </tr>
                                <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>active</b>
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
                        <div>If true, the APIKey can be used to authenticate. If false, the APIKey is locked out. Searchable as Boolean.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>created</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Timestamp of the APIKey&#x27;s creation, in milliseconds since epoch. Searchable as Date.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>current</b>
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
                        <div>If true, generates a new secret key for the current API key.</div>
                        <div>Valid param only with secret_key.</div>
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
                        <div>Description of the APIKey. Searchable as String.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>expiry_date</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Timestamp of the APIKey&#x27;s expiry date, in milliseconds since epoch. Searchable as Date.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The ID number of the API key to modify. Required when modifying the API key</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>key_name</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Display name of the APIKey. Searchable as String.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>last_sign_in</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Timestamp of the APIKey&#x27;s last successful authentication, in milliseconds since epoch. Searchable as Date.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>locale</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>en-US</li>
                                    <li>ja-JP</li>
                        </ul>
                </td>
                <td>
                        <div>Country and language for the APIKey.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>role_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>ID of the role assigned to the APIKey. Searchable as Numeric.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>secret_key</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Secret key used to authenticate API requests. Only returned when creating a new APIKey or regenerating the secret key.</div>
                        <div>With secret key generation as everytime request is fired it&#x27;ll try to create a new secret key, so with secret key idempotency will not be maintained</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>service_account</b>
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
                        <div>If true, the APIKey was created by the primary tenant (T0) to authenticate API calls against other tenants&#x27; databases. Searchable as Boolean.</div>
                        <div>Valid param only with secret_key.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>time_zone</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Display name of the APIKey&#x27;s time zone, e.g. America/New_York. Searchable as String.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>unlock_time</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Timestamp of when a locked out APIKey will be unlocked, in milliseconds since epoch. Searchable as Date.</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>unsuccessful_sign_in_attempts</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Number of unsuccessful authentication attempts made since the last successful authentication. Searchable as Numeric.</div>
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
                                    <li><div style="color: blue"><b>present</b>&nbsp;&larr;</div></li>
                                    <li>absent</li>
                                    <li>gathered</li>
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

    - name: Create a new API key
      trendmicro.deepsec.deepsec_apikey:
        state: present
        api_keys:
          - key_name: admin_apiKeys
            description: test API keys 1
            active: true
            role_id: 1
            locale: en-US
          - key_name: auditor_apiKeys
            description: test API keys 2
            active: true
            role_id: 2
            locale: en-US

    - name: Generate Secret key for current API key
      trendmicro.deepsec.deepsec_apikey:
        state: present
        api_keys:
          - current: true

    - name: Generate Secret key for specified API key
      trendmicro.deepsec.deepsec_apikey:
        state: present
        api_keys:
          - key_name: admin_apiKeys
            secret_key: test_secret

    - name: Get the API keys by Name
      trendmicro.deepsec.deepsec_apikey:
        api_keys:
          - key_name: admin_apiKeys
        state: gathered

    # Gathered output:
    #  "gathered": {
    #     "api_keys": [
    #           {
    #               "active": true,
    #               "created": 1621845321503,
    #               "description": "test API keys 1",
    #               "id": 1,
    #               "key_name": "admin_apiKeys",
    #               "locale": "en-US",
    #               "role_id": 1,
    #               "service_account": false,
    #               "time_zone": "UTC",
    #               "unsuccessful_sign_in_attempts": 0
    #           }
    #        ]
    #     },

    - name: Get all the API keys
      trendmicro.deepsec.deepsec_apikey:
        state: gathered

    #   "gathered": {
    #         "api_keys": [
    #             {
    #                 "active": true,
    #                 "created": 1621845321503,
    #                 "description": "test API keys 1",
    #                 "id": 1,
    #                 "key_name": "admin_apiKeys",
    #                 "locale": "en-US",
    #                 "role_id": 1,
    #                 "service_account": false,
    #                 "time_zone": "UTC",
    #                 "unsuccessful_sign_in_attempts": 0
    #             },
    #             {
    #                 "active": true,
    #                 "created": 1621845321503,
    #                 "description": "test API keys 2",
    #                 "id": 2,
    #                 "key_name": "auditor_apiKeys",
    #                 "locale": "en-US",
    #                 "role_id": 1,
    #                 "service_account": false,
    #                 "time_zone": "UTC",
    #                 "unsuccessful_sign_in_attempts": 0
    #             }
    #         ]
    #     },

    - name: Delete/Remove the API key by name
      trendmicro.deepsec.deepsec_apikey:
        state: absent
        key_name: test_apiKeys




Status
------


Authors
~~~~~~~

- Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"

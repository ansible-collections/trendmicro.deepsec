.. _trendmicro.deepsec.deepsec_syslog_module:


*********************************
trendmicro.deepsec.deepsec_syslog
*********************************

**Configure or create a syslog configuration for TrendMicro Deep Security**


Version added: 1.0.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Configure or create a syslog configuration for TrendMicro Deep Security




Parameters
----------

.. raw:: html

    <table  border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Parameter</th>
            <th>Choices/<font color="blue">Defaults</font></th>
            <th width="100%">Comments</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>certificate_chain</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The identity certificate chain the Deep Security Manager will use when it contacts the syslog server over TLS.</div>
                        <div>The identity certificate must be the first certificate in the list, followed by the certificate for the issuing certificate authority (if any) and continuing up the issuer chain.</div>
                        <div>The root certificate authority&#x27;s certificate does not need to be included.</div>
                        <div>Each element in the list will be an unencrypted PEM-encoded certificate.</div>
                </td>
            </tr>
            <tr>
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
                        <div>The description for this syslog configuration.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>direct</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>no</b>&nbsp;&larr;</div></li>
                                    <li>yes</li>
                        </ul>
                </td>
                <td>
                        <div>The &quot;direct delivery from agent to syslog server&quot; flag</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>event_format</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>standard</li>
                                    <li><div style="color: blue"><b>cef</b>&nbsp;&larr;</div></li>
                                    <li>leef</li>
                        </ul>
                </td>
                <td>
                        <div>The event format to use when sending syslog messages.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>facility</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>kernel</li>
                                    <li>user</li>
                                    <li>mail</li>
                                    <li>daemon</li>
                                    <li>authorization</li>
                                    <li>syslog</li>
                                    <li>printer</li>
                                    <li>news</li>
                                    <li>uucp</li>
                                    <li>clock</li>
                                    <li>authpriv</li>
                                    <li>ftp</li>
                                    <li>ntp</li>
                                    <li>log-audit</li>
                                    <li>log-alert</li>
                                    <li>cron</li>
                                    <li><div style="color: blue"><b>local0</b>&nbsp;&larr;</div></li>
                                    <li>local1</li>
                                    <li>local2</li>
                                    <li>local3</li>
                                    <li>local4</li>
                                    <li>local5</li>
                                    <li>local6</li>
                                    <li>local7</li>
                        </ul>
                </td>
                <td>
                        <div>The facility value to send with each syslog message.</div>
                </td>
            </tr>
            <tr>
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
                        <div>The ID of the syslog configuration (when editing an existing configuration).</div>
                </td>
            </tr>
            <tr>
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
                        <div>The name for this syslog configuration.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>port</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">514</div>
                </td>
                <td>
                        <div>The destination port for syslog messages.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>private_key</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The private key the Deep Security Manager will use when it contacts the syslog server over TLS.</div>
                        <div>The private key must be an RSA key in PEM-encoded PKCS#1 or PKCS#8 format.</div>
                        <div>To prevent accidental disclosure of the private key, the Deep Security Manager will not return this value; therefore Ansible does not have access to it and it can only be used to set the private key.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>server</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The destination server for syslog messages.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
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
                        <div>The state <em>gathered</em> will make a get call to the module API and transform it into structured data in the format as per the resource module argspec and the value is returned in the <em>gathered</em> key within the result.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>transport</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>udp</b>&nbsp;&larr;</div></li>
                                    <li>tcp</li>
                                    <li>tls</li>
                        </ul>
                </td>
                <td>
                        <div>The transport to use when sending syslog messages.</div>
                </td>
            </tr>
    </table>
    <br/>




Examples
--------

.. code-block:: yaml

    - name: Create/Config a new Syslog Config
      trendmicro.deepsec.deepsec_syslog:
        state: present
        name: TEST_SYSLOG
        facility: local0
        event_format: leef
        direct: false
        server: 192.0.2.1
        port: 514
        transport: udp
        description: Syslog Api request from Ansible
    - name: Delete/Remove the existing Syslog Config
      trendmicro.deepsec.deepsec_syslog:
        state: absent
        name: TEST_SYSLOG




Status
------


Authors
~~~~~~~

- Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>

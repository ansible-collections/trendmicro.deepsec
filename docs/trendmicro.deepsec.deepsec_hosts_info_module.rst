.. _trendmicro.deepsec.deepsec_hosts_info_module:


*************************************
trendmicro.deepsec.deepsec_hosts_info
*************************************

**Obtain information about one or many Hosts defined by TrendMicro Deep Security**


Version added: 1.0.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- This module obtains information about Hosts defined by TrendMicro Deep Security




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
                    <b>id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Obtain only information of the Rule with provided ID</div>
                </td>
            </tr>
    </table>
    <br/>




Examples
--------

.. code-block:: yaml

    - name: Get the Host Info
      trendmicro.deepsec.deepsec_hosts_info:
    - name: Get the Host Info by ID
      trendmicro.deepsec.deepsec_hosts_info:
        id: 1




Status
------


Authors
~~~~~~~

- Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>

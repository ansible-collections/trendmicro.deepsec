# TrendMicro DeepSecurity Ansible Collection

The Ansible TrendMicro DeepSecurity collection includes a variety of Ansible content to help automate the management of TrendMicro DeepSecurity Endpoint Security solutions.

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.9.10**.

Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

## Tested with Ansible

This collection has been tested against TrendMicro DeepSecurity with version 12.5.855.
<!-- List the versions of Ansible the collection has been tested with. Must match what is in galaxy.yml. -->

## External requirements
<!-- List any external resources the collection depends on, for example minimum versions of an OS, libraries, or utilities. Do not list other Ansible collections here. -->
### Supported connections
The TrendMicro DeepSecurity collection supports ``httpapi`` connections.

## Included content

<!--start collection content-->
### Httpapi plugins
Name | Description
--- | ---
[trendmicro.deepsec.deepsec](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/docs/trendmicro.deepsec.deepsec_httpapi.rst)|HttpApi Plugin for Trend Micro Deep Security

### Modules
Name | Description
--- | ---
[trendmicro.deepsec.deepsec_anti_malware](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/docs/trendmicro.deepsec.deepsec_anti_malware_module.rst)|Create a new antimalware under TrendMicro Deep Security Policy
[trendmicro.deepsec.deepsec_apikey](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/docs/trendmicro.deepsec.deepsec_apikey_module.rst)|Create a new and manage API Keys.
[trendmicro.deepsec.deepsec_firewallrules](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/docs/trendmicro.deepsec.deepsec_firewallrules_module.rst)|Create a new firewall rule.
[trendmicro.deepsec.deepsec_hosts_info](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/docs/trendmicro.deepsec.deepsec_hosts_info_module.rst)|Obtain information about one or many Hosts defined by TrendMicro Deep Security
[trendmicro.deepsec.deepsec_log_inspectionrules](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/docs/trendmicro.deepsec.deepsec_log_inspectionrules_module.rst)|Create a new log inspection rule.
[trendmicro.deepsec.deepsec_syslog](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/docs/trendmicro.deepsec.deepsec_syslog_module.rst)|Configure or create a syslog configuration for TrendMicro Deep Security
[trendmicro.deepsec.deepsec_system_settings](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/docs/trendmicro.deepsec.deepsec_system_settings_module.rst)|Modify the system settings for TrendMicro Deep Security.

<!--end collection content-->

## Installing this collection

You can install the TrendMicro DeepSecurity collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install trendmicro.deepsec

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: trendmicro.deepsec
```
<!-- ## Using this collection -->

### Using TrendMicro DeepSecurity Ansible Collection

An example for using this collection to manage a TM deepsecurity policy resource
[TM DeepSecurity Polcies](https://help.deepsecurity.trendmicro.com/policy-create.html?Highlight=Policies)
is as follows:

`inventory.ini` (Note the password should be managed by a [Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) for a production environment.
Trend Micro Deep security currently supports two ways as to how their REST API can be interacted with, and for each of the respective cases, the Ansible inventory will be changed slightly as mentioned below:
1. In case of the [newer REST APIs](https://automation.deepsecurity.trendmicro.com/article/fr/api-reference/) the Ansible inventory will work with the network OS `trendmicro.deepsec.deepsec`, a Trend Micro `api-secret-key` and `api-version` key:
```
[deepsec]
host_deepsec.example.com

[deepsec:vars]
ansible_network_os=trendmicro.deepsec.deepsec
ansible_httpapi_use_ssl=true
ansible_httpapi_validate_certs=false
ansible_connection=httpapi
ansible_python_interpreter=/usr/bin/python
ansible_httpapi_session_key={'api-secret-key': 'secret-key', 'api-version': 'v1'}
```
2. In case of APIs using the [legacy REST APIs](https://automation.deepsecurity.trendmicro.com/legacy-rest/12_5/index.html?env=onprem#overview), the Ansible inventory will also require the network OS `trendmicro.deepsec.deepsec`, but uses a `username` and a `password`. 
```
[deepsec]
host_deepsec.example.com

[deepsec:vars]
ansible_user=admin
ansible_httpapi_pass=password
ansible_httpapi_use_ssl=true
ansible_httpapi_validate_certs=false
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=trendmicro.deepsec.deepsec
ansible_python_interpreter=python
```

#### Using the modules with Fully Qualified Collection Name (FQCN)

You can either call modules by their Fully Qualified Collection Namespace (FQCN), like `trendmicro.deepsec.deepsec`, or you can call modules by their short name if you list the `trendmicro.deepsec` collection in the playbook's `collections`, as follows:

```yaml
---
- hosts: trendmicro
  gather_facts: false
  connection: httpapi

  collections:
    - trendmicro.deepsec

  tasks:
    - name: Create/Config a new Firewall Rule Config
      trendmicro.deepsec.deepsec_firewallrules:
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
```

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [TrendMicro DeepSecurity collection repository](https://github.com/ansible-collections/trendmicro.deepsec). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

You can also join us on:

- IRC - the ``#ansible-security`` [irc.libera.chat](https://libera.chat/) channel

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Release notes
<!--Add a link to a changelog.md file or an external docsite to cover this information. -->
Release notes are available [here](https://github.com/ansible-collections/trendmicro.deepsec/blob/main/changelogs/CHANGELOG.rst).

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

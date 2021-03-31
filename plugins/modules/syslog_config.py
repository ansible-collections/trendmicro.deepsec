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
module: syslog_config
short_description: Configure or create a syslog configuration for TrendMicro Deep Security
description:
  - Configure or create a syslog configuration for TrendMicro Deep Security
version_added: "2.9"
options:
  name:
    description:
      - The name for this syslog configuration.
    required: true
    type: str
  id:
    description:
      - The ID of the syslog configuration (when editing an existing configuration).
    required: true
    type: str
  description:
    description:
      - The description for this syslog configuration.
    type: str
  server:
    description:
      - The destination server for syslog messages.
    required: true
    type: str
  port:
    description:
      - The destination port for syslog messages.
    type: int
    default: 514
  transport:
    description:
      - The transport to use when sending syslog messages.
    type: str
    choices:
      - 'udp'
      - 'tcp'
      - 'tls'
    default: 'udp'
  event_format:
    description:
      - The event format to use when sending syslog messages.
    type: str
    choices:
      - 'standard'
      - 'cef'
      - 'leef'
    default: 'cef'
  facility:
    description:
      - The facility value to send with each syslog message.
    type: str
    choices:
      - 'kernel'
      - 'user'
      - 'mail'
      - 'daemon'
      - 'authorization'
      - 'syslog'
      - 'printer'
      - 'news'
      - 'uucp'
      - 'clock'
      - 'authpriv'
      - 'ftp'
      - 'ntp'
      - 'log-audit'
      - 'log-alert'
      - 'cron'
      - 'local0'
      - 'local1'
      - 'local2'
      - 'local3'
      - 'local4'
      - 'local5'
      - 'local6'
      - 'local7'
    default: 'local0'
  private_key:
    description:
      - The private key the Deep Security Manager will use when it contacts the syslog server over TLS.
      - The private key must be an RSA key in PEM-encoded PKCS#1 or PKCS#8 format.
      - To prevent accidental disclosure of the private key, the Deep Security Manager will not return this value;
        therefore Ansible does not have access to it and it can only be used to set the private key.
    type: str
  certificate_chain:
    description:
      - The identity certificate chain the Deep Security Manager will use when it contacts the syslog server over TLS.
      - The identity certificate must be the first certificate in the list,
        followed by the certificate for the issuing certificate authority (if any) and continuing up the issuer chain.
      - The root certificate authority's certificate does not need to be included.
      - Each element in the list will be an unencrypted PEM-encoded certificate.
    type: list
  direct:
    description:
      - The "direct delivery from agent to syslog server" flag
    type: bool
    default: false
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
- name: Create/Config a new Syslog Config
  trendmicro.deepsec.syslog_config:
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
  trendmicro.deepsec.syslog_config:
    state: absent
    name: TEST_SYSLOG
"""

RETURN = """
updates:
  description: The set of commands that will be pushed to the remote device
  returned: always
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    delete_config_with_id,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
)


def check_if_syslog_config_exists(
    deepsec_request, config_name, api_object, api_return
):
    # parse syslog  get output and search for want syslog name
    syslog_response = deepsec_request.get(api_object)
    for k in syslog_response.values():
        for each in k.get(api_return):
            if each.get("name") == config_name:
                return each
    return {}


def map_params_to_obj(module_params):
    # populate the syslog dict with actual api expected values
    obj = {}
    obj["name"] = module_params["name"]
    if module_params.get("id"):
        obj["ID"] = module_params.get("id")
    if module_params.get("description"):
        obj["description"] = module_params.get("description")
    if module_params.get("server"):
        obj["server"] = module_params.get("server")
    if module_params.get("port"):
        obj["port"] = module_params.get("port")
    if module_params.get("transport"):
        obj["transport"] = module_params.get("transport")
    if module_params.get("event_format"):
        obj["eventFormat"] = module_params.get("event_format")
    if module_params.get("facility"):
        obj["facility"] = module_params.get("facility")
    if module_params.get("private_key"):
        obj["privateKey"] = module_params.get("private_key")
    if module_params.get("certificate_chain"):
        obj["certificateChain"] = module_params.get("certificate_chain")
    if module_params.get("direct"):
        obj["direct"] = module_params.get("direct")

    return obj


def main():
    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        id=dict(type="int"),
        name=dict(required=True, type="str"),
        description=dict(type="str"),
        server=dict(type="str"),
        port=dict(type="int", default=514),
        transport=dict(
            type="str", choices=["udp", "tcp", "tls"], default="udp"
        ),
        event_format=dict(
            type="str", choices=["standard", "cef", "leef"], default="cef"
        ),
        facility=dict(
            type="str",
            choices=[
                "kernel",
                "user",
                "mail",
                "daemon",
                "authorization",
                "syslog",
                "printer",
                "news",
                "uucp",
                "clock",
                "authpriv",
                "ftp",
                "ntp",
                "log-audit",
                "log-alert",
                "cron",
                "local0",
                "local1",
                "local2",
                "local3",
                "local4",
                "local5",
                "local6",
                "local7",
            ],
            default="local0",
        ),
        certificate_chain=dict(type="list"),
        private_key=dict(type="str", no_log=True),
        direct=dict(type="bool", default=False),
    )
    api_object = "/rest/syslog-configurations"
    api_return = "syslogConfiguration"
    api_get_return = "syslogConfigurations"
    api_create_obj = "CreateSyslogConfigurationRequest"

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))
    # Search for existing syslog config via Get call
    search_existing_syslog_config = check_if_syslog_config_exists(
        deepsec_request, want["name"], api_object, api_get_return
    )

    if (
        "ID" in search_existing_syslog_config
        and module.params["state"] == "absent"
    ):
        delete_config_with_id(
            module,
            deepsec_request,
            api_object.split("/")[2],
            search_existing_syslog_config["ID"],
            api_return,
            False,
        )
    elif (
        "ID" not in search_existing_syslog_config
        and module.params["state"] == "absent"
    ):
        module.exit_json(changed=False)
    else:
        # create legacy API request body for creating Syslog-Configurations
        want = {api_create_obj: {api_return: want}}
        syslog_config = deepsec_request.post(
            "{0}".format(api_object), data=want
        )
        if "ID" in search_existing_syslog_config:
            module.exit_json(
                syslog_config=search_existing_syslog_config, changed=False
            )
        elif syslog_config.get("message"):
            module.fail_json(msg=syslog_config["message"])
        else:
            module.exit_json(syslog_config=syslog_config, changed=True)


if __name__ == "__main__":
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
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
from ansible.module_utils.six.moves.urllib.parse import quote, urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
import copy
import json


def translate_syslog_dict_keys(
    key_to_translate, to_camel_case=False, to_snake_case=False
):
    """
  It is not idiomatic Ansible to use snake case so, we do bookkeeping here for that
  """
    snake_to_camel_case = {
        "certificate_chain": "certificateChain",
        "event_format": "eventFormat",
        "private_key": "privateKey",
        "id": "ID",
    }
    for each in key_to_translate:
        if each in snake_to_camel_case:
            key_to_translate[snake_to_camel_case[each]] = key_to_translate[
                each
            ]
            del key_to_translate[each]
    # return key_to_translate

    # if to_camel_case:
    #     if key_to_translate in camel_case_to_snake_case:
    #         return camel_case_to_snake_case[key_to_translate]
    # if to_snake_case:
    #     snake_case_to_camel_case = {}

    #     for key in camel_case_to_snake_case:
    #         snake_case_to_camel_case[camel_case_to_snake_case[key]] = key

    #     if key_to_translate in snake_case_to_camel_case:
    #         return snake_case_to_camel_case[key_to_translate]

    return key_to_translate


def main():
    argspec = dict(
        id=dict(required=True, type="int"),
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
        private_key=dict(type="str"),
        direct=dict(type="bool", default=False),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    api_object = "/rest/syslog-configurations"

    check = DeepSecurityRequest(module).check_api_object_with_id(
        module, api_object
    )

    if not check:
        params = translate_syslog_dict_keys(
            utils.remove_empties(module.params), True
        )
        syslog_body = {
            "CreateSyslogConfigurationRequest": {"syslogConfiguration": params}
        }
        result = DeepSecurityRequest(module).create_api_object(
            syslog_body, api_object
        )
        module.exit_json(**result)
    else:
        result = module.params
        result["changed"] = False
        module.exit_json(**result)
    # if not result['changed']:
    #   module.exit_json(**result)

    # result = DeepSecurityRequest.create_api_object(module, api_object)


if __name__ == "__main__":
    main()

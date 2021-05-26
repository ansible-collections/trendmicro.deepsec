#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
module: deepsec_hosts_info
short_description: Obtain information about one or many Hosts defined by TrendMicro Deep Security
description:
  - This module obtains information about Hosts defined by TrendMicro Deep Security
version_added: 1.0.0
author: "Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
options:
  id:
    description:
      - Obtain only information of the Rule with provided ID
    required: false
    type: int
"""

EXAMPLES = """
- name: Get the Host Info
  trendmicro.deepsec.deepsec_hosts_info:
- name: Get the Host Info by ID
  trendmicro.deepsec.deepsec_hosts_info:
    id: 1
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
)


def main():

    argspec = dict(id=dict(required=False, type="int"))

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    deepsec_request = DeepSecurityRequest(module)

    if module.params["id"]:
        hosts = deepsec_request.get(
            "/rest/hosts/{0}".format(module.params["id"])
        )
    else:
        hosts = deepsec_request.get("/rest/hosts")

    if "hosts" in hosts:
        module.exit_json(hosts=hosts["hosts"]["hosts"], changed=False)
    else:
        if "error" in hosts:
            module.fail_json(msg=hosts["error"]["message"])
        else:
            module.fail_json(msg=hosts["message"])


if __name__ == "__main__":
    main()

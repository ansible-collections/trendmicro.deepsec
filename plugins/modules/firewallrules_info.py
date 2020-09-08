#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Sumit Jaiswal (sjaiswal@redhat.com)
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
module: firewallrules_info
short_description: Obtain information about one or many Firewall rules defined under TrendMicro Deep Security
description:
  - This module obtains information about Firewall rules defined under TrendMicro Deep Security
version_added: "2.10"
options:
  id:
    description:
      - Obtain only information of the Rule with provided ID
    required: false
    type: int

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
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
)

import copy
import json


def main():

    argspec = dict(id=dict(required=False, type="int"))
    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    deepsec_request = DeepSecurityRequest(module)

    if module.params["id"]:
        firewall_rules = deepsec_request.get(
            "/api/firewallrules/{0}".format(module.params["id"])
        )
    else:
        firewall_rules = deepsec_request.get("/api/firewallrules")
    if "firewallRules" in firewall_rules:
        module.exit_json(
            firewall_rules=firewall_rules["firewallRules"], changed=False
        )
    elif firewall_rules.get("ID"):
        module.exit_json(firewall_rules=firewall_rules, changed=False)
    else:
        module.fail_json(msg=firewall_rules["message"])


if __name__ == "__main__":
    main()

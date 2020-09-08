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
module: policies_info
short_description: Obtain information about one or many Policies defined under TrendMicro Deep Security
description:
  - This module obtains information about Policies defined under TrendMicro Deep Security
version_added: "2.10"
options:
  id:
    description:
      - Obtain only information of the Policies with provided ID
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
        policies_info = deepsec_request.get(
            "/api/policies/{0}".format(module.params["id"])
        )
    else:
        policies_info = deepsec_request.get("/api/policies")

    if "policies" in policies_info:
        module.exit_json(
            policies_info=policies_info["policies"], changed=False
        )
    elif policies_info.get("ID"):
        module.exit_json(policies_info=policies_info, changed=False)
    else:
        module.fail_json(msg=policies_info["message"])


if __name__ == "__main__":
    main()

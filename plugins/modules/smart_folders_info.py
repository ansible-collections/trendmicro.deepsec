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
module: smart_folers_info
short_description: Obtain information about Smart Folders defined by TrendMicro Deep Security
description:
  - This module obtains information about Smart Folders defined by TrendMicro Deep Security
version_added: "2.9"
options:
  id:
    description:
      - Obtain only information of the Smart Folder with provided ID
    required: false
    type: str

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
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
        smart_folders = deepsec_request.get(
            "/rest/smart-folders/{0}".format(module.params["id"])
        )
    else:
        smart_folders = deepsec_request.get("/rest/smart-folders")

    if "ListSmartFoldersResponse" in smart_folders:
        module.exit_json(
            smart_folders=smart_folders["ListSmartFoldersResponse"][
                "smartFolders"
            ],
            changed=False,
        )
    else:
        module.fail_json(msg="Unable to retrieve Smart Folders info.")


if __name__ == "__main__":
    main()

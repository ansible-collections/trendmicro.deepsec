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
module: apikeys_config
short_description: Create a new and manage API Keys. 
description:
  - This module creates a new firewall rule under TrendMicro Deep Security.
version_added: "1.0.0"
options:
  name:
    description: Display name of the APIKey. Searchable as String.
    required: true
    type: str
  id:
    description: The ID number of the API key to modify. Required when modifying
    the API key
    required: false
    type: str
  description:
    description: Description of the APIKey. Searchable as String.
    required: false
    type: str
  locale:
    description: Country and language for the APIKey.
    required: false
    choices: ["en-US", "ja-JP"]
    type: str
  role_id:
    description: ID of the role assigned to the APIKey. Searchable as Numeric.
    required: false
    type: int
  time_zone:
    description: Display name of the APIKey's time zone, e.g. America/New_York.
    Searchable as String.
    required: false
    type: str
  active:
    description: If true, the APIKey can be used to authenticate. If false, the APIKey
    is locked out. Searchable as Boolean.
    required: false
    type: bool
  created:
    description: Timestamp of the APIKey's creation, in milliseconds since epoch.
    Searchable as Date.
    required: false
    type: int
  last_sign_in:
    description: Timestamp of the APIKey's last successful authentication, in milliseconds
    since epoch. Searchable as Date.
    required: false
    type: int
  unlock_time:
    description: Timestamp of when a locked out APIKey will be unlocked, in milliseconds since epoch.
    Searchable as Date.
    required: false
    type: str
  unsuccessful_sign_in_attempts:
    description: Number of unsuccessful authentication attempts made since the last successful
    authentication. Searchable as Numeric.
    required: false
    type: int
  expiry_date:
    description: Timestamp of the APIKey's expiry date, in milliseconds since epoch.
    Searchable as Date.
    required: false
    type: int
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


# FIXME - provide correct example here
RETURN = """
"""

EXAMPLES = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    check_if_config_exists,
    delete_config_with_id,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
)


def map_params_to_obj(module_params):
    # populate the apikey dict with actual api expected values
    obj = {}
    obj["keyName"] = module_params["name"]
    if module_params.get("id"):
        obj["apiKeyID"] = module_params.get("key_id")
    if module_params.get("description"):
        obj["description"] = module_params.get("description")
    if module_params.get("locale"):
        obj["locale"] = module_params.get("locale")
    if module_params.get("role_id"):
        obj["roleID"] = module_params.get("role_id")
    if module_params.get("time_zone"):
        obj["timeZone"] = module_params.get("time_zone")
    if module_params.get("active"):
        obj["active"] = module_params.get("active")
    if module_params.get("created"):
        obj["created"] = module_params.get("created")
    if module_params.get("last_sign_in"):
        obj["lastSignIn"] = module_params.get("last_sign_in")
    if module_params.get("unlock_time"):
        obj["unlockTime"] = module_params.get("unlock_time")
    if module_params.get("unsuccessful_sign_in_attempts"):
        obj["unsuccessfulSignInAttempts"] = module_params.get("unsuccessful_sign_in_attempts")
    if module_params.get("expiry_date"):
        obj["expiryDate"] = module_params.get("expiry_date")

    return obj


def main():

    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        name=dict(required=True, type="str"),
        id=dict(required=False, type="str"),
        description=dict(type="str", required=False),
        locale=dict(
            type="str",
            choices=["en-US", "ja-JP"],
            required=False,
        ),
        role_id=dict(
            type="int", required=False
        ),
        time_zone=dict(
            type="str", required=False
        ),
        active=dict(
            type="bool",
            required=False,
        ),
        created=dict(type="int", required=False),
        last_sign_in=dict(type="int", required=False),
        unlock_time=dict(
            type="int",
            required=False,
        ),
        unsuccessful_sign_in_attempts=dict(type="int", required=False),
        expiry_date=dict(type="int", required=False),
    )

    api_object = '/api/apikeys'
    api_return = 'apiKeys'
    api_current = 'current'

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(remove_empties(module.params))

    search_existing_apikey = check_if_config_exists(
        deepsec_request, want["keyName"], api_object.split('/')[2], api_return, 'keyName'
    )

    if (
        "ID" in search_existing_apikey
        and module.params["state"] == "absent"
    ):
        delete_config_with_id(
            module,
            deepsec_request,
            api_object.split('/')[2],
            search_existing_apikey["ID"],
            api_return,
        )
    elif (
        "ID" not in search_existing_apikey
        and module.params["state"] == "absent"
    ):
        module.exit_json(changed=False)
    else:
        apikey = deepsec_request.post('{0}'.format(api_object), data=want)

        if "ID" in search_existing_apikey:
            module.exit_json(
                apikey=search_existing_apikey, changed=False
            )
        elif apikey.get("message"):
            module.fail_json(msg=apikey["message"])
        else:
            module.exit_json(apikey=apikey, changed=True)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

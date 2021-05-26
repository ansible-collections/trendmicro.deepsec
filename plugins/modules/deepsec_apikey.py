#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: deepsec_apikey
short_description: Create a new and manage API Keys.
description:
  - This module create and manages API key under TrendMicro Deep Security.
version_added: "1.1.0"
options:
  api_keys:
    description: List of API keys that needs to be configured
    type: list
    elements: dict
    suboptions:
      key_name:
        description: Display name of the APIKey. Searchable as String.
        type: str
      id:
        description: The ID number of the API key to modify. Required when modifying
          the API key
        type: str
      description:
        description: Description of the APIKey. Searchable as String.
        type: str
      locale:
        description: Country and language for the APIKey.
        choices: ["en-US", "ja-JP"]
        type: str
      role_id:
        description: ID of the role assigned to the APIKey. Searchable as Numeric.
        type: int
      time_zone:
        description: Display name of the APIKey's time zone, e.g. America/New_York.
          Searchable as String.
        type: str
      active:
        description: If true, the APIKey can be used to authenticate. If false, the APIKey
          is locked out. Searchable as Boolean.
        type: bool
      created:
        description: Timestamp of the APIKey's creation, in milliseconds since epoch.
          Searchable as Date.
        type: int
      last_sign_in:
        description: Timestamp of the APIKey's last successful authentication, in milliseconds
          since epoch. Searchable as Date.
        type: int
      unlock_time:
        description: Timestamp of when a locked out APIKey will be unlocked, in milliseconds since epoch.
          Searchable as Date.
        type: int
      unsuccessful_sign_in_attempts:
        description: Number of unsuccessful authentication attempts made since the last successful
          authentication. Searchable as Numeric.
        type: int
      expiry_date:
        description: Timestamp of the APIKey's expiry date, in milliseconds since epoch. Searchable as Date.
        type: int
      secret_key:
        description:
          - Secret key used to authenticate API requests. Only returned when creating a new APIKey or
            regenerating the secret key.
          - With secret key generation as everytime request is fired it'll try to create a new secret key,
            so with secret key idempotency will not be maintained
        type: str
      service_account:
        description:
          - If true, the APIKey was created by the primary tenant (T0) to authenticate API calls against
            other tenants' databases. Searchable as Boolean.
          - Valid param only with secret_key.
        type: bool
      current:
        description:
          - If true, generates a new secret key for the current API key.
          - Valid param only with secret_key.
        type: bool
  state:
    description:
      - The state the configuration should be left in
      - The state I(gathered) will get the module API configuration from the device and
        transform it into structured data in the format as per the module argspec and
        the value is returned in the I(gathered) key within the result.
    type: str
    choices:
      - present
      - absent
      - gathered
    default: present
author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
"""

EXAMPLES = """
- name: Create a new API key
  trendmicro.deepsec.deepsec_apikey:
    state: present
    api_keys:
      - key_name: admin_apiKeys
        description: test API keys 1
        active: true
        role_id: 1
        locale: en-US
      - key_name: auditor_apiKeys
        description: test API keys 2
        active: true
        role_id: 2
        locale: en-US

- name: Generate Secret key for current API key
  trendmicro.deepsec.deepsec_apikey:
    state: present
    api_keys:
      - current: true

- name: Generate Secret key for specified API key
  trendmicro.deepsec.deepsec_apikey:
    state: present
    api_keys:
      - key_name: admin_apiKeys
        secret_key: test_secret

- name: Get the API keys by Name
  trendmicro.deepsec.deepsec_apikey:
    api_keys:
      - key_name: admin_apiKeys
    state: gathered

# Gathered output:
#  "gathered": {
#     "api_keys": [
#           {
#               "active": true,
#               "created": 1621845321503,
#               "description": "test API keys 1",
#               "id": 1,
#               "key_name": "admin_apiKeys",
#               "locale": "en-US",
#               "role_id": 1,
#               "service_account": false,
#               "time_zone": "UTC",
#               "unsuccessful_sign_in_attempts": 0
#           }
#        ]
#     },

- name: Get all the API keys
  trendmicro.deepsec.deepsec_apikey:
    state: gathered

#   "gathered": {
#         "api_keys": [
#             {
#                 "active": true,
#                 "created": 1621845321503,
#                 "description": "test API keys 1",
#                 "id": 1,
#                 "key_name": "admin_apiKeys",
#                 "locale": "en-US",
#                 "role_id": 1,
#                 "service_account": false,
#                 "time_zone": "UTC",
#                 "unsuccessful_sign_in_attempts": 0
#             },
#             {
#                 "active": true,
#                 "created": 1621845321503,
#                 "description": "test API keys 2",
#                 "id": 2,
#                 "key_name": "auditor_apiKeys",
#                 "locale": "en-US",
#                 "role_id": 1,
#                 "service_account": false,
#                 "time_zone": "UTC",
#                 "unsuccessful_sign_in_attempts": 0
#             }
#         ]
#     },

- name: Delete/Remove the API key by name
  trendmicro.deepsec.deepsec_apikey:
    state: absent
    key_name: test_apiKeys
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
    check_if_config_exists,
    delete_config_with_id,
    map_params_to_obj,
    map_obj_to_params,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)

key_transform = {
    "key_name": "keyName",
    "description": "description",
    "id": "ID",
    "locale": "locale",
    "role_id": "roleID",
    "time_zone": "timeZone",
    "active": "active",
    "created": "created",
    "last_sign_in": "lastSignIn",
    "unlock_time": "unlockTime",
    "unsuccessful_sign_in_attempts": "unsuccessfulSignInAttempts",
    "expiry_date": "expiryDate",
    "secret_key": "secretKey",
    "service_account": "serviceAccount",
}

api_object = "/api/apikeys"
api_get_object = "/api/apikeys/search"
api_secretkey_current_object = "/api/apikeys/current/secretkey"
api_return = "apiKeys"


def display_gathered_result(argspec, module, deepsec_request):
    return_val = {}
    if module.params and module.params.get("api_keys"):
        return_val["api_keys"] = []
        for each in module.params["api_keys"]:
            want = map_params_to_obj(each, key_transform)
            search_by_id = search_for_pre_existing_key(want, deepsec_request)
            if search_by_id.get("id"):
                request_api = "{0}/{1}".format(api_object, search_by_id["id"])
                get_key_by_id = deepsec_request.get("{0}".format(request_api))
                get_key_by_id = map_obj_to_params(
                    get_key_by_id, key_transform, api_return
                )
                return_val["api_keys"].append(get_key_by_id)
            if get_key_by_id.get("message"):
                module.fail_json(msg=get_key_by_id["message"])
    else:
        return_get = deepsec_request.post(api_get_object)
        if return_get:
            return_val["api_keys"] = map_obj_to_params(
                return_get, key_transform, api_return
            )[api_return]

    utils.validate_config(argspec, return_val)
    module.exit_json(gathered=return_val, changed=False)


def search_for_pre_existing_key(want, deepsec_api_request):
    search_existing_apikey = check_if_config_exists(
        deepsec_api_request,
        want["keyName"],
        api_object.split("/")[2],
        api_return,
        "keyName",
    )
    return map_obj_to_params(search_existing_apikey, key_transform, api_return)


def delete_module_api_config(argspec, module, deepsec_request):
    if module.params and module.params.get("api_keys"):
        deleted_key = []
        for each in module.params["api_keys"]:
            key_name = each["key_name"]
            want = map_params_to_obj(each, key_transform)
            search_by_id = search_for_pre_existing_key(want, deepsec_request)
            if "id" in search_by_id:
                delete_return = delete_config_with_id(
                    module,
                    deepsec_request,
                    api_object.split("/")[2],
                    search_by_id["id"],
                    api_return,
                )
                if delete_return.get("message"):
                    error_msg = "Delete for ApiKey with key_name: {0}, failed with error: {1}".format(
                        key_name, delete_return["message"]
                    )
                    module.fail_json(msg=error_msg)
                deleted_key.append(key_name)
        if deleted_key:
            module.exit_json(
                msg="{0} with name: {1} deleted successfully!".format(
                    api_return, deleted_key
                ),
                changed=True,
            )
        else:
            module.exit_json(changed=False)


def configure_module_api(argspec, module, deepsec_request):
    if module.params and module.params.get("api_keys"):
        return_val = {}
        return_val["api_keys"] = []
        changed = False
        for each in module.params["api_keys"]:
            want = map_params_to_obj(each, key_transform)
            if not each.get("current"):
                search_existing_apikey = search_for_pre_existing_key(
                    want, deepsec_request
                )
            if each.get("current") or each.get("secret_key"):
                if each.get("current"):
                    api_key = deepsec_request.post(
                        "{0}".format(api_secretkey_current_object), data=want
                    )
                elif "id" in search_existing_apikey:
                    id = search_existing_apikey["id"]
                    request_api = "/api/apikeys/{0}/secretkey".format(id)
                    api_key = deepsec_request.post(
                        "{0}".format(request_api), data=want
                    )
                if api_key.get("message"):
                    module.fail_json(msg=api_key["message"])
                else:
                    changed = True
                    api_key = map_obj_to_params(
                        api_key, key_transform, api_return
                    )
                    return_val["api_keys"].append(api_key)
            else:
                if "id" in search_existing_apikey:
                    return_val["api_keys"].append(search_existing_apikey)
                    continue
                apikey = deepsec_request.post(
                    "{0}".format(api_object), data=want
                )
                if apikey.get("message"):
                    module.fail_json(msg=apikey["message"])
                else:
                    changed = True
                    apikey = map_obj_to_params(
                        apikey, key_transform, api_return
                    )
                    return_val["api_keys"].append(apikey)
    utils.validate_config(argspec, return_val)
    module.exit_json(config=return_val, changed=changed)


def main():
    api_keys_list_spec = {
        "key_name": dict(type="str"),
        "id": dict(type="str"),
        "description": dict(type="str"),
        "locale": dict(type="str", choices=["en-US", "ja-JP"]),
        "role_id": dict(type="int"),
        "time_zone": dict(type="str"),
        "active": dict(type="bool"),
        "created": dict(type="int"),
        "last_sign_in": dict(type="int"),
        "unlock_time": dict(type="int"),
        "unsuccessful_sign_in_attempts": dict(type="int"),
        "expiry_date": dict(type="int"),
        "secret_key": dict(no_log=True, type="str"),
        "service_account": dict(type="bool"),
        "current": dict(type="bool"),
    }

    argspec = dict(
        state=dict(
            choices=["present", "absent", "gathered"], default="present"
        ),
        api_keys=dict(
            type="list",
            elements="dict",
            options=api_keys_list_spec,
            no_log=False,
        ),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    module.params = utils.remove_empties(module.params)

    if module.params["state"] == "gathered":
        display_gathered_result(
            argspec=argspec, module=module, deepsec_request=deepsec_request
        )
    elif module.params["state"] == "absent":
        delete_module_api_config(
            argspec=argspec, module=module, deepsec_request=deepsec_request
        )
    elif module.params["state"] == "present":
        configure_module_api(
            argspec=argspec, module=module, deepsec_request=deepsec_request
        )


if __name__ == "__main__":
    main()

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
  name:
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
    name: test_apiKeys
    description: test API keys
    active: true
    locale: en-US

- name: Generate Secret key for current API key
  trendmicro.deepsec.deepsec_apikey:
    state: present
    name: test_apiKeys
    description: test API keys
    active: true
    locale: en-US
    secret_key: test_secret
    current: true

- name: Generate Secret key for specific API key with ID
  trendmicro.deepsec.deepsec_apikey:
    state: present
    name: test_apiKeys
    description: test API keys
    active: true
    locale: en-US
    secret_key: test_secret
    id: 1

- name: Get the API keys by ID
  trendmicro.deepsec.deepsec_apikey:
    id: 1
    state: gathered

- name: Get all the API keys
  trendmicro.deepsec.deepsec_apikey:
    state: gathered

- name: Delete/Remove the API key by name
  trendmicro.deepsec.deepsec_apikey:
    state: absent
    name: test_apiKeys
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
    if module_params.get("role_id") or module_params.get("role_id") == 0:
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
        obj["unsuccessfulSignInAttempts"] = module_params.get(
            "unsuccessful_sign_in_attempts"
        )
    if module_params.get("expiry_date"):
        obj["expiryDate"] = module_params.get("expiry_date")
    if module_params.get("secret_key"):
        obj["secretKey"] = module_params.get("secret_key")
        if module_params.get("service_account"):
            obj["serviceAccount"] = module_params.get("service_account")
    return obj


def main():
    argspec = dict(
        state=dict(choices=["present", "absent", "gathered"], default="present"),
        name=dict(type="str"),
        id=dict(type="str"),
        description=dict(type="str"),
        locale=dict(type="str", choices=["en-US", "ja-JP"]),
        role_id=dict(type="int"),
        time_zone=dict(type="str"),
        active=dict(type="bool"),
        created=dict(type="int"),
        last_sign_in=dict(type="int"),
        unlock_time=dict(type="int"),
        unsuccessful_sign_in_attempts=dict(type="int"),
        expiry_date=dict(type="int"),
        secret_key=dict(type="str"),
        service_account=dict(type="bool"),
        current=dict(type="bool"),
    )

    api_object = "/api/apikeys"
    api_get_object = "/api/apikeys/search"
    api_secretkey_current_object = "/api/apikeys/current/secretkey"
    api_return = "apiKeys"

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    module.params = remove_empties(module.params)

    if module.params["state"] == "gathered":
        if module.params.get("id"):
            request_api = "{0}/{1}".format(api_object, module.params["id"])
            get_key_by_id = deepsec_request.get("{0}".format(request_api))
        else:
            get_key_by_id = deepsec_request.post(api_get_object)
        if get_key_by_id.get("message"):
            module.fail_json(msg=get_key_by_id["message"])
        else:
            module.exit_json(apikey=get_key_by_id, changed=False)

    want = map_params_to_obj(module.params)
    search_existing_apikey = check_if_config_exists(
        deepsec_request,
        want["keyName"],
        api_object.split("/")[2],
        api_return,
        "keyName",
    )
    if "ID" in search_existing_apikey and module.params["state"] == "absent":
        delete_config_with_id(
            module,
            deepsec_request,
            api_object.split("/")[2],
            search_existing_apikey["ID"],
            api_return,
        )
    elif (
        "ID" not in search_existing_apikey
        and module.params["state"] == "absent"
    ):
        module.exit_json(changed=False)
    elif module.params.get("secret_key"):
        if module.params.get("current"):
            api_secret_key = deepsec_request.post(
                "{0}".format(api_secretkey_current_object), data=want
            )
        else:
            id = module.params.get("id")
            request_api = "/api/apikeys/{0}/secretkey".format(id)
            api_secret_key = deepsec_request.post(
                "{0}".format(request_api), data=want
            )
        if api_secret_key.get("message"):
            module.fail_json(msg=api_secret_key["message"])
        else:
            module.exit_json(apikey=api_secret_key, changed=True)
    else:
        apikey = deepsec_request.post("{0}".format(api_object), data=want)

        if "ID" in search_existing_apikey:
            module.exit_json(apikey=search_existing_apikey, changed=False)
        elif apikey.get("message"):
            module.fail_json(msg=apikey["message"])
        else:
            module.exit_json(apikey=apikey, changed=True)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

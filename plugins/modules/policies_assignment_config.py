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
module: policies_assignment_config
short_description: Assign/Un-Assign rules to a policy based on ruleIDs. 
description:
  - This module creates a new intrusion preventin rul under TrendMicro Deep Security.
version_added: "1.0.0"
options:
  id:
    description:
      - Obtain only information of the Rule with provided ID
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
from ansible.module_utils._text import to_text

from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
)
import copy
import json


def log_inspection_policy_assignment(
    module, deepsec_request, api, policy_id, rule_id, state
):

    if state == "present":
        want = {}
        request_api = "/api/policies/{0}/{1}/assignments".format(
            policy_id, api
        )
        want["ruleIDs"] = rule_id
        policy_assignment = deepsec_request.post(request_api, data=want)
        module.exit_json(policy_assignment=policy_assignment, changed=True)
    elif state == "absent":
        policy_assignment = []
        for each in rule_id:
            request_api = "/api/policies/{0}/{1}/assignments/{2}".format(
                policy_id, api, each
            )
            del_policy_assignment = deepsec_request.delete(request_api)
            policy_assignment.append(del_policy_assignment)
        if policy_assignment:
            module.exit_json(policy_assignment=policy_assignment, changed=True)
        else:
            module.exit_json(
                policy_assignment=policy_assignment, changed=False
            )


def map_params_to_obj(module, deepsec_request):
    obj = {}
    module_params = remove_empties(module.params)
    policy_id = module_params["policy_id"]
    rule_id = module_params["rule_id"]
    state = module_params["state"]
    policies_assignment_type = module_params["policy_assignment_type"]
    if policies_assignment_type == "log-inspection":
        exists_rule_id = check_if_policy_assignment_exists(
            deepsec_request,
            "loginspection",
            policy_id,
            rule_id,
            policies_assignment_type,
            state,
        )
        if exists_rule_id or state == "absent":
            log_inspection_policy_assignment(
                module,
                deepsec_request,
                "loginspection",
                policy_id,
                exists_rule_id,
                state,
            )
        else:
            module.exit_json(
                msg="logInspectionRules with id: {0} assigned to Policy with ID: {1}".format(
                    rule_id, policy_id
                ),
                changed=False,
            )
    elif policies_assignment_type == "firewall":
        exists_rule_id = check_if_policy_assignment_exists(
            deepsec_request,
            "firewall",
            policy_id,
            rule_id,
            policies_assignment_type,
            state,
        )
        if exists_rule_id or state == "absent":
            log_inspection_policy_assignment(
                module,
                deepsec_request,
                "firewall",
                policy_id,
                exists_rule_id,
                state,
            )
        else:
            module.exit_json(
                msg="firewallRules with id: {0} assigned to Policy with ID: {1}".format(
                    rule_id, policy_id
                ),
                changed=False,
            )
    elif policies_assignment_type == "intrusion-prevention":
        exists_rule_id = check_if_policy_assignment_exists(
            deepsec_request,
            "intrusionprevention",
            policy_id,
            rule_id,
            policies_assignment_type,
            state,
        )
        if exists_rule_id or state == "absent":
            log_inspection_policy_assignment(
                module,
                deepsec_request,
                "intrusionprevention",
                policy_id,
                exists_rule_id,
                state,
            )
        else:
            module.exit_json(
                msg="intrusionPreventionRules with id: {0} assigned to Policy with ID: {1}".format(
                    rule_id, policy_id
                ),
                changed=False,
            )


def check_if_policy_assignment_exists(
    deepsec_request, api, policy_id, rule_id, policies_assignment_type, state
):
    """ The fn check if the antimalware detect based on antimalware name
    :param deepsec_request: the objects from which the configuration should be read
    :param antimalware_name: antimalware name with which antimalware will be searched
    in existing antimalware configurations
    :rtype: A dict
    :returns: dict with search result value
    """
    exists_rule_id = []
    search_result = deepsec_request.get(
        "/api/policies/{0}/{1}/assignments".format(policy_id, api)
    )
    if search_result.get("assignedRuleIDs"):
        for each in rule_id:
            if each not in search_result["assignedRuleIDs"]:
                exists_rule_id.append(each)
        if not exists_rule_id and state == "absent":
            exists_rule_id = rule_id
    elif not search_result.get("assignedRuleIDs") and state == "present":
        exists_rule_id = rule_id
    return exists_rule_id


def main():

    argspec = dict(
        state=dict(choices=["present", "absent"], required=True),
        policy_id=dict(required=True, type="str"),
        policy_assignment_type=dict(
            choices=["firewall", "intrusion-prevention", "log-inspection"],
            required=True,
        ),
        rule_id=dict(type="list", elements="int", required=True),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)
    deepsec_request = DeepSecurityRequest(module)
    want = map_params_to_obj(module, deepsec_request)


if __name__ == "__main__":
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
from ansible.module_utils.urls import CertificateError
from ansible.module_utils.connection import ConnectionError
from ansible.module_utils.connection import Connection
from ansible.module_utils._text import to_text
from ansible.module_utils.six import iteritems

BASE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def find_dict_in_list(some_list, key, value):
    text_type = False
    try:
        to_text(value)
        text_type = True
    except TypeError:
        pass
    for some_dict in some_list:
        if key in some_dict:
            if text_type:
                if to_text(some_dict[key]).strip() == to_text(value).strip():
                    return some_dict, some_list.index(some_dict)
            else:
                if some_dict[key] == value:
                    return some_dict, some_list.index(some_dict)
    return None


def map_params_to_obj(module_params, key_transform):
    """ The fn to convert the api returned params to module params
    :param module_params: Module params
    :param key_transform: Dict with module equivalent API params
    :rtype: A dict
    :returns: dict with module prams transformed having API expected params
    """
    obj = {}
    for k, v in iteritems(key_transform):
        if module_params.get(k):
            obj[v] = module_params.get(k)
    return obj


def map_obj_to_params(module_return_params, key_transform, return_param):
    """ The fn to convert the api returned params to module params
    :param module_return_params: API returned response params
    :param key_transform: Module params
    :rtype: A dict
    :returns: dict with api returned value to module param value
    """
    temp = {}
    if module_return_params.get(return_param):
        temp[return_param] = []
        for each in module_return_params[return_param]:
            api_temp = {}
            for k, v in iteritems(key_transform):
                if v in each and each.get(v):
                    api_temp[k] = each[v]
            temp[return_param].append(api_temp)
    else:
        for k, v in iteritems(key_transform):
            if v in module_return_params and (
                module_return_params.get(v) or module_return_params.get(v) == 0
            ):
                temp[k] = module_return_params[v]
    return temp


def check_if_config_exists(
    deepsec_request,
    config_name,
    api,
    api_search_result,
    field_name="name",
    api_request="post",
):
    """ The fn check if the config_name detect based on config
    :param deepsec_request: the objects from which the configuration should be read
    :param config_name: config_name rule with which config will be searched
    :param api: REST API for which search POST call is made
    :param api_search_result: Search result in to dict which need to be filtered
    based on its api_search_result var
    :param field_name: Search field name which by default is set to name
    in existing config configurations
    :rtype: A dict
    :returns: dict with search result value
    """
    search_dict = {}
    search_dict["searchCriteria"] = []
    temp_criteria = {}
    temp_criteria["fieldName"] = field_name
    temp_criteria["stringTest"] = "equal"
    temp_criteria["stringValue"] = config_name
    search_dict["searchCriteria"].append(temp_criteria)

    if api_request == "get":
        search_result = deepsec_request.get(
            "/api/{0}/{1}".format(api, config_name)
        )
    else:
        search_result = deepsec_request.post(
            "/api/{0}/search".format(api), data=search_dict
        )
    if search_result.get(api_search_result):
        return search_result[api_search_result][0]
    return search_result


def delete_config_with_id(
    module,
    deepsec_request,
    api,
    config_id,
    api_var,
    api_or_rest=True,
    handle_return=False,
):
    """ The fn calls the delete API based on the config id
    :param deepsec_request: connection obj for TM
    :param config_id: config id for the config that's supposed to be deleted
    :param api_or_rest: Fire request for legacy or latest API call
    value has dict as its value
    :rtype: A dict
    :returns: Based on API response this fn. exits with appropriate msg
    """
    if api_or_rest:
        delete_return = deepsec_request.delete(
            "/api/{0}/{1}".format(api, config_id)
        )
    else:
        delete_return = deepsec_request.delete(
            "/rest/{0}/{1}".format(api, config_id)
        )
    if handle_return:
        module.exit_json(
            msg="{0} with id: {1} deleted successfully!".format(
                api_var, config_id
            ),
            changed=True,
        )
    else:
        return delete_return


class DeepSecurityRequest(object):
    def __init__(self, module, headers=None, not_rest_data_keys=None):
        self.module = module
        self.connection = Connection(self.module._socket_path)
        # This allows us to exclude specific argspec keys from being included by
        # the rest data that don't follow the deepsec_* naming convention
        if not_rest_data_keys:
            self.not_rest_data_keys = not_rest_data_keys
        else:
            self.not_rest_data_keys = []
        self.not_rest_data_keys.append("validate_certs")
        self.headers = headers if headers else BASE_HEADERS

    def _httpapi_error_handle(self, method, uri, **kwargs):
        # FIXME - make use of handle_httperror(self, exception) where applicable
        #   https://docs.ansible.com/ansible/latest/network/dev_guide/developing_plugins_network.html#developing-plugins-httpapi

        try:
            code, response = self.connection.send_request(
                method, uri, **kwargs
            )
        except ConnectionError as e:
            self.module.fail_json(
                msg="connection error occurred: {0}".format(e)
            )
        except CertificateError as e:
            self.module.fail_json(
                msg="certificate error occurred: {0}".format(e)
            )
        except ValueError as e:
            self.module.fail_json(msg="certificate not found: {0}".format(e))

        return response

    def get(self, url, **kwargs):
        return self._httpapi_error_handle("GET", url, **kwargs)

    def put(self, url, **kwargs):
        return self._httpapi_error_handle("PUT", url, **kwargs)

    def post(self, url, **kwargs):
        return self._httpapi_error_handle("POST", url, **kwargs)

    def patch(self, url, **kwargs):
        return self._httpapi_error_handle("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self._httpapi_error_handle("DELETE", url, **kwargs)

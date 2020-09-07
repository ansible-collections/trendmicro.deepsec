#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
from ansible.module_utils.urls import CertificateError
from ansible.module_utils.six.moves.urllib.parse import urlencode, quote_plus
from ansible.module_utils.connection import ConnectionError
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.connection import Connection
from ansible.module_utils._text import to_text
import json

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


def check_if_config_exists(deepsec_request, config_name, api, searched_result):
    """ The fn check if the config_name detect based on config
    :param deepsec_request: the objects from which the configuration should be read
    :param config_name: config_name rule with which config will be searched
    in existing config configurations
    :rtype: A dict
    :returns: dict with search result value
    """
    search_dict = {}
    search_dict["searchCriteria"] = []
    temp_criteria = {}
    temp_criteria["fieldName"] = "name"
    temp_criteria["stringTest"] = "equal"
    temp_criteria["stringValue"] = config_name
    search_dict["searchCriteria"].append(temp_criteria)

    search_result = deepsec_request.post(
        "/api/{0}/search".format(api), data=search_dict
    )
    if search_result.get(searched_result):
        return search_result[searched_result][0]
    return search_result


def delete_config_with_id(module, deepsec_request, api, config_id, api_var):
    """ The fn calls the delete API based on the config id
    :param module: ansible module object
    :param deepsec_request: connection obj for TM
    :param config_id: config id for the config that's supposed to be deleted
    value has dict as its value
    :rtype: A dict
    :returns: Based on API response this fn. exits with appropriate msg
    """
    deepsec_request.delete("/api/{0}/{1}".format(api, config_id))
    module.exit_json(
        msg="{0} with id: {1} deleted successfully!".format(
            api_var, config_id
        ),
        changed=True,
    )


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

    def check_api_object_with_id(self, module, api_uri, **kwargs):
        """ Get n Check the API based on the ID provided
        :param api: the API against which ID need to be checked
        :param id: ID against which entry needs to be checked
        :rtype: A dicts
        :returns: dict with the info related to already registered
            API entry
        """
        method = "GET"
        api_uri = api_uri + "/{0}".format(module.params["id"])
        code, response = self.connection.send_request(
            method, api_uri, **kwargs
        )
        if (
            response.get("error")
            and response.get("error").get("message") == "Object not found."
        ):
            return False
        return True

    def create_api_object(self, payload_data, api_uri, **kwargs):
        """ Get n Check the API based on the ID provided
        :param api: the API against which ID need to be checked
        :param id: ID against which entry needs to be checked
        :rtype: A dicts
        :returns: dict with the info related to already registered
            API entry
        """
        method = "POST"
        api_uri = api_uri + "/{0}".format(module.params["id"])
        code, response = self.connection.send_request(
            method, api_uri, None, payload_data
        )
        if code == 200:
            response["changed"] = True
            return response
        elif code >= 400:
            self.module.fail_json(msg=response.get("error").get("message"))
        if (
            response.get("error")
            and response.get("error").get("message") == "Object not found."
        ):
            return False
        return True

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

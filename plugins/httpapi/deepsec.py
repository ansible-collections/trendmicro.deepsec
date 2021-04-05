# (c) 2020 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
author: Ansible Security Automation Team
httpapi: deepsec
short_description: HttpApi Plugin for Trend Micro Deep Security
description:
  - This HttpApi plugin provides methods to connect to Trend Micro Deep Security
    over a HTTP(S)-based api.
version_added: "2.9"
"""

import json

from ansible.module_utils.basic import to_text, to_bytes
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.errors import AnsibleAuthenticationFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.plugins.httpapi import HttpApiBase

BASE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


class HttpApi(HttpApiBase):
    def send_request(
        self,
        request_method,
        url,
        params=None,
        data=None,
        headers=None,
        query_string_auth=False,
    ):
        params = params if params else {}
        headers = headers if headers else BASE_HEADERS
        data = data if data else {}

        # Some Trend Micro API Endpoints require the sID in the query string
        # instead of honoring the session Cookie
        if query_string_auth:
            self.connection._connect()
            params["sID"] = self._auth_token

        if params:
            params_with_val = {}
            for param in params:
                if params[param] is not None:
                    params_with_val[param] = params[param]
            url = "{0}?{1}".format(url, urlencode(params_with_val))
        try:
            self._display_request(request_method)
            response, response_data = self.connection.send(
                url,
                to_bytes(json.dumps(data)),
                method=request_method,
                headers=headers,
            )
            value = self._get_response_value(response_data)

        except HTTPError as e:
            error = json.loads(e.read())
            return e.code, error
        return response.getcode(), self._response_to_json(value)

    def _display_request(self, request_method):
        self.connection.queue_message(
            "vvvv",
            "Deep Security REST: %s %s"
            % (request_method, self.connection._url),
        )

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            return response_text

    def login(self, username, password):
        login_path = "/rest/authentication/login/primary"
        data = {
            "dsCredentials": {
                "password": to_text(password),
                "userName": to_text(username),
            }
        }

        code, auth_token = self.send_request("POST", login_path, data=data)
        try:
            if code >= 400 and isinstance(auth_token, dict):
                raise AnsibleAuthenticationFailure(
                    message="{0} Failed to acquire login token.".format(
                        auth_token["error"].get("message")
                    )
                )
            # This is still sent as an HTTP header, so we can set our connection's _auth
            # variable manually. If the token is returned to the device in another way,
            # you will have to keep track of it another way and make sure that it is sent
            # with the rest of the request from send_request()
            self.connection._auth = {"Cookie": "sID={0}".format(auth_token)}

            # Have to carry this around because variuous Trend Micro Deepsecurity REST
            # API endpoints want the sID as a querystring parameter instead of honoring
            # the session Cookie
            self._auth_token = auth_token
        except KeyError:
            raise AnsibleAuthenticationFailure(
                message="Failed to acquire login token."
            )

    def logout(self):
        if self.connection._auth is not None:
            self.send_request(
                "DELETE",
                "/rest/authentication/logout?sID={0}".format(
                    self.connection._auth["Cookie"].split("=")[-1]
                ),
            )

            # Clean up tokens
            self.connection._auth = None
            self._auth_token = None

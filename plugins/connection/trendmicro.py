#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
author: Ansible Security Team
connection: trendmicro.deepsec.trendmicro
short_description: Connect to Trendmicro Deepsec instance
description:
- This connection plugin provides a connection to remote devices over a HTTP(S)- REST based
  api.
version_added: 1.0.0
options:
  tm_access_token:
    type: str
    description:
    - The Trendmicro access token
    vars:
    - name: ansible_tm_access_token
    env:
    - name: ANSIBLE_TM_ACCESS_TOKEN
  validate_certs:
    type: boolean
    description:
    - Whether to validate SSL certificates
    default: false
    vars:
    - name: ansible_httpapi_validate_certs
  use_proxy:
    type: boolean
    description:
    - Whether to use https_proxy for requests.
    default: true
    vars:
    - name: ansible_httpapi_use_proxy
  use_ssl:
    type: boolean
    description:
    - Whether to connect using SSL (HTTPS) or not (HTTP).
    default: false
    vars:
    - name: ansible_use_ssl
  host:
    description:
    - Specifies the remote device FQDN or IP address to establish the HTTP(S) connection
      to.
    default: inventory_hostname
    vars:
    - name: ansible_host
  remote_user:
    description:
    - The username used to authenticate to the remote device when the API connection
      is first established.  If the remote_user is not specified, the connection will
      use the username of the logged in user.
    - Can be configured from the CLI via the C(--user) or C(-u) options.
    ini:
    - section: defaults
      key: remote_user
    env:
    - name: ANSIBLE_REMOTE_USER
    vars:
    - name: ansible_user
  password:
    description:
    - Configures the user password used to authenticate to the remote device when
      needed for the device API.
    vars:
    - name: ansible_password
    - name: ansible_pass
  port:
    type: int
    description:
    - Specifies the port on the remote device that listens for connections when establishing
      the HTTP(S) connection.
    - When unspecified, will pick 80 or 443 based on the value of use_ssl.
    ini:
    - section: defaults
      key: remote_port
    env:
    - name: ANSIBLE_REMOTE_PORT
    vars:
    - name: ansible_httpapi_port
  persistent_connect_timeout:
    type: int
    description:
    - Configures, in seconds, the amount of time to wait when trying to initially
      establish a persistent connection.  If this value expires before the connection
      to the remote device is completed, the connection will fail.
    default: 30
    ini:
    - section: persistent_connection
      key: connect_timeout
    env:
    - name: ANSIBLE_PERSISTENT_CONNECT_TIMEOUT
    vars:
    - name: ansible_connect_timeout
  persistent_command_timeout:
    type: int
    description:
    - Configures, in seconds, the amount of time to wait for a command to return from
      the remote device.  If this timer is exceeded before the command returns, the
      connection plugin will raise an exception and close.
    default: 60
    ini:
    - section: persistent_connection
      key: command_timeout
    env:
    - name: ANSIBLE_PERSISTENT_COMMAND_TIMEOUT
    vars:
    - name: ansible_command_timeout
  persistent_log_messages:
    type: boolean
    description:
    - This flag will enable logging the command executed and response received from
      target device in the ansible log file. For this option to work 'log_path' ansible
      configuration option is required to be set to a file path with write access.
    - Be sure to fully understand the security implications of enabling this option
      as it could create a security vulnerability by logging sensitive information
      in log file.
    default: false
    ini:
    - section: persistent_connection
      key: log_messages
    env:
    - name: ANSIBLE_PERSISTENT_LOG_MESSAGES
    vars:
    - name: ansible_persistent_log_messages
  persistent_log_message_length_max:
    type: int
    description:
    - Specify the maximum length for an individual persistent log message.
    default: 1000
    ini:
    - section: persistent_connection
      key: log_message_length_max
    env:
    - name: ANSIBLE_PERSISTENT_LOG_MESSAGE_LENGTH_MAX
    vars:
    - name: ansible_persistent_log_message_length_max
  persistent_log_file_only:
    type: bool
    description:
    - Limit persistent log file messages to the log file specified by ansible_log_file
    - This disables persistent log messages being shown in stdout
    default: False
    ini:
    - section: persistent_connection
      key: log_file_only
    env:
    - name: ANSIBLE_PERSISTENT_LOG_FILE_ONLY
    vars:
    - name: ansible_persistent_log_file_only

"""
import logging
import os
import subprocess
from functools import wraps
from functools import partial
from io import BytesIO
import json

from ansible.errors import AnsibleAuthenticationFailure
from ansible.module_utils.basic import to_text
from ansible.module_utils._text import to_bytes
from ansible.module_utils.six import PY3
from ansible.module_utils.six.moves import cPickle
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url
from ansible.errors import AnsibleConnectionFailure
from ansible.playbook.play_context import PlayContext
from ansible.plugins.connection import NetworkConnectionBase, ensure_connect

# Map ansible verbosity level to a python log level
# in the case surfacing dep python moduel logs is desired
ANSIBLE_VERBOSITY_TO_LOG_LEVEL = (0, 40, 30, 20, 10)


class PersistentConnection(NetworkConnectionBase):
    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(PersistentConnection, self).__init__(
            play_context, new_stdin, *args, **kwargs
        )
        self._play_context = play_context
        self._log_level = None
        self._set_up_logger()

    def log_with_pid(func):
        """decorator used to create a log message with PID and proc name"""

        @wraps(func)
        def wrapped(self, *args, **kwargs):
            self._log_with_pid(
                msg="Called: {name}".format(name=func.__name__)
            )()
            return func(self, *args, **kwargs)

        return wrapped

    def _log_with_pid(self, msg):
        """Create a log message with the PID and process name while debugging

        :param msg: The message for the log entry
        :type msg: str
        :return: A partial that can be execed in the calling function for accutate log source
        :rtype: Callable
        """
        if self._log_level == logging.DEBUG:
            try:
                pid = os.getpid()
                name = subprocess.check_output(
                    "ps -p {pid} -o cmd=".format(pid=pid), shell=True
                ).decode()
                msg = "({name}:{pid}) {msg}".format(
                    msg=msg, name=name, pid=pid
                )
                return partial(self._logger.log, level=logging.DEBUG, msg=msg)
            except subprocess.CalledProcessError:
                pid = os.getpid()
                name = subprocess.check_output(
                    "ps -p {pid} -o command=".format(pid=pid), shell=True
                ).decode()
                msg = "({name}:{pid}) {msg}".format(
                    msg=msg, name=name, pid=pid
                )
                return partial(self._logger.log, level=logging.DEBUG, msg=msg)
        return lambda *args: None

    def _set_up_logger(self):
        """Set up logging

        This allows the use of python style logging and logging levels
        and allow for logging from other python modules
        Log entries will be sent to the log file or log file and stdout
        based on the connection configuration
        """
        log_level = ANSIBLE_VERBOSITY_TO_LOG_LEVEL[
            min(self._play_context.verbosity, 4)
        ]
        if log_level != self._log_level:
            self._log_level = log_level
            logging.getLogger().setLevel(self._log_level)
            # Set the log level for individual modules
            logging.getLogger("trendmicro").setLevel(self._log_level)

            # Or all imported modules
            self._logger = logging.getLogger(__name__)

            old_factory = logging.getLogRecordFactory()

            def log_bridge(*args, **kwargs):
                """Bridge python package logs to the persistent log output
                Using python log level to set the ansible verbosity
                """
                record = old_factory(*args, **kwargs)
                message = "{levelname} {name} {funcName} {message}".format(
                    **record.__dict__, message=record.getMessage()
                )
                if self.get_option("persistent_log_file_only"):
                    log_type = "log"
                else:
                    log_type = "v" * ANSIBLE_VERBOSITY_TO_LOG_LEVEL.index(
                        record.levelno
                    )
                self.queue_message(
                    log_type,
                    message[
                        0 : self.get_option(
                            "persistent_log_message_length_max"
                        )
                    ],
                )
                return record

            logging.setLogRecordFactory(log_bridge)

    @log_with_pid
    def set_options(self, task_keys=None, var_options=None, direct=None):
        """ Handle inbound options, it is sent each time the Connection
        is initialized, per task. The NetworkConnectionBase class handles set_options
        It is unlikely that the new options received across the socket
        need to be used here at all"""

        super().set_options(
            task_keys=task_keys, var_options=var_options, direct=direct
        )

    @log_with_pid
    def update_play_context(self, pc_data):
        """Handle the inbound play context, it is sent each time the Connection
        is initialized, per task

        Although it may not be possible to change ansible verbosity mid playbook
        this remains here as an example of how and why processing the updated
        playbook context may be necessary
        """
        pc_data = to_bytes(pc_data)
        if PY3:
            pc_data = cPickle.loads(pc_data, encoding="bytes")
        else:
            pc_data = cPickle.loads(pc_data)
        play_context = PlayContext()
        play_context.deserialize(pc_data)
        self._play_context = play_context
        self._set_up_logger()


class Connection(PersistentConnection):
    """A sample persistent connection usign the PyGithub package
    Although this Connection will be instantiated with every task
    the first instance is handed over to ansible-connection and will continue to run
    on the other side of the socket. Methods within this connection
    should be called as:

    <do this>

    from ansible.module_utils.connection import Connection

    connection_proxy = Connection(self._connection._socket_path)
    result = connection_proxy.xxx()

    If called directly, a new connection will be created for every task
    as no object persist across tasks

    <don't do this>

    result = self._connection..xxx()
    """

    # Required for identification as connection, the value is not used in this case
    # but customarily set to the connection path
    transport = "trendmicro.deepsec.trendmicro"

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(Connection, self).__init__(
            play_context, new_stdin, *args, **kwargs
        )
        self._trendmicro = None
        self._connected = False
        self._tm_access_token = None
        self._auth = None
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def ensure_current_token(func):
        """Wrapper to detect changes mid playbook of the GH access token
        when this occurs, set the self._connected state to false
        so the Gitub instance is reinitialized with the new access token
        """

        @wraps(func)
        def wrapped(self, *args, **kwargs):
            current = None
            try:
                if self.get_option("tm_access_token"):
                    self._auth = {
                        "api-secret-key": self.get_option(
                            option="tm_access_token"
                        )
                    }
            except KeyError:
                pass
            if current != self._tm_access_token:
                self._connected = False
                msg = "TM access token changed, connection closed. Connection state = {state}".format(
                    state=self._connected
                )
                self._log_with_pid(msg=msg)()
            return func(self, *args, **kwargs)

        return wrapped

    @property
    def _url(self):
        protocol = "https" if self.get_option("use_ssl") else "http"
        host = self.get_option("host")
        port = self.get_option("port") or (443 if protocol == "https" else 80)
        return "%s://%s:%s" % (protocol, host, port)

    def login(self, username, password):
        if self._tm_access_token is None:
            login_path = "/rest/authentication/login/primary"
            data = {
                "dsCredentials": {
                    "password": to_text(password),
                    "userName": to_text(username),
                }
            }
            code, auth_token = self.send(
                login_path,
                to_bytes(json.dumps(data)),
                method="POST",
                headers=self._headers,
            )
            try:
                if code.getcode() >= 400 and isinstance(auth_token, dict):
                    raise AnsibleAuthenticationFailure(
                        message="{0} Failed to acquire login token.".format(
                            auth_token["error"].get("message")
                        )
                    )
                # This is still sent as an HTTP header, so we can set our connection's _auth
                # variable manually. If the token is returned to the device in another way,
                # you will have to keep track of it another way and make sure that it is sent
                # with the rest of the request from send_request()
                self._auth = {"Cookie": "sID={0}".format(auth_token)}
                # Have to carry this around because variuous Trend Micro Deepsecurity REST
                # API endpoints want the sID as a querystring parameter instead of honoring
                # the session Cookie
                self._tm_access_token = auth_token
            except KeyError:
                raise AnsibleAuthenticationFailure(
                    message="Failed to acquire login token."
                )

    def send(self, path, data, **kwargs):
        """
        Sends the command to the device over api
        """
        url_kwargs = dict(
            timeout=self.get_option("persistent_command_timeout"),
            validate_certs=self.get_option("validate_certs"),
            use_proxy=self.get_option("use_proxy"),
        )
        url_kwargs.update(kwargs)
        if self._auth:
            # Avoid modifying passed-in headers
            headers = self._headers
            headers.update(self._auth)
            headers.update({"api-version": "v1"})

        try:
            url = self._url + path
            self._log_messages(
                "send url '%s' with data '%s' and kwargs '%s'"
                % (url, data, url_kwargs)
            )

            response = open_url(url, data=data, **url_kwargs)
        except HTTPError as exc:
            response = exc
            raise AnsibleConnectionFailure(
                "Could not connect to {0}: {1}".format(
                    self._url + path, exc.reason
                )
            )
        except URLError as exc:
            raise AnsibleConnectionFailure(
                "Could not connect to {0}: {1}".format(
                    self._url + path, exc.reason
                )
            )
        response_buffer = BytesIO()
        resp_data = response.read()
        self._log_messages("received response: '%s'" % resp_data)
        response_buffer.write(resp_data)

        # Try to assign a new auth token if one is given
        response_buffer.seek(0)
        if isinstance(response_buffer, str):
            value = response_buffer
        else:
            value = self._get_response_value(response_buffer)
        return response, value

    @PersistentConnection.log_with_pid
    def _connect(self):
        """Although the Githu library doesn't establish a connection
        until requried, initalize the Github library with the access token
        """
        if not self._connected:
            super(Connection, self)._connect()
            if self.get_option("tm_access_token"):
                self.tm_access_token_auth = self.get_option(
                    option="tm_access_token"
                )
            else:
                self.login(
                    self.get_option("remote_user"), self.get_option("password")
                )

            self._log_with_pid(msg="Trendmicro initialized")()
            self._connected = True

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            return response_text

    def logout(self):
        if self._tm_access_token is not None:
            data = "{}"
            self.send(
                "/rest/authentication/logout?sID={0}".format(
                    self._tm_access_token
                ),
                to_bytes(json.dumps(data)),
                method="DELETE",
                headers=self._headers,
            )
            # Clean up tokens
            self._tm_access_token = None
            self._auth_token = None

    @PersistentConnection.log_with_pid
    @ensure_current_token
    @ensure_connect
    def request_method(self, url, *args, **kwargs):
        """Call a method in the GH library directly by passing a string as the function name
        useful when:

        1) a 1:1 relationship exists between the action and the underlying library
        2) the library returns by default or can be instructued to return serializable data
        """
        msg = "Request indirect method called: {method}".format(method=url)
        self._log_with_pid(msg=msg)()
        try:
            if kwargs.get("data"):
                data = kwargs["data"]
            else:
                data = "{}"
            response, response_data = self.send(
                url,
                to_bytes(json.dumps(data)),
                method=kwargs["request_method"],
                headers=self._headers,
            )
            if isinstance(response_data, str):
                value = response_data
            else:
                value = self._get_response_value(response_data)
            return response.getcode(), self._response_to_json(value)
        except AttributeError as exc:
            error = "Unhandled exception in connection"
            self._logger.exception(msg=error)
            raise AnsibleConnectionFailure(message=error, orig_exc=exc)
        finally:
            self.logout()

"""A simple IMAP/SMTP proxy that intercepts authenticate and login commands, transparently replacing them with OAuth 2.0
SASL authentication. Designed for apps/clients that don't support OAuth 2.0 but need to connect to modern servers."""

__author__ = 'Simon Robinson'
__copyright__ = 'Copyright (c) 2021 Simon Robinson'
__license__ = 'Apache 2.0'
__version__ = '2021-05-28'  # ISO 8601

import argparse
import asyncore
import base64
import binascii
import configparser
import datetime
import enum
import json
import logging
import logging.handlers
import os
import pathlib
import plistlib
import queue
import socket
import ssl
import re
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
import urllib.error

import pystray
import timeago
import webview

# for drawing the menu bar icon
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont

# for encrypting/decrypting the locally-stored credentials
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# for macOS-specific functionality: retina icon; updating menu on click
if sys.platform == 'darwin':
    import AppKit
    from AppKit import Foundation

APP_NAME = 'Email OAuth 2.0 Proxy'
APP_SHORT_NAME = 'emailproxy'
APP_PACKAGE = 'ac.robinson.email-oauth2-proxy'

VERBOSE = False  # whether to print verbose logs (controlled via 'Debug mode' option in menu, or at startup here)
CENSOR_MESSAGE = b'[[ Credentials removed from proxy log ]]'  # replaces credentials; must be a byte-type string

CONFIG_FILE_NAME = '%s.config' % APP_SHORT_NAME
CONFIG_FILE_PATH = '%s/%s' % (os.path.dirname(os.path.realpath(__file__)), CONFIG_FILE_NAME)
CONFIG_SERVER_MATCHER = re.compile(r'(?P<type>(IMAP|SMTP))-(?P<port>[\d]{4,5})')

MAX_CONNECTIONS = 0  # maximum concurrent IMAP/SMTP connections; 0 = no limit; limit is per server
CONNECTION_TIMEOUT = 15  # timeout for socket connections (seconds)

# maximum number of bytes to read from the socket at once (limit is per socket) - note that we assume clients send one
# line at once (at least during the authentication phase), and we don't handle clients that flush the connection after
# each individual character (e.g., the inbuilt Windows telnet client)
RECEIVE_BUFFER_SIZE = 65536

# seconds to wait before cancelling authentication requests (i.e., the user has this long to log in) - note that the
# actual server timeout is often around 60 seconds, so the connection may be closed in the background and immediately
# disconnect after login completes; however, the login credentials will still be saved and used for future requests
AUTHENTICATION_TIMEOUT = 600

TOKEN_EXPIRY_MARGIN = 600  # seconds before its expiry to refresh the OAuth 2.0 token

IMAP_AUTHENTICATION_REQUEST_MATCHER = re.compile(r'(?P<tag>\w+) (?P<command>(LOGIN|AUTHENTICATE)) (?P<flags>.*)',
                                                 flags=re.IGNORECASE)
IMAP_AUTHENTICATION_RESPONSE_MATCHER = re.compile(r'(?P<tag>\w+) OK AUTHENTICATE.*', flags=re.IGNORECASE)

REQUEST_QUEUE = queue.Queue()  # requests for authentication
RESPONSE_QUEUE = queue.Queue()  # responses from client web view
WEBVIEW_QUEUE = queue.Queue()  # authentication window events (macOS only)
QUEUE_SENTINEL = object()  # object to send to signify queues should exit loops

PLIST_FILE_PATH = pathlib.Path('~/Library/LaunchAgents/%s.plist' % APP_PACKAGE).expanduser()  # launchctl file location
CMD_FILE_PATH = pathlib.Path('~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/%s.cmd' %
                             APP_PACKAGE).expanduser()  # Windows startup .cmd file location

EXITING = False  # used to check whether to restart failed threads - is set to True if the user has requested to exit


class Log:
    """Simple logging to syslog/Console.app on Linux/macOS and to a local file on Windows"""

    _LOGGER = None
    _DATE_FORMAT = '%Y-%m-%d %H:%M:%S:'
    _DEFAULT_MESSAGE_FORMAT = '%s: %%(message)s' % APP_NAME

    @staticmethod
    def initialise():
        Log._LOGGER = logging.getLogger(APP_NAME)
        Log._LOGGER.setLevel(logging.INFO if sys.platform == 'darwin' else logging.DEBUG)
        if sys.platform == 'win32':
            handler = logging.FileHandler('%s/%s.log' % (os.path.dirname(os.path.realpath(__file__)), APP_SHORT_NAME))
            handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
        else:
            handler = logging.handlers.SysLogHandler(
                address='/var/run/syslog' if sys.platform == 'darwin' else '/dev/log')
            handler.setFormatter(logging.Formatter(Log._DEFAULT_MESSAGE_FORMAT))
        Log._LOGGER.addHandler(handler)

    @staticmethod
    def _log(level, *args):
        message = ' '.join(map(str, args))
        print(datetime.datetime.now().strftime(Log._DATE_FORMAT), message)

        # note: need LOG_ALERT (i.e., warning) or higher to show in syslog on macOS
        severity = Log._LOGGER.warning if sys.platform == 'darwin' else level
        if len(message) > 2048:
            truncation_message = ' [ NOTE: message over syslog length limit truncated to 2048 characters; run `%s' \
                                 ' --debug` in a terminal to see the full output ] ' % os.path.basename(__file__)
            message = message[0:2048 - len(Log._DEFAULT_MESSAGE_FORMAT) - len(truncation_message)] + truncation_message
        severity(message)

    @staticmethod
    def debug(*args):
        if VERBOSE:
            Log._log(Log._LOGGER.debug, *args)

    @staticmethod
    def info(*args):
        Log._log(Log._LOGGER.info, *args)

    @staticmethod
    def error_string(error):
        return getattr(error, 'message', repr(error))


class AppConfig:
    """Helper wrapper around ConfigParser to cache servers/accounts, and avoid writing to the file until necessary"""

    _PARSER = None
    _LOADED = False

    _SERVERS = []
    _ACCOUNTS = []

    @staticmethod
    def _load():
        AppConfig._PARSER = configparser.ConfigParser()
        AppConfig._PARSER.read(CONFIG_FILE_PATH)

        config_sections = AppConfig._PARSER.sections()
        AppConfig._SERVERS = [s for s in config_sections if CONFIG_SERVER_MATCHER.match(s)]
        AppConfig._ACCOUNTS = [s for s in config_sections if not CONFIG_SERVER_MATCHER.match(s)]
        AppConfig._LOADED = True

    @staticmethod
    def get():
        if not AppConfig._LOADED:
            AppConfig._load()
        return AppConfig._PARSER

    @staticmethod
    def reload():
        AppConfig._LOADED = False
        return AppConfig.get()

    @staticmethod
    def servers():
        AppConfig.get()  # make sure config is loaded
        return AppConfig._SERVERS

    @staticmethod
    def accounts():
        AppConfig.get()  # make sure config is loaded
        return AppConfig._ACCOUNTS

    @staticmethod
    def save():
        with open(CONFIG_FILE_PATH, 'w') as config_output:
            AppConfig._PARSER.write(config_output)


class OAuth2Helper:
    @staticmethod
    def get_oauth2_credentials(username, password, connection_info, recurse_retries=True):
        """Using the given username (i.e., email address) and password, reads account details from AppConfig and
        handles OAuth 2.0 token request and renewal, saving the updated details back to AppConfig (or removing them
        if invalid). Returns either (True, '[OAuth2 string for authentication]') or (False, '[Error message]')"""
        if username not in AppConfig.accounts():
            Log.info('Proxy config file entry missing for account', username, '- aborting login')
            return (False, '%s: No config file entry found for account %s - please add a new section with values '
                           'for permission_url, token_url, oauth2_scope, redirect_uri, client_id and '
                           'client_secret' % (APP_NAME, username))

        config = AppConfig.get()
        current_time = int(time.time())

        permission_url = config.get(username, 'permission_url', fallback=None)
        token_url = config.get(username, 'token_url', fallback=None)
        oauth2_scope = config.get(username, 'oauth2_scope', fallback=None)
        redirect_uri = config.get(username, 'redirect_uri', fallback=None)
        client_id = config.get(username, 'client_id', fallback=None)
        client_secret = config.get(username, 'client_secret', fallback=None)

        if not (permission_url and token_url and oauth2_scope and redirect_uri and client_id and client_secret):
            Log.info('Proxy config file entry incomplete for account', username, '- aborting login')
            return (False, '%s: Incomplete config file entry found for account %s - please make sure all required '
                           'fields are added (permission_url, token_url, oauth2_scope, redirect_uri, client_id '
                           'and client_secret)' % (APP_NAME, username))

        token_salt = config.get(username, 'token_salt', fallback=None)
        access_token = config.get(username, 'access_token', fallback=None)
        access_token_expiry = config.getint(username, 'access_token_expiry', fallback=current_time)
        refresh_token = config.get(username, 'refresh_token', fallback=None)

        # we hash locally-stored tokens with the given password
        if not token_salt:
            token_salt = base64.b64encode(os.urandom(16)).decode('utf-8')

        # generate encrypter/decrypter based on password and random salt
        key_derivation_function = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                                             salt=base64.b64decode(token_salt.encode('utf-8')), iterations=100000,
                                             backend=default_backend())
        key = base64.urlsafe_b64encode(key_derivation_function.derive(password.encode('utf-8')))
        cryptographer = Fernet(key)

        try:
            if not refresh_token:
                permission_url = OAuth2Helper.construct_oauth2_permission_url(permission_url, redirect_uri, client_id,
                                                                              oauth2_scope)
                # note: get_oauth2_authorisation_code is a blocking call
                (success, authorisation_code) = OAuth2Helper.get_oauth2_authorisation_code(permission_url, redirect_uri,
                                                                                           username, connection_info)
                if not success:
                    Log.info('Authentication request failed or expired for account', username, '- aborting login')
                    return False, '%s: Login failed - the authentication request expired or was cancelled for ' \
                                  'account %s' % (APP_NAME, username)

                response = OAuth2Helper.get_oauth2_authorisation_tokens(token_url, redirect_uri, client_id,
                                                                        client_secret, authorisation_code)

                access_token = response['access_token']
                config.set(username, 'token_salt', token_salt)
                config.set(username, 'access_token', OAuth2Helper.encrypt(cryptographer, access_token))
                config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                config.set(username, 'refresh_token', OAuth2Helper.encrypt(cryptographer, response['refresh_token']))
                AppConfig.save()

            else:
                if access_token_expiry - current_time < TOKEN_EXPIRY_MARGIN:  # if expiring soon, refresh token
                    response = OAuth2Helper.refresh_oauth2_access_token(token_url, client_id, client_secret,
                                                                        OAuth2Helper.decrypt(cryptographer,
                                                                                             refresh_token))

                    access_token = response['access_token']
                    config.set(username, 'access_token', OAuth2Helper.encrypt(cryptographer, access_token))
                    config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                    AppConfig.save()
                else:
                    access_token = OAuth2Helper.decrypt(cryptographer, access_token)

            # send authentication command to server (response checked in ServerConnection) - note: we only support
            # single-trip authentication (SASL) without actually checking the server's capabilities - improve?
            oauth2_string = OAuth2Helper.construct_oauth2_string(username, access_token)
            return True, oauth2_string

        except InvalidToken as e:
            # if invalid details are the reason for failure we need to remove our cached version and re-authenticate
            config.remove_option(username, 'token_salt')
            config.remove_option(username, 'access_token')
            config.remove_option(username, 'access_token_expiry')
            config.remove_option(username, 'refresh_token')
            AppConfig.save()

            if recurse_retries:
                Log.info('Retrying login due to exception while requesting OAuth 2.0 credentials:', Log.error_string(e))
                return OAuth2Helper.get_oauth2_credentials(username, password, connection_info, recurse_retries=False)

        except Exception as e:
            # note that we don't currently remove cached credentials here, as failures on the initial request are
            # before caching happens, and the assumption is that refresh token request exceptions are temporal (e.g.,
            # network errors) rather than e.g., bad requests
            Log.info('Caught exception while requesting OAuth 2.0 credentials:', Log.error_string(e))
            return False, '%s: Login failure - saved authentication data invalid for account %s' % (
                APP_NAME, username)

    @staticmethod
    def encrypt(cryptographer, byte_input):
        return cryptographer.encrypt(byte_input.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decrypt(cryptographer, byte_input):
        return cryptographer.decrypt(byte_input.encode('utf-8')).decode('utf-8')

    @staticmethod
    def oauth2_url_escape(text):
        return urllib.parse.quote(text, safe='~-._')  # see https://tools.ietf.org/html/rfc3986#section-2.3

    @staticmethod
    def oauth2_url_unescape(text):
        return urllib.parse.unquote(text)

    @staticmethod
    def construct_oauth2_permission_url(permission_url, redirect_uri, client_id, scope):
        """Constructs and returns the URL to request permission for this client to access the given scope"""
        params = {'client_id': client_id, 'redirect_uri': redirect_uri, 'scope': scope, 'response_type': 'code',
                  'access_type': 'offline'}
        param_pairs = []
        for param in sorted(iter(params.items()), key=lambda x: x[0]):
            param_pairs.append('%s=%s' % (param[0], OAuth2Helper.oauth2_url_escape(param[1])))
        return '%s?%s' % (permission_url, '&'.join(param_pairs))

    @staticmethod
    def get_oauth2_authorisation_code(permission_url, redirect_uri, username, connection_info):
        """Submit an authorisation request to the parent app and block until it is provided (or the request fails)"""
        token_request = {'connection': connection_info, 'permission_url': permission_url,
                         'redirect_uri': redirect_uri, 'username': username, 'expired': False}
        REQUEST_QUEUE.put(token_request)
        wait_time = 0
        while True:
            try:
                data = RESPONSE_QUEUE.get(block=True, timeout=1)
            except queue.Empty:
                wait_time += 1
                if wait_time < AUTHENTICATION_TIMEOUT:
                    continue
                else:
                    token_request['expired'] = True
                    REQUEST_QUEUE.put(token_request)  # re-insert the request as expired so the parent app can remove it
                    return False, None

            if data is QUEUE_SENTINEL:  # app is closing
                RESPONSE_QUEUE.put(QUEUE_SENTINEL)  # make sure all watchers exit
                return False, None

            elif data['connection'] == connection_info:  # found an authentication response meant for us
                if data['response_url'] and 'code=' in data['response_url']:
                    authorisation_code = OAuth2Helper.oauth2_url_unescape(
                        data['response_url'].split('code=')[1].split('&')[0])
                    if authorisation_code:
                        return True, authorisation_code
                return False, None

            else:  # not for this thread - put back into queue
                RESPONSE_QUEUE.put(data)
                time.sleep(1)

    @staticmethod
    def get_oauth2_authorisation_tokens(token_url, redirect_uri, client_id, client_secret, authorisation_code):
        """Requests OAuth 2.0 access and refresh tokens from token_url using the given client_id, client_secret,
        authorisation_code and redirect_uri, returning a dict with 'access_token', 'expires_in', and 'refresh_token'
        on success, or throwing an exception on failure (e.g., HTTP 400)"""
        params = {'client_id': client_id, 'client_secret': client_secret, 'code': authorisation_code,
                  'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'}
        response = urllib.request.urlopen(token_url, urllib.parse.urlencode(params).encode('utf-8')).read()
        return json.loads(response)

    @staticmethod
    def refresh_oauth2_access_token(token_url, client_id, client_secret, refresh_token):
        """Obtains a new access token from token_url using the given client_id, client_secret and refresh token,
        returning a dict with 'access_token', 'expires_in', and 'refresh_token' on success; exception on failure"""
        params = {'client_id': client_id, 'client_secret': client_secret, 'refresh_token': refresh_token,
                  'grant_type': 'refresh_token'}
        response = urllib.request.urlopen(token_url, urllib.parse.urlencode(params).encode('utf-8')).read()
        return json.loads(response)

    @staticmethod
    def construct_oauth2_string(username, access_token):
        """Constructs an OAuth 2.0 SASL authentication string from the given username and access token"""
        return 'user=%s\1auth=Bearer %s\1\1' % (username, access_token)

    @staticmethod
    def encode_oauth2_string(input_string):
        """We use encode() from imaplib's _Authenticator, but it is a private class so we can't just import it. That
        method's docstring is:
            Invoke binascii.b2a_base64 iteratively with short even length buffers, strip the trailing line feed from
            the result and append. 'Even' means a number that factors to both 6 and 8, so when it gets to the end of
            the 8-bit input there's no partial 6-bit output."""
        output_bytes = b''
        if isinstance(input_string, str):
            input_string = input_string.encode('utf-8')
        while input_string:
            if len(input_string) > 48:
                t = input_string[:48]
                input_string = input_string[48:]
            else:
                t = input_string
                input_string = b''
            e = binascii.b2a_base64(t)
            if e:
                output_bytes = output_bytes + e[:-1]
        return output_bytes

    @staticmethod
    def strip_quotes(text):
        """Remove double quotes (i.e., " characters) around a string - used for IMAP LOGIN command"""
        if text.startswith('"') and text.endswith('"'):
            return text[1:-1].replace('\\"', '"')  # also need to fix any escaped quotes within the string
        return text

    @staticmethod
    def decode_credentials(str_data):
        """Decode credentials passed as a base64-encoded string: [some data we don't need]\x00username\x00password"""
        try:
            (_, bytes_username, bytes_password) = base64.b64decode(str_data).split(b'\x00')
            return bytes_username.decode('utf-8'), bytes_password.decode('utf-8')
        except (ValueError, binascii.Error):
            # ValueError is from incorrect number of arguments; binascii.Error from incorrect encoding
            return '', ''  # no or invalid credentials provided


class OAuth2ClientConnection(asyncore.dispatcher_with_send):
    """The base client-side connection that is subclassed to handle IMAP/SMTP client interaction (note that there is
    some IMAP-specific code in here, but it is not essential, and only used to avoid logging credentials)"""

    def __init__(self, proxy_type, connection, socket_map, connection_info, server_connection, proxy_parent,
                 custom_configuration):
        asyncore.dispatcher_with_send.__init__(self, connection, map=socket_map)
        self.proxy_type = proxy_type
        self.connection_info = connection_info
        self.server_connection = server_connection
        self.proxy_parent = proxy_parent
        self.custom_configuration = custom_configuration

        self.censor_next_log = False  # try to avoid logging credentials
        self.authenticated = False

    def handle_connect(self):
        pass

    def handle_read(self):
        # note: we don't handle clients that send one character at a time (e.g., inbuilt Windows telnet client)
        byte_data = self.recv(RECEIVE_BUFFER_SIZE)

        # client is established after server; this state should not happen unless already closing
        if not self.server_connection:
            if byte_data:
                Log.debug(self.proxy_type, self.connection_info,
                          'Data received without server connection - ignoring and closing:', byte_data)
            self.close()
            return

        # we have already authenticated - nothing to do; just pass data directly to server (slightly more involved
        # than the server connection because we censor commands that contain passwords or authentication tokens)
        if self.authenticated:
            Log.debug(self.proxy_type, self.connection_info, '-->', byte_data)
            OAuth2ClientConnection.process_data(self, byte_data)

        else:
            # try to remove credentials from logged data - both inline (via regex) and those as a separate request
            if self.censor_next_log:
                log_data = CENSOR_MESSAGE
                self.censor_next_log = False
            else:
                # IMAP LOGIN command with username/password in plain text inline, and IMAP/SMTP AUTH(ENTICATE) command
                log_data = re.sub(b'(\\w+) (LOGIN) (.*)\r\n', b'\\1 \\2 %s\r\n' % CENSOR_MESSAGE, byte_data,
                                  flags=re.IGNORECASE)
                log_data = re.sub(b'(\\w*)( ?)(AUTH)(ENTICATE)? (PLAIN) (.*)\r\n',
                                  b'\\1\\2\\3\\4 \\5 %s\r\n' % CENSOR_MESSAGE, log_data, flags=re.IGNORECASE)

            Log.debug(self.proxy_type, self.connection_info, '-->', log_data)
            self.process_data(byte_data)

    def process_data(self, byte_data, censor_server_log=False):
        self.server_connection.send(byte_data, censor_server_log)  # by default just send everything straight to server

    def send(self, byte_data):
        if not self.authenticated:  # after authentication these are identical to server-side logs (in process_data)
            Log.debug(self.proxy_type, self.connection_info, '<--', byte_data)
        super().send(byte_data)

    def handle_close(self):
        Log.debug(self.proxy_type, self.connection_info, '--> [ Client disconnected ]')
        self.close()

    def close(self):
        if self.server_connection:
            self.server_connection.client_connection = None
            self.server_connection.close()
            self.server_connection = None
        self.proxy_parent.remove_client(self)
        super().close()


class IMAPOAuth2ClientConnection(OAuth2ClientConnection):
    """The client side of the connection - intercept LOGIN/AUTHENTICATE commands and replace with OAuth 2.0 SASL"""

    def __init__(self, connection, socket_map, connection_info, server_connection, proxy_parent, custom_configuration):
        super().__init__('IMAP', connection, socket_map, connection_info, server_connection, proxy_parent,
                         custom_configuration)
        self.authentication_tag = None
        self.authentication_command = None
        self.awaiting_credentials = False

    def process_data(self, byte_data, censor_server_log=False):
        str_data = byte_data.decode('utf-8', 'replace').rstrip('\r\n')

        # AUTHENTICATE PLAIN can be a two-stage request - handle credentials if they are separate from command
        if self.awaiting_credentials:
            self.awaiting_credentials = False
            (username, password) = OAuth2Helper.decode_credentials(str_data)
            self.authenticate_connection(username, password, 'authenticate')

        else:
            match = IMAP_AUTHENTICATION_REQUEST_MATCHER.match(str_data)
            if not match:  # probably an invalid command, but just let the server handle it
                super().process_data(byte_data)
                return

            # we replace the standard LOGIN/AUTHENTICATE commands with OAuth 2.0 authentication
            self.authentication_command = match.group('command').lower()
            client_flags = match.group('flags')
            if self.authentication_command == 'login':
                split_flags = client_flags.split(' ')
                if len(split_flags) > 1:
                    username = OAuth2Helper.strip_quotes(split_flags[0])
                    password = OAuth2Helper.strip_quotes(' '.join(split_flags[1:]))
                    self.authentication_tag = match.group('tag')
                    self.authenticate_connection(username, password)
                else:
                    # wrong number of arguments - let the server handle the error
                    super().process_data(byte_data)

            elif self.authentication_command == 'authenticate':
                split_flags = client_flags.split(' ')
                authentication_type = split_flags[0].lower()
                if authentication_type == 'plain':  # plain can be submitted as a single command or multiline
                    self.authentication_tag = match.group('tag')
                    if len(split_flags) > 1:
                        (username, password) = OAuth2Helper.decode_credentials(' '.join(split_flags[1:]))
                        self.authenticate_connection(username, password, 'authenticate')
                    else:
                        self.awaiting_credentials = True
                        self.censor_next_log = True
                        self.send(b'+ \r\n')  # request credentials
                else:
                    # we don't support any other methods - let the server handle the error
                    super().process_data(byte_data)

            else:
                # we haven't yet authenticated, but this is some other matched command - pass through
                super().process_data(byte_data)

    def authenticate_connection(self, username, password, command='login'):
        (success, result) = OAuth2Helper.get_oauth2_credentials(username, password, self.connection_info)
        if success:
            # send authentication command to server (response checked in ServerConnection)
            # note: we only support single-trip authentication (SASL) without checking server capabilities - improve?
            super().process_data(b'%s AUTHENTICATE XOAUTH2 ' % self.authentication_tag.encode('utf-8'))
            super().process_data(OAuth2Helper.encode_oauth2_string(result), True)
            super().process_data(b'\r\n')
            self.server_connection.authenticated_username = username

        else:
            error_message = '%s NO %s %s\r\n' % (self.authentication_tag, command.upper(), result)
            self.send(error_message.encode('utf-8'))
            self.send(b'* BYE Autologout; authentication failed\r\n')
            self.close()


class SMTPOAuth2ClientConnection(OAuth2ClientConnection):
    """The client side of the connection - intercept AUTH LOGIN commands and replace with OAuth 2.0"""

    class AUTH(enum.Enum):
        PENDING = 1
        PLAIN_AWAITING_CREDENTIALS = 2
        LOGIN_AWAITING_USERNAME = 3
        LOGIN_AWAITING_PASSWORD = 4
        AUTH_CREDENTIALS_SENT = 5

    def __init__(self, connection, socket_map, connection_info, server_connection, proxy_parent, custom_configuration):
        super().__init__('SMTP', connection, socket_map, connection_info, server_connection, proxy_parent,
                         custom_configuration)
        self.authentication_state = self.AUTH.PENDING

    def process_data(self, byte_data, censor_server_log=False):
        str_data = byte_data.decode('utf-8', 'replace').rstrip('\r\n')
        str_data_lower = str_data.lower()

        # intercept EHLO so we can add STARTTLS (in parent class)
        if self.server_connection.ehlo is None and self.custom_configuration['starttls']:
            if str_data_lower.startswith('ehlo') or str_data_lower.startswith('helo'):
                self.server_connection.ehlo = str_data  # save the command so we can replay later from the server side
            super().process_data(byte_data)
            return

        # intercept AUTH PLAIN and AUTH LOGIN to replace with AUTH XOAUTH2
        if self.authentication_state is self.AUTH.PENDING and str_data_lower.startswith('auth plain'):
            if len(str_data) > 11:  # 11 = len('AUTH PLAIN ') - this method can have the login details either inline...
                (self.server_connection.username, self.server_connection.password) = OAuth2Helper.decode_credentials(
                    str_data[11:])
                self.send_authentication_request()
            else:  # ...or requested separately
                self.authentication_state = self.AUTH.PLAIN_AWAITING_CREDENTIALS
                self.censor_next_log = True
                self.send(b'334 \r\n')  # request details (note: space after response code is mandatory)

        elif self.authentication_state is self.AUTH.PLAIN_AWAITING_CREDENTIALS:
            (self.server_connection.username, self.server_connection.password) = OAuth2Helper.decode_credentials(
                str_data)
            self.send_authentication_request()

        elif self.authentication_state is self.AUTH.PENDING and str_data_lower.startswith('auth login'):
            self.authentication_state = self.AUTH.LOGIN_AWAITING_USERNAME
            self.send(b'334 %s\r\n' % base64.b64encode(b'Username:'))

        elif self.authentication_state is self.AUTH.LOGIN_AWAITING_USERNAME:
            try:
                self.server_connection.username = base64.b64decode(str_data).decode('utf-8')
            except binascii.Error:
                self.server_connection.username = ''
            self.authentication_state = self.AUTH.LOGIN_AWAITING_PASSWORD
            self.censor_next_log = True
            self.send(b'334 %s\r\n' % base64.b64encode(b'Password:'))

        elif self.authentication_state is self.AUTH.LOGIN_AWAITING_PASSWORD:
            try:
                self.server_connection.password = base64.b64decode(str_data).decode('utf-8')
            except binascii.Error:
                self.server_connection.password = ''
            self.send_authentication_request()

        # some other command that we don't handle - pass directly to server
        else:
            super().process_data(byte_data)

    def send_authentication_request(self):
        self.authentication_state = self.AUTH.PENDING
        self.server_connection.authentication_state = SMTPOAuth2ServerConnection.AUTH.STARTED
        super().process_data(b'AUTH XOAUTH2\r\n')


class OAuth2ServerConnection(asyncore.dispatcher_with_send):
    """The base server-side connection, setting up STARTTLS if requested, subclassed for IMAP/SMTP server interaction"""

    def __init__(self, proxy_type, socket_map, server_address, connection_info, proxy_parent, custom_configuration):
        asyncore.dispatcher_with_send.__init__(self, map=socket_map)  # note: establish connection later due to STARTTLS
        self.proxy_type = proxy_type
        self.connection_info = connection_info
        self.client_connection = None
        self.server_address = server_address
        self.proxy_parent = proxy_parent
        self.custom_configuration = custom_configuration

        self.authenticated_username = None  # used only for showing last activity in the menu
        self.last_activity = 0

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect(self.server_address)

    def handle_connect(self):
        Log.debug(self.proxy_type, self.connection_info, '--> [ Client connected ]')

    def create_socket(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM):
        new_socket = socket.socket(socket_family, socket_type)
        new_socket.setblocking(True)

        # connections can either be wrapped via the STARTTLS command, or SSL from the start
        if self.custom_configuration['starttls']:
            self.set_socket(new_socket)
        else:
            ssl_context = ssl.create_default_context()
            self.set_socket(ssl_context.wrap_socket(new_socket, server_hostname=self.server_address[0]))

    def handle_read(self):
        # note: we don't handle servers that send one character at a time (no known instances, but see client side note)
        byte_data = self.recv(RECEIVE_BUFFER_SIZE)

        # data received before client is connected (or after client has disconnected) - ignore
        if not self.client_connection:
            if byte_data:
                Log.debug(self.proxy_type, self.connection_info, 'Data received without client connection - ignoring:',
                          byte_data)
            return

        # we have already authenticated - nothing to do; just pass data directly to client, ignoring overridden method
        if self.client_connection.authenticated:
            OAuth2ServerConnection.process_data(self, byte_data)

            # receiving data from the server while authenticated counts as activity (i.e., ignore pre-login negotiation)
            if self.authenticated_username is not None:
                activity_time = int(time.time())
                if activity_time > self.last_activity:
                    config = AppConfig.get()
                    config.set(self.authenticated_username, 'last_activity', str(activity_time))
                    self.last_activity = activity_time
        else:
            Log.debug(self.proxy_type, self.connection_info, '    <--', byte_data)  # command received before editing
            self.process_data(byte_data)

    def process_data(self, byte_data):
        self.client_connection.send(byte_data)  # by default we just send everything straight to the client
        if self.client_connection.authenticated:
            Log.debug(self.proxy_type, self.connection_info, '<--', byte_data)  # command after any editing/interception

    def send(self, byte_data, censor_log=False):
        if not self.client_connection.authenticated:  # after authentication these are identical to server-side logs
            Log.debug(self.proxy_type, self.connection_info, '    -->', CENSOR_MESSAGE if censor_log else byte_data)
        super().send(byte_data)

    def handle_close(self):
        Log.debug(self.proxy_type, self.connection_info, '<-- [ Server disconnected ]')
        if self.client_connection:
            self.client_connection.server_connection = None
            self.client_connection.close()
            self.client_connection = None
        self.close()


class IMAPOAuth2ServerConnection(OAuth2ServerConnection):
    """The IMAP server side - watch for the OK AUTHENTICATE response, then ignore all subsequent data"""

    # IMAP: https://tools.ietf.org/html/rfc3501
    # IMAP SASL-IR: https://tools.ietf.org/html/rfc4959
    def __init__(self, socket_map, server_address, connection_info, proxy_parent, custom_configuration):
        super().__init__('IMAP', socket_map, server_address, connection_info, proxy_parent, custom_configuration)

    def process_data(self, byte_data):
        # note: there is no reason why IMAP STARTTLS (https://tools.ietf.org/html/rfc2595) couldn't be supported here
        # as with SMTP, but it doesn't seem like any well-known servers support this, so left unimplemented for now
        str_response = byte_data.decode('utf-8', 'replace').rstrip('\r\n')

        if str_response.startswith('* CAPABILITY'):
            # intercept CAPABILITY response and replace with what we can actually do
            updated_response = re.sub(r'(AUTH=[\w]+ )+', 'AUTH=PLAIN ', str_response, flags=re.IGNORECASE)
            byte_data = (b'%s\r\n' % updated_response.encode('utf-8'))

        else:
            # if authentication succeeds, remove our proxy from the client and ignore all further communication
            match = IMAP_AUTHENTICATION_RESPONSE_MATCHER.match(str_response)
            if match and match.group('tag') == self.client_connection.authentication_tag:
                Log.info(self.proxy_type, self.connection_info,
                         '[ Successfully authenticated IMAP connection - removing proxy ]')
                if self.client_connection.authentication_command == 'login':
                    byte_data = byte_data.replace(b'OK AUTHENTICATE', b'OK LOGIN')  # make sure response is correct
                self.client_connection.authenticated = True

        super().process_data(byte_data)


class SMTPOAuth2ServerConnection(OAuth2ServerConnection):
    """The SMTP server side - setup STARTTLS, request any credentials, then watch for 235 and ignore subsequent data"""

    # SMTP: https://tools.ietf.org/html/rfc2821
    # SMTP STARTTLS: https://tools.ietf.org/html/rfc3207
    # SMTP AUTH: https://tools.ietf.org/html/rfc4954
    class STARTTLS(enum.Enum):
        PENDING = 1
        NEGOTIATING = 2
        COMPLETE = 3

    class AUTH(enum.Enum):
        PENDING = 1
        STARTED = 2
        CREDENTIALS_SENT = 3

    def __init__(self, socket_map, server_address, connection_info, proxy_parent, custom_configuration):
        super().__init__('SMTP', socket_map, server_address, connection_info, proxy_parent, custom_configuration)
        self.ehlo = None
        if self.custom_configuration['starttls']:
            self.starttls = self.STARTTLS.PENDING
        else:
            self.starttls = self.STARTTLS.COMPLETE
        self.authentication_state = self.AUTH.PENDING

        self.username = None
        self.password = None

    def process_data(self, byte_data):
        # SMTP setup and authentication involves a little more back-and-forth than IMAP as the default is STARTTLS...
        str_data = byte_data.decode('utf-8', 'replace').rstrip('\r\n')

        # before we can do anything we need to intercept EHLO/HELO and add STARTTLS...
        if self.ehlo is not None and self.starttls is not self.STARTTLS.COMPLETE:
            if self.starttls is self.STARTTLS.PENDING:
                self.send(b'STARTTLS\r\n')
                self.starttls = self.STARTTLS.NEGOTIATING

            elif self.starttls is self.STARTTLS.NEGOTIATING:
                if str_data.startswith('220'):
                    ssl_context = ssl.create_default_context()
                    super().set_socket(ssl_context.wrap_socket(self.socket, server_hostname=self.server_address[0]))
                    self.starttls = self.STARTTLS.COMPLETE
                    Log.info(self.proxy_type, self.connection_info,
                             '[ Successfully negotiated SMTP STARTTLS connection - re-sending greeting ]')
                    self.send(b'%s\r\n' % self.ehlo.encode('utf-8'))  # re-send original EHLO/HELO to server
                else:
                    super().process_data(byte_data)  # an error occurred - just send to the client and exit
                    self.client_connection.close()

        # ...then, once we have the username and password we can respond to the '334 ' response with credentials
        elif self.authentication_state is self.AUTH.STARTED and self.username is not None and self.password is not None:
            if str_data.startswith('334'):  # 334 = 'please send credentials' (note startswith; actually '334 ')
                (success, result) = OAuth2Helper.get_oauth2_credentials(self.username, self.password,
                                                                        self.connection_info)
                if success:
                    self.authentication_state = self.AUTH.CREDENTIALS_SENT
                    self.send(OAuth2Helper.encode_oauth2_string(result), True)
                    self.send(b'\r\n')
                    self.authenticated_username = self.username

                self.username = None
                self.password = None
                if not success:
                    # a local authentication error occurred - send details to the client and exit
                    super().process_data(
                        b'535 5.7.8  Authentication credentials invalid. %s\r\n' % result.encode('utf-8'))
                    self.client_connection.close()
                    return

            else:
                super().process_data(byte_data)  # an error occurred - just send to the client and exit
                self.client_connection.close()

        elif self.authentication_state is self.AUTH.CREDENTIALS_SENT:
            if str_data.startswith('235'):
                Log.info(self.proxy_type, self.connection_info,
                         '[ Successfully authenticated SMTP connection - removing proxy ]')
                self.client_connection.authenticated = True
                super().process_data(byte_data)
            else:
                super().process_data(byte_data)  # an error occurred - just send to the client and exit
                self.client_connection.close()

        else:
            # intercept EHLO response AUTH capabilities and replace with what we can actually do
            if str_data.startswith('250-'):
                updated_response = re.sub(r'250-AUTH[\w ]+', '250-AUTH PLAIN LOGIN', str_data, flags=re.IGNORECASE)
                super().process_data(b'%s\r\n' % updated_response.encode('utf-8'))
            else:
                super().process_data(byte_data)  # a server->client interaction we don't handle; ignore


class OAuth2Proxy(asyncore.dispatcher):
    """Listen on SERVER_ADDRESS:SERVER_PORT, creating a ServerConnection + ClientConnection for each new connection"""

    def __init__(self, proxy_type, local_address, server_address, custom_configuration):
        asyncore.dispatcher.__init__(self)
        self.proxy_type = proxy_type
        self.local_address = local_address
        self.server_address = server_address
        self.custom_configuration = custom_configuration
        self.client_connections = []

    def info_string(self):
        return '%s server at %s:%d proxying %s:%d' % (self.proxy_type, self.local_address[0], self.local_address[1],
                                                      self.server_address[0], self.server_address[1])

    def handle_accepted(self, connection, address):
        if MAX_CONNECTIONS <= 0 or len(self.client_connections) < MAX_CONNECTIONS:
            try:
                socket_map = {}
                server_class = globals()['%sOAuth2ServerConnection' % self.proxy_type]
                new_server_connection = server_class(socket_map, self.server_address, address, self,
                                                     self.custom_configuration)
                client_class = globals()['%sOAuth2ClientConnection' % self.proxy_type]
                new_client_connection = client_class(connection, socket_map, address, new_server_connection, self,
                                                     self.custom_configuration)
                new_server_connection.client_connection = new_client_connection
                self.client_connections.append(new_client_connection)

                threading.Thread(target=self.run_server, args=(new_client_connection, socket_map, address),
                                 name='EmailOAuth2Proxy-connection-%d' % address[1]).start()
            except ssl.SSLError:
                error_text = '%s encountered an SSL error - is the server\'s starttls setting correct? Current ' \
                             'value: %s' % (self.info_string(), self.custom_configuration['starttls'])
                Log.info(error_text)
                connection.send(b'%s\r\n' % self.bye_message(error_text).encode('utf-8'))
                connection.close()
        else:
            error_text = '%s rejecting new connection above MAX_CONNECTIONS limit of %d' % (
                self.info_string(), MAX_CONNECTIONS)
            Log.info(error_text)
            connection.send(b'%s\r\n' % self.bye_message(error_text).encode('utf-8'))
            connection.close()

    @staticmethod
    def run_server(client, socket_map, address):
        try:
            asyncore.loop(map=socket_map, timeout=CONNECTION_TIMEOUT)  # loop for a single connection thread
        except Exception as e:
            if not EXITING:
                Log.info('Caught asyncore exception in', address, 'thread loop:', Log.error_string(e))
                client.close()

    def start(self):
        Log.info('Starting %s' % self.info_string())
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(self.local_address)
        self.listen(1)

    def remove_client(self, client):
        if client in self.client_connections:  # remove closed clients
            self.client_connections.remove(client)
        del client

    def bye_message(self, error_text=None):
        if self.proxy_type == 'IMAP':
            return '* BYE %s' % ('Server shutting down' if error_text is None else error_text)
        elif self.proxy_type == 'SMTP':
            return '221 %s' % ('2.0.0 Service closing transmission channel' if error_text is None else error_text)
        else:
            return ''

    def stop(self):
        Log.info('Stopping %s' % self.info_string())
        for connection in self.client_connections[:]:  # iterate over a copy; remove (in close()) from original
            connection.send(b'%s\r\n' % self.bye_message().encode('utf-8'))  # try to exit gracefully
            connection.close()  # closes both client and server
        self.close()

    def restart(self):
        self.stop()
        self.start()

    def handle_close(self):
        # if we encounter an exception in asyncore, handle_close() is called; restart this server - typically one of:
        # - (<class 'socket.gaierror'>:[Errno 8] nodename nor servname provided, or not known (asyncore.py|read)
        # - (<class 'TimeoutError'>:[Errno 60] Operation timed out (asyncore.py|read)
        # note - intentionally not overriding handle_error() so we see errors in the log rather than hiding them
        Log.info('Unexpected close of proxy connection - restarting %s' % self.info_string())
        try:
            self.restart()
        except Exception as e:
            Log.info('Abandoning server restart of %s due to repeated exception: %s' % (self.info_string(),
                                                                                        Log.error_string(e)))


class AuthorisationWindow:
    """Used to dynamically add the missing get_title method to a pywebview window"""

    # noinspection PyUnresolvedReferences
    def get_title(self):
        return self.title


# noinspection PyPackageRequirements,PyUnresolvedReferences,PyProtectedMember
class RetinaIcon(pystray.Icon):
    """Used to dynamically override the default pystray behaviour on macOS to support high-dpi ('retina') icons and
    regeneration of certain parts of the menu each time the icon is clicked """

    def _create_menu(self, descriptors, callbacks):
        # we add a new delegate to each created menu/submenu so that we can respond to menuNeedsUpdate
        menu = super()._create_menu(descriptors, callbacks)
        menu.setDelegate_(self._refresh_delegate)
        return menu

    def _mark_ready(self):
        # in order to create the delegate *after* the NSApplication has been initialised, but only once, we override
        # _mark_ready() to do so before the super() call that itself calls _create_menu()
        self._refresh_delegate = self.MenuDelegate.alloc().init()
        super()._mark_ready()

    if sys.platform == 'darwin':
        # noinspection PyUnresolvedReferences
        class MenuDelegate(Foundation.NSObject):
            # noinspection PyMethodMayBeStatic,PyProtectedMember,PyPep8Naming
            def menuNeedsUpdate_(self, sender):
                # update account menu items' last activity times from config cache - it would be better to delegate this
                # entirely to App.create_config_menu() via update_menu(), but can't replace the menu while creating it
                config_accounts = AppConfig.accounts()
                menu_items = sender._itemArray()
                for item in menu_items:
                    for account in config_accounts:
                        account_title = '\t%s (' % account  # needed to avoid matching authentication menu
                        if account_title in item.title():
                            item.setTitle_(App.get_last_activity(account))
                            break
                return True

    def _assert_image(self):
        # pystray does some scaling here which breaks macOS retina icons - we replace that with the actual menu bar size
        # PIL to NSImage - partly duplicates what we do to load the icon, but kept to preserve platform compatibility
        bytes_image = BytesIO()
        self.icon.save(bytes_image, 'png')
        data = Foundation.NSData(bytes_image.getvalue())
        self._icon_image = AppKit.NSImage.alloc().initWithData_(data)

        thickness = self._status_bar.thickness()  # macOS menu bar size - default = 22px, but can be scaled
        self._icon_image.setSize_((int(thickness), int(thickness)))
        self._icon_image.setTemplate_(True)  # so macOS applies the default shading and inverse on click
        self._status_item.button().setImage_(self._icon_image)


class App:
    """Manage the menu bar icon, server loading, authorisation and notifications, and start the main proxy thread"""

    def __init__(self):
        Log.initialise()

        parser = argparse.ArgumentParser(description=APP_NAME)
        parser.add_argument('--no-gui', action='store_true', help='start the proxy without a menu bar icon (note: '
                                                                  'account authorisation requests will fail)')
        parser.add_argument('--debug', action='store_true', help='enable debug mode, printing client<->proxy<->server '
                                                                 'interaction to the system log')
        parser.add_argument('--manual-auth', action='store_true', help='handle authorisation via an external browser '
                                                                       'rather than within this script')
        self.args = parser.parse_args()
        if self.args.debug:
            global VERBOSE
            VERBOSE = True

        if sys.platform == 'darwin':
            # hide dock icon (but not LSBackgroundOnly as we need input via webview)
            # noinspection PyUnresolvedReferences
            info = AppKit.NSBundle.mainBundle().infoDictionary()
            info['LSUIElement'] = '1'

        self.proxies = []
        self.authorisation_requests = []

        self.web_view_started = False

        if self.args.no_gui:
            self.icon = None
            self.load_servers(self.icon)
        else:
            self.icon = self.create_icon()
            self.icon.run(self.post_create)

    def create_icon(self):
        icon_class = RetinaIcon if sys.platform == 'darwin' else pystray.Icon
        return icon_class(APP_NAME, App.get_image(), APP_NAME, menu=pystray.Menu(
            pystray.MenuItem('Servers and accounts', pystray.Menu(self.create_config_menu)),
            pystray.MenuItem('Authorise account', pystray.Menu(self.create_authorisation_menu)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Start at login', self.toggle_start_at_login,
                             checked=self.started_at_login, visible=sys.platform in ['darwin', 'win32']),
            pystray.MenuItem('Debug mode', self.toggle_verbose, checked=lambda _: VERBOSE),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quit %s' % APP_NAME, self.exit)))

    @staticmethod
    def get_image():
        # we use an icon font for better multiplatform compatibility and icon size flexibility
        icon_font_file = '%s/icon.ttf' % os.path.dirname(os.path.realpath(__file__))
        icon_colour = 'black' if sys.platform == 'darwin' else 'white'
        icon_character = 'e'
        icon_background_width = 44
        icon_background_height = 44
        icon_width = 40  # to allow for padding between icon and background image size

        # find the largest font size that will let us draw the icon within the available width
        minimum_font_size = 1
        maximum_font_size = 255
        font, font_width, font_height = App.get_icon_size(icon_font_file, icon_character, minimum_font_size)
        while maximum_font_size - minimum_font_size > 1:
            current_font_size = round((minimum_font_size + maximum_font_size) / 2)  # ImageFont only supports integers
            font, font_width, font_height = App.get_icon_size(icon_font_file, icon_character, current_font_size)
            if font_width > icon_width:
                maximum_font_size = current_font_size
            elif font_width < icon_width:
                minimum_font_size = current_font_size
            else:
                break
        if font_width > icon_width:  # because we have to round font sizes we need one final check for oversize width
            font, font_width, font_height = App.get_icon_size(icon_font_file, icon_character, minimum_font_size)

        icon_image = Image.new('RGBA', (icon_background_width, icon_background_height))
        draw = ImageDraw.Draw(icon_image)
        icon_x = (icon_background_width - font_width) / 2
        icon_y = (icon_background_height - font_height) / 2
        draw.text((icon_x, icon_y), icon_character, font=font, fill=icon_colour)

        return icon_image

    @staticmethod
    def get_icon_size(font_file, text, font_size):
        font = ImageFont.truetype(font_file, size=font_size)
        font_width, font_height = font.getsize(text)
        return font, font_width, font_height

    def create_config_menu(self):
        items = [pystray.MenuItem('Servers:', None, enabled=False)]
        if len(self.proxies) <= 0:
            items.append(pystray.MenuItem('\tNo servers configured', None, enabled=False))
        else:
            for proxy in self.proxies:
                items.append(pystray.MenuItem('\t%s:%d ➝ %s:%d' % (proxy.local_address[0], proxy.local_address[1],
                                                                   proxy.server_address[0], proxy.server_address[1]),
                                              None, enabled=False))
        items.append(pystray.Menu.SEPARATOR)

        config_accounts = AppConfig.accounts()
        items.append(pystray.MenuItem('Accounts (+ last authenticated activity):', None, enabled=False))
        if len(config_accounts) <= 0:
            items.append(pystray.MenuItem('\tNo accounts configured', None, enabled=False))
        else:
            for account in config_accounts:
                items.append(pystray.MenuItem(App.get_last_activity(account), None, enabled=False))
            if not sys.platform == 'darwin':
                items.append(pystray.MenuItem('\tRefresh activity data', self.icon.update_menu))
        items.append(pystray.Menu.SEPARATOR)

        items.append(pystray.MenuItem('Edit configuration file...', self.edit_config))
        items.append(pystray.MenuItem('Reload configuration file', self.load_servers))
        return items

    @staticmethod
    def get_last_activity(account):
        config = AppConfig.get()
        last_sync = config.get(account, 'last_activity', fallback=None)
        if last_sync is not None:
            formatted_sync_time = timeago.format(datetime.datetime.fromtimestamp(float(last_sync)),
                                                 datetime.datetime.now(), 'en_short')
        else:
            formatted_sync_time = 'never'
        return '\t%s (%s)' % (account, formatted_sync_time)

    @staticmethod
    def edit_config(_):
        if sys.platform == 'darwin':
            os.system('open %s' % CONFIG_FILE_PATH)
        elif sys.platform == 'win32':
            os.startfile(CONFIG_FILE_PATH)
        elif sys.platform.startswith('linux'):
            os.system('xdg-open %s' % CONFIG_FILE_PATH)
        else:
            pass  # nothing we can do

    def create_authorisation_menu(self):
        items = []
        if len(self.authorisation_requests) <= 0:
            items.append(pystray.MenuItem('No pending authorisation requests', None, enabled=False))
        else:
            usernames = []
            for request in self.authorisation_requests:
                if not request['username'] in usernames:
                    items.append(pystray.MenuItem(request['username'], self.authorise_account))
                    usernames.append(request['username'])
        return items

    def authorise_account(self, _, item):
        for request in self.authorisation_requests:
            if str(item) == request['username']:  # use str(item) because item.text() hangs
                if not self.web_view_started:
                    # pywebview on macOS needs start() to be called only once, so we use a dummy window to keep it open
                    # Windows is the opposite - the macOS technique freezes the tray icon; Linux is fine either way
                    self.create_authorisation_window(request)
                    if sys.platform == 'darwin':
                        webview.start(self.handle_authorisation_windows)
                        self.web_view_started = True
                    else:
                        webview.start()
                else:
                    WEBVIEW_QUEUE.put(request)  # future requests need to use the same thread
                return
        self.notify(APP_NAME, 'There are no pending authorisation requests')

    def create_authorisation_window(self, request):
        # note that the webview title *must* end with a space and then the email address/username
        window_title = 'Authorise your account: %s' % request['username']
        if not self.args.manual_auth:
            manual_auth_html = '''<html>
                <p>Visit the following link in your browser to authorise the login request for %s:
                <textarea rows="3" style="width:100%%">%s</textarea></p>
                <form onsubmit="window.location.assign(document.forms[0].auth.value); return false">
                <p>After logging in and authorising your account, enter the result URL from the browser 
                address bar in the box below. Note that your browser may show a navigation error (e.g., 404) 
                at the end of the login process, but the URL is the important part (typically 
                <em>http://localhost [...] &amp;code=[code] &amp; [...]</em>)</p>
                <label for="auth">Authorisation URL: </label><input type="text" id="auth">
                <input type="submit">
                </form>
                </html>''' % (request['username'], request['permission_url'])
            authorisation_window = webview.create_window(window_title, html=manual_auth_html, on_top=True)
        else:
            authorisation_window = webview.create_window(window_title, request['permission_url'], on_top=True)
        setattr(authorisation_window, 'get_title', AuthorisationWindow.get_title)  # add missing get_title method
        authorisation_window.loaded += self.authorisation_loaded

    def handle_authorisation_windows(self):
        # needed on macOS because otherwise closing the last remaining webview window exits the application
        dummy_window = webview.create_window('%s hidden (dummy) window' % APP_NAME, html='<html></html>', hidden=True)
        dummy_window.hide()  # hidden=True (above) doesn't seem to work on Linux

        while True:
            data = WEBVIEW_QUEUE.get()  # note: blocking call
            if data is QUEUE_SENTINEL:  # app is closing
                break
            else:
                self.create_authorisation_window(data)

    def authorisation_loaded(self):
        for window in webview.windows[:]:  # iterate over a copy; remove (in destroy()) from original
            if not hasattr(window, 'get_title'):
                continue  # skip dummy window

            url = window.get_current_url()
            account_name = window.get_title(window).split(' ')[-1]  # see note above: title *must* match this format
            if not url or not account_name:
                continue  # skip any invalid windows

            # respond to both the original request and any duplicates in the list
            completed_request = None
            for request in self.authorisation_requests[:]:  # iterate over a copy; remove from original
                if url.startswith(request['redirect_uri']) and account_name == request['username']:
                    Log.info('Successfully authorised request for', request['username'])
                    RESPONSE_QUEUE.put({'connection': request['connection'], 'response_url': url})
                    self.authorisation_requests.remove(request)
                    completed_request = request

            if completed_request is None:
                continue  # no requests processed for this window - nothing to do yet

            window.destroy()
            self.icon.update_menu()

            # note that in this part of the interaction we don't actually check the *use* of the authorisation code,
            # but just whether it was successfully acquired - if there is an error in the subsequent access/refresh
            # token request then we still send an 'authentication completed' notification here, but in the background
            # we close the connection with a failure message and re-request authorisation next time the client
            # interacts, which may potentially lead to repeated and conflicting (and confusing) notifications - improve?
            if len(self.authorisation_requests) > 0:
                self.notify(APP_NAME,
                            'Authentication completed for %s. Please authorise an additional account %s from the '
                            'menu' % (completed_request['username'], self.authorisation_requests[0]['username']))
            else:
                self.notify(APP_NAME, 'Authentication completed for %s' % completed_request['username'])

    def toggle_start_at_login(self, icon):
        if sys.platform == 'darwin':
            if not PLIST_FILE_PATH.exists():
                # need to create and load the plist
                plist = {
                    'Label': APP_PACKAGE,
                    'ProgramArguments': [
                        subprocess.check_output('which python3', shell=True).decode('utf-8').strip(),
                        os.path.realpath(__file__)],
                    'RunAtLoad': True
                }
            else:
                # just toggle the disabled value rather than loading/unloading, so we don't need to restart the app
                with open(PLIST_FILE_PATH, 'rb') as plist_file:
                    plist = plistlib.load(plist_file)
                plist['Disabled'] = True if 'Disabled' not in plist else not plist['Disabled']

            with open(PLIST_FILE_PATH, 'wb') as plist_file:
                plistlib.dump(plist, plist_file)

            # if loading, need to exit so we're not running twice (note: relies on exiting completing before loading)
            # noinspection PyPackageRequirements
            import launchctl
            if not launchctl.job(APP_PACKAGE):
                launchctl.load(PLIST_FILE_PATH)
                self.exit(icon)

        elif sys.platform == 'win32':
            if not CMD_FILE_PATH.exists():
                windows_command = 'start %s %s' % (
                    subprocess.check_output('where pythonw', shell=True).decode('utf-8').strip(),
                    os.path.realpath(__file__))

                with open(CMD_FILE_PATH, 'w') as cmd_file:
                    cmd_file.write(windows_command)

                subprocess.call(windows_command, shell=True)  # as above, relies on exiting completing before loading
                self.exit(icon)
            else:
                os.remove(CMD_FILE_PATH)

        else:
            pass  # see https://github.com/simonrob/email-oauth2-proxy/issues/2#issuecomment-839713677 for Linux options

    @staticmethod
    def started_at_login(_):
        if sys.platform == 'darwin':
            # note: menu state will be stale if changed externally, but clicking menu item forces a refresh
            if PLIST_FILE_PATH.exists():
                # noinspection PyPackageRequirements
                import launchctl
                if launchctl.job(APP_PACKAGE):
                    with open(PLIST_FILE_PATH, 'rb') as plist_file:
                        plist = plistlib.load(plist_file)
                    if 'Disabled' in plist:
                        return not plist['Disabled']
                    return True  # job is loaded and is not disabled

        elif sys.platform == 'win32':
            return CMD_FILE_PATH.exists()  # we assume that the file's contents are correct

        return False

    @staticmethod
    def toggle_verbose(_, item):
        global VERBOSE
        VERBOSE = not item.checked

    def notify(self, title, text):
        if self.icon and self.icon.HAS_NOTIFICATION:
            self.icon.remove_notification()
            self.icon.notify('%s: %s' % (title, text))
        elif sys.platform == 'darwin':
            os.system('osascript -e \'display notification "%s" with title "%s"\'' % (text, title))
        else:
            Log.info(title, text)  # last resort

    def load_servers(self, icon):
        # we allow reloading, so must first stop any existing servers
        global RESPONSE_QUEUE
        RESPONSE_QUEUE.put(QUEUE_SENTINEL)
        RESPONSE_QUEUE = queue.Queue()  # recreate so existing queue closes watchers but we don't have to wait here
        for proxy in self.proxies:
            proxy.stop()
            proxy.close()
        self.proxies = []
        self.authorisation_requests = []  # these requests are no-longer valid

        config = AppConfig.reload()

        # load server types and configurations
        server_load_error = False
        for section in AppConfig.servers():
            match = CONFIG_SERVER_MATCHER.match(section)
            server_type = match.group('type')

            local_address = config.get(section, 'local_address', fallback='localhost')
            str_local_port = match.group('port')
            try:
                local_port = int(str_local_port)
                if local_port <= 0 or local_port > 65535:
                    raise ValueError
            except ValueError:
                server_load_error = True
                break

            server_address = config.get(section, 'server_address', fallback=None)
            server_port = config.getint(section, 'server_port', fallback=-1)
            if server_port <= 0 or server_port > 65535:
                server_load_error = True
                break

            custom_configuration = {
                'starttls': config.getboolean(section, 'starttls', fallback=False) if server_type == 'SMTP' else False
            }

            if server_address:  # all other values are checked, regex matched or have a fallback above
                new_proxy = OAuth2Proxy(server_type, (local_address, local_port), (server_address, server_port),
                                        custom_configuration)
                try:
                    new_proxy.start()
                    self.proxies.append(new_proxy)
                except Exception as e:
                    Log.info('Unable to start server:', Log.error_string(e))
                    server_load_error = True
                    break
            else:
                server_load_error = True
                break

        if server_load_error or len(self.proxies) <= 0:
            Log.info('No (or invalid) server details found - exiting')
            self.notify(APP_NAME, 'No (or invalid) server details found. Please add your accounts and servers in %s' %
                        CONFIG_FILE_NAME)
            self.exit(icon)
            return False

        if self.icon:
            self.icon.update_menu()  # force refresh the menu to show running proxy servers
        threading.Thread(target=self.run_proxy, name='EmailOAuth2Proxy-main').start()
        return True

    def post_create(self, icon):
        icon.visible = True

        if not self.load_servers(icon):
            return

        Log.info('Initialised', APP_NAME, '- listening for authentication requests')
        while True:
            data = REQUEST_QUEUE.get()  # note: blocking call
            if data is QUEUE_SENTINEL:  # app is closing
                break
            else:
                if not data['expired']:
                    Log.info('Authorisation request received for', data['username'])
                    self.authorisation_requests.append(data)
                    self.icon.update_menu()  # force refresh the menu
                    self.notify(APP_NAME, 'Please authorise your account %s from the menu' % data['username'])
                else:
                    for request in self.authorisation_requests[:]:  # iterate over a copy; remove from original
                        if request['connection'] == data['connection']:
                            self.authorisation_requests.remove(request)
                            break

    @staticmethod
    def run_proxy():
        while not EXITING:
            try:
                # loop for main proxy servers, accepting requests and starting connection threads
                # note: we need to make sure there are always proxy servers started when run_proxy is called (i.e., must
                # exit on config parse/load failure), otherwise this will throw an error every time and loop infinitely
                asyncore.loop(timeout=CONNECTION_TIMEOUT)
            except Exception as e:
                if not EXITING:
                    Log.info('Caught asyncore exception in main loop:', Log.error_string(e))

    def exit(self, icon):
        Log.info('Stopping', APP_NAME)
        global EXITING
        EXITING = True

        AppConfig.save()

        REQUEST_QUEUE.put(QUEUE_SENTINEL)
        RESPONSE_QUEUE.put(QUEUE_SENTINEL)
        WEBVIEW_QUEUE.put(QUEUE_SENTINEL)

        if self.web_view_started:
            for window in webview.windows[:]:  # iterate over a copy; remove (in destroy()) from original
                window.show()
                window.destroy()

        for proxy in self.proxies:  # no need to copy - proxies are never removed, we just restart them on error
            proxy.stop()
            proxy.close()

        if icon:
            icon.stop()


if __name__ == '__main__':
    App()

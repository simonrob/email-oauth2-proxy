"""A simple IMAP/SMTP proxy that intercepts authenticate and login commands, transparently replacing them with OAuth 2.0
SASL authentication. Designed for apps/clients that don't support OAuth 2.0 but need to connect to modern servers."""

import asyncore
import base64
import binascii
import configparser
import datetime
import enum
import json
import os
import queue
import socket
import ssl
import re
import sys
import syslog
import threading
import time
import traceback
import urllib.request
import urllib.parse
import urllib.error

import pystray
import setproctitle
import webview

# for drawing the SVG icon
from io import BytesIO
import cairosvg
from PIL import Image

# for encrypting/decrypting the locally-stored credentials
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_NAME = 'Email OAuth 2.0 Proxy'
VERBOSE = False  # whether to print verbose logs (controlled via 'Debug mode' option in menu, or at startup here)
CENSOR_MESSAGE = b'[[ Credentials removed from proxy log ]]'  # must be byte type string

CONFIG_FILE_NAME = 'emailproxy.config'
CONFIG_FILE_PATH = '%s/%s' % (os.path.dirname(os.path.realpath(__file__)), CONFIG_FILE_NAME)
CONFIG_SERVER_MATCHER = re.compile(r'(?P<type>(IMAP|SMTP))-(?P<port>[\d]{4,5})')

MAX_CONNECTIONS = 0  # IMAP/SMTP connections to accept (clients often open several); 0 = no limit; limit is per server
RECEIVE_BUFFER_SIZE = 65536  # in bytes, limit is per socket

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
WEBVIEW_QUEUE = queue.Queue()  # authentication window events
QUEUE_SENTINEL = object()  # object to send to signify queues should exit loops

EXITING = False  # used to check whether to restart failed threads - is set to True if the user has requested exit


class Log:
    """Simple logging that also appears in macOS syslog/Console.app"""
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S:'

    @staticmethod
    def debug(*args):
        if VERBOSE:
            message = ' '.join(map(str, args))
            print(datetime.datetime.now().strftime(Log.DATE_FORMAT), message)
            syslog.syslog(syslog.LOG_ALERT, message)  # note: need LOG_ALERT or higher to show in syslog on macOS

    @staticmethod
    def info(*args):
        message = ' '.join(map(str, args))
        print(datetime.datetime.now().strftime(Log.DATE_FORMAT), message)
        syslog.syslog(syslog.LOG_ALERT, message)  # note: need LOG_ALERT or higher to show in syslog on macOS


class OAuth2Helper:
    @staticmethod
    def get_oauth2_credentials(username, password, connection_info, recurse_retries=True):
        """Using the given username (i.e., email address) and password, reads account details from CONFIG_FILE and
        handles OAuth 2.0 token request and renewal, saving the updated details back to CONFIG_FILE (or removing them
        if invalid). Returns either (True, 'OAuth2 string for authentication') or (False, 'Error message')"""
        config = configparser.ConfigParser(allow_no_value=True)
        config.read(CONFIG_FILE_PATH)

        if not config.has_section(username):
            return (False, '%s: No config file entry found for account %s - please add a new section with values '
                           'for permission_url, token_url, oauth2_scope, redirect_uri, client_id, and '
                           'client_secret' % (APP_NAME, username))

        current_time = int(time.time())

        permission_url = config.get(username, 'permission_url', fallback=None)
        token_url = config.get(username, 'token_url', fallback=None)
        oauth2_scope = config.get(username, 'oauth2_scope', fallback=None)
        redirect_uri = config.get(username, 'redirect_uri', fallback=None)
        client_id = config.get(username, 'client_id', fallback=None)
        client_secret = config.get(username, 'client_secret', fallback=None)

        token_salt = config.get(username, 'token_salt', fallback=None)
        access_token = config.get(username, 'access_token', fallback=None)
        access_token_expiry = config.getint(username, 'access_token_expiry', fallback=current_time)
        refresh_token = config.get(username, 'refresh_token', fallback=None)

        # we hash locally-stored tokens with the given password
        if not (permission_url and token_url and redirect_uri and client_id and client_secret):
            return (False, '%s: Incomplete config file entry found for account %s - please make sure all required '
                           'fields are added (permission_url, token_url, oauth2_scope, redirect_uri, client_id, '
                           'and client_secret)' % (APP_NAME, username))

        if not token_salt:
            token_salt = base64.b64encode(os.urandom(16)).decode('utf-8')

        # generate encryptor/decrypter based on password and random salt
        key_derivation_function = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                                             salt=base64.b64decode(token_salt.encode('utf-8')), iterations=100000)
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
                    return False, '%s: Login failure - connection timed out for account %s' % (APP_NAME, username)

                response = OAuth2Helper.get_oauth2_authorisation_tokens(token_url, redirect_uri, client_id,
                                                                        client_secret, authorisation_code)

                config.read(CONFIG_FILE_PATH)  # re-read (here and below) so parallel requests aren't overwritten
                access_token = response['access_token']
                config.set(username, 'token_salt', token_salt)
                config.set(username, 'access_token', OAuth2Helper.encrypt(cryptographer, access_token))
                config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                config.set(username, 'refresh_token', OAuth2Helper.encrypt(cryptographer, response['refresh_token']))
                with open(CONFIG_FILE_PATH, 'w') as config_output:
                    config.write(config_output)

            else:
                if access_token_expiry - current_time < TOKEN_EXPIRY_MARGIN:  # if expiring soon, refresh token
                    response = OAuth2Helper.refresh_oauth2_access_token(token_url, client_id, client_secret,
                                                                        OAuth2Helper.decrypt(cryptographer,
                                                                                             refresh_token))

                    config.read(CONFIG_FILE_PATH)
                    access_token = response['access_token']
                    config.set(username, 'access_token', OAuth2Helper.encrypt(cryptographer, access_token))
                    config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                    with open(CONFIG_FILE_PATH, 'w') as config_output:
                        config.write(config_output)
                else:
                    access_token = OAuth2Helper.decrypt(cryptographer, access_token)

            # send authentication command to server (response checked in ServerConnection)
            # note: we only support single-trip authentication (SASL) without checking server capabilities - improve?
            oauth2_string = OAuth2Helper.construct_oauth2_string(username, access_token)
            return True, oauth2_string

        except InvalidToken as e:
            # if invalid details are the reason for failure we need to remove our cached version and re-authenticate
            config.read(CONFIG_FILE_PATH)
            config.remove_option(username, 'token_salt')
            config.remove_option(username, 'access_token')
            config.remove_option(username, 'access_token_expiry')
            config.remove_option(username, 'refresh_token')
            with open(CONFIG_FILE_PATH, 'w') as config_output:
                config.write(config_output)

            if recurse_retries:
                Log.info('Retrying login due to exception while requesting OAuth 2.0 credentials:',
                         getattr(e, 'message', repr(e)))
                return OAuth2Helper.get_oauth2_credentials(username, password, connection_info, recurse_retries=False)

        except Exception as e:
            Log.info('Caught exception while requesting OAuth 2.0 credentials:', getattr(e, 'message', repr(e)))
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
        """Requests OAuth 2.0 access refresh tokens from token_url using the given client_id, client_secret and
        authorisation_code, returning a dict with 'access_token', 'expires_in', and 'refresh_token' on success"""
        params = {'client_id': client_id, 'client_secret': client_secret, 'code': authorisation_code,
                  'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'}
        response = urllib.request.urlopen(token_url, urllib.parse.urlencode(params).encode('utf-8')).read()
        return json.loads(response)

    @staticmethod
    def refresh_oauth2_access_token(token_url, client_id, client_secret, refresh_token):
        """Obtains a new access token from token_url using the given refresh token, returning a dict with
        'access_token', 'expires_in', and 'refresh_token' on success"""
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
        method's docstring is: Invoke binascii.b2a_base64 iteratively with short even length buffers, strip the
        trailing line feed from the result and append. 'Even' means a number that factors to both 6 and 8, so
        when it gets to the end of the 8-bit input there's no partial 6-bit output."""
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
        """Remove double quotes (i.e., ") around a string - used for IMAP LOGIN command"""
        if text.startswith('"') and text.endswith('"'):
            return text[1:-1].replace('\\"', '"')  # also need to fix any escaped quotes within the string
        return text

    @staticmethod
    def decode_credentials(str_data):
        """Decode credentials passed as a base64-encoded string: <some data we don't need>\x00username\x00password"""
        try:
            (_, bytes_username, bytes_password) = base64.b64decode(str_data).split(b'\x00')
            return bytes_username.decode('utf-8'), bytes_password.decode('utf-8')
        except (ValueError, binascii.Error):
            # ValueError is from incorrect number of arguments; binascii.Error from incorrect encoding
            return '', ''  # no or invalid credentials provided


class OAuth2ClientConnection(asyncore.dispatcher_with_send):
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
    """The client side of the connection - intercept LOGIN/AUTHENTICATE commands and replace with OAuth2.0 SASL"""

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
                    print(username,  '---', password, '---')
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

        else:
            error_message = '%s NO %s %s\r\n' % (self.authentication_tag, command.upper(), result)
            self.send(error_message.encode('utf-8'))
            self.send(b'* BYE Autologout; authentication failed\r\n')
            self.close()


class SMTPOAuth2ClientConnection(OAuth2ClientConnection):
    """The client side of the connection - intercept AUTH LOGIN commands and replace with OAuth2.0"""

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

        # intercept EHLO so we can add STARTTLS
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
            self.send(b'334 VXNlcm5hbWU6\r\n')  # VXNlcm5hbWU6 = base64 encoded 'Username:'

        elif self.authentication_state is self.AUTH.LOGIN_AWAITING_USERNAME:
            try:
                self.server_connection.username = base64.b64decode(str_data).decode('utf-8')
            except binascii.Error:
                self.server_connection.username = ''
            self.authentication_state = self.AUTH.LOGIN_AWAITING_PASSWORD
            self.censor_next_log = True
            self.send(b'334 UGFzc3dvcmQ6\r\n')  # UGFzc3dvcmQ6 = base64 encoded 'Password:'

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
    def __init__(self, proxy_type, socket_map, server_address, connection_info, proxy_parent, custom_configuration):
        asyncore.dispatcher_with_send.__init__(self, map=socket_map)  # note: establish connection later due to STARTTLS
        self.proxy_type = proxy_type
        self.connection_info = connection_info
        self.client_connection = None
        self.server_address = server_address
        self.proxy_parent = proxy_parent
        self.custom_configuration = custom_configuration
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect(self.server_address)

    def handle_connect(self):
        Log.debug(self.proxy_type, self.connection_info, '--> [ Client connected ]')

    def create_socket(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM):
        new_socket = socket.socket(socket_family, socket_type)
        new_socket.setblocking(True)

        # connections can either wrapped via the STARTTLS command, or SSL from the start
        if self.custom_configuration['starttls']:
            self.set_socket(new_socket)
        else:
            ssl_context = ssl.create_default_context()
            self.set_socket(ssl_context.wrap_socket(new_socket, server_hostname=self.server_address[0]))

    def handle_read(self):
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

        # before we can do anything we need to intercept EHLO/HELO and add STARTTLS
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

        # then, once we have the username and password we can respond to the '334 ' response with credentials
        elif self.authentication_state is self.AUTH.STARTED and self.username is not None \
                and self.password is not None:
            if str_data.startswith('334'):  # 334 = "please send credentials"
                (success, result) = OAuth2Helper.get_oauth2_credentials(self.username, self.password,
                                                                        self.connection_info)
                self.username = None
                self.password = None
                if success:
                    self.authentication_state = self.AUTH.CREDENTIALS_SENT
                    self.send(OAuth2Helper.encode_oauth2_string(result), True)
                    self.send(b'\r\n')

                else:
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

    def handle_accepted(self, connection, address):
        if MAX_CONNECTIONS <= 0 or len(self.client_connections) < MAX_CONNECTIONS:
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
        else:
            Log.info('Rejecting new', self.proxy_type, 'connection above MAX_CONNECTIONS limit of', MAX_CONNECTIONS)
            self.close()
            self.start()

    @staticmethod
    def run_server(client, socket_map, address):
        try:
            asyncore.loop(map=socket_map)  # loop for a single connection thread
        except Exception as e:
            if not EXITING:
                Log.info('Caught asyncore exception in', address, 'thread loop:', getattr(e, 'message', repr(e)))
                client.close()
                traceback.print_exc()

    def start(self):
        Log.info('Starting %s server at %s:%d proxying %s:%d' % (
            self.proxy_type, self.local_address[0], self.local_address[1], self.server_address[0],
            self.server_address[1]))
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(self.local_address)
        self.listen(1)

    def remove_client(self, client):
        if client in self.client_connections:  # remove closed clients
            self.client_connections.remove(client)
        del client

    def bye_message(self):
        if self.proxy_type == 'IMAP':
            return '* BYE Server shutting down'
        elif self.proxy_type == 'SMTP':
            return '221 2.0.0 Service closing transmission channel'
        else:
            return ''

    def stop(self):
        for connection in self.client_connections[:]:  # iterate over a copy; remove (in close()) from original
            connection.send(b'%s\r\n' % self.bye_message().encode('utf-8'))  # try to exit gracefully
            connection.close()  # closes both client and server
        self.close()

    def restart(self):
        self.stop()
        self.start()

    def handle_close(self):
        # if we encounter an exception in asyncore, handle_close() is called - restart this server - typically one of:
        # - (<class 'socket.gaierror'>:[Errno 8] nodename nor servname provided, or not known (asyncore.py|read)
        # - (<class 'TimeoutError'>:[Errno 60] Operation timed out (asyncore.py|read)
        # note - intentionally not overriding handle_error() so we see errors in the log rather than hiding them
        Log.info('Unexpected close of proxy connection - restarting server')
        try:
            self.restart()
        except Exception as e:
            Log.info('Abandoning server restart due to repeated exception:', getattr(e, 'message', repr(e)))
            traceback.print_exc()


class AuthorisationWindow:
    """Used to dynamically add the missing get_title method to a pywebview window"""

    # noinspection PyUnresolvedReferences
    def get_title(self):
        return self.title


# noinspection PyPackageRequirements,PyUnresolvedReferences
class RetinaIcon(pystray.Icon):
    """Used to dynamically override the default pystray icon behaviour on macOS and allow high-dpi (retina) icons"""

    def _assert_image(self):
        # pystray does some scaling here which breaks macOS retina icons - we replace that with the actual menu bar size
        if sys.platform == 'darwin':
            import io
            import AppKit
            import Foundation

            # PIL to NSImage - duplicates what we do to load the icon, but kept to preserve platform compatibility
            bytes_image = io.BytesIO()
            self.icon.save(bytes_image, 'png')
            data = Foundation.NSData(bytes_image.getvalue())
            self._icon_image = AppKit.NSImage.alloc().initWithData_(data)

            thickness = self._status_bar.thickness()  # macOS menu bar size - default = 22px, but can be scaled
            self._icon_image.setSize_((int(thickness), int(thickness)))
            self._icon_image.setTemplate_(True)  # so macOS applies the default shading and inverse on click
            self._status_item.button().setImage_(self._icon_image)

        else:
            # noinspection PyProtectedMember
            return super()._assert_image()


class App:
    """Manage the menu bar icon, web view authorisation popup, notifications and start the main proxy thread"""

    def __init__(self, argv):
        self.argv = argv
        setproctitle.setproctitle(APP_NAME)
        syslog.openlog(APP_NAME)

        if sys.platform == 'darwin':
            import AppKit
            # hide dock icon (but not LSBackgroundOnly as we need input via web view)
            # noinspection PyUnresolvedReferences
            info = AppKit.NSBundle.mainBundle().infoDictionary()
            info['LSUIElement'] = '1'

        self.proxies = []
        self.authorisation_requests = []

        self.web_view_started = False

        self.icon = self.create_icon()
        self.icon.run(self.post_create)

    def create_icon(self):
        image_out = BytesIO()
        cairosvg.svg2png(url='%s/icon.svg' % os.path.dirname(os.path.realpath(__file__)), write_to=image_out)
        return RetinaIcon(APP_NAME, Image.open(image_out), APP_NAME, menu=pystray.Menu(
            pystray.MenuItem('Authorise account', pystray.Menu(self.create_authorisation_menu)),
            pystray.MenuItem('Accounts and servers...', self.edit_config),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Debug mode', self.toggle_verbose, checked=lambda _: VERBOSE),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quit %s' % APP_NAME, self.exit)
        ))

    @staticmethod
    def edit_config():
        if sys.platform == 'darwin':
            os.system("""open {}""".format(CONFIG_FILE_PATH))
        elif sys.platform == 'win32':
            os.startfile(CONFIG_FILE_PATH)
        elif sys.platform.startswith('linux'):
            os.system("""xdg-open {}""".format(CONFIG_FILE_PATH))  # not tested but is apparently near-universal
        else:
            pass  # nothing we can do

    # noinspection PyUnusedLocal
    @staticmethod
    def toggle_verbose(icon, item):
        global VERBOSE
        VERBOSE = not item.checked

    def post_create(self, icon):
        icon.visible = True

        config = configparser.ConfigParser(allow_no_value=True)
        config.read(CONFIG_FILE_PATH)

        # load server types and configurations
        server_load_error = False
        for section in config.sections():
            match = CONFIG_SERVER_MATCHER.match(section)
            if not match:
                continue

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
                'starttls': config.getboolean(section, 'starttls', fallback=False)
            }

            if server_address:  # all other values are checked, regex matched or have a fallback above
                new_proxy = OAuth2Proxy(server_type, (local_address, local_port), (server_address, server_port),
                                        custom_configuration)
                try:
                    new_proxy.start()
                    self.proxies.append(new_proxy)
                except Exception as e:
                    Log.info('Unable to start server:', getattr(e, 'message', repr(e)))
                    server_load_error = True
                    break
            else:
                server_load_error = True
                break

        if server_load_error:
            Log.info('No (or invalid) server details found - exiting')
            self.notify(APP_NAME, 'No (or invalid) server details found. Please add your accounts and servers in %s' %
                        CONFIG_FILE_NAME)
            self.exit(icon)
            return

        threading.Thread(target=self.run_proxy, name='EmailOAuth2Proxy-main').start()

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
                asyncore.loop()  # loop for main proxy servers, accepting requests and starting connection threads
            except Exception as e:
                if not EXITING:
                    Log.info('Caught asyncore exception in main loop:', getattr(e, 'message', repr(e)))
                    traceback.print_exc()

    def notify(self, title, text):
        if self.icon.HAS_NOTIFICATION:
            self.icon.notify('%s: %s' % (title, text))  # note: not tested; based on pystray documentation
        elif sys.platform == 'darwin':
            os.system("""osascript -e 'display notification "{}" with title "{}"'""".format(text, title))
        else:
            Log.info(title, text)  # last resort

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

    # noinspection PyUnusedLocal
    def authorise_account(self, icon, item):
        for request in self.authorisation_requests:
            if str(item) == request['username']:  # use str(item) because item.text() hangs
                if not self.web_view_started:
                    self.create_authorisation_window(request)
                    webview.start(self.handle_authorisation_windows)
                    self.web_view_started = True
                else:
                    WEBVIEW_QUEUE.put(request)  # future requests need to use the same thread
                return
        self.notify(APP_NAME, 'There are no pending authorisation requests')

    def create_authorisation_window(self, request):
        # note that the webview title *must* end with a space and then the email address/username
        authorisation_window = webview.create_window('Authorise your account: %s' % request['username'],
                                                     request['permission_url'], on_top=True)
        setattr(authorisation_window, 'get_title', AuthorisationWindow.get_title)  # add missing get_title method
        authorisation_window.loaded += self.authorisation_loaded

    def handle_authorisation_windows(self):
        # needed because otherwise closing the last remaining webview window exits the application
        webview.create_window('%s hidden (dummy) window' % APP_NAME, html='', hidden=True)

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

            if len(self.authorisation_requests) > 0:
                self.notify(APP_NAME,
                            'Authentication successful for %s. Please authorise an additional account %s from the '
                            'menu' % (completed_request['username'], self.authorisation_requests[0]['username']))
            else:
                self.notify(APP_NAME, 'Authentication successful for %s' % completed_request['username'])

    def exit(self, icon):
        Log.info('Stopping', APP_NAME)
        global EXITING
        EXITING = True

        REQUEST_QUEUE.put(QUEUE_SENTINEL)
        RESPONSE_QUEUE.put(QUEUE_SENTINEL)
        WEBVIEW_QUEUE.put(QUEUE_SENTINEL)

        if self.web_view_started:
            for window in webview.windows[:]:  # iterate over a copy; remove (in destroy()) from original
                window.show()
                window.destroy()

        for proxy in self.proxies:  # no need to copy - proxies are never removed; we just restart them on error
            proxy.stop()
            proxy.close()

        icon.stop()

        syslog.closelog()
        sys.exit(0)


if __name__ == '__main__':
    App(sys.argv)

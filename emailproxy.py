"""A simple IMAP/SMTP proxy that intercepts authenticate and login commands, transparently replacing them with OAuth 2.0
SASL authentication. Designed for apps/clients that don't support OAuth 2.0 but need to connect to modern servers. """

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
import webview

# for drawing the SVG icon
from io import BytesIO
import cairosvg
from PIL import Image

# for encrypting/decrypting the locally-stored credentials
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_NAME = 'Email OAuth 2.0 Proxy'
VERBOSE = False

CONFIG_FILE = '%s/emailproxy.config' % os.path.dirname(__file__)
CONFIG_SERVER_MATCHER = re.compile(r'(?P<type>(IMAP|SMTP){1})-(?P<port>[\d]{4,5})')

MAX_CONNECTIONS = 0  # IMAP/SMTP connections to accept (clients often open several); 0 = no limit; limit is per server
RECEIVE_BUFFER_SIZE = 65536  # in bytes
AUTHENTICATION_TIMEOUT = 60  # seconds to wait before cancelling authentication requests
TOKEN_EXPIRY_MARGIN = 600  # seconds before its expiry to refresh the OAuth 2.0 token

IMAP_AUTHENTICATION_REQUEST_MATCHER = re.compile(r'(?P<tag>\w+)'
                                                 r'\s(?P<command>(LOGIN|AUTHENTICATE))'
                                                 r'\s(?P<flags>.*)', flags=re.IGNORECASE)

IMAP_AUTHENTICATION_RESPONSE_MATCHER = re.compile(r'(?P<tag>\w+) OK AUTHENTICATE.*', flags=re.IGNORECASE)

REQUEST_QUEUE = queue.Queue()  # requests for authentication
RESPONSE_QUEUE = queue.Queue()  # responses from client web view
QUEUE_SENTINEL = object()  # object to send to signify queues should exit loops


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
    def get_oauth2_credentials(username, password, connection_info):
        """Using the given username (i.e., email address) and password, reads account details from CONFIG_FILE and
        handles OAuth 2.0 token request and renewal, saving the updated details back to CONFIG_FILE (or removing them
        if invalid). Returns either (True, 'OAuth2 string for authentication') or (False, 'Error message') """
        config = configparser.ConfigParser(allow_no_value=True)
        config.read(CONFIG_FILE)

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

                access_token = response['access_token']
                config.set(username, 'token_salt', token_salt)
                config.set(username, 'access_token', OAuth2Helper.encrypt(cryptographer, access_token))
                config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                config.set(username, 'refresh_token', OAuth2Helper.encrypt(cryptographer, response['refresh_token']))
                with open(CONFIG_FILE, 'w') as config_output:
                    config.write(config_output)

            else:
                if access_token_expiry - current_time < TOKEN_EXPIRY_MARGIN:  # if expiring soon, refresh token
                    response = OAuth2Helper.refresh_oauth2_access_token(token_url, client_id, client_secret,
                                                                        OAuth2Helper.decrypt(cryptographer,
                                                                                             refresh_token))

                    access_token = response['access_token']
                    config.set(username, 'access_token', OAuth2Helper.encrypt(cryptographer, access_token))
                    config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                    with open(CONFIG_FILE, 'w') as config_output:
                        config.write(config_output)
                else:
                    access_token = OAuth2Helper.decrypt(cryptographer, access_token)

            # send authentication command to server (response checked in ServerConnection)
            # note: we only support single-trip authentication (SASL) without checking server capabilities - improve?
            oauth2_string = OAuth2Helper.construct_oauth2_string(username, access_token)
            return True, oauth2_string

        except Exception:
            # if invalid details are the reason for failure we need to remove our cached version and reauthenticate
            config.remove_option(username, 'token_salt')
            config.remove_option(username, 'access_token')
            config.remove_option(username, 'access_token_expiry')
            config.remove_option(username, 'refresh_token')
            with open(CONFIG_FILE, 'w') as config_output:
                config.write(config_output)

            # we could probably handle this a bit better depending on what the exception actually is (e.g., try
            # authentication again), but given that a repeat request will do this, it's easiest to just remove
            # the potentially invalid credentials and rely on the client to retry
            return False, '%s: Login failure - saved authentication data invalid for account %s' % (APP_NAME, username)

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
        params = {'client_id': client_id, 'redirect_uri': redirect_uri, 'scope': scope, 'response_type': 'code'}
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
                    authorisation_code = data['response_url'].split('code=')[1].split('&session_state=')[0]
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
        'access_token', 'expires_in', and 'refresh_token' on success """
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
        when it gets to the end of the 8-bit input there's no partial 6-bit output. """
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
            return text[1:-1]
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
    def __init__(self, proxy_type, connection, connection_info, server_connection, proxy_parent):
        asyncore.dispatcher_with_send.__init__(self, connection)
        self.proxy_type = proxy_type
        self.connection_info = connection_info
        self.server_connection = server_connection
        self.proxy_parent = proxy_parent

        self.authenticated = False

    def handle_read(self):
        byte_data = self.recv(RECEIVE_BUFFER_SIZE)
        Log.debug(self.proxy_type, self.connection_info, '-->', byte_data)  # TODO: filter out credentials from logs

        # client is established after server; this state should not happen unless already closing
        if not self.server_connection:
            self.close()
            return

        # we have already authenticated - nothing to do; just pass data directly to server
        if self.authenticated:
            self.server_connection.send(byte_data)
            return

        self.process_data(byte_data)

    def process_data(self, byte_data):
        self.server_connection.send(byte_data)  # by default we just send everything straight to the server

    def close(self):
        if self.server_connection:
            self.server_connection.client_connection = None
            self.server_connection.close()
            self.server_connection = None
        self.proxy_parent.remove_client(self)
        asyncore.dispatcher_with_send.close(self)


class IMAPOAuth2ClientConnection(OAuth2ClientConnection):
    """The client side of the connection - intercept LOGIN/AUTHENTICATE commands and replace with OAuth2.0 SASL"""

    def __init__(self, connection, connection_info, server_connection, proxy_parent):
        super().__init__('IMAP', connection, connection_info, server_connection, proxy_parent)
        self.authentication_tag = None
        self.awaiting_credentials = False

    def process_data(self, byte_data):
        str_data = byte_data.decode('utf-8').rstrip('\r\n')

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
            client_command = match.group('command').lower()
            client_flags = match.group('flags')
            if client_command == 'login' and ' ' in client_flags:
                (username, password) = client_flags.split(' ')  # we check for ' ' above to avoid crash if no arguments
                username = OAuth2Helper.strip_quotes(username)
                password = OAuth2Helper.strip_quotes(password)
                self.authentication_tag = match.group('tag')
                self.authenticate_connection(username, password)

            elif client_command == 'authenticate':
                split_flags = client_flags.split(' ')  # no need to check for ' ' like above as we only require item 0
                authentication_type = split_flags[0].lower()
                if authentication_type == 'plain':  # plain can be submitted as a single command or multiline
                    if len(split_flags) > 1:
                        (username, password) = OAuth2Helper.decode_credentials(' '.join(split_flags[1:]))
                        self.authenticate_connection(username, password, 'authenticate')
                    else:
                        self.awaiting_credentials = True
                        self.authentication_tag = match.group('tag')
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
            super().process_data(('%s AUTHENTICATE XOAUTH2 ' % self.authentication_tag).encode('utf-8'))
            super().process_data(OAuth2Helper.encode_oauth2_string(result))
            super().process_data(b'\r\n')

        else:
            error_message = '%s NO %s %s\r\n' % (self.authentication_tag, command.upper(), result)
            self.send(error_message.encode('utf-8'))
            self.send('* BYE Autologout; authentication failed\r\n'.encode('utf-8'))
            self.close()


class SMTPOAuth2ClientConnection(OAuth2ClientConnection):
    """The client side of the connection - intercept AUTH LOGIN commands and replace with OAuth2.0"""

    class AUTH(enum.Enum):
        PENDING = 1
        PLAIN_AWAITING_CREDENTIALS = 2
        LOGIN_AWAITING_USERNAME = 3
        LOGIN_AWAITING_PASSWORD = 4
        AUTH_CREDENTIALS_SENT = 5

    def __init__(self, connection, connection_info, server_connection, proxy_parent):
        super().__init__('SMTP', connection, connection_info, server_connection, proxy_parent)
        self.authentication_state = self.AUTH.PENDING

    def process_data(self, byte_data):
        str_data = byte_data.decode('utf-8').rstrip('\r\n')
        str_data_lower = str_data.lower()

        # intercept EHLO so we can add STARTTLS
        if self.server_connection.ehlo is None:
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
                self.send('334 \r\n'.encode('utf-8'))  # request details (note: space after response code is mandatory)

        elif self.authentication_state is self.AUTH.PLAIN_AWAITING_CREDENTIALS:
            (self.server_connection.username, self.server_connection.password) = OAuth2Helper.decode_credentials(
                str_data)
            self.send_authentication_request()

        elif self.authentication_state is self.AUTH.PENDING and str_data_lower.startswith('auth login'):
            self.authentication_state = self.AUTH.LOGIN_AWAITING_USERNAME
            self.send('334 VXNlcm5hbWU6\r\n'.encode('utf-8'))  # VXNlcm5hbWU6 = base64 encoded 'Username:'

        elif self.authentication_state is self.AUTH.LOGIN_AWAITING_USERNAME:
            try:
                self.server_connection.username = base64.b64decode(str_data).decode('utf-8')
            except binascii.Error:
                self.server_connection.username = ''
            self.authentication_state = self.AUTH.LOGIN_AWAITING_PASSWORD
            self.send('334 UGFzc3dvcmQ6\r\n'.encode('utf-8'))  # UGFzc3dvcmQ6 = base64 encoded 'Password:'

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
        super().process_data('AUTH XOAUTH2\r\n'.encode('utf-8'))


class OAuth2ServerConnection(asyncore.dispatcher_with_send):
    def __init__(self, proxy_type, server_address, connection_info):
        asyncore.dispatcher_with_send.__init__(self)
        self.proxy_type = proxy_type
        self.connection_info = connection_info
        self.client_connection = None
        self.server_address = server_address
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect(self.server_address)

    def create_socket(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM):
        new_socket = socket.socket(socket_family, socket_type)
        new_socket.setblocking(True)
        self.set_socket(new_socket)

    def handle_read(self):
        data = self.recv(RECEIVE_BUFFER_SIZE)
        Log.debug(self.proxy_type, self.connection_info, '<--', data)  # TODO: filter out credentials from logs
        if self.client_connection:
            self.process_data(data)

    def process_data(self, byte_data):
        self.client_connection.send(byte_data)  # by default we just send everything straight to the client

    def handle_close(self):
        if self.client_connection:
            self.client_connection.server_connection = None
            self.client_connection.close()
            self.client_connection = None
        self.close()


class IMAPOAuth2ServerConnection(OAuth2ServerConnection):
    """The IMAP server side - watch for the OK AUTHENTICATE response, then ignore all subsequent data"""

    # IMAP: https://tools.ietf.org/html/rfc3501
    # IMAP SASL-IR: https://tools.ietf.org/html/rfc4959
    def __init__(self, server_address, connection_info):
        super().__init__('IMAP', server_address, connection_info)

    def set_socket(self, new_socket, channel_map=None):
        # IMAP connections are SSL from the start; SMTP is only wrapped once STARTTLS command is provided
        ssl_context = ssl.create_default_context()
        super().set_socket(ssl_context.wrap_socket(new_socket, server_hostname=self.server_address[0]), channel_map)

    def process_data(self, byte_data):
        if not self.client_connection.authenticated:
            str_response = byte_data.decode('utf-8').rstrip('\r\n')

            if str_response.startswith('* CAPABILITY'):
                # intercept CAPABILITY response and replace with what we can actually do
                updated_response = re.sub(r'(AUTH=[\w]+ )+', 'AUTH=PLAIN ', str_response, flags=re.IGNORECASE)
                byte_data = ('%s\r\n' % updated_response).encode('utf-8')

            else:
                # if authentication succeeds, remove our proxy from the client and ignore all further communication
                match = IMAP_AUTHENTICATION_RESPONSE_MATCHER.match(str_response)
                if match and match.group('tag') == self.client_connection.authentication_tag:
                    Log.info('Successfully authenticated IMAP connection - removing proxy')
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

    def __init__(self, server_address, connection_info):
        super().__init__('SMTP', server_address, connection_info)

        self.ehlo = None
        self.starttls = self.STARTTLS.PENDING
        self.authentication_state = self.AUTH.PENDING

        self.username = None
        self.password = None

    def process_data(self, byte_data):
        if self.client_connection.authenticated:
            super().process_data(byte_data)

        # SMTP setup and authentication involves a little more back-and-forth than IMAP...
        else:
            str_data = byte_data.decode('utf-8').rstrip('\r\n')

            # before we can do anything we need to intercept EHLO/HELO and add STARTTLS
            if self.ehlo is not None and self.starttls is not self.STARTTLS.COMPLETE:
                if self.starttls is self.STARTTLS.PENDING:
                    self.send('STARTTLS\r\n'.encode('utf-8'))
                    self.starttls = self.STARTTLS.NEGOTIATING

                elif self.starttls is self.STARTTLS.NEGOTIATING:
                    if str_data.startswith('220'):
                        ssl_context = ssl.create_default_context()
                        super().set_socket(ssl_context.wrap_socket(self.socket, server_hostname=self.server_address[0]))
                        self.starttls = self.STARTTLS.COMPLETE
                        Log.info('Successfully negotiated SMTP STARTTLS connection - re-sending greeting')
                        self.send(('%s\r\n' % self.ehlo).encode('utf-8'))  # re-send original EHLO/HELO to server
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
                        self.send(OAuth2Helper.encode_oauth2_string(result))
                        self.send(b'\r\n')

                    else:
                        # a local authentication error occurred - send details to the client and exit
                        super().process_data(
                            ('535 5.7.8  Authentication credentials invalid. %s\r\n' % result).encode('utf-8'))
                        self.client_connection.close()
                        return

                else:
                    super().process_data(byte_data)  # an error occurred - just send to the client and exit
                    self.client_connection.close()

            elif self.authentication_state is self.AUTH.CREDENTIALS_SENT:
                if str_data.startswith('235'):
                    Log.info('Successfully authenticated SMTP connection - removing proxy')
                    self.client_connection.authenticated = True
                    super().process_data(byte_data)
                else:
                    super().process_data(byte_data)  # an error occurred - just send to the client and exit
                    self.client_connection.close()

            else:
                # intercept EHLO response AUTH capabilities and replace with what we can actually do
                if str_data.startswith('250-'):
                    updated_response = re.sub(r'250-AUTH[\w ]+', '250-AUTH PLAIN LOGIN', str_data, flags=re.IGNORECASE)
                    super().process_data(('%s\r\n' % updated_response).encode('utf-8'))
                else:
                    super().process_data(byte_data)  # a server->client interaction we don't handle; ignore


class OAuth2Proxy(asyncore.dispatcher_with_send):
    """Listen on SERVER_ADDRESS:SERVER_PORT, creating a ServerConnection + ClientConnection for each new connection"""

    def __init__(self, proxy_type, local_address, server_address):
        asyncore.dispatcher_with_send.__init__(self)
        self.proxy_type = proxy_type
        self.local_address = local_address
        self.server_address = server_address
        self.client_connections = []

    def handle_accepted(self, connection, address):
        if MAX_CONNECTIONS <= 0 or len(self.client_connections) < MAX_CONNECTIONS:
            server_class = globals()['%sOAuth2ServerConnection' % self.proxy_type]
            new_server_connection = server_class(self.server_address, address)
            client_class = globals()['%sOAuth2ClientConnection' % self.proxy_type]
            new_client_connection = client_class(connection, address, new_server_connection, self)
            new_server_connection.client_connection = new_client_connection
            self.client_connections.append(new_client_connection)
        else:
            Log.info('Rejecting new', self.proxy_type, 'connection above MAX_CONNECTIONS limit of', MAX_CONNECTIONS)
            self.close()
            self.start()

    def start(self):
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
        for connection in self.client_connections:
            connection.send(('%s\r\n' % self.bye_message()).encode('utf-8'))  # try to exit gracefully
            connection.close()
        self.close()


class App:
    """ Manage the menu bar icon, web view authorisation popup, notifications and start the main proxy thread"""

    def __init__(self, argv):
        self.argv = argv
        syslog.openlog(APP_NAME)

        if sys.platform == 'darwin':
            import AppKit
            # hide dock icon (but not LSBackgroundOnly as we need input via web view)
            # noinspection PyUnresolvedReferences
            info = AppKit.NSBundle.mainBundle().infoDictionary()
            info['LSUIElement'] = '1'

        self.exiting = False

        self.proxies = []
        self.authorisation_requests = []

        self.web_view_started = False
        self.hidden_window = self.create_hidden_window()  # web views from back without quitting self when they close

        self.icon = self.create_icon()
        self.icon.run(self.post_create)

    def create_icon(self):
        image_out = BytesIO()
        cairosvg.svg2png(url='%s/icon.svg' % os.path.dirname(__file__), write_to=image_out)

        return pystray.Icon('test', Image.open(image_out), menu=pystray.Menu(
            pystray.MenuItem(APP_NAME, None, enabled=False),
            pystray.MenuItem('–––––––––––––––––––––––', None, enabled=False),
            pystray.MenuItem('Authorise account...', self.authorise),
            pystray.MenuItem('Accounts and servers...', self.edit_config),
            pystray.MenuItem('–––––––––––––––––––––––', None, enabled=False),
            pystray.MenuItem('Debug mode', self.toggle_verbose, checked=lambda item: VERBOSE),
            pystray.MenuItem('–––––––––––––––––––––––', None, enabled=False),
            pystray.MenuItem('Quit', self.exit)
        ))

    # noinspection PyUnusedLocal
    @staticmethod
    def edit_config(icon, item):
        if sys.platform == 'darwin':
            os.system("""open {}""".format(CONFIG_FILE))
        else:
            # TODO: will this work cross-platform?
            os.system("""start {}""".format(CONFIG_FILE))

    # noinspection PyUnusedLocal
    @staticmethod
    def toggle_verbose(icon, item):
        global VERBOSE
        VERBOSE = not item.checked

    def post_create(self, icon):
        icon.visible = True

        config = configparser.ConfigParser(allow_no_value=True)
        config.read(CONFIG_FILE)

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
            except ValueError:
                server_load_error = True
                break

            server_address = config.get(section, 'server_address', fallback=None)
            str_server_port = config.get(section, 'server_port', fallback=None)
            try:
                server_port = int(str_server_port)
            except ValueError:
                server_load_error = True
                break

            if server_address:  # all other values are checked, regex matched or have a fallback above
                Log.info('Starting %s server at %s:%d proxying %s:%d' % (
                    server_type, local_address, local_port, server_address, server_port))
                new_proxy = OAuth2Proxy(server_type, (local_address, local_port), (server_address, server_port))
                new_proxy.start()
                self.proxies.append(new_proxy)
            else:
                server_load_error = True
                break

        if server_load_error:
            Log.info('No (or invalid) server details found - exiting')
            self.notify(APP_NAME, 'No (or invalid) server details found. Please add your accounts and servers from '
                                  'the menu')
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
                    self.notify(APP_NAME, 'Please authorise your account %s from the menu' % data['username'])
                else:
                    for request in self.authorisation_requests:
                        if request['connection'] == data['connection']:
                            self.authorisation_requests.remove(request)
                            break

    def run_proxy(self):
        try:
            asyncore.loop()
        except Exception:
            if not self.exiting:
                traceback.print_exc()

    @staticmethod
    def notify(title, text):
        # TODO: do this in a cross-platform way
        os.system("""osascript -e 'display notification "{}" with title "{}"'""".format(text, title))

    def authorise(self):
        if len(self.authorisation_requests) > 0:
            current_request = self.authorisation_requests[0]
            authorisation_window = webview.create_window('Authorise your account: %s' % current_request['username'],
                                                         current_request['permission_url'], on_top=True)
            authorisation_window.loaded += self.authorisation_loaded
            webview.start(self.configure_windows)
            self.web_view_started = True
        else:
            self.notify(APP_NAME, 'There are no pending authorisation requests')

    @staticmethod
    def create_hidden_window():
        return webview.create_window('%s hidden (dummy) window' % APP_NAME, html='', hidden=True)

    def configure_windows(self):
        self.hidden_window = self.create_hidden_window()
        if len(webview.windows) > 2:
            webview.windows[0].destroy()

    def authorisation_loaded(self):
        for window in webview.windows:
            url = window.get_current_url()
            if len(self.authorisation_requests) > 0:
                current_request = self.authorisation_requests[0]
                if url and url.startswith(current_request['redirect_uri']):
                    Log.info('Successfully authorised request for', current_request['username'])
                    RESPONSE_QUEUE.put(
                        {'connection': self.authorisation_requests.pop(0)['connection'], 'response_url': url})
                    window.destroy()
                    if len(self.authorisation_requests) > 0:
                        # TODO: remove other auth requests that match the same username
                        self.notify(APP_NAME,
                                    'Authentication successful for %s. Please authorise a further request for account '
                                    '%s from the menu' % (
                                        current_request['username'], self.authorisation_requests[0]['username']))
                    else:
                        self.notify(APP_NAME, 'Authentication successful for %s' % current_request['username'])

    def exit(self, icon):
        Log.info('Stopping', APP_NAME)
        self.exiting = True

        REQUEST_QUEUE.put(QUEUE_SENTINEL)
        RESPONSE_QUEUE.put(QUEUE_SENTINEL)

        for proxy in self.proxies:
            proxy.stop()
            proxy.close()

        if self.web_view_started:
            for window in webview.windows:
                window.show()
                window.destroy()

        icon.stop()

        syslog.closelog()
        sys.exit(0)


if __name__ == '__main__':
    App(sys.argv)

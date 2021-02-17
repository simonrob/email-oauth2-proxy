"""A simple IMAP proxy that intercepts authenticate and login commands, transparently replacing them with OAuth 2.0
SASL authentication. Designed for IMAP clients that don't support OAuth 2.0 but need to connect to modern servers. """

import asyncore
import base64
import binascii
import configparser
import datetime
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

CONFIG_FILE = '%s/oauth2proxy.config' % os.path.dirname(__file__)

MAX_CONNECTIONS = 0  # number of connections to accept locally (IMAP clients often open several); 0 = no limit

LISTEN_ADDRESS = 'localhost'
LISTEN_PORT = 1433

SERVER_ADDRESS = 'outlook.office365.com'
SERVER_PORT = 993

VERBOSE = False
RECEIVE_BUFFER_SIZE = 65536
AUTHENTICATION_TIMEOUT = 60  # seconds to wait before cancelling authentication requests
TOKEN_EXPIRY_MARGIN = 600  # seconds before expiry to refresh the OAuth 2.0 token

AUTHENTICATION_REQUEST_MATCHER = re.compile(r'(?P<tag>[A-Z0-9]+)'
                                            r'\s(?P<command>(LOGIN|AUTHENTICATE))'
                                            r'(\s(?P<flags>.*))', flags=re.IGNORECASE)

AUTHENTICATION_RESPONSE_MATCHER = re.compile(r'\A(?P<tag>[A-Z0-9]+) OK AUTHENTICATE.*', flags=re.IGNORECASE)

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


class ClientConnection(asyncore.dispatcher_with_send):
    """The client side of the connection - intercept LOGIN/AUTHENTICATE commands and replace with OAuth2.0 SASL"""

    def __init__(self, connection, connection_info, server_connection, proxy_parent):
        asyncore.dispatcher_with_send.__init__(self, connection)
        self.connection_info = connection_info
        self.server_connection = server_connection
        self.proxy_parent = proxy_parent

        self.authenticated = False
        self.authentication_tag = None
        self.awaiting_credentials = False

    def handle_read(self):
        data = self.recv(RECEIVE_BUFFER_SIZE)
        Log.debug(self.connection_info, '-->', data)

        # client is established after server; this state should not happen unless already closing
        if not self.server_connection:
            self.close()
            return

        # we have already authenticated - nothing to do; just pass data directly to server
        if self.authenticated:
            self.server_connection.send(data)
            return

        str_data = data.decode('utf-8').rstrip('\r\n')

        # authenticate plain is a two-stage request - handle credentials
        if self.awaiting_credentials:
            self.awaiting_credentials = False
            (_, bytes_username, bytes_password) = base64.b64decode(str_data).split(b'\x00')
            username = bytes_username.decode('utf-8')
            password = bytes_password.decode('utf-8')
            self.authenticate_connection(username, password, 'authenticate')

        else:
            match = AUTHENTICATION_REQUEST_MATCHER.match(str_data)
            if not match:  # probably an invalid command, but just let the server handle it
                self.server_connection.send(data)
                return

            # we replace the standard login/authenticate commands with OAuth 2.0 authentication
            client_command = match.group('command').lower()
            client_flags = match.group('flags')
            if client_command == 'login':
                (username, password) = client_flags.split(' ')
                username = self.strip_quotes(username)
                password = self.strip_quotes(password)
                self.authentication_tag = match.group('tag')
                self.authenticate_connection(username, password)

            elif client_command == 'authenticate':
                authentication_type = client_flags.split(' ')[0].lower()
                if authentication_type == 'plain':
                    self.awaiting_credentials = True
                    self.authentication_tag = match.group('tag')
                    self.send(b'+\r\n')  # request authentication credentials
                else:
                    # we don't support any other methods - let the server handle the error
                    self.server_connection.send(data)

            else:
                # we haven't yet authenticated, but this is some other matched command - pass through
                self.server_connection.send(data)

    def close(self):
        if self.server_connection:
            self.server_connection.client_connection = None
            self.server_connection.close()
            self.server_connection = None
        self.proxy_parent.remove_client(self)
        asyncore.dispatcher_with_send.close(self)

    def authenticate_connection(self, username, password, command='login'):
        config = configparser.ConfigParser(allow_no_value=True)
        config.read(CONFIG_FILE)

        if not config.has_section(username):
            error_message = '%s NO %s No %s file entry found for account - please add a new section [%s] with values ' \
                            'for permission_url, token_url, oauth2_scope, redirect_uri, tenant_id, client_id, and ' \
                            'client_secret\r\n' % (self.authentication_tag, command.upper(), CONFIG_FILE, username)
            self.send(error_message.encode('utf-8'))
            return

        current_time = int(time.time())

        permission_url = config.get(username, 'permission_url', fallback=None)
        token_url = config.get(username, 'token_url', fallback=None)
        oauth2_scope = config.get(username, 'oauth2_scope', fallback=None)
        redirect_uri = config.get(username, 'redirect_uri', fallback=None)
        tenant_id = config.get(username, 'tenant_id', fallback=None)
        client_id = config.get(username, 'client_id', fallback=None)
        client_secret = config.get(username, 'client_secret', fallback=None)

        token_salt = config.get(username, 'token_salt', fallback=None)
        access_token = config.get(username, 'access_token', fallback=None)
        access_token_expiry = config.getint(username, 'access_token_expiry', fallback=current_time)
        refresh_token = config.get(username, 'refresh_token', fallback=None)

        # we hash locally-stored tokens with the given password
        if not (permission_url and token_url and redirect_uri and tenant_id and client_id and client_secret):
            error_message = '%s NO %s Incomplete %s file entry found for %s - please make sure all required ' \
                            'fields are added (permission_url, token_url, oauth2_scope, redirect_uri, ' \
                            'tenant_id, client_id, and client_secret)\r\n' % (
                                self.authentication_tag, command.upper(), CONFIG_FILE, username)
            self.send(error_message.encode('utf-8'))
            return

        if not token_salt:
            token_salt = base64.b64encode(os.urandom(16)).decode('utf-8')

        # generate encryptor/decrypter based on password and random salt
        key_derivation_function = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                                             salt=base64.b64decode(token_salt.encode('utf-8')),
                                             iterations=100000)
        key = base64.urlsafe_b64encode(key_derivation_function.derive(password.encode('utf-8')))
        cryptographer = Fernet(key)

        try:
            if not refresh_token:
                permission_url = self.construct_oauth2_permission_url(permission_url, redirect_uri, client_id,
                                                                      oauth2_scope)
                (success, authorisation_code) = self.get_oauth2_authorisation_code(permission_url, redirect_uri,
                                                                                   username)  # note: blocking
                if not success:
                    error_message = '%s NO %s Login failure: connection timed out for %s\r\n' % (
                        self.authentication_tag, command.upper(), username)
                    self.send(error_message.encode('utf-8'))
                    self.send('* BYE Autologout; idle for too long'.encode('utf-8'))
                    self.close()

                response = self.get_oauth2_authorisation_tokens(token_url, redirect_uri, client_id, client_secret,
                                                                authorisation_code)

                access_token = response['access_token']
                config.set(username, 'token_salt', token_salt)
                config.set(username, 'access_token', self.encrypt(cryptographer, access_token))
                config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                config.set(username, 'refresh_token', self.encrypt(cryptographer, response['refresh_token']))
                with open(CONFIG_FILE, 'w') as config_output:
                    config.write(config_output)

            else:
                if access_token_expiry - current_time < TOKEN_EXPIRY_MARGIN:  # if expiring soon, refresh token
                    response = self.refresh_oauth2_access_token(token_url, client_id, client_secret,
                                                                self.decrypt(cryptographer, refresh_token))

                    access_token = response['access_token']
                    config.set(username, 'access_token', self.encrypt(cryptographer, access_token))
                    config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                    with open(CONFIG_FILE, 'w') as config_output:
                        config.write(config_output)
                else:
                    access_token = self.decrypt(cryptographer, access_token)

            # send authentication command to server (response checked in ServerConnection)
            # note: we only support single-trip authentication (SASL) without checking server capabilities - improve?
            oauth2_string = self.construct_oauth2_string(username, access_token)
            self.server_connection.send(('%s AUTHENTICATE XOAUTH2 ' % self.authentication_tag).encode('utf-8'))
            self.server_connection.send(self.encode_oauth2_string(oauth2_string))
            self.server_connection.send(b'\r\n')

        except Exception:
            # we could probably handle this a bit better depending on what the exception actually is (e.g., try
            # authentication again), but given that a repeat request will do this, it's easiest to just remove
            # the potentially invalid credentials and rely on the client to retry
            error_message = '%s NO %s Login failure: saved %s authentication data invalid for %s\r\n' % (
                self.authentication_tag, command.upper(), CONFIG_FILE, username)
            self.send(error_message.encode('utf-8'))

            # if invalid details are the reason for failure we need to remove them
            config.remove_option(username, 'token_salt')
            config.remove_option(username, 'access_token')
            config.remove_option(username, 'access_token_expiry')
            config.remove_option(username, 'refresh_token')
            with open(CONFIG_FILE, 'w') as config_output:
                config.write(config_output)

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
            param_pairs.append('%s=%s' % (param[0], ClientConnection.oauth2_url_escape(param[1])))
        return '%s?%s' % (permission_url, '&'.join(param_pairs))

    def get_oauth2_authorisation_code(self, permission_url, redirect_uri, username):
        """Submit an authorisation request to the parent app and block until it is provided (or the request fails)"""
        token_request = {'connection': self.connection_info, 'permission_url': permission_url,
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
                self.close()
                return False, None

            elif data['connection'] == self.connection_info:  # found an authentication response meant for us
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
        """Constructs an IMAP OAuth2 SASL authentication string from the given username and access token"""
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
        if text.startswith('"') and text.endswith('"'):
            return text[1:-1]
        return text


class ServerConnection(asyncore.dispatcher_with_send):
    """The server side of the connection - watch for the OK AUTHENTICATE response, then ignore all subsequent data"""

    def __init__(self, server_address, connection_info):
        asyncore.dispatcher_with_send.__init__(self)
        self.connection_info = connection_info
        self.client_connection = None
        self.server_address = server_address
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect(self.server_address)

    def create_socket(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM):
        new_socket = socket.socket(socket_family, socket_type)
        new_socket.setblocking(True)
        ssl_context = ssl.create_default_context()
        self.set_socket(ssl_context.wrap_socket(new_socket, server_hostname=self.server_address[0]))

    def handle_read(self):
        data = self.recv(RECEIVE_BUFFER_SIZE)
        Log.debug(self.connection_info, '<--', data)

        if self.client_connection:
            # if authentication succeeds, remove our proxy from the client and ignore all further communication
            if not self.client_connection.authenticated:
                str_response = data.decode('utf-8').rstrip('\r\n')
                match = AUTHENTICATION_RESPONSE_MATCHER.match(str_response)
                if match and match.group('tag') == self.client_connection.authentication_tag:
                    Log.info('Successfully authenticated connection - removing proxy')
                    self.client_connection.authenticated = True

            self.client_connection.send(data)

    def handle_close(self):
        if self.client_connection:
            self.client_connection.server_connection = None
            self.client_connection.close()
            self.client_connection = None
        self.close()


class IMAPOAuth2Proxy(asyncore.dispatcher_with_send):
    """Listen on SERVER_ADDRESS:SERVER_PORT, creating a ServerConnection + ClientConnection for each new connection"""

    def __init__(self, listener_address):
        asyncore.dispatcher_with_send.__init__(self)
        self.listener_address = listener_address
        self.client_connections = []

    def handle_accepted(self, connection, address):
        if MAX_CONNECTIONS <= 0 or len(self.client_connections) < MAX_CONNECTIONS:
            new_server_connection = ServerConnection((SERVER_ADDRESS, SERVER_PORT), address)
            new_client_connection = ClientConnection(connection, address, new_server_connection, self)
            new_server_connection.client_connection = new_client_connection
            self.client_connections.append(new_client_connection)
        else:
            Log.info('Rejecting new connection above MAX_CONNECTIONS limit of', MAX_CONNECTIONS)
            self.close()
            self.start()

    def start(self):
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(self.listener_address)
        self.listen(1)

    def remove_client(self, client):
        if client in self.client_connections:  # remove closed clients
            self.client_connections.remove(client)
        del client

    def stop(self):
        for connection in self.client_connections:
            connection.send('* BYE Server shutting down\r\n'.encode('utf-8'))  # try to exit gracefully
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

        self.proxy = None
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
            pystray.MenuItem('–––––––––––––––––––––', None, enabled=False),
            pystray.MenuItem('Authorise account...', self.authorise),
            pystray.MenuItem('Edit accounts...', self.edit_config),
            pystray.MenuItem('–––––––––––––––––––––', None, enabled=False),
            pystray.MenuItem('Debug mode', self.toggle_verbose, checked=lambda item: VERBOSE),
            pystray.MenuItem('–––––––––––––––––––––', None, enabled=False),
            pystray.MenuItem('Quit', self.exit)
        ))

    # noinspection PyUnusedLocal
    @staticmethod
    def edit_config(icon, item):
        if sys.platform == 'darwin':
            os.system("""open {}""".format(CONFIG_FILE))
        else:
            # TODO: will this work cross-platform
            os.system("""start {}""".format(CONFIG_FILE))

    # noinspection PyUnusedLocal
    @staticmethod
    def toggle_verbose(icon, item):
        global VERBOSE
        VERBOSE = not item.checked

    def post_create(self, icon):
        icon.visible = True

        self.proxy = IMAPOAuth2Proxy((LISTEN_ADDRESS, LISTEN_PORT))
        self.proxy.start()
        threading.Thread(target=self.run_proxy, name='IMAPOAuth2Proxy-main').start()

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

        if self.proxy:
            self.proxy.stop()
            self.proxy.close()

        if self.web_view_started:
            for window in webview.windows:
                window.show()
                window.destroy()

        icon.stop()

        syslog.closelog(APP_NAME)
        sys.exit(0)


if __name__ == '__main__':
    App(sys.argv)

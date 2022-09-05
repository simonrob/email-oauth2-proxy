"""A simple IMAP/POP/SMTP proxy that intercepts authenticate and login commands, transparently replacing them with OAuth
2.0 authentication. Designed for apps/clients that don't support OAuth 2.0 but need to connect to modern servers."""

__author__ = 'Simon Robinson'
__copyright__ = 'Copyright (c) 2022 Simon Robinson'
__license__ = 'Apache 2.0'
__version__ = '2022-09-05'  # ISO 8601 (YYYY-MM-DD)

import argparse
import base64
import binascii
import configparser
import datetime
import enum
import errno
import io
import json
import logging
import logging.handlers
import os
import pathlib
import plistlib
import queue
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
import wsgiref.simple_server
import wsgiref.util
import zlib

# asyncore is essential, but has been deprecated and will be removed in python 3.12 (see PEP 594)
# pyasyncore is our workaround, so suppress this warning until the proxy is rewritten in, e.g., asyncio
with warnings.catch_warnings():
    warnings.simplefilter('ignore', DeprecationWarning)
    import asyncore

# for encrypting/decrypting the locally-stored credentials
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# for macOS-specific unified logging
if sys.platform == 'darwin':
    # pyoslog *is* present; see youtrack.jetbrains.com/issue/PY-11963 (same for others with this suppressed inspection)
    # noinspection PyPackageRequirements
    import pyoslog

# by default the proxy is a GUI application with a menu bar/taskbar icon, but it is also useful in 'headless' contexts
# where not having to install GUI-only requirements can be helpful - see the proxy's readme and requirements-no-gui.txt
no_gui_parser = argparse.ArgumentParser()
no_gui_parser.add_argument('--no-gui', action='store_true')
if not no_gui_parser.parse_known_args()[0].no_gui:
    import pkg_resources  # from setuptools - used to check package versions and choose compatible methods
    import pystray  # the menu bar/taskbar GUI
    import timeago  # the last authenticated activity hint
    from PIL import Image, ImageDraw, ImageFont  # draw the menu bar icon from the TTF font stored in APP_ICON

    # noinspection PyPackageRequirements
    import webview  # the popup authentication window (in default and `--external-auth` modes only)

    # for macOS-specific functionality
    if sys.platform == 'darwin':
        # noinspection PyPackageRequirements
        import AppKit  # retina icon, menu update on click, native notifications and receiving system events
        import PyObjCTools  # SIGTERM handling (only needed when in GUI mode; `signal` is sufficient otherwise)
        import SystemConfiguration  # network availability monitoring

else:
    # dummy implementations to allow use regardless of whether pystray or AppKit are available
    # noinspection PyPep8Naming
    class pystray:
        class Icon:
            pass


    class AppKit:
        class NSObject:
            pass
del no_gui_parser

APP_NAME = 'Email OAuth 2.0 Proxy'
APP_SHORT_NAME = 'emailproxy'
APP_PACKAGE = 'ac.robinson.email-oauth2-proxy'

# noinspection SpellCheckingInspection
APP_ICON = b'''eNp1Uc9rE0EUfjM7u1nyq0m72aQxpnbTbFq0TbJNNkGkNpVKb2mxtgjWsqRJU+jaQHOoeMlVeoiCHqQXrwX/gEK9efGgNy+C4MWbHjxER
    DCJb3dTUdQH733zvW/ezHszQADAAy3gIFO+kdbW3lXWAUgRs2sV02igdoL8MfLctrHf6PeBAXBe5OL27r2acry6hPprdLleNbbiXfkUtRfoeh0T4gaju
    O6gT9TN5gEWo5GHGNjuXsVAPET+yuKmcdAAETaRR5BfuGuYVRCs/fQjBqGxt98En80/WzpYvaN3tPsvN4eufAWPc/r707dvLPyg/PiCcMSAq1n9AgXHs
    MbeedvZz+zMH0YGZ99x7v9LxwyzpuBBpA8oTg9tB8kn0IiIHQLPwT9tuba4BfNQhervPZzdMGBWp1a9hJHYyHBeS2Y2r+I/2LF/9Ku3Q7tXZ9ogJKEEN
    +EWbODRqpoaFwRXUJbDvK4Xghlek+WQ5KfKDM3N0dlshiQEQVHzuYJeKMxRVMNhWRISClYmc6qaUPxUitNZTdfz2QyfcmXIOK8xoOZKt7ViUkRqYXekW
    J6Sp0urC5fCken5STr0KDoUlyhjVd4nxSUvq3tCftEn8r2ro+mxUDIaCMQmQrGZGHmi53tAT3rPGH1e3qF0p9w7LtcohwuyvnRxWZ8sZUej6WvlhXSk1
    7k+POJ1iR73N/+w2xN0f4+GJcHtfqoWzgfi6cuZscC54lSq3SbN1tmzC4MXtcwN/zOC78r9BIfNc3M='''  # TTF ('e') -> zlib -> base64

CENSOR_MESSAGE = b'[[ Credentials removed from proxy log ]]'  # replaces actual credentials; must be a byte-type string

CONFIG_FILE_PATH = '%s/%s.config' % (os.path.dirname(os.path.realpath(__file__)), APP_SHORT_NAME)
CONFIG_SERVER_MATCHER = re.compile(r'^(?P<type>(IMAP|POP|SMTP))-(?P<port>\d+)$')

MAX_CONNECTIONS = 0  # maximum concurrent IMAP/POP/SMTP connections; 0 = no limit; limit is per server

RECEIVE_BUFFER_SIZE = 65536  # number of bytes to try to read from the socket at a time (limit is per socket)

MAX_SSL_HANDSHAKE_ATTEMPTS = 65536  # maximum number of attempts before aborting local SSL/TLS handshake; 0 = no limit

# IMAP/POP/SMTP require \r\n as a line terminator (we use lines only pre-authentication; afterwards just pass through)
LINE_TERMINATOR = b'\r\n'
LINE_TERMINATOR_LENGTH = len(LINE_TERMINATOR)

# seconds to wait before cancelling authentication requests (i.e., the user has this long to log in) - note that the
# actual server timeout is often around 60 seconds, so the connection may be closed in the background and immediately
# disconnect after login completes; however, the login credentials will still be saved and used for future requests
AUTHENTICATION_TIMEOUT = 600

TOKEN_EXPIRY_MARGIN = 600  # seconds before its expiry to refresh the OAuth 2.0 token

IMAP_TAG_PATTERN = r"[!#$&',-\[\]-z|}~]+"  # https://ietf.org/rfc/rfc9051.html#name-formal-syntax
IMAP_AUTHENTICATION_REQUEST_MATCHER = re.compile(
    r'^(?P<tag>%s) (?P<command>(LOGIN|AUTHENTICATE)) (?P<flags>.*)$' % IMAP_TAG_PATTERN, flags=re.IGNORECASE)
IMAP_CAPABILITY_MATCHER = re.compile(r'^(\* |\* OK \[)CAPABILITY .*$', flags=re.IGNORECASE)  # note: '* ' and '* OK ['

REQUEST_QUEUE = queue.Queue()  # requests for authentication
RESPONSE_QUEUE = queue.Queue()  # responses from user
WEBVIEW_QUEUE = queue.Queue()  # authentication window events (macOS only)
QUEUE_SENTINEL = object()  # object to send to signify queues should exit loops

PLIST_FILE_PATH = pathlib.Path('~/Library/LaunchAgents/%s.plist' % APP_PACKAGE).expanduser()  # launchctl file location
CMD_FILE_PATH = pathlib.Path('~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/%s.cmd' %
                             APP_PACKAGE).expanduser()  # Windows startup .cmd file location
AUTOSTART_FILE_PATH = pathlib.Path('~/.config/autostart/%s.desktop' % APP_PACKAGE).expanduser()  # XDG Autostart file

EXTERNAL_AUTH_HTML = '''<html><head><script type="text/javascript">function copyLink(targetLink){
    var copySource=document.createElement('textarea');copySource.value=targetLink;copySource.style.position='absolute';
    copySource.style.left='-9999px';document.body.appendChild(copySource);copySource.select();
    document.execCommand('copy');document.body.removeChild(copySource);
    document.getElementById('copy').innerText='✔'}</script><style type="text/css">body{margin:20px auto;line-height:1.3;
    font-family:sans-serif;font-size:16px;color:#444;padding:0 24px}</style></head><body>
    <h3 style="margin:0.3em 0;">Login authorisation request for %s</h3>
    <p style="margin-top:0">Click the following link to open your browser and approve the request:</p>
    <p><a href="%s" target="_blank" style="word-wrap:break-word;word-break:break-all">%s</a>
    <a id="copy" onclick="copyLink('%s')" style="margin-left:0.5em;margin-top:0.1em;font-weight:bold;font-size:150%%;
    text-decoration:none;cursor:pointer;float:right" title="Copy link">⧉</a></p>
    <p style="margin-top:2em">After logging in and successfully authorising your account, paste and submit the 
    resulting URL from the browser's address bar using the box at the bottom of this page to allow the %s script to
    transparently handle login requests on your behalf in future.</p>
    <p>Note that your browser may show a navigation error (e.g., <em>"localhost refused to connect"</em>) after 
    successfully logging in, but the final URL is the only important part, and as long as this begins with the  
    correct redirection URI and contains a valid authorisation code your email client's request will succeed.''' + (
    ' If you are using Windows, submitting can take a few seconds.' if sys.platform == 'win32' else '') + '''</p> 
    <p style="margin-top:2em">According to your proxy configuration file, the expected URL will be of the form:</p>
    <p><pre>%s <em>[...]</em> code=<em><strong>[code]</strong> [...]</em></em></pre></p>
    <form name="auth" onsubmit="window.location.assign(document.forms.auth.url.value); 
    document.auth.submit.value='Submitting...'; document.auth.submit.disabled=true; return false">
    <div style="display:flex;flex-direction:row;margin-top:4em"><label for="url">Authorisation success URL: 
    </label><input type="text" name="url" id="url" style="flex:1;margin:0 5px;width:65%%"><input type="submit" 
    id="submit" value="Submit"></div></form></body></html>'''

EXITING = False  # used to check whether to restart failed threads - is set to True if the user has requested to exit


class Log:
    """Simple logging to syslog/Console.app on Linux/macOS and to a local file on Windows"""

    _LOGGER = None
    _HANDLER = None
    _DATE_FORMAT = '%Y-%m-%d %H:%M:%S:'
    _SYSLOG_MESSAGE_FORMAT = '%s: %%(message)s' % APP_NAME
    _MACOS_USE_SYSLOG = not pyoslog.is_supported() if sys.platform == 'darwin' else False

    @staticmethod
    def initialise():
        Log._LOGGER = logging.getLogger(APP_NAME)
        if sys.platform == 'win32':
            handler = logging.FileHandler('%s/%s.log' % (os.path.dirname(os.path.realpath(__file__)), APP_SHORT_NAME))
            handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
        elif sys.platform == 'darwin':
            if Log._MACOS_USE_SYSLOG:  # syslog prior to 10.12
                handler = logging.handlers.SysLogHandler(address='/var/run/syslog')
                handler.setFormatter(logging.Formatter(Log._SYSLOG_MESSAGE_FORMAT))
            else:  # unified logging in 10.12+
                handler = pyoslog.Handler()
                handler.setSubsystem(APP_PACKAGE)
        else:
            if os.path.exists('/dev/log'):
                handler = logging.handlers.SysLogHandler(address='/dev/log')
                handler.setFormatter(logging.Formatter(Log._SYSLOG_MESSAGE_FORMAT))
            else:
                handler = logging.StreamHandler()
        Log._HANDLER = handler
        Log._LOGGER.addHandler(Log._HANDLER)
        Log.set_level(logging.INFO)

    @staticmethod
    def get_level():
        return Log._LOGGER.getEffectiveLevel()

    @staticmethod
    def set_level(level):
        # set both handler and logger level as we just want a direct mapping input->output
        Log._HANDLER.setLevel(level)
        Log._LOGGER.setLevel(level)

    @staticmethod
    def _log(level_method, level, *args):
        message = ' '.join(map(str, args))
        if Log.get_level() <= level:
            print(datetime.datetime.now().strftime(Log._DATE_FORMAT), message)

        if len(message) > 2048 and (sys.platform not in ['win32', 'darwin'] or Log._MACOS_USE_SYSLOG):
            truncation_message = ' [ NOTE: message over syslog length limit truncated to 2048 characters; run `%s' \
                                 ' --debug` in a terminal to see the full output ] ' % os.path.basename(__file__)
            message = message[0:2048 - len(Log._SYSLOG_MESSAGE_FORMAT) - len(truncation_message)] + truncation_message

        # note: need LOG_ALERT (i.e., warning) or higher to show in syslog on macOS
        severity = Log._LOGGER.warning if Log._MACOS_USE_SYSLOG else level_method
        severity(message)

    @staticmethod
    def debug(*args):
        Log._log(Log._LOGGER.debug, logging.DEBUG, *args)

    @staticmethod
    def info(*args):
        Log._log(Log._LOGGER.info, logging.INFO, *args)

    @staticmethod
    def error(*args):
        Log._log(Log._LOGGER.error, logging.ERROR, *args)

    @staticmethod
    def error_string(error):
        return getattr(error, 'message', repr(error))


class AppConfig:
    """Helper wrapper around ConfigParser to cache servers/accounts, and avoid writing to the file until necessary"""

    _PARSER = None
    _LOADED = False

    _GLOBALS = None
    _SERVERS = []
    _ACCOUNTS = []

    @staticmethod
    def _load():
        AppConfig.unload()
        AppConfig._PARSER = configparser.ConfigParser()
        AppConfig._PARSER.read(CONFIG_FILE_PATH)

        config_sections = AppConfig._PARSER.sections()
        if APP_SHORT_NAME in config_sections:
            AppConfig._GLOBALS = AppConfig._PARSER[APP_SHORT_NAME]
        else:
            AppConfig._GLOBALS = configparser.SectionProxy(AppConfig._PARSER, APP_SHORT_NAME)
        AppConfig._SERVERS = [s for s in config_sections if CONFIG_SERVER_MATCHER.match(s)]
        AppConfig._ACCOUNTS = [s for s in config_sections if '@' in s]
        AppConfig._LOADED = True

    @staticmethod
    def get():
        if not AppConfig._LOADED:
            AppConfig._load()
        return AppConfig._PARSER

    @staticmethod
    def unload():
        AppConfig._PARSER = None
        AppConfig._LOADED = False

        AppConfig._GLOBALS = None
        AppConfig._SERVERS = []
        AppConfig._ACCOUNTS = []

    @staticmethod
    def reload():
        AppConfig.unload()
        return AppConfig.get()

    @staticmethod
    def globals():
        AppConfig.get()  # make sure config is loaded
        return AppConfig._GLOBALS

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
        if AppConfig._LOADED:
            with open(CONFIG_FILE_PATH, 'w') as config_output:
                AppConfig._PARSER.write(config_output)


class OAuth2Helper:
    @staticmethod
    def get_oauth2_credentials(username, password, recurse_retries=True):
        """Using the given username (i.e., email address) and password, reads account details from AppConfig and
        handles OAuth 2.0 token request and renewal, saving the updated details back to AppConfig (or removing them
        if invalid). Returns either (True, '[OAuth2 string for authentication]') or (False, '[Error message]')"""
        if username not in AppConfig.accounts():
            Log.error('Proxy config file entry missing for account', username, '- aborting login')
            return (False, '%s: No config file entry found for account %s - please add a new section with values '
                           'for permission_url, token_url, oauth2_scope, redirect_uri, client_id and '
                           'client_secret' % (APP_NAME, username))

        config = AppConfig.get()
        current_time = int(time.time())

        permission_url = config.get(username, 'permission_url', fallback=None)
        token_url = config.get(username, 'token_url', fallback=None)
        oauth2_scope = config.get(username, 'oauth2_scope', fallback=None)
        redirect_uri = config.get(username, 'redirect_uri', fallback=None)
        redirect_listen_address = config.get(username, 'redirect_listen_address', fallback=None)
        client_id = config.get(username, 'client_id', fallback=None)
        client_secret = config.get(username, 'client_secret', fallback=None)

        # note that we don't require client_secret here because it can be optional for Office 365 configurations
        if not (permission_url and token_url and oauth2_scope and redirect_uri and client_id):
            Log.error('Proxy config file entry incomplete for account', username, '- aborting login')
            return (False, '%s: Incomplete config file entry found for account %s - please make sure all required '
                           'fields are added (permission_url, token_url, oauth2_scope, redirect_uri, client_id '
                           'and client_secret)' % (APP_NAME, username))

        # while not technically forbidden (RFC 6749, A.1 and A.2), it is highly unlikely the example value is valid
        example_client_value = '*** your client'
        example_client_status = [example_client_value in i for i in [client_id, client_secret] if i]
        if any(example_client_status):
            if all(example_client_status) or example_client_value in client_id:
                Log.info('Warning: client configuration for account', username, 'seems to contain example values -',
                         'if authentication fails, please double-check these values are correct')
            elif example_client_value in client_secret:
                Log.info('Warning: client secret for account', username, 'seems to contain the example value - if you',
                         'are using an Office 365 setup that does not need a secret, please delete this line entirely;',
                         'otherwise, if authentication fails, please double-check this value is correct')

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
            if access_token:
                if access_token_expiry - current_time < TOKEN_EXPIRY_MARGIN:
                    if refresh_token:
                        # if expiring soon, refresh token (if possible)
                        response = OAuth2Helper.refresh_oauth2_access_token(token_url, client_id, client_secret,
                                                                            OAuth2Helper.decrypt(cryptographer,
                                                                                                 refresh_token))

                        access_token = response['access_token']
                        config.set(username, 'access_token', OAuth2Helper.encrypt(cryptographer, access_token))
                        config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                        if 'refresh_token' in response:
                            config.set(username, 'refresh_token',
                                       OAuth2Helper.encrypt(cryptographer, response['refresh_token']))
                        AppConfig.save()

                    elif access_token_expiry <= current_time:
                        # cannot get another access token without a refresh token - must submit another manual request
                        access_token = None
                else:
                    access_token = OAuth2Helper.decrypt(cryptographer, access_token)

            if not access_token:
                permission_url = OAuth2Helper.construct_oauth2_permission_url(permission_url, redirect_uri, client_id,
                                                                              oauth2_scope, username)
                # note: get_oauth2_authorisation_code is a blocking call
                success, authorisation_code = OAuth2Helper.get_oauth2_authorisation_code(permission_url, redirect_uri,
                                                                                         redirect_listen_address,
                                                                                         username)
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
                if 'refresh_token' in response:
                    config.set(username, 'refresh_token',
                               OAuth2Helper.encrypt(cryptographer, response['refresh_token']))
                else:
                    Log.info('Warning: no refresh token returned for', username, '- you will need to re-authenticate',
                             'each time the access token expires (does your `oauth2_scope` value allow `offline` use?)')
                AppConfig.save()

            # send authentication command to server (response checked in ServerConnection) - note: we only support
            # single-trip authentication (SASL) without actually checking the server's capabilities - improve?
            oauth2_string = OAuth2Helper.construct_oauth2_string(username, access_token)
            return True, oauth2_string

        except InvalidToken as e:
            # if invalid details are the reason for failure we remove our cached version and re-authenticate - this can
            # be disabled by a configuration setting, but note that we always remove credentials on 400 Bad Request
            if e.args == (400, APP_PACKAGE) or AppConfig.globals().getboolean('delete_account_token_on_password_error',
                                                                              fallback=True):
                config.remove_option(username, 'token_salt')
                config.remove_option(username, 'access_token')
                config.remove_option(username, 'access_token_expiry')
                config.remove_option(username, 'refresh_token')
                AppConfig.save()
            else:
                recurse_retries = False  # no need to recurse if we are just trying the same credentials again

            if recurse_retries:
                Log.info('Retrying login due to exception while requesting OAuth 2.0 credentials:', Log.error_string(e))
                return OAuth2Helper.get_oauth2_credentials(username, password, recurse_retries=False)
            else:
                Log.error('Invalid password to decrypt', username, 'credentials - aborting login:', Log.error_string(e))
                return False, '%s: Login failed - the password for account %s is incorrect' % (APP_NAME, username)

        except Exception as e:
            # note that we don't currently remove cached credentials here, as failures on the initial request are before
            # caching happens, and the assumption is that refresh token request exceptions are temporal (e.g., network
            # errors: URLError(OSError(50, 'Network is down'))) - access token 400 Bad Request HTTPErrors with messages
            # such as 'authorisation code was already redeemed' are caused by our support for simultaneous requests,
            # and will work from the next request; however, please report an issue if you encounter problems here
            Log.info('Caught exception while requesting OAuth 2.0 credentials:', Log.error_string(e))
            return False, '%s: Login failed for account %s - please check your internet connection and retry' % (
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
    def start_redirection_receiver_server(token_request):
        """Starts a local WSGI web server at token_request['redirect_uri'] to receive OAuth responses"""
        redirect_listen_type = 'redirect_listen_address' if token_request['redirect_listen_address'] else 'redirect_uri'
        parsed_uri = urllib.parse.urlparse(token_request[redirect_listen_type])
        parsed_port = 80 if parsed_uri.port is None else parsed_uri.port
        Log.debug('Local server auth mode (%s:%d): starting server to listen for authentication response' % (
            parsed_uri.hostname, parsed_port))

        class LoggingWSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
            def log_message(self, format_string, *args):
                Log.debug('Local server auth mode (%s:%d): received authentication response' % (
                    parsed_uri.hostname, parsed_port), *args)

        class RedirectionReceiverWSGIApplication:
            def __call__(self, environ, start_response):
                start_response('200 OK', [('Content-type', 'text/html; charset=utf-8')])
                token_request['response_url'] = wsgiref.util.request_uri(environ)
                return [('<html><head><title>%s authentication complete (%s)</title><style type="text/css">body{margin:'
                         '20px auto;line-height:1.3;font-family:sans-serif;font-size:16px;color:#444;padding:0 24px}'
                         '</style></head><body><p>%s successfully authenticated account %s.</p><p>You can close this '
                         'window.</p></body></html>' % ((APP_NAME, token_request['username']) * 2)).encode('utf-8')]

        try:
            wsgiref.simple_server.WSGIServer.allow_reuse_address = False
            wsgiref.simple_server.WSGIServer.timeout = AUTHENTICATION_TIMEOUT
            redirection_server = wsgiref.simple_server.make_server(str(parsed_uri.hostname), parsed_port,
                                                                   RedirectionReceiverWSGIApplication(),
                                                                   handler_class=LoggingWSGIRequestHandler)

            Log.info('Please visit the following URL to authenticate account %s: %s' %
                     (token_request['username'], token_request['permission_url']))
            redirection_server.handle_request()
            try:
                redirection_server.server_close()
            except socket.error:
                pass

            if 'response_url' in token_request:
                Log.debug('Local server auth mode (%s:%d): closing local server and returning response' % (
                    parsed_uri.hostname, parsed_port), token_request['response_url'])
            else:
                # failed, likely because of an incorrect address (e.g., https vs http), but can also be due to timeout
                Log.info('Local server auth mode (%s:%d):' % (parsed_uri.hostname, parsed_port), 'request failed - if',
                         'this error reoccurs, please check `%s` for' % redirect_listen_type, token_request['username'],
                         'is not specified as `https` mistakenly. See the sample configuration file for documentation')
                token_request['expired'] = True

        except socket.error as e:
            Log.error('Local server auth mode (%s:%d):' % (parsed_uri.hostname, parsed_port), 'unable to start local',
                      'server. Please check that `%s` for %s is unique across accounts, specifies a port number, and '
                      'is not already in use. See the documentation in the proxy\'s sample configuration file.' % (
                          redirect_listen_type, token_request['username']), Log.error_string(e))
            token_request['expired'] = True

        del token_request['local_server_auth']
        RESPONSE_QUEUE.put(token_request)

    @staticmethod
    def construct_oauth2_permission_url(permission_url, redirect_uri, client_id, scope, username):
        """Constructs and returns the URL to request permission for this client to access the given scope, hinting
        the username where possible (note that delegated accounts without direct login enabled will need to select the
        'Sign in with another account' option)"""
        params = {'client_id': client_id, 'redirect_uri': redirect_uri, 'scope': scope, 'response_type': 'code',
                  'access_type': 'offline', 'login_hint': username}
        param_pairs = []
        for param in params:
            param_pairs.append('%s=%s' % (param, OAuth2Helper.oauth2_url_escape(params[param])))
        return '%s?%s' % (permission_url, '&'.join(param_pairs))

    @staticmethod
    def get_oauth2_authorisation_code(permission_url, redirect_uri, redirect_listen_address, username):
        """Submit an authorisation request to the parent app and block until it is provided (or the request fails)"""
        token_request = {'permission_url': permission_url, 'redirect_uri': redirect_uri,
                         'redirect_listen_address': redirect_listen_address, 'username': username, 'expired': False}
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

            elif data['permission_url'] == permission_url and data['username'] == username:  # a response meant for us
                # to improve no-GUI mode we also support the use of a local server to receive the OAuth redirection
                # (note: not enabled by default because no-GUI mode is typically unattended, but useful in some cases)
                if 'expired' in data and data['expired']:  # local server auth wsgi request error or failure
                    return False, None

                elif 'local_server_auth' in data:
                    threading.Thread(target=OAuth2Helper.start_redirection_receiver_server, args=(data,),
                                     name='EmailOAuth2Proxy-auth-%s' % data['username'], daemon=True).start()

                else:
                    if 'response_url' in data and 'code=' in data['response_url'] and data['response_url'].startswith(
                            token_request['redirect_uri']):
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
        if not client_secret:
            del params['client_secret']  # client secret can be optional for O365, but we don't want a None entry
        try:
            response = urllib.request.urlopen(token_url, urllib.parse.urlencode(params).encode('utf-8')).read()
            return json.loads(response)
        except urllib.error.HTTPError as e:
            Log.debug('Error requesting access token - received invalid response:', json.loads(e.read()))
            raise e

    @staticmethod
    def refresh_oauth2_access_token(token_url, client_id, client_secret, refresh_token):
        """Obtains a new access token from token_url using the given client_id, client_secret and refresh token,
        returning a dict with 'access_token', 'expires_in', and 'refresh_token' on success; exception on failure"""
        params = {'client_id': client_id, 'client_secret': client_secret, 'refresh_token': refresh_token,
                  'grant_type': 'refresh_token'}
        if not client_secret:
            del params['client_secret']  # client secret can be optional for O365, but we don't want a None entry
        try:
            response = urllib.request.urlopen(token_url, urllib.parse.urlencode(params).encode('utf-8')).read()
            return json.loads(response)
        except urllib.error.HTTPError as e:
            Log.debug('Error refreshing access token - received invalid response:', json.loads(e.read()))
            if e.code == 400:  # 400 Bad Request typically means re-authentication is required (refresh token expired)
                raise InvalidToken(e.code, APP_PACKAGE)
            raise e

    @staticmethod
    def construct_oauth2_string(username, access_token):
        """Constructs an OAuth 2.0 SASL authentication string from the given username and access token"""
        return 'user=%s\1auth=Bearer %s\1\1' % (username, access_token)

    @staticmethod
    def encode_oauth2_string(input_string):
        """We use encode() from imaplib's _Authenticator, but it is a private class so we shouldn't just import it. That
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
            # formal syntax: https://tools.ietf.org/html/rfc4616#section-2
            _, bytes_username, bytes_password = base64.b64decode(str_data).split(b'\x00')
            return bytes_username.decode('utf-8'), bytes_password.decode('utf-8')
        except (ValueError, binascii.Error):
            # ValueError is from incorrect number of arguments; binascii.Error from incorrect encoding
            return '', ''  # no (or invalid) credentials provided


class SSLAsyncoreDispatcher(asyncore.dispatcher_with_send):
    def __init__(self, connection=None, socket_map=None):
        asyncore.dispatcher_with_send.__init__(self, sock=connection, map=socket_map)
        self.ssl_connection, self.ssl_handshake_attempts, self.ssl_handshake_completed = self.reset()

    def reset(self, is_ssl=False):
        self.ssl_connection = is_ssl
        self.ssl_handshake_attempts = 0
        self.ssl_handshake_completed = not is_ssl
        return self.ssl_connection, self.ssl_handshake_attempts, self.ssl_handshake_completed

    def info_string(self):
        return 'SSLDispatcher'  # override in subclasses to provide more detailed connection information

    def set_ssl_connection(self, is_ssl=False):
        # note that the actual SSLContext.wrap_socket (and associated unwrap()) are handled outside this class
        if not self.ssl_connection and is_ssl:
            self.reset(True)
            if is_ssl:
                # we don't start negotiation here because a failed handshake in __init__ means remove_client also fails
                Log.debug(self.info_string(), '<-> [ Starting TLS handshake ]')

        elif self.ssl_connection and not is_ssl:
            self.reset()

    def ssl_handshake(self):
        self.ssl_handshake_attempts += 1
        if 0 < MAX_SSL_HANDSHAKE_ATTEMPTS < self.ssl_handshake_attempts:
            raise ssl.SSLError(-1, APP_PACKAGE)

        # see: https://github.com/python/cpython/issues/54293
        try:
            # note that attempting to connect insecurely to a secure socket may loop indefinitely here - we attempt
            # to catch this in handle_error() when the client gives up, but there's not much else we can do
            # noinspection PyUnresolvedReferences
            self.socket.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
            self.handle_close()
            return
        else:
            Log.debug(self.info_string(), '<-> [ TLS handshake complete ]')
            self.ssl_handshake_attempts = 0
            self.ssl_handshake_completed = True

    def handle_read_event(self):
        if not self.ssl_handshake_completed:
            self.ssl_handshake()
        else:
            # on the first connection event to a secure server we need to handle SSL handshake events (because we don't
            # have a 'not_currently_ssl_but_will_be_once_connected'-type state) - a version of this class that didn't
            # have to deal with both unsecured, wrapped *and* STARTTLS-type sockets would only need this in recv/send
            try:
                super().handle_read_event()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                self.ssl_handshake_completed = False

    def handle_write_event(self):
        if not self.ssl_handshake_completed:
            self.ssl_handshake()
        else:
            # as in handle_read_event, we need to handle SSL handshake events
            try:
                super().handle_write_event()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                self.ssl_handshake_completed = False

    def recv(self, buffer_size):
        try:
            return super().recv(buffer_size)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            self.ssl_handshake_completed = False
            return b''
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
            self.handle_close()
            return b''
        except ssl.SSLError:
            self.handle_error()
            return b''

    def send(self, byte_data):
        try:
            return super().send(byte_data)  # buffers before sending via the socket, so failure is okay; will auto-retry
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            self.ssl_handshake_completed = False
            return 0
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
            self.handle_close()
            return 0
        except ssl.SSLError:
            self.handle_error()
            return 0

    def handle_error(self):
        error_type, value, _traceback = sys.exc_info()
        del _traceback  # used to be required in python 2; may no-longer be needed, but best to be safe
        if self.ssl_connection:
            # OSError 0 ('Error') and SSL errors here are caused by connection handshake failures or timeouts
            # APP_PACKAGE is used when we throw our own SSLError on handshake timeout
            ssl_errors = ['SSLV3_ALERT_BAD_CERTIFICATE', 'PEER_DID_NOT_RETURN_A_CERTIFICATE', 'WRONG_VERSION_NUMBER',
                          'CERTIFICATE_VERIFY_FAILED', APP_PACKAGE]
            if error_type == OSError and value.errno == 0 or issubclass(error_type, ssl.SSLError) and \
                    any([i in value.args[1] for i in ssl_errors]):
                Log.error('Caught connection error in', self.info_string(), '- you have set `local_certificate_path`',
                          'and `local_key_path`; is your client using a secure connection?', 'Error type', error_type,
                          'with message:', value)
                self.handle_close()
            else:
                super().handle_error()
        else:
            super().handle_error()


class OAuth2ClientConnection(SSLAsyncoreDispatcher):
    """The base client-side connection that is subclassed to handle IMAP/POP/SMTP client interaction (note that there
    is some protocol-specific code in here, but it is not essential, and only used to avoid logging credentials)"""

    def __init__(self, proxy_type, connection, socket_map, connection_info, server_connection, proxy_parent,
                 custom_configuration):
        SSLAsyncoreDispatcher.__init__(self, connection, socket_map)
        self.receive_buffer = b''
        self.proxy_type = proxy_type
        self.connection_info = connection_info
        self.server_connection = server_connection
        self.local_address = proxy_parent.local_address
        self.server_address = server_connection.server_address
        self.proxy_parent = proxy_parent
        self.custom_configuration = custom_configuration

        self.censor_next_log = False  # try to avoid logging credentials
        self.authenticated = False

        self.set_ssl_connection(
            custom_configuration['local_certificate_path'] and custom_configuration['local_key_path'])

    def info_string(self):
        if Log.get_level() == logging.DEBUG:
            return '%s (%s:%d; %s:%d->%s:%d%s)' % (
                self.proxy_type, self.local_address[0], self.local_address[1], self.connection_info[0],
                self.connection_info[1], self.server_address[0], self.server_address[1],
                '; %s' % self.server_connection.authenticated_username if
                self.server_connection and self.server_connection.authenticated_username else '')
        else:
            return '%s (%s:%d)' % (self.proxy_type, self.local_address[0], self.local_address[1])

    def handle_read(self):
        byte_data = self.recv(RECEIVE_BUFFER_SIZE)
        if not byte_data:
            return

        # client is established after server; this state should not happen unless already closing
        if not self.server_connection:
            Log.debug(self.info_string(), 'Data received without server connection - ignoring and closing:', byte_data)
            self.close()
            return

        # we have already authenticated - nothing to do; just pass data directly to server
        if self.authenticated:
            Log.debug(self.info_string(), '-->', byte_data)
            OAuth2ClientConnection.process_data(self, byte_data)

        # if not authenticated, buffer incoming data and process line-by-line (slightly more involved than the server
        # connection because we censor commands that contain passwords or authentication tokens)
        else:
            self.receive_buffer += byte_data
            complete_lines = []
            while True:
                terminator_index = self.receive_buffer.find(LINE_TERMINATOR)
                if terminator_index != -1:
                    split_position = terminator_index + LINE_TERMINATOR_LENGTH
                    complete_lines.append(self.receive_buffer[:split_position])
                    self.receive_buffer = self.receive_buffer[split_position:]
                else:
                    break

            for line in complete_lines:
                # try to remove credentials from logged data - both inline (via regex) and as separate requests
                if self.censor_next_log:
                    log_data = CENSOR_MESSAGE
                    self.censor_next_log = False
                else:
                    # IMAP LOGIN command with inline username/password, POP PASS and IMAP/POP/SMTP AUTH(ENTICATE)
                    tag_pattern = IMAP_TAG_PATTERN.encode('utf-8')
                    log_data = re.sub(b'(%s) (LOGIN) (.*)\r\n' % tag_pattern, b'\\1 \\2 %s\r\n' % CENSOR_MESSAGE,
                                      line, flags=re.IGNORECASE)
                    log_data = re.sub(b'(PASS) (.*)\r\n', b'\\1 %s\r\n' % CENSOR_MESSAGE, log_data, flags=re.IGNORECASE)
                    log_data = re.sub(b'(%s)?( ?)(AUTH)(ENTICATE)? (PLAIN|LOGIN) (.*)\r\n' % tag_pattern,
                                      b'\\1\\2\\3\\4 \\5 %s\r\n' % CENSOR_MESSAGE, log_data, flags=re.IGNORECASE)

                Log.debug(self.info_string(), '-->', log_data)
                self.process_data(line)

    def process_data(self, byte_data, censor_server_log=False):
        try:
            self.server_connection.send(byte_data, censor_log=censor_server_log)  # default = send everything to server
        except AttributeError:  # AttributeError("'NoneType' object has no attribute 'send'")
            Log.info(self.info_string(), 'Caught client exception; server connection closed before data could be sent')
            self.close()

    def send(self, byte_data):
        Log.debug(self.info_string(), '<--', byte_data)
        return super().send(byte_data)

    def log_info(self, message, message_type='info'):
        # override to redirect error messages to our own log
        if message_type not in self.ignore_log_types:
            Log.info(self.info_string(), 'Caught asyncore info message (client) -', message_type, ':', message)

    def handle_close(self):
        Log.debug(self.info_string(), '--> [ Client disconnected ]')
        self.close()

    def close(self):
        if self.server_connection:
            self.server_connection.client_connection = None
            try:
                self.server_connection.close()
            except AttributeError:
                pass
            self.server_connection = None
        self.proxy_parent.remove_client(self)
        try:
            super().close()
        except OSError:
            pass


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
            username, password = OAuth2Helper.decode_credentials(str_data)
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
                        username, password = OAuth2Helper.decode_credentials(' '.join(split_flags[1:]))
                        self.authenticate_connection(username, password, 'authenticate')
                    else:
                        self.awaiting_credentials = True
                        self.censor_next_log = True
                        self.send(b'+ \r\n')  # request credentials (note: space after response code is mandatory)
                else:
                    # we don't support any other methods - let the server handle this
                    super().process_data(byte_data)

            else:
                # we haven't yet authenticated, but this is some other matched command - pass through
                super().process_data(byte_data)

    def authenticate_connection(self, username, password, command='login'):
        success, result = OAuth2Helper.get_oauth2_credentials(username, password)
        if success:
            # send authentication command to server (response checked in ServerConnection)
            # note: we only support single-trip authentication (SASL) without checking server capabilities - improve?
            super().process_data(b'%s AUTHENTICATE XOAUTH2 ' % self.authentication_tag.encode('utf-8'))
            super().process_data(OAuth2Helper.encode_oauth2_string(result), censor_server_log=True)
            super().process_data(b'\r\n')

            # because get_oauth2_credentials blocks, the server could have disconnected, and may no-longer exist
            if self.server_connection:
                self.server_connection.authenticated_username = username

        else:
            error_message = '%s NO %s %s\r\n' % (self.authentication_tag, command.upper(), result)
            self.send(error_message.encode('utf-8'))
            self.send(b'* BYE Autologout; authentication failed\r\n')
            self.close()


class POPOAuth2ClientConnection(OAuth2ClientConnection):
    """The client side of the connection - watch for AUTH, USER and PASS commands and replace with OAuth 2.0"""

    class STATE(enum.Enum):
        PENDING = 1
        CAPA_AWAITING_RESPONSE = 2
        AUTH_PLAIN_AWAITING_CREDENTIALS = 3
        USER_AWAITING_PASS = 4
        XOAUTH2_AWAITING_CONFIRMATION = 5
        XOAUTH2_CREDENTIALS_SENT = 6

    def __init__(self, connection, socket_map, connection_info, server_connection, proxy_parent, custom_configuration):
        super().__init__('POP', connection, socket_map, connection_info, server_connection, proxy_parent,
                         custom_configuration)
        self.connection_state = self.STATE.PENDING

    def process_data(self, byte_data, censor_server_log=False):
        str_data = byte_data.decode('utf-8', 'replace').rstrip('\r\n')
        str_data_lower = str_data.lower()

        if self.connection_state is self.STATE.PENDING:
            if str_data_lower == 'capa':
                self.server_connection.capa = []
                self.connection_state = self.STATE.CAPA_AWAITING_RESPONSE
                super().process_data(byte_data)

            elif str_data_lower == 'auth':  # a bare 'auth' command is another way to request capabilities
                self.send(b'+OK\r\nPLAIN\r\n.\r\n')  # no need to actually send to the server - we know what we support

            elif str_data_lower.startswith('auth plain'):
                if len(str_data) > 11:  # 11 = len('AUTH PLAIN ') - can have the login details either inline...
                    self.server_connection.username, self.server_connection.password = OAuth2Helper.decode_credentials(
                        str_data[11:])
                    self.send_authentication_request()
                else:  # ...or requested separately
                    self.connection_state = self.STATE.AUTH_PLAIN_AWAITING_CREDENTIALS
                    self.censor_next_log = True
                    self.send(b'+ \r\n')  # request details

            elif str_data_lower.startswith('user'):
                self.server_connection.username = str_data[5:]  # 5 = len('USER ')
                self.connection_state = self.STATE.USER_AWAITING_PASS
                self.send(b'+OK\r\n')  # request password

            else:
                super().process_data(byte_data)  # some other command that we don't handle - pass directly to server

        elif self.connection_state is self.STATE.AUTH_PLAIN_AWAITING_CREDENTIALS:
            if str_data == '*':  # request cancelled by the client - reset state (must be a negative response)
                self.connection_state = self.STATE.PENDING
                self.send(b'-ERR\r\n')
            else:
                self.server_connection.username, self.server_connection.password = OAuth2Helper.decode_credentials(
                    str_data)
                self.send_authentication_request()

        elif self.connection_state is self.STATE.USER_AWAITING_PASS:
            if str_data_lower.startswith('pass'):
                self.server_connection.password = str_data[5:]  # 5 = len('PASS ')
                self.send_authentication_request()

            else:
                # the only valid input here is PASS (above) or QUIT
                self.send(b'+OK Bye\r\n')
                self.close()

        else:
            super().process_data(byte_data)  # some other command that we don't handle - pass directly to server

    def send_authentication_request(self):
        if self.server_connection.username and self.server_connection.password:
            self.connection_state = self.STATE.XOAUTH2_AWAITING_CONFIRMATION
            super().process_data(b'AUTH XOAUTH2\r\n')
        else:
            self.send(b'-ERR Authentication failed.\r\n')
            self.close()


class SMTPOAuth2ClientConnection(OAuth2ClientConnection):
    """The client side of the connection - intercept AUTH PLAIN and AUTH LOGIN commands and replace with OAuth 2.0"""

    class STATE(enum.Enum):
        PENDING = 1
        EHLO_AWAITING_RESPONSE = 2
        AUTH_PLAIN_AWAITING_CREDENTIALS = 3
        AUTH_LOGIN_AWAITING_USERNAME = 4
        AUTH_LOGIN_AWAITING_PASSWORD = 5
        XOAUTH2_AWAITING_CONFIRMATION = 6
        XOAUTH2_CREDENTIALS_SENT = 7

    def __init__(self, connection, socket_map, connection_info, server_connection, proxy_parent, custom_configuration):
        super().__init__('SMTP', connection, socket_map, connection_info, server_connection, proxy_parent,
                         custom_configuration)
        self.connection_state = self.STATE.PENDING

    def process_data(self, byte_data, censor_server_log=False):
        str_data = byte_data.decode('utf-8', 'replace').rstrip('\r\n')
        str_data_lower = str_data.lower()

        # intercept EHLO so we can correct capabilities and replay after STARTTLS if needed (in server connection class)
        if self.connection_state is self.STATE.PENDING:
            if str_data_lower.startswith('ehlo') or str_data_lower.startswith('helo'):
                self.connection_state = self.STATE.EHLO_AWAITING_RESPONSE
                self.server_connection.ehlo = byte_data  # save the command so we can replay later if needed (STARTTLS)
                super().process_data(byte_data)  # don't just go to STARTTLS - most servers require EHLO first

            # intercept AUTH PLAIN and AUTH LOGIN to replace with AUTH XOAUTH2
            elif str_data_lower.startswith('auth plain'):
                if len(str_data) > 11:  # 11 = len('AUTH PLAIN ') - can have the login details either inline...
                    self.server_connection.username, self.server_connection.password = OAuth2Helper.decode_credentials(
                        str_data[11:])
                    self.send_authentication_request()
                else:  # ...or requested separately
                    self.connection_state = self.STATE.AUTH_PLAIN_AWAITING_CREDENTIALS
                    self.censor_next_log = True
                    self.send(b'334 \r\n')  # request details (note: space after response code is mandatory)

            elif str_data_lower.startswith('auth login'):
                if len(str_data) > 11:  # 11 = len('AUTH LOGIN ') - this method can have the username either inline...
                    self.decode_username_and_request_password(str_data[11:])
                else:  # ...or requested separately
                    self.connection_state = self.STATE.AUTH_LOGIN_AWAITING_USERNAME
                    self.send(b'334 %s\r\n' % base64.b64encode(b'Username:'))

            else:
                super().process_data(byte_data)  # some other command that we don't handle - pass directly to server

        elif self.connection_state is self.STATE.AUTH_PLAIN_AWAITING_CREDENTIALS:
            self.server_connection.username, self.server_connection.password = OAuth2Helper.decode_credentials(
                str_data)
            self.send_authentication_request()

        elif self.connection_state is self.STATE.AUTH_LOGIN_AWAITING_USERNAME:
            self.decode_username_and_request_password(str_data)

        elif self.connection_state is self.STATE.AUTH_LOGIN_AWAITING_PASSWORD:
            try:
                self.server_connection.password = base64.b64decode(str_data).decode('utf-8')
            except binascii.Error:
                self.server_connection.password = ''
            self.send_authentication_request()

        # some other command that we don't handle - pass directly to server
        else:
            super().process_data(byte_data)

    def decode_username_and_request_password(self, encoded_username):
        try:
            self.server_connection.username = base64.b64decode(encoded_username).decode('utf-8')
        except binascii.Error:
            self.server_connection.username = ''
        self.connection_state = self.STATE.AUTH_LOGIN_AWAITING_PASSWORD
        self.censor_next_log = True
        self.send(b'334 %s\r\n' % base64.b64encode(b'Password:'))

    def send_authentication_request(self):
        if self.server_connection.username and self.server_connection.password:
            self.connection_state = self.STATE.XOAUTH2_AWAITING_CONFIRMATION
            super().process_data(b'AUTH XOAUTH2\r\n')
        else:
            self.send(b'535 5.7.8  Authentication credentials invalid.\r\n')
            self.close()


class OAuth2ServerConnection(SSLAsyncoreDispatcher):
    """The base server-side connection that is subclassed to handle IMAP/POP/SMTP server interaction"""

    def __init__(self, proxy_type, socket_map, server_address, connection_info, proxy_parent, custom_configuration):
        SSLAsyncoreDispatcher.__init__(self, socket_map=socket_map)  # note: establish connection later due to STARTTLS
        self.receive_buffer = b''
        self.proxy_type = proxy_type
        self.connection_info = connection_info
        self.client_connection = None
        self.local_address = proxy_parent.local_address
        self.server_address = server_address
        self.proxy_parent = proxy_parent
        self.custom_configuration = custom_configuration

        self.authenticated_username = None  # used only for showing last activity in the menu
        self.last_activity = 0

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect(self.server_address)

    def info_string(self):
        if Log.get_level() == logging.DEBUG:
            return '%s (%s:%d; %s:%d->%s:%d%s)' % (
                self.proxy_type, self.local_address[0], self.local_address[1], self.connection_info[0],
                self.connection_info[1], self.server_address[0], self.server_address[1],
                '; %s' % self.authenticated_username if self.authenticated_username else '')
        else:
            return '%s (%s:%d)' % (self.proxy_type, self.local_address[0], self.local_address[1])

    def handle_connect(self):
        Log.debug(self.info_string(), '--> [ Client connected ]')

        # connections can either be upgraded (wrapped) after setup via the STARTTLS command, or secure from the start
        if not self.custom_configuration['starttls']:
            # noinspection PyTypeChecker
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            super().set_socket(ssl_context.wrap_socket(self.socket, server_hostname=self.server_address[0],
                                                       suppress_ragged_eofs=True, do_handshake_on_connect=False))
            self.set_ssl_connection(True)

    def handle_read(self):
        byte_data = self.recv(RECEIVE_BUFFER_SIZE)
        if not byte_data:
            return

        # data received before client is connected (or after client has disconnected) - ignore
        if not self.client_connection:
            Log.debug(self.info_string(), 'Data received without client connection - ignoring:', byte_data)
            return

        # we have already authenticated - nothing to do; just pass data directly to client, ignoring overridden method
        if self.client_connection.authenticated:
            OAuth2ServerConnection.process_data(self, byte_data)

            # receiving data from the server while authenticated counts as activity (i.e., ignore pre-login negotiation)
            if self.authenticated_username:
                activity_time = time.time() // 10  # only update once every 10 or so seconds (timeago shows "just now")
                if activity_time > self.last_activity:
                    config = AppConfig.get()
                    config.set(self.authenticated_username, 'last_activity', str(int(time.time())))
                    self.last_activity = activity_time

        # if not authenticated, buffer incoming data and process line-by-line
        else:
            self.receive_buffer += byte_data
            complete_lines = []
            while True:
                terminator_index = self.receive_buffer.find(LINE_TERMINATOR)
                if terminator_index != -1:
                    split_position = terminator_index + LINE_TERMINATOR_LENGTH
                    complete_lines.append(self.receive_buffer[:split_position])
                    self.receive_buffer = self.receive_buffer[split_position:]
                else:
                    break

            for line in complete_lines:
                Log.debug(self.info_string(), '    <--', line)  # (log before edits)
                self.process_data(line)

    def process_data(self, byte_data):
        try:
            self.client_connection.send(byte_data)  # by default we just send everything straight to the client
        except AttributeError:  # AttributeError("'NoneType' object has no attribute 'send'")
            Log.info(self.info_string(), 'Caught server exception; client connection closed before data could be sent')
            self.close()

    def send(self, byte_data, censor_log=False):
        if not self.client_connection.authenticated:  # after authentication these are identical to server-side logs
            Log.debug(self.info_string(), '    -->', CENSOR_MESSAGE if censor_log else byte_data)
        return super().send(byte_data)

    def handle_error(self):
        error_type, value, _traceback = sys.exc_info()
        del _traceback  # used to be required in python 2; may no-longer be needed, but best to be safe
        if error_type == TimeoutError and value.errno == errno.ETIMEDOUT or \
                error_type == OSError and value.errno in [0, errno.ENETDOWN, errno.EHOSTUNREACH]:
            # TimeoutError 60 = 'Operation timed out'; OSError 0 = 'Error' (typically network failure);
            # OSError 50 = 'Network is down'; OSError 65 = 'No route to host'
            Log.info(self.info_string(), 'Caught network error (server) - is there a network connection?',
                     'Error type', error_type, 'with message:', value)
            self.handle_close()
        else:
            super().handle_error()

    def log_info(self, message, message_type='info'):
        # override to redirect error messages to our own log
        if message_type not in self.ignore_log_types:
            Log.info(self.info_string(), 'Caught asyncore info message (server) -', message_type, ':', message)

    def handle_close(self):
        Log.debug(self.info_string(), '<-- [ Server disconnected ]')
        self.close()

    def close(self):
        if self.client_connection:
            self.client_connection.server_connection = None
            try:
                self.client_connection.close()
            except AttributeError:
                pass
            self.client_connection = None
        try:
            super().close()
        except OSError:
            pass


class IMAPOAuth2ServerConnection(OAuth2ServerConnection):
    """The IMAP server side - watch for the OK AUTHENTICATE response, then ignore all subsequent data"""

    # IMAP: https://tools.ietf.org/html/rfc3501
    # IMAP SASL-IR: https://tools.ietf.org/html/rfc4959
    def __init__(self, socket_map, server_address, connection_info, proxy_parent, custom_configuration):
        super().__init__('IMAP', socket_map, server_address, connection_info, proxy_parent, custom_configuration)

    def process_data(self, byte_data):
        # note: there is no reason why IMAP STARTTLS (https://tools.ietf.org/html/rfc2595) couldn't be supported here
        # as with SMTP, but all well-known servers provide a non-STARTTLS variant, so left unimplemented for now
        str_response = byte_data.decode('utf-8', 'replace').rstrip('\r\n')

        # if authentication succeeds, remove our proxy from the client and ignore all further communication
        # don't use a regex here as the tag must match exactly; RFC 3501 specifies uppercase 'OK', so startswith is fine
        if str_response.startswith('%s OK' % self.client_connection.authentication_tag):
            Log.info(self.info_string(), '[ Successfully authenticated IMAP connection - removing proxy ]')
            self.client_connection.authenticated = True

        # intercept pre-auth CAPABILITY response to advertise only AUTH=PLAIN (+SASL-IR) and re-enable LOGIN if required
        if IMAP_CAPABILITY_MATCHER.match(str_response):
            capability = r"[!#$&'+-\[^-z|}~]+"  # https://ietf.org/rfc/rfc9051.html#name-formal-syntax
            updated_response = re.sub(r'( AUTH=' + capability + r')+', ' AUTH=PLAIN', str_response, flags=re.IGNORECASE)
            if not re.search(r' AUTH=PLAIN', updated_response, re.IGNORECASE):
                # cannot just replace e.g., one 'CAPABILITY ' match because IMAP4 must be first if present (RFC 1730)
                updated_response = re.sub(r'(CAPABILITY)( IMAP' + capability + r')?', r'\g<1>\g<2> AUTH=PLAIN',
                                          updated_response, count=1, flags=re.IGNORECASE)
            updated_response = updated_response.replace(' AUTH=PLAIN', '', updated_response.count(' AUTH=PLAIN') - 1)
            if not re.search(r' SASL-IR', updated_response, re.IGNORECASE):
                updated_response = updated_response.replace(' AUTH=PLAIN', ' AUTH=PLAIN SASL-IR')
            updated_response = re.sub(r' LOGINDISABLED', '', updated_response, count=1, flags=re.IGNORECASE)
            byte_data = (b'%s\r\n' % updated_response.encode('utf-8'))

        super().process_data(byte_data)


class POPOAuth2ServerConnection(OAuth2ServerConnection):
    """The POP server side - submit credentials, then watch for +OK and ignore subsequent data"""

    # POP3: https://tools.ietf.org/html/rfc1939
    # POP3 CAPA: https://tools.ietf.org/html/rfc2449
    # POP3 AUTH: https://tools.ietf.org/html/rfc1734
    # POP3 SASL: https://tools.ietf.org/html/rfc5034
    def __init__(self, socket_map, server_address, connection_info, proxy_parent, custom_configuration):
        super().__init__('POP', socket_map, server_address, connection_info, proxy_parent, custom_configuration)
        self.capa = []
        self.username = None
        self.password = None

    def process_data(self, byte_data):
        # note: there is no reason why POP STARTTLS (https://tools.ietf.org/html/rfc2595) couldn't be supported here
        # as with SMTP, but all well-known servers provide a non-STARTTLS variant, so left unimplemented for now
        str_data = byte_data.decode('utf-8', 'replace').rstrip('\r\n')

        # we cache and replay the CAPA response so we can ensure it contains the right capabilities
        if self.client_connection.connection_state is POPOAuth2ClientConnection.STATE.CAPA_AWAITING_RESPONSE:
            if str_data.startswith('-'):  # error
                self.client_connection.connection_state = POPOAuth2ClientConnection.STATE.PENDING
                super().process_data(byte_data)

            elif str_data == '.':  # end - send our cached response, adding USER and SASL PLAIN if required
                has_sasl = False
                has_user = False
                for capa in self.capa:
                    capa_lower = capa.lower()
                    if capa_lower.startswith('sasl'):
                        super().process_data(b'SASL PLAIN\r\n')
                        has_sasl = True
                    else:
                        if capa_lower == 'user':
                            has_user = True
                        super().process_data(b'%s\r\n' % capa.encode('utf-8'))

                if not has_sasl:
                    super().process_data(b'SASL PLAIN\r\n')
                if not has_user:
                    super().process_data(b'USER\r\n')

                self.client_connection.connection_state = POPOAuth2ClientConnection.STATE.PENDING
                super().process_data(byte_data)

            else:
                self.capa.append(str_data)

        elif self.client_connection.connection_state is POPOAuth2ClientConnection.STATE.XOAUTH2_AWAITING_CONFIRMATION:
            if str_data.startswith('+') and self.username and self.password:  # '+ ' = 'please send credentials'
                success, result = OAuth2Helper.get_oauth2_credentials(self.username, self.password)
                if success:
                    self.client_connection.connection_state = POPOAuth2ClientConnection.STATE.XOAUTH2_CREDENTIALS_SENT
                    self.send(b'%s\r\n' % OAuth2Helper.encode_oauth2_string(result), censor_log=True)
                    self.authenticated_username = self.username

                self.username = None
                self.password = None
                if not success:
                    # a local authentication error occurred - send details to the client and exit
                    super().process_data(b'-ERR Authentication failed. %s\r\n' % result.encode('utf-8'))
                    self.close()

            else:
                super().process_data(byte_data)  # an error occurred - just send to the client and exit
                self.close()

        elif self.client_connection.connection_state is POPOAuth2ClientConnection.STATE.XOAUTH2_CREDENTIALS_SENT:
            if str_data.startswith('+OK'):
                Log.info(self.info_string(), '[ Successfully authenticated POP connection - removing proxy ]')
                self.client_connection.authenticated = True
                super().process_data(byte_data)
            else:
                super().process_data(byte_data)  # an error occurred - just send to the client and exit
                self.close()

        else:
            super().process_data(byte_data)  # a server->client interaction we don't handle; ignore


class SMTPOAuth2ServerConnection(OAuth2ServerConnection):
    """The SMTP server side - setup STARTTLS, request any credentials, then watch for 235 and ignore subsequent data"""

    # SMTP: https://tools.ietf.org/html/rfc2821
    # SMTP STARTTLS: https://tools.ietf.org/html/rfc3207
    # SMTP AUTH: https://tools.ietf.org/html/rfc4954
    # SMTP LOGIN: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
    class STARTTLS(enum.Enum):
        PENDING = 1
        NEGOTIATING = 2
        COMPLETE = 3

    def __init__(self, socket_map, server_address, connection_info, proxy_parent, custom_configuration):
        super().__init__('SMTP', socket_map, server_address, connection_info, proxy_parent, custom_configuration)
        self.ehlo = None
        if self.custom_configuration['starttls']:
            self.starttls_state = self.STARTTLS.PENDING
        else:
            self.starttls_state = self.STARTTLS.COMPLETE

        self.username = None
        self.password = None

    def process_data(self, byte_data):
        # SMTP setup/authentication involves a little more back-and-forth than IMAP/POP as the default is STARTTLS...
        str_data = byte_data.decode('utf-8', 'replace').rstrip('\r\n')

        # an EHLO request has been sent - wait for it to complete, then begin STARTTLS if required
        if self.client_connection.connection_state is SMTPOAuth2ClientConnection.STATE.EHLO_AWAITING_RESPONSE:
            # intercept EHLO response AUTH capabilities and replace with what we can actually do - note that we assume
            # an AUTH line will be included in the response; if there are any servers for which this is not the case, we
            # could cache and re-stream as in POP. Formal syntax: https://tools.ietf.org/html/rfc4954#section-8
            updated_response = re.sub(r'250([ -])AUTH( [!-*,-<>-~]+)+', '250\\1AUTH PLAIN LOGIN', str_data,
                                      flags=re.IGNORECASE)
            updated_response = b'%s\r\n' % updated_response.encode('utf-8')
            if self.starttls_state is self.STARTTLS.COMPLETE:
                super().process_data(updated_response)  # (we replay the EHLO command after STARTTLS for that situation)

            if str_data.startswith('250 '):  # space signifies final response to HELO (single line) or EHLO (multiline)
                self.client_connection.connection_state = SMTPOAuth2ClientConnection.STATE.PENDING
                if self.starttls_state is self.STARTTLS.PENDING:
                    self.send(b'STARTTLS\r\n')
                    self.starttls_state = self.STARTTLS.NEGOTIATING

        elif self.starttls_state is self.STARTTLS.NEGOTIATING:
            if str_data.startswith('220'):
                # noinspection PyTypeChecker
                ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                super().set_socket(ssl_context.wrap_socket(self.socket, server_hostname=self.server_address[0],
                                                           suppress_ragged_eofs=True, do_handshake_on_connect=False))
                self.set_ssl_connection(True)

                self.starttls_state = self.STARTTLS.COMPLETE
                Log.debug(self.info_string(), '[ Successfully negotiated SMTP STARTTLS connection -',
                          're-sending greeting ]')
                self.client_connection.connection_state = SMTPOAuth2ClientConnection.STATE.EHLO_AWAITING_RESPONSE
                self.send(self.ehlo)  # re-send original EHLO/HELO to server (includes domain, so can't just be generic)
            else:
                super().process_data(byte_data)  # an error occurred - just send to the client and exit
                self.close()

        # ...then, once we have the username and password we can respond to the '334 ' response with credentials
        elif self.client_connection.connection_state is SMTPOAuth2ClientConnection.STATE.XOAUTH2_AWAITING_CONFIRMATION:
            if str_data.startswith('334') and self.username and self.password:  # '334 ' = 'please send credentials'
                success, result = OAuth2Helper.get_oauth2_credentials(self.username, self.password)
                if success:
                    self.client_connection.connection_state = SMTPOAuth2ClientConnection.STATE.XOAUTH2_CREDENTIALS_SENT
                    self.authenticated_username = self.username
                    self.send(OAuth2Helper.encode_oauth2_string(result), censor_log=True)
                    self.send(b'\r\n')

                self.username = None
                self.password = None
                if not success:
                    # a local authentication error occurred - send details to the client and exit
                    super().process_data(
                        b'535 5.7.8  Authentication credentials invalid. %s\r\n' % result.encode('utf-8'))
                    self.close()

            else:
                super().process_data(byte_data)  # an error occurred - just send to the client and exit
                self.close()

        elif self.client_connection.connection_state is SMTPOAuth2ClientConnection.STATE.XOAUTH2_CREDENTIALS_SENT:
            if str_data.startswith('235'):
                Log.info(self.info_string(), '[ Successfully authenticated SMTP connection - removing proxy ]')
                self.client_connection.authenticated = True
                super().process_data(byte_data)
            else:
                super().process_data(byte_data)  # an error occurred - just send to the client and exit
                self.close()

        else:
            super().process_data(byte_data)  # a server->client interaction we don't handle; ignore


class OAuth2Proxy(asyncore.dispatcher):
    """Listen on local_address, creating an OAuth2ServerConnection + OAuth2ClientConnection for each new connection"""

    def __init__(self, proxy_type, local_address, server_address, custom_configuration):
        asyncore.dispatcher.__init__(self)
        self.proxy_type = proxy_type
        self.local_address = local_address
        self.server_address = server_address
        self.custom_configuration = custom_configuration
        self.ssl_connection = custom_configuration['local_certificate_path'] and custom_configuration['local_key_path']
        self.client_connections = []

    def info_string(self):
        return '%s server at %s:%d (%s) proxying %s:%d (%s)' % (
            self.proxy_type, self.local_address[0], self.local_address[1],
            'TLS' if self.ssl_connection else 'unsecured',
            self.server_address[0], self.server_address[1],
            'STARTTLS' if self.custom_configuration['starttls'] else 'SSL/TLS')

    def handle_accept(self):
        Log.debug('New incoming connection to', self.info_string())
        connected_address = self.accept()
        if connected_address:
            self.handle_accepted(*connected_address)
        else:
            Log.debug('Ignoring incoming connection to', self.info_string(), '- no connection information')

    def handle_accepted(self, connection, address):
        if MAX_CONNECTIONS <= 0 or len(self.client_connections) < MAX_CONNECTIONS:
            new_server_connection = None
            try:
                Log.debug('Accepting new connection to', self.info_string(), 'via', connection.getpeername())
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
                                 name='EmailOAuth2Proxy-connection-%d' % address[1], daemon=True).start()

            except ssl.SSLError:
                error_text = '%s encountered an SSL error - is the server\'s starttls setting correct? Current ' \
                             'value: %s' % (self.info_string(), self.custom_configuration['starttls'])
                Log.error(error_text)
                if sys.platform in ['darwin', 'win32']:
                    Log.error('If you encounter this error repeatedly, please check that you have correctly configured '
                              'python root certificates; see: https://github.com/simonrob/email-oauth2-proxy/issues/14')
                connection.send(b'%s\r\n' % self.bye_message(error_text).encode('utf-8'))
                connection.close()

            except Exception:
                connection.close()
                if new_server_connection:
                    new_server_connection.handle_close()
                raise
        else:
            error_text = '%s rejecting new connection above MAX_CONNECTIONS limit of %d' % (
                self.info_string(), MAX_CONNECTIONS)
            Log.error(error_text)
            connection.send(b'%s\r\n' % self.bye_message(error_text).encode('utf-8'))
            connection.close()

    @staticmethod
    def run_server(client, socket_map, address):
        try:
            asyncore.loop(map=socket_map)  # loop for a single connection thread
        except Exception as e:
            if not EXITING:
                # OSError 9 = 'Bad file descriptor', thrown when closing connections after network interruption
                if isinstance(e, OSError) and e.errno == errno.EBADF:
                    Log.debug(client.proxy_type, address, '[ Connection closed ]')
                else:
                    Log.info('Caught asyncore exception in', client.proxy_type, address, 'thread loop:',
                             Log.error_string(e))

    def start(self):
        Log.info('Starting', self.info_string())
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(self.local_address)
        self.listen(5)

    def create_socket(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM):
        if self.ssl_connection:
            new_socket = socket.socket(socket_family, socket_type)
            new_socket.setblocking(False)

            # noinspection PyTypeChecker
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=self.custom_configuration['local_certificate_path'],
                                        keyfile=self.custom_configuration['local_key_path'])

            # suppress_ragged_eofs=True: see test_ssl.py documentation in https://github.com/python/cpython/pull/5266
            self.set_socket(ssl_context.wrap_socket(new_socket, server_side=True, suppress_ragged_eofs=True,
                                                    do_handshake_on_connect=False))
        else:
            super().create_socket(socket_family, socket_type)

    def remove_client(self, client):
        if client in self.client_connections:  # remove closed clients
            self.client_connections.remove(client)
        else:
            Log.info('Warning:', self.info_string(), 'unable to remove orphan client connection', client)

    def bye_message(self, error_text=None):
        if self.proxy_type == 'IMAP':
            return '* BYE %s' % ('Server shutting down' if error_text is None else error_text)
        elif self.proxy_type == 'POP':
            return '+OK Server signing off' if error_text is None else ('-ERR %s' % error_text)
        elif self.proxy_type == 'SMTP':
            return '221 %s' % ('2.0.0 Service closing transmission channel' if error_text is None else error_text)
        else:
            return ''

    def close_clients(self):
        for connection in self.client_connections[:]:  # iterate over a copy; remove (in close()) from original
            connection.send(b'%s\r\n' % self.bye_message().encode('utf-8'))  # try to exit gracefully
            connection.close()  # closes both client and server

    def stop(self):
        Log.info('Stopping', self.info_string())
        self.close_clients()
        self.close()

    def restart(self):
        self.stop()
        self.start()

    def handle_error(self):
        error_type, value, _traceback = sys.exc_info()
        del _traceback  # used to be required in python 2; may no-longer be needed, but best to be safe
        if error_type == socket.gaierror and value.errno in [8, 11001] or \
                error_type == TimeoutError and value.errno == errno.ETIMEDOUT or \
                error_type == ConnectionResetError and value.errno == errno.ECONNRESET or \
                error_type == ConnectionRefusedError and value.errno == errno.ECONNREFUSED or \
                error_type == OSError and value.errno in [0, errno.EINVAL, errno.ENETDOWN, errno.EHOSTUNREACH]:
            # gaierror 8 = 'nodename nor servname provided, or not known'; gaierror 11001 = 'getaddrinfo failed'
            # (caused by getpeername() failing due to no network connection); TimeoutError 60 = 'Operation timed out';
            # ConnectionResetError 54 = 'Connection reset by peer';  ConnectionRefusedError 61 = 'Connection refused';
            # OSError 0 = 'Error' (local SSL failure); OSError 22 = 'Invalid argument' (same cause as gaierror 11001);
            # OSError 50 = 'Network is down'; OSError 65 = 'No route to host'
            Log.info('Caught network error in', self.info_string(), '- is there a network connection?',
                     'Error type', error_type, 'with message:', value)
        else:
            super().handle_error()

    def log_info(self, message, message_type='info'):
        # override to redirect error messages to our own log
        if message_type not in self.ignore_log_types:
            Log.info('Caught asyncore info message in', self.info_string(), '-', message_type, ':', message)

    def handle_close(self):
        # if we encounter an unhandled exception in asyncore, handle_close() is called; restart this server
        Log.info('Unexpected close of proxy connection - restarting', self.info_string())
        try:
            self.restart()
        except Exception as e:
            Log.error('Abandoning restart of', self.info_string(), 'due to repeated exception:', Log.error_string(e))


if sys.platform == 'darwin':
    # noinspection PyUnresolvedReferences,PyMethodMayBeStatic,PyPep8Naming,PyUnusedLocal
    class ProvisionalNavigationBrowserDelegate:
        """Used to give pywebview the ability to navigate to unresolved local URLs (only required for macOS)"""

        # note: there is also webView_didFailProvisionalNavigation_withError_ as a broader alternative to these two
        # callbacks, but using that means that window.get_current_url() returns None when the loaded handler is called
        def webView_didStartProvisionalNavigation_(self, web_view, nav):
            # called when a user action (i.e., clicking our external authorisation mode submit button) redirects locally
            browser_view_instance = webview.platforms.cocoa.BrowserView.get_instance('webkit', web_view)
            if browser_view_instance:
                browser_view_instance.loaded.set()

        def webView_didReceiveServerRedirectForProvisionalNavigation_(self, web_view, nav):
            # called when the server initiates a local redirect
            browser_view_instance = webview.platforms.cocoa.BrowserView.get_instance('webkit', web_view)
            if browser_view_instance:
                browser_view_instance.loaded.set()

if sys.platform == 'darwin':
    # noinspection PyUnresolvedReferences,PyProtectedMember
    class RetinaIcon(pystray.Icon):
        """Used to dynamically override the default pystray behaviour on macOS to support high-dpi ('retina') icons and
        regeneration of the last activity time for each account every time the icon is clicked"""

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

        # noinspection PyUnresolvedReferences
        class MenuDelegate(AppKit.NSObject):
            # noinspection PyMethodMayBeStatic,PyProtectedMember,PyPep8Naming
            def menuNeedsUpdate_(self, sender):
                # update account menu items' last activity times from config cache - it would be better to delegate this
                # entirely to App.create_config_menu() via update_menu(), but can't replace the menu while creating it
                config_accounts = AppConfig.accounts()
                menu_items = sender._itemArray()
                for item in menu_items:
                    for account in config_accounts:
                        account_title = '    %s (' % account  # needed to avoid matching authentication menu
                        if account_title in item.title():
                            item.setTitle_(App.get_last_activity(account))
                            break

        def _assert_image(self):
            # pystray does some scaling which breaks macOS retina icons - we replace that with the actual menu bar size
            bytes_image = io.BytesIO()
            self.icon.save(bytes_image, 'png')
            data = AppKit.NSData(bytes_image.getvalue())
            self._icon_image = AppKit.NSImage.alloc().initWithData_(data)

            thickness = self._status_bar.thickness()  # macOS menu bar size: default = 22px, but can be scaled
            self._icon_image.setSize_((int(thickness), int(thickness)))
            self._icon_image.setTemplate_(AppKit.YES)  # so macOS applies default shading + inverse on click
            self._status_item.button().setImage_(self._icon_image)


class App:
    """Manage the menu bar icon, server loading, authorisation and notifications, and start the main proxy thread"""

    def __init__(self):
        Log.initialise()

        global CONFIG_FILE_PATH
        parser = argparse.ArgumentParser(description=APP_NAME)
        parser.add_argument('--external-auth', action='store_true', help='handle authorisation via an external browser '
                                                                         'rather than this script\'s own popup window')
        parser.add_argument('--no-gui', action='store_true', help='start the proxy without a menu bar icon (note: '
                                                                  'account authorisation requests will fail unless a '
                                                                  'pre-authorised configuration file is used, or you '
                                                                  'enable `--local-server-auth` and monitor output)')
        parser.add_argument('--local-server-auth', action='store_true', help='handle authorisation by printing request '
                                                                             'URLs to the log and starting a local web '
                                                                             'server on demand to receive responses')
        parser.add_argument('--config-file', default=None, help='the full path to the proxy\'s configuration file '
                                                                '(optional; default: `%s` in the same directory as the '
                                                                'proxy script)' % os.path.basename(CONFIG_FILE_PATH))
        parser.add_argument('--debug', action='store_true', help='enable debug mode, printing client<->proxy<->server '
                                                                 'interaction to the system log')
        self.args = parser.parse_args()
        if self.args.debug:
            Log.set_level(logging.DEBUG)

        if self.args.config_file:
            CONFIG_FILE_PATH = self.args.config_file
        Log.info('Initialising', APP_NAME, 'from config file', CONFIG_FILE_PATH)

        self.proxies = []
        self.authorisation_requests = []

        self.web_view_started = False

        self.init_platforms()

        if self.args.no_gui:
            self.icon = None
            self.post_create(None)
        else:
            self.icon = self.create_icon()
            try:
                self.icon.run(self.post_create)
            except NotImplementedError:
                Log.error('Unable to initialise icon - did you mean to run in --no-gui mode?')
                self.exit(None)
                # noinspection PyProtectedMember
                self.icon._Icon__queue.put(False)  # pystray sets up the icon thread even in dummy mode; need to exit

    # PyAttributeOutsideInit inspection suppressed because init_platforms() is itself called from __init__()
    # noinspection PyUnresolvedReferences,PyAttributeOutsideInit
    def init_platforms(self):
        if sys.platform == 'darwin' and not self.args.no_gui:
            # hide dock icon (but not LSBackgroundOnly as we need input via webview)
            info = AppKit.NSBundle.mainBundle().infoDictionary()
            info['LSUIElement'] = '1'

            # any launchctl plist changes need reloading, but this must be scheduled on exit (see discussion below)
            self.macos_unload_plist_on_exit = False

            # track shutdown and network loss events and exit or close proxy connections appropriately
            # note: no need to explicitly remove this observer after OS X 10.11 (https://developer.apple.com/library
            # /archive/releasenotes/Foundation/RN-FoundationOlderNotes/index.html#10_11NotificationCenter)
            notification_listener = 'macos_nsworkspace_notification_listener:'
            notification_centre = AppKit.NSWorkspace.sharedWorkspace().notificationCenter()
            notification_centre.addObserver_selector_name_object_(self, notification_listener,
                                                                  AppKit.NSWorkspaceWillPowerOffNotification, None)
            notification_centre.addObserver_selector_name_object_(self, notification_listener,
                                                                  SystemConfiguration.SCNetworkReachabilityRef, None)

            # we use a zero/blank address because we only care about general availability rather than a specific host
            # see reachabilityForInternetConnection: https://developer.apple.com/library/archive/samplecode/Reachability
            # use of SCNetworkReachabilityRef is a little hacky (requires a callback name) but it works
            address = ('', 0)
            post_reachability_update = notification_centre.postNotificationName_object_
            self.macos_reachability_target = SystemConfiguration.SCNetworkReachabilityCreateWithAddress(None, address)
            SystemConfiguration.SCNetworkReachabilitySetCallback(self.macos_reachability_target,
                                                                 lambda _target, flags, _info: post_reachability_update(
                                                                     SystemConfiguration.SCNetworkReachabilityRef,
                                                                     flags), address)
            success, result = SystemConfiguration.SCNetworkReachabilityGetFlags(self.macos_reachability_target, None)
            if success:
                post_reachability_update(SystemConfiguration.SCNetworkReachabilityRef, result)  # update initial state
            SystemConfiguration.SCNetworkReachabilityScheduleWithRunLoop(self.macos_reachability_target,
                                                                         SystemConfiguration.CFRunLoopGetCurrent(),
                                                                         SystemConfiguration.kCFRunLoopCommonModes)

            # on macOS, catching SIGINT/SIGTERM/SIGQUIT while in pystray's main loop needs a Mach signal handler
            PyObjCTools.MachSignals.signal(signal.SIGINT, lambda signum: self.exit(self.icon))
            PyObjCTools.MachSignals.signal(signal.SIGTERM, lambda signum: self.exit(self.icon))
            PyObjCTools.MachSignals.signal(signal.SIGQUIT, lambda signum: self.exit(self.icon))

        else:
            # for other platforms, or in no-GUI mode, just try to exit gracefully if SIGINT/SIGTERM/SIGQUIT is received
            signal.signal(signal.SIGINT, lambda signum, frame: self.exit(self.icon))
            signal.signal(signal.SIGTERM, lambda signum, frame: self.exit(self.icon))
            if hasattr(signal, 'SIGQUIT'):  # SIGQUIT does not exist on all platforms (e.g., Windows)
                signal.signal(signal.SIGQUIT, lambda signum, frame: self.exit(self.icon))

    # noinspection PyUnresolvedReferences,PyAttributeOutsideInit
    def macos_nsworkspace_notification_listener_(self, notification):
        notification_name = notification.name()
        if notification_name == SystemConfiguration.SCNetworkReachabilityRef:
            flags = notification.object()
            if flags & SystemConfiguration.kSCNetworkReachabilityFlagsReachable == 0:
                Log.info('Received network unreachable notification - closing existing proxy connections')
                for proxy in self.proxies:
                    proxy.close_clients()
            else:
                Log.debug('Received network reachable notification - status:', flags)
        elif notification_name == AppKit.NSWorkspaceWillPowerOffNotification:
            Log.info('Received power off notification; exiting', APP_NAME)
            self.exit(self.icon)

    def create_icon(self):
        icon_class = RetinaIcon if sys.platform == 'darwin' else pystray.Icon
        return icon_class(APP_NAME, App.get_image(), APP_NAME, menu=pystray.Menu(
            pystray.MenuItem('Servers and accounts', pystray.Menu(self.create_config_menu)),
            pystray.MenuItem('Authorise account', pystray.Menu(self.create_authorisation_menu)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Start at login', self.toggle_start_at_login, checked=self.started_at_login),
            pystray.MenuItem('Debug mode', self.toggle_debug, checked=lambda _: Log.get_level() == logging.DEBUG),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quit %s' % APP_NAME, self.exit)))

    @staticmethod
    def get_image():
        # we use an icon font for better multiplatform compatibility and icon size flexibility
        icon_colour = 'white'  # note: value is irrelevant on macOS - we set as a template to get the platform's colours
        icon_character = 'e'
        icon_background_width = 44
        icon_background_height = 44
        icon_width = 40  # to allow for padding between icon and background image size

        # find the largest font size that will let us draw the icon within the available width
        minimum_font_size = 1
        maximum_font_size = 255
        font, font_width, font_height = App.get_icon_size(icon_character, minimum_font_size)
        while maximum_font_size - minimum_font_size > 1:
            current_font_size = round((minimum_font_size + maximum_font_size) / 2)  # ImageFont only supports integers
            font, font_width, font_height = App.get_icon_size(icon_character, current_font_size)
            if font_width > icon_width:
                maximum_font_size = current_font_size
            elif font_width < icon_width:
                minimum_font_size = current_font_size
            else:
                break
        if font_width > icon_width:  # because we have to round font sizes we need one final check for oversize width
            font, font_width, font_height = App.get_icon_size(icon_character, minimum_font_size)

        icon_image = Image.new('RGBA', (icon_background_width, icon_background_height))
        draw = ImageDraw.Draw(icon_image)
        icon_x = (icon_background_width - font_width) / 2
        icon_y = (icon_background_height - font_height) / 2
        draw.text((icon_x, icon_y), icon_character, font=font, fill=icon_colour)

        return icon_image

    @staticmethod
    def get_icon_size(text, font_size):
        font = ImageFont.truetype(io.BytesIO(zlib.decompress(base64.b64decode(APP_ICON))), size=font_size)

        # pillow's getsize method was deprecated in 9.2.0 (see docs for PIL.ImageFont.ImageFont.getsize)
        if pkg_resources.parse_version(
                pkg_resources.get_distribution('pillow').version) < pkg_resources.parse_version('9.2.0'):
            font_width, font_height = font.getsize(text)
            return font, font_width, font_height
        else:
            left, top, right, bottom = font.getbbox(text)
            return font, right, bottom

    def create_config_menu(self):
        items = [pystray.MenuItem('Servers:', None, enabled=False)]
        if len(self.proxies) <= 0:
            items.append(pystray.MenuItem('    No servers configured', None, enabled=False))
        else:
            for proxy in self.proxies:
                items.append(pystray.MenuItem('    %s:%d ➝ %s:%d' % (proxy.local_address[0], proxy.local_address[1],
                                                                     proxy.server_address[0], proxy.server_address[1]),
                                              None, enabled=False))
        items.append(pystray.Menu.SEPARATOR)

        config_accounts = AppConfig.accounts()
        items.append(pystray.MenuItem('Accounts (+ last authenticated activity):', None, enabled=False))
        if len(config_accounts) <= 0:
            items.append(pystray.MenuItem('    No accounts configured', None, enabled=False))
        else:
            for account in config_accounts:
                items.append(pystray.MenuItem(App.get_last_activity(account), None, enabled=False))
            if not sys.platform == 'darwin':
                items.append(pystray.MenuItem('    Refresh activity data', self.icon.update_menu))
        items.append(pystray.Menu.SEPARATOR)

        items.append(pystray.MenuItem('Edit configuration file...', self.edit_config))

        # asyncore sockets on Linux have a shutdown delay (the time.sleep() call in asyncore.poll), which means we can't
        # easily reload the server configuration without exiting the script and relying on daemon threads to be stopped
        items.append(pystray.MenuItem('Reload configuration file', self.linux_restart if sys.platform.startswith(
            'linux') else self.load_and_start_servers))
        return items

    @staticmethod
    def get_last_activity(account):
        config = AppConfig.get()
        last_sync = config.getint(account, 'last_activity', fallback=None)
        if last_sync:
            formatted_sync_time = timeago.format(datetime.datetime.fromtimestamp(last_sync), datetime.datetime.now(),
                                                 'en_short')
        else:
            formatted_sync_time = 'never'
        return '    %s (%s)' % (account, formatted_sync_time)

    @staticmethod
    def edit_config():
        AppConfig.save()  # so we are always editing the most recent version of the file
        if sys.platform == 'darwin':
            result = os.system('open %s' % CONFIG_FILE_PATH)
            if result != 0:  # no default editor found for this file type; open as a text file
                os.system('open -t %s' % CONFIG_FILE_PATH)
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
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem('External authorisation mode', self.toggle_external_auth,
                                      checked=lambda _: self.args.external_auth))
        return items

    def toggle_external_auth(self):
        self.args.external_auth = not self.args.external_auth
        if self.started_at_login(None):
            self.toggle_start_at_login(self.icon, True)  # update launch command to preserve external auth preference

    def authorise_account(self, _, item):
        for request in self.authorisation_requests:
            if str(item) == request['username']:  # use str(item) because item.text() hangs
                if not self.web_view_started:
                    # pywebview on macOS needs start() to be called only once, so we use a dummy window to keep it open
                    # Windows is the opposite - the macOS technique freezes the tray icon; Linux is fine either way
                    # (we also set pywebview debug mode to match our own mode because copy/paste via keyboard shortcuts
                    # can be unreliable with 'mshtml'; and, python virtual environments sometimes break keyboard entry
                    # entirely on macOS - debug mode works around this in both cases via the right-click context menu)
                    self.create_authorisation_window(request)
                    if sys.platform == 'darwin':
                        webview.start(self.handle_authorisation_windows, debug=Log.get_level() == logging.DEBUG)
                        self.web_view_started = True  # note: not set for other platforms so we start() every time
                    else:
                        # on Windows, most pywebview engine options return None for get_current_url() on pages created
                        # using 'html=' even on redirection to an actual URL; 'mshtml', though archaic, does work
                        forced_gui = 'mshtml' if sys.platform == 'win32' and self.args.external_auth else None
                        webview.start(gui=forced_gui, debug=Log.get_level() == logging.DEBUG)
                else:
                    WEBVIEW_QUEUE.put(request)  # future requests need to use the same thread
                return
        self.notify(APP_NAME, 'There are no pending authorisation requests')

    def create_authorisation_window(self, request):
        # note that the webview title *must* end with a space and then the email address/username
        window_title = 'Authorise your account: %s' % request['username']
        if self.args.external_auth:
            auth_page = EXTERNAL_AUTH_HTML % (request['username'], request['permission_url'], request['permission_url'],
                                              request['permission_url'], APP_NAME, request['redirect_uri'])
            authorisation_window = webview.create_window(window_title, html=auth_page, on_top=True, text_select=True)
        else:
            authorisation_window = webview.create_window(window_title, request['permission_url'], on_top=True)
        setattr(authorisation_window, 'get_title', lambda window: window.title)  # add missing get_title method

        # pywebview 3.6+ moved window events to a separate namespace in a non-backwards-compatible way
        if pkg_resources.parse_version(
                pkg_resources.get_distribution('pywebview').version) < pkg_resources.parse_version('3.6'):
            authorisation_window.loaded += self.authorisation_window_loaded
        else:
            authorisation_window.events.loaded += self.authorisation_window_loaded

    def handle_authorisation_windows(self):
        if not sys.platform == 'darwin':
            return

        # on macOS we need to add extra webview functions to detect when redirection starts, because otherwise the
        # pywebview window can get into a state in which http://localhost navigation, rather than failing, just hangs
        # noinspection PyPackageRequirements
        import webview.platforms.cocoa
        setattr(webview.platforms.cocoa.BrowserView.BrowserDelegate, 'webView_didStartProvisionalNavigation_',
                ProvisionalNavigationBrowserDelegate.webView_didStartProvisionalNavigation_)
        setattr(webview.platforms.cocoa.BrowserView.BrowserDelegate, 'webView_didReceiveServerRedirectForProvisional'
                                                                     'Navigation_',
                ProvisionalNavigationBrowserDelegate.webView_didReceiveServerRedirectForProvisionalNavigation_)

        # also needed only on macOS because otherwise closing the last remaining webview window exits the application
        dummy_window = webview.create_window('%s hidden (dummy) window' % APP_NAME, html='<html></html>', hidden=True)
        dummy_window.hide()  # hidden=True (above) doesn't seem to work in all cases

        while True:
            data = WEBVIEW_QUEUE.get()  # note: blocking call
            if data is QUEUE_SENTINEL:  # app is closing
                break
            else:
                self.create_authorisation_window(data)

    def authorisation_window_loaded(self):
        for window in webview.windows[:]:  # iterate over a copy; remove (in destroy()) from original
            if not hasattr(window, 'get_title'):
                continue  # skip dummy window

            url = window.get_current_url()
            username = window.get_title(window).split(' ')[-1]  # see note above: title *must* match this format
            if not url or not username:
                continue  # skip any invalid windows

            # respond to both the original request and any duplicates in the list
            completed_request = None
            for request in self.authorisation_requests[:]:  # iterate over a copy; remove from original
                if url.startswith(request['redirect_uri']) and username == request['username']:
                    Log.info('Successfully authorised request for', request['username'])
                    RESPONSE_QUEUE.put(
                        {'permission_url': request['permission_url'], 'response_url': url, 'username': username})
                    self.authorisation_requests.remove(request)
                    completed_request = request
                else:
                    Log.debug('Waiting for URL matching `redirect_uri`; following browser redirection to',
                              '%s/[...]' % urllib.parse.urlparse(url).hostname)

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

    def toggle_start_at_login(self, icon, force_rewrite=False):
        # we reuse this function to force-overwrite the startup file when changing the external auth option, but pystray
        # verifies actions have a maximum of two parameters (_assert_action()), so we must use 'item' and check its type
        recreate_login_file = False if isinstance(force_rewrite, pystray.MenuItem) else force_rewrite

        start_command = self.get_script_start_command()

        if sys.platform == 'darwin':
            if recreate_login_file or not PLIST_FILE_PATH.exists():
                # need to create and load the plist
                plist = {
                    'Label': APP_PACKAGE,
                    'RunAtLoad': True
                }
            else:
                # just toggle the disabled value rather than loading/unloading, so we don't need to restart the proxy
                with open(PLIST_FILE_PATH, 'rb') as plist_file:
                    plist = plistlib.load(plist_file)
                plist['Disabled'] = True if 'Disabled' not in plist else not plist['Disabled']

            plist['Program'] = start_command[0]
            plist['ProgramArguments'] = start_command

            os.makedirs(PLIST_FILE_PATH.parent, exist_ok=True)
            with open(PLIST_FILE_PATH, 'wb') as plist_file:
                plistlib.dump(plist, plist_file)

            # if loading, need to exit so we're not running twice (also exits the terminal instance for convenience)
            if not self.macos_launchctl('list'):
                self.exit(icon, restart_callback=self.macos_launchctl('load'))
            elif recreate_login_file:
                # Launch Agents need to be unloaded and reloaded to reflect changes in their plist file, but we can't
                # do this ourselves because 1) unloading exits the agent; and, 2) we can't launch a completely separate
                # subprocess (see man launchd.plist) - instead, we schedule the unload action when we next exit, because
                # this is likely to be caused by a system restart, and unloaded Launch Agents still run at startup (only
                # an issue if calling `launchctl start` after exiting, which will error until the Agent is reloaded)
                # noinspection PyAttributeOutsideInit
                self.macos_unload_plist_on_exit = True
                Log.info('Updating', PLIST_FILE_PATH, 'requires unloading and reloading; scheduling on next exit')

        elif sys.platform == 'win32':
            if recreate_login_file or not CMD_FILE_PATH.exists():
                windows_start_command = 'start %s' % ' '.join(start_command)

                os.makedirs(CMD_FILE_PATH.parent, exist_ok=True)
                with open(CMD_FILE_PATH, 'w') as cmd_file:
                    cmd_file.write(windows_start_command)

                # on Windows we don't have a service to run, but it is still useful to exit the terminal instance
                if sys.stdin.isatty() and not recreate_login_file:
                    self.exit(icon, restart_callback=lambda: subprocess.call(windows_start_command, shell=True))
            else:
                os.remove(CMD_FILE_PATH)

        elif sys.platform.startswith('linux'):
            # see https://github.com/simonrob/email-oauth2-proxy/issues/2#issuecomment-839713677 for systemctl option
            if recreate_login_file or not AUTOSTART_FILE_PATH.exists():
                xdg_autostart = {
                    'Type': 'Application',
                    'Name': APP_NAME,
                    'Exec': ' '.join(start_command),
                    'NoDisplay': 'true'
                }

                os.makedirs(AUTOSTART_FILE_PATH.parent, exist_ok=True)
                with open(AUTOSTART_FILE_PATH, 'w') as desktop_file:
                    desktop_file.write('[Desktop Entry]\n')
                    for key, value in xdg_autostart.items():
                        desktop_file.write('%s=%s\n' % (key, value))

                # like on Windows we don't have a service to run, but it is still useful to exit the terminal instance
                if sys.stdin.isatty() and not recreate_login_file:
                    AppConfig.save()  # because linux_restart needs to unload to prevent saving on exit
                    self.linux_restart(icon)
            else:
                os.remove(AUTOSTART_FILE_PATH)

        else:
            pass  # nothing we can do

    def get_script_start_command(self):
        python_command = sys.executable
        if sys.platform == 'win32':
            # pythonw to avoid a terminal when background launching on Windows
            python_command = 'pythonw.exe'.join(python_command.rsplit('python.exe', 1))

        # preserve selected options if starting automatically (note: could do the same for --debug but that is unlikely
        # to be useful; similarly for --no-gui, but that makes no sense as the GUI is needed for this interaction)
        script_command = [python_command, os.path.realpath(__file__)]
        if self.args.external_auth:
            script_command.append('--external-auth')
        if self.args.local_server_auth:
            script_command.append('--local-server-auth')
        if self.args.config_file:
            script_command.append('--config-file')
            script_command.append(CONFIG_FILE_PATH)

        return script_command

    def linux_restart(self, icon):
        # Linux restarting is separate because it is used for reloading the configuration file as well as start at login
        AppConfig.unload()  # so that we don't overwrite the just-updated file when exiting
        command = ' '.join(self.get_script_start_command())
        self.exit(icon, restart_callback=lambda: subprocess.call('nohup %s </dev/null >/dev/null 2>&1 &' % command,
                                                                 shell=True))

    @staticmethod
    def macos_launchctl(command='list'):
        # this used to use the python launchctl package, but it has a bug (github.com/andrewp-as-is/values.py/pull/2)
        # in a sub-package, so we reproduce just the core features - supported commands are 'list', 'load' and 'unload'
        proxy_command = APP_PACKAGE if command == 'list' else PLIST_FILE_PATH
        try:
            output = subprocess.check_output(['/bin/launchctl', command, proxy_command], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            return False
        else:
            if output and command != 'list':
                return False  # load/unload gives no output unless unsuccessful (return code is always 0 regardless)
            return True

    @staticmethod
    def started_at_login(_):
        # note: menu state will be stale if changed externally, but clicking menu items forces a refresh
        if sys.platform == 'darwin':
            if PLIST_FILE_PATH.exists():
                if App.macos_launchctl('list'):
                    with open(PLIST_FILE_PATH, 'rb') as plist_file:
                        plist = plistlib.load(plist_file)
                    if 'Disabled' in plist:
                        return not plist['Disabled']
                    return True  # job is loaded and is not disabled

        elif sys.platform == 'win32':
            return CMD_FILE_PATH.exists()  # we assume that the file's contents are correct

        elif sys.platform.startswith('linux'):
            return AUTOSTART_FILE_PATH.exists()  # we assume that the file's contents are correct

        return False

    @staticmethod
    def toggle_debug(_, item):
        Log.set_level(logging.INFO if item.checked else logging.DEBUG)

    # noinspection PyUnresolvedReferences
    def notify(self, title, text):
        if self.icon:
            if sys.platform == 'darwin':  # prefer native notifications over the osascript approach
                user_notification = AppKit.NSUserNotification.alloc().init()
                user_notification.setTitle_(title)
                user_notification.setInformativeText_(text)
                notification_centre = AppKit.NSUserNotificationCenter.defaultUserNotificationCenter()

                # noinspection PyBroadException
                try:
                    notification_centre.deliverNotification_(user_notification)
                except Exception:
                    for replacement in (('\\', '\\\\'), ('"', '\\"')):  # osascript approach requires sanitisation
                        text = text.replace(*replacement)
                        title = title.replace(*replacement)
                    os.system('osascript -e \'display notification "%s" with title "%s"\'' % (text, title))

            elif self.icon.HAS_NOTIFICATION:
                self.icon.remove_notification()
                self.icon.notify('%s: %s' % (title, text))

            else:
                Log.info(title, text)  # last resort
        else:
            Log.info(title, text)

    def stop_servers(self):
        global RESPONSE_QUEUE
        RESPONSE_QUEUE.put(QUEUE_SENTINEL)
        RESPONSE_QUEUE = queue.Queue()  # recreate so existing queue closes watchers but we don't have to wait here
        while True:
            try:
                REQUEST_QUEUE.get(block=False)  # remove any pending requests (unlikely any exist, but safest)
            except queue.Empty:
                break
        for proxy in self.proxies:
            # noinspection PyBroadException
            try:
                proxy.stop()
            except Exception:
                pass
        self.proxies = []
        self.authorisation_requests = []  # these requests are no-longer valid

    def load_and_start_servers(self, icon=None, reload=True):
        # we allow reloading, so must first stop any existing servers
        self.stop_servers()
        config = AppConfig.reload() if reload else AppConfig.get()

        # load server types and configurations
        server_load_error = False
        server_start_error = False
        for section in AppConfig.servers():
            match = CONFIG_SERVER_MATCHER.match(section)
            server_type = match.group('type')

            local_address = config.get(section, 'local_address', fallback='localhost')
            str_local_port = match.group('port')
            local_port = -1
            try:
                local_port = int(str_local_port)
                if local_port <= 0 or local_port > 65535:
                    raise ValueError
            except ValueError:
                Log.error('Error: invalid value', str_local_port, 'for local server port in section', match.string)
                server_load_error = True

            server_address = config.get(section, 'server_address', fallback=None)
            server_port = config.getint(section, 'server_port', fallback=-1)
            if server_port <= 0 or server_port > 65535:
                Log.error('Error: invalid value', server_port, 'for remote server port in section', match.string)
                server_load_error = True

            custom_configuration = {
                'starttls': config.getboolean(section, 'starttls', fallback=False) if server_type == 'SMTP' else False,
                'local_certificate_path': config.get(section, 'local_certificate_path', fallback=None),
                'local_key_path': config.get(section, 'local_key_path', fallback=None)
            }

            if not server_address:  # all other values are checked, regex matched or have a fallback above
                Log.error('Error: remote server address is missing in section', match.string)
                server_load_error = True

            if not server_load_error:
                new_proxy = OAuth2Proxy(server_type, (local_address, local_port), (server_address, server_port),
                                        custom_configuration)
                try:
                    new_proxy.start()
                    self.proxies.append(new_proxy)
                except Exception as e:
                    Log.error('Error: unable to start server:', Log.error_string(e))
                    server_start_error = True

        if server_start_error or server_load_error or len(self.proxies) <= 0:
            if server_start_error:
                Log.error('Abandoning setup as one or more servers failed to start - is the proxy already running?')
            else:
                error_text = 'Invalid' if len(AppConfig.servers()) > 0 else 'No'
                Log.error(error_text, 'server configuration(s) found in', CONFIG_FILE_PATH, '- exiting')
                self.notify(APP_NAME, error_text + ' server configuration(s) found. ' +
                            'Please verify your account and server details in %s' % CONFIG_FILE_PATH)
            AppConfig.unload()  # so we don't overwrite the invalid file with a blank configuration
            self.exit(icon)
            return False

        if icon:
            icon.update_menu()  # force refresh the menu to show running proxy servers

        threading.Thread(target=self.run_proxy, name='EmailOAuth2Proxy-main', daemon=True).start()
        return True

    def post_create(self, icon):
        if EXITING:
            return  # to handle launch in pystray 'dummy' mode without --no-gui option (partial initialisation failure)

        if icon:
            icon.visible = True

        if not self.load_and_start_servers(icon, reload=False):
            return

        Log.info('Initialised', APP_NAME, '- listening for authentication requests')
        while True:
            data = REQUEST_QUEUE.get()  # note: blocking call
            if data is QUEUE_SENTINEL:  # app is closing
                break
            else:
                if not data['expired']:
                    Log.info('Authorisation request received for', data['username'],
                             '(local server auth mode)' if self.args.local_server_auth else '(interactive mode)')
                    if self.args.local_server_auth:
                        data['local_server_auth'] = True
                        RESPONSE_QUEUE.put(data)  # local server auth is handled by the client/server connections
                        self.notify(APP_NAME, 'Local server auth mode: please authorise a request for account %s' %
                                    data['username'])
                    elif icon:
                        self.authorisation_requests.append(data)
                        icon.update_menu()  # force refresh the menu
                        self.notify(APP_NAME, 'Please authorise your account %s from the menu' % data['username'])
                else:
                    for request in self.authorisation_requests[:]:  # iterate over a copy; remove from original
                        if request['permission_url'] == data['permission_url']:
                            self.authorisation_requests.remove(request)
                            break  # we could have multiple simultaneous requests, some not yet expired

    @staticmethod
    def run_proxy():
        while not EXITING:
            error_count = 0
            try:
                # loop for main proxy servers, accepting requests and starting connection threads
                # note: we need to make sure there are always proxy servers started when run_proxy is called (i.e., must
                # exit on server start failure), otherwise this will throw an error every time and loop indefinitely
                asyncore.loop()
            except Exception as e:
                if not EXITING and not (isinstance(e, OSError) and e.errno == errno.EBADF):
                    Log.info('Caught asyncore exception in main loop; attempting to continue:', Log.error_string(e))
                    error_count += 1
                    time.sleep(error_count)

    def exit(self, icon, restart_callback=None):
        Log.info('Stopping', APP_NAME)
        global EXITING
        EXITING = True

        AppConfig.save()

        if sys.platform == 'darwin' and not self.args.no_gui:
            # noinspection PyUnresolvedReferences
            SystemConfiguration.SCNetworkReachabilityUnscheduleFromRunLoop(self.macos_reachability_target,
                                                                           SystemConfiguration.CFRunLoopGetCurrent(),
                                                                           SystemConfiguration.kCFRunLoopDefaultMode)

        REQUEST_QUEUE.put(QUEUE_SENTINEL)
        RESPONSE_QUEUE.put(QUEUE_SENTINEL)
        WEBVIEW_QUEUE.put(QUEUE_SENTINEL)

        if self.web_view_started:
            for window in webview.windows[:]:  # iterate over a copy; remove (in destroy()) from original
                window.show()
                window.destroy()

        for proxy in self.proxies:  # no need to copy - proxies are never removed, we just restart them on error
            # noinspection PyBroadException
            try:
                proxy.stop()
            except Exception:
                pass

        if icon:
            icon.stop()

        # for the 'Start at login' option we need a callback to restart the script the first time this preference is
        # configured (macOS) or every time (other platforms) - note that just as in toggle_start_at_login(), pystray
        # verifies that actions have a maximum of two parameters, so we must override the 'item' one but check its type
        if restart_callback and not isinstance(restart_callback, pystray.MenuItem):
            Log.info('Restarted', APP_NAME, 'as a background task')
            restart_callback()

        # macOS Launch Agents need reloading when changed; unloading exits immediately so this must be our final action
        if sys.platform == 'darwin' and not self.args.no_gui and self.macos_unload_plist_on_exit:
            self.macos_launchctl('unload')


if __name__ == '__main__':
    App()

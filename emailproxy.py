#!/usr/bin/env python3

"""A simple IMAP/POP/SMTP proxy that intercepts authenticate and login commands, transparently replacing them with OAuth
2.0 authentication. Designed for apps/clients that don't support OAuth 2.0 but need to connect to modern servers."""

__author__ = 'Simon Robinson'
__copyright__ = 'Copyright (c) 2023 Simon Robinson'
__license__ = 'Apache 2.0'
__version__ = '2023-11-01'  # ISO 8601 (YYYY-MM-DD)
__package_version__ = '.'.join([str(int(i)) for i in __version__.split('-')])  # for pyproject.toml usage only

import abc
import argparse
import base64
import binascii
import configparser
import contextlib
import datetime
import enum
import errno
import io
import ipaddress
import json
import logging
import logging.handlers
import os
import pathlib
import plistlib
import queue
import re
import select
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
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# by default the proxy is a GUI application with a menu bar/taskbar icon, but it is also useful in 'headless' contexts
# where not having to install GUI-only requirements can be helpful - see the proxy's readme (the `--no-gui` option)
MISSING_GUI_REQUIREMENTS = []

try:
    import pystray  # the menu bar/taskbar GUI
except ImportError as gui_requirement_import_error:
    MISSING_GUI_REQUIREMENTS.append(gui_requirement_import_error)


    class DummyPystray:  # dummy implementation allows initialisation to complete
        class Icon:
            pass


    pystray = DummyPystray  # this is just to avoid unignorable IntelliJ warnings about naming and spacing

try:
    # noinspection PyUnresolvedReferences
    from PIL import Image, ImageDraw, ImageFont  # draw the menu bar icon from the TTF font stored in APP_ICON
except ImportError as gui_requirement_import_error:
    MISSING_GUI_REQUIREMENTS.append(gui_requirement_import_error)

try:
    # noinspection PyUnresolvedReferences
    import timeago  # the last authenticated activity hint
except ImportError as gui_requirement_import_error:
    MISSING_GUI_REQUIREMENTS.append(gui_requirement_import_error)

try:
    # noinspection PyUnresolvedReferences
    import webview  # the popup authentication window (in default and GUI `--external-auth` modes only)
except ImportError as gui_requirement_import_error:
    MISSING_GUI_REQUIREMENTS.append(gui_requirement_import_error)

with warnings.catch_warnings():
    warnings.simplefilter('ignore', DeprecationWarning)
    try:
        # noinspection PyDeprecation,PyUnresolvedReferences
        import pkg_resources  # from setuptools - to change to importlib.metadata and packaging.version once min. is 3.8
    except ImportError as gui_requirement_import_error:
        MISSING_GUI_REQUIREMENTS.append(gui_requirement_import_error)

# for macOS-specific functionality
if sys.platform == 'darwin':
    try:
        # PyUnresolvedReferences; see: youtrack.jetbrains.com/issue/PY-11963 (same for others with this suppression)
        # noinspection PyPackageRequirements,PyUnresolvedReferences
        import PyObjCTools  # SIGTERM handling (only needed when in GUI mode; `signal` is sufficient otherwise)
    except ImportError as gui_requirement_import_error:
        MISSING_GUI_REQUIREMENTS.append(gui_requirement_import_error)

    try:
        # noinspection PyPackageRequirements,PyUnresolvedReferences
        import SystemConfiguration  # network availability monitoring
    except ImportError as gui_requirement_import_error:
        MISSING_GUI_REQUIREMENTS.append(gui_requirement_import_error)

    try:
        # noinspection PyPackageRequirements
        import AppKit  # retina icon, menu update on click, native notifications and receiving system events
    except ImportError as gui_requirement_import_error:
        MISSING_GUI_REQUIREMENTS.append(gui_requirement_import_error)


        class AppKit:  # dummy implementation allows initialisation to complete
            class NSObject:
                pass

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

CENSOR_CREDENTIALS = True
CENSOR_MESSAGE = b'[[ Credentials removed from proxy log ]]'  # replaces actual credentials; must be a byte-type string

script_path = sys.executable if getattr(sys, 'frozen', False) else os.path.realpath(__file__)  # for pyinstaller etc
if sys.platform == 'darwin' and '.app/Contents/MacOS/' in script_path:  # pyinstaller .app binary is within the bundle
    script_path = '/'.join(script_path.split('Contents/MacOS/')[0].split('/')[:-1])
script_path = os.getcwd() if __package__ is not None else os.path.dirname(script_path)  # for packaged version (PyPI)
CONFIG_FILE_PATH = CACHE_STORE = os.path.join(script_path, '%s.config' % APP_SHORT_NAME)
CONFIG_SERVER_MATCHER = re.compile(r'^(?P<type>(IMAP|POP|SMTP))-(?P<port>\d+)$')
del script_path

MAX_CONNECTIONS = 0  # maximum concurrent IMAP/POP/SMTP connections; 0 = no limit; limit is per server

RECEIVE_BUFFER_SIZE = 65536  # number of bytes to try to read from the socket at a time (limit is per socket)

MAX_SSL_HANDSHAKE_ATTEMPTS = 1024  # number of attempts before aborting SSL/TLS handshake (max 10ms each); 0 = no limit

# IMAP/POP/SMTP require \r\n as a line terminator (we use lines only pre-authentication; afterwards just pass through)
LINE_TERMINATOR = b'\r\n'
LINE_TERMINATOR_LENGTH = len(LINE_TERMINATOR)

# seconds to wait before cancelling authentication requests (i.e., the user has this long to log in) - note that the
# actual server timeout is often around 60 seconds, so the connection may be closed in the background and immediately
# disconnect after login completes; however, the login credentials will still be saved and used for future requests
AUTHENTICATION_TIMEOUT = 600

TOKEN_EXPIRY_MARGIN = 600  # seconds before its expiry to refresh the OAuth 2.0 token

LOG_FILE_MAX_SIZE = 32 * 1024 * 1024  # when using a log file, its maximum size in bytes before rollover (0 = no limit)
LOG_FILE_MAX_BACKUPS = 10  # the number of log files to keep when LOG_FILE_MAX_SIZE is exceeded (0 = disable rollover)

IMAP_TAG_PATTERN = r'[!#$&\',-\[\]-z|}~]+'  # https://ietf.org/rfc/rfc9051.html#name-formal-syntax
IMAP_AUTHENTICATION_REQUEST_MATCHER = re.compile('^(?P<tag>%s) (?P<command>(LOGIN|AUTHENTICATE)) '
                                                 '(?P<flags>.*)$' % IMAP_TAG_PATTERN, flags=re.IGNORECASE)
IMAP_LITERAL_MATCHER = re.compile(r'^{(?P<length>\d+)(?P<continuation>\+?)}$')
IMAP_CAPABILITY_MATCHER = re.compile(r'^\* (?:OK \[)?CAPABILITY .*$', flags=re.IGNORECASE)  # note: '* ' *and* '* OK ['

REQUEST_QUEUE = queue.Queue()  # requests for authentication
RESPONSE_QUEUE = queue.Queue()  # responses from user
QUEUE_SENTINEL = object()  # object to send to signify queues should exit loops
MENU_UPDATE = object()  # object to send to trigger a force-refresh of the GUI menu (new catch-all account added)

PLIST_FILE_PATH = pathlib.Path('~/Library/LaunchAgents/%s.plist' % APP_PACKAGE).expanduser()  # launchctl file location
CMD_FILE_PATH = pathlib.Path('~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/%s.cmd' %
                             APP_PACKAGE).expanduser()  # Windows startup .cmd file location
AUTOSTART_FILE_PATH = pathlib.Path('~/.config/autostart/%s.desktop' % APP_PACKAGE).expanduser()  # XDG Autostart file

# noinspection SpellCheckingInspection
SECURE_SERVER_ICON = '''iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAAApElEQVR4Ae3VsQ2DMBBA0ZQs4NIreA03GSbyAl6DAbyN+xvh
    Ovp0yY9EkQZ8XELHSa+x0S9OAm75cT+F+UFm+vhbmClQLCtF+SnMNAji11lcz5orzCQopo21KJIn3FB37iuaJ9yRd+4zuicsSINViSesyEgbMtQcZgIE
    TyNBsIQrXgdVS3h2hGdf+Apf4eIIF+ub16FYBhQd4ci3IiAOBP8/z+kNGUS6hBN6UlIAAAAASUVORK5CYII='''  # 22px SF Symbols lock.fill

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
    _MACOS_USE_SYSLOG = False

    @staticmethod
    def initialise(log_file=None):
        Log._LOGGER = logging.getLogger(APP_NAME)
        if log_file or sys.platform == 'win32':
            handler = logging.handlers.RotatingFileHandler(
                log_file or '%s/%s.log' % (os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else
                                                           os.path.realpath(__file__)), APP_SHORT_NAME),
                maxBytes=LOG_FILE_MAX_SIZE, backupCount=LOG_FILE_MAX_BACKUPS)
            handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))

        elif sys.platform == 'darwin':
            # noinspection PyPackageRequirements
            import pyoslog  # for macOS-specific unified logging
            Log._MACOS_USE_SYSLOG = not pyoslog.is_supported()
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

    @staticmethod
    def format_host_port(address):
        host, port, *_ = address
        with contextlib.suppress(ValueError):
            ip = ipaddress.ip_address(host)
            host = '[%s]' % host if type(ip) is ipaddress.IPv6Address else host
        return '%s:%d' % (host, port)

    @staticmethod
    def get_last_error():
        error_type, value, _traceback = sys.exc_info()
        del _traceback  # used to be required in python 2; may no-longer be needed, but best to be safe
        return error_type, value  # note that if no exception has currently been raised, this will return `None, None`


class CacheStore(abc.ABC):
    """Override this class to provide additional cache store options for a dictionary of OAuth 2.0 credentials, then add
    an entry in AppConfig's `_EXTERNAL_CACHE_STORES` to make them available via the proxy's `--cache-store` parameter"""

    @staticmethod
    @abc.abstractmethod
    def load(store_id):
        return {}

    @staticmethod
    @abc.abstractmethod
    def save(store_id, config_dict):
        pass


class AWSSecretsManagerCacheStore(CacheStore):
    # noinspection PyGlobalUndefined,PyPackageRequirements
    @staticmethod
    def _get_boto3_client(store_id):
        try:
            global boto3, botocore
            import boto3
            import botocore.exceptions
        except ModuleNotFoundError:
            Log.error('Unable to load AWS SDK - please install the `boto3` module: `python -m pip install boto3`')
            return None, None
        else:
            # allow a profile to be chosen by prefixing the store_id - the separator used (`||`) will not be in an ARN
            # or secret name (see: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html)
            split_id = store_id.split('||', maxsplit=1)
            if '||' in store_id:
                return split_id[1], boto3.session.Session(profile_name=split_id[0]).client('secretsmanager')
            return store_id, boto3.client(service_name='secretsmanager')

    @staticmethod
    def _create_secret(aws_client, store_id):
        if store_id.startswith('arn:'):
            Log.info('Creating new AWS Secret "%s" failed - it is not possible to choose specific ARNs for new secrets')
            return False

        try:
            aws_client.create_secret(Name=store_id, ForceOverwriteReplicaSecret=False)
            Log.info('Created new AWS Secret "%s"' % store_id)
            return True

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                AWSSecretsManagerCacheStore._log_error(
                    'Creating new AWS Secret "%s" failed - access denied: does the IAM user have the '
                    '`secretsmanager:CreateSecret` permission?' % store_id, e)
            else:
                AWSSecretsManagerCacheStore._log_error('Creating new AWS Secret "%s" failed with an unexpected error; '
                                                       'see the proxy\'s debug log' % store_id, e)
        return False

    @staticmethod
    def _log_error(error_message, debug_error):
        Log.debug('AWS %s: %s' % (debug_error.response['Error']['Code'], debug_error.response['Error']['Message']))
        Log.error(error_message)

    @staticmethod
    def load(store_id):
        store_id, aws_client = AWSSecretsManagerCacheStore._get_boto3_client(store_id)
        if aws_client:
            try:
                Log.debug('Requesting credential cache from AWS Secret "%s"' % store_id)
                retrieved_secrets = json.loads(aws_client.get_secret_value(SecretId=store_id)['SecretString'])
                Log.info('Fetched', len(retrieved_secrets), 'cached account entries from AWS Secret "%s"' % store_id)
                return retrieved_secrets

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    Log.info('AWS Secret "%s" does not exist - attempting to create it' % store_id)
                    AWSSecretsManagerCacheStore._create_secret(aws_client, store_id)
                elif error_code == 'AccessDeniedException':
                    AWSSecretsManagerCacheStore._log_error(
                        'Fetching AWS Secret "%s" failed - access denied: does the IAM user have the '
                        '`secretsmanager:GetSecretValue` permission?' % store_id, e)
                else:
                    AWSSecretsManagerCacheStore._log_error(
                        'Fetching AWS Secret "%s" failed - unexpected error; see the proxy debug log' % store_id, e)
        else:
            Log.error('Unable to get AWS SDK client; cannot fetch credentials from AWS Secrets Manager')
        return {}

    @staticmethod
    def save(store_id, config_dict, create_secret=True):
        store_id, aws_client = AWSSecretsManagerCacheStore._get_boto3_client(store_id)
        if aws_client:
            try:
                Log.debug('Saving credential cache to AWS Secret "%s"' % store_id)
                aws_client.put_secret_value(SecretId=store_id, SecretString=json.dumps(config_dict))
                Log.info('Cached', len(config_dict), 'account entries to AWS Secret "%s"' % store_id)

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException' and create_secret:
                    Log.info('AWS Secret "%s" does not exist - attempting to create it' % store_id)
                    if AWSSecretsManagerCacheStore._create_secret(aws_client, store_id):
                        AWSSecretsManagerCacheStore.save(store_id, config_dict, create_secret=False)
                elif error_code == 'AccessDeniedException':
                    AWSSecretsManagerCacheStore._log_error(
                        'Caching to AWS Secret "%s" failed - access denied: does the IAM user have the '
                        '`secretsmanager:PutSecretValue` permission?' % store_id, e)
                else:
                    AWSSecretsManagerCacheStore._log_error(
                        'Caching to AWS Secret "%s" failed - unexpected error; see the proxy debug log' % store_id, e)
        else:
            Log.error('Unable to get AWS SDK client; cannot cache credentials to AWS Secrets Manager')


class ConcurrentConfigParser:
    """Helper wrapper to add locking to a ConfigParser object (note: only wraps the methods used in this script)"""

    def __init__(self):
        self.config = configparser.ConfigParser()
        self.lock = threading.Lock()

    def read(self, filename):
        with self.lock:
            self.config.read(filename)

    def sections(self):
        with self.lock:
            return self.config.sections()

    def add_section(self, section):
        with self.lock:
            self.config.add_section(section)

    def get(self, section, option, fallback=None):
        with self.lock:
            return self.config.get(section, option, fallback=fallback)

    def getint(self, section, option, fallback=None):
        with self.lock:
            return self.config.getint(section, option, fallback=fallback)

    def getboolean(self, section, option, fallback=None):
        with self.lock:
            return self.config.getboolean(section, option, fallback=fallback)

    def set(self, section, option, value):
        with self.lock:
            self.config.set(section, option, value)

    def remove_option(self, section, option):
        with self.lock:
            self.config.remove_option(section, option)

    def write(self, file):
        with self.lock:
            self.config.write(file)

    def items(self):
        with self.lock:
            return self.config.items()  # used in read_dict when saving to cache store


class AppConfig:
    """Helper wrapper around ConfigParser to cache servers/accounts, and avoid writing to the file until necessary"""

    _PARSER = None
    _PARSER_LOCK = threading.Lock()

    # note: removing the unencrypted version of `client_secret_encrypted` is not automatic with --cache-store (see docs)
    _CACHED_OPTION_KEYS = ['access_token', 'access_token_expiry', 'refresh_token', 'token_salt', 'token_iterations',
                           'client_secret_encrypted', 'last_activity']

    # additional cache stores may be implemented by extending CacheStore and adding a prefix entry in this dict
    _EXTERNAL_CACHE_STORES = {'aws:': AWSSecretsManagerCacheStore}

    @staticmethod
    def _load():
        config_parser = ConcurrentConfigParser()
        config_parser.read(CONFIG_FILE_PATH)

        # cached account credentials can be stored in the configuration file (default) or, via `--cache-store`, a
        # separate local file or external service (such as a secrets manager) - we combine these sources at load time
        if CACHE_STORE != CONFIG_FILE_PATH:
            # it would be cleaner to avoid specific options here, but best to load unexpected sections only when enabled
            allow_catch_all_accounts = config_parser.getboolean(APP_SHORT_NAME, 'allow_catch_all_accounts',
                                                                fallback=False)

            cache_file_parser = AppConfig._load_cache(CACHE_STORE)
            cache_file_accounts = [s for s in cache_file_parser.sections() if '@' in s]
            for account in cache_file_accounts:
                if allow_catch_all_accounts and account not in config_parser.sections():  # missing sub-accounts
                    config_parser.add_section(account)
                for option in cache_file_parser.options(account):
                    if option in AppConfig._CACHED_OPTION_KEYS:
                        config_parser.set(account, option, cache_file_parser.get(account, option))

        return config_parser

    @staticmethod
    def _load_cache(cache_store_identifier):
        cache_file_parser = configparser.ConfigParser()
        for prefix, cache_store_handler in AppConfig._EXTERNAL_CACHE_STORES.items():
            if cache_store_identifier.startswith(prefix):
                cache_file_parser.read_dict(cache_store_handler.load(cache_store_identifier[len(prefix):]))
                return cache_file_parser
        cache_file_parser.read(cache_store_identifier)  # default cache is a local file (does not error if non-existent)
        return cache_file_parser

    @staticmethod
    def get():
        with AppConfig._PARSER_LOCK:
            if AppConfig._PARSER is None:
                AppConfig._PARSER = AppConfig._load()
            return AppConfig._PARSER

    @staticmethod
    def unload():
        with AppConfig._PARSER_LOCK:
            AppConfig._PARSER = None

    @staticmethod
    def get_global(name, fallback):
        return AppConfig.get().getboolean(APP_SHORT_NAME, name, fallback)

    @staticmethod
    def servers():
        return [s for s in AppConfig.get().sections() if CONFIG_SERVER_MATCHER.match(s)]

    @staticmethod
    def accounts():
        return [s for s in AppConfig.get().sections() if '@' in s]

    @staticmethod
    def save():
        with AppConfig._PARSER_LOCK:
            if AppConfig._PARSER is None:  # intentionally using _PARSER not get() so we don't (re-)load if unloaded
                return

            if CACHE_STORE != CONFIG_FILE_PATH:
                # in `--cache-store` mode we ignore everything except _CACHED_OPTION_KEYS (OAuth 2.0 tokens, etc)
                output_config_parser = configparser.ConfigParser()
                output_config_parser.read_dict(AppConfig._PARSER)  # a deep copy of the current configuration
                config_accounts = [s for s in output_config_parser.sections() if '@' in s]

                for account in config_accounts:
                    for option in output_config_parser.options(account):
                        if option not in AppConfig._CACHED_OPTION_KEYS:
                            output_config_parser.remove_option(account, option)

                for section in output_config_parser.sections():
                    if section not in config_accounts or len(output_config_parser.options(section)) <= 0:
                        output_config_parser.remove_section(section)

                AppConfig._save_cache(CACHE_STORE, output_config_parser)

            else:
                # by default we cache to the local configuration file, and rewrite all values each time
                try:
                    with open(CONFIG_FILE_PATH, mode='w', encoding='utf-8') as config_output:
                        AppConfig._PARSER.write(config_output)
                except IOError:
                    Log.error('Error saving state to config file at', CONFIG_FILE_PATH, '- is the file writable?')

    @staticmethod
    def _save_cache(cache_store_identifier, output_config_parser):
        for prefix, cache_store_handler in AppConfig._EXTERNAL_CACHE_STORES.items():
            if cache_store_identifier.startswith(prefix):
                cache_store_handler.save(cache_store_identifier[len(prefix):],
                                         {account: dict(output_config_parser.items(account)) for account in
                                          output_config_parser.sections()})
                return
        try:
            with open(cache_store_identifier, mode='w', encoding='utf-8') as config_output:
                output_config_parser.write(config_output)
        except IOError:
            Log.error('Error saving state to cache store file at', cache_store_identifier, '- is the file writable?')


class Cryptographer:
    ITERATIONS = 870_000  # taken from cryptography's suggestion of using Django's defaults
    LEGACY_ITERATIONS = 100_000  # fallback when the iteration count is not in the config file (versions < 2023-10-17)

    def __init__(self, config, username, password):
        """Creates a cryptographer which allows encrypting and decrypting sensitive information for this account,
        (such as stored tokens), and also supports increasing the encryption/decryption iterations (i.e., strength)"""
        self._salt = None

        token_salt = config.get(username, 'token_salt', fallback=None)
        if token_salt:
            try:
                self._salt = base64.b64decode(token_salt.encode('utf-8'))  # catch incorrect third-party proxy guide
            except (binascii.Error, UnicodeError):
                Log.info('%s: Invalid `token_salt` value found in config file entry for account %s - this value is not '
                         'intended to be manually created; generating new `token_salt`' % (APP_NAME, username))

        if not self._salt:
            self._salt = os.urandom(16)  # either a failed decode or the initial run when no salt exists

        # the iteration count is stored with the credentials, so could if required be user-edited (see PR #198 comments)
        iterations = config.getint(username, 'token_iterations', fallback=self.LEGACY_ITERATIONS)

        # with MultiFernet each fernet is tried in order to decrypt a value, but encryption always uses the first
        # fernet, so sort unique iteration counts in descending order (i.e., use the best available encryption)
        self._iterations_options = sorted({self.ITERATIONS, iterations, self.LEGACY_ITERATIONS}, reverse=True)

        # generate encrypter/decrypter based on the password and salt
        self._fernets = [Fernet(base64.urlsafe_b64encode(
            PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self._salt, iterations=iterations,
                       backend=default_backend()).derive(password.encode('utf-8')))) for iterations in
            self._iterations_options]
        self.fernet = MultiFernet(self._fernets)

    @property
    def salt(self):
        return base64.b64encode(self._salt).decode('utf-8')

    @property
    def iterations(self):
        return self._iterations_options[0]

    def encrypt(self, value):
        return self.fernet.encrypt(value.encode('utf-8')).decode('utf-8')

    def decrypt(self, value):
        return self.fernet.decrypt(value.encode('utf-8')).decode('utf-8')

    def requires_rotation(self, value):
        try:
            self._fernets[0].decrypt(value.encode('utf-8'))  # if the first fernet works, everything is up-to-date
            return False
        except InvalidToken:
            try:  # check to see if any fernet can decrypt the value - if so we can upgrade the encryption strength
                self.decrypt(value)
                return True
            except InvalidToken:
                return False

    def rotate(self, value):
        return self.fernet.rotate(value.encode('utf-8')).decode('utf-8')


class OAuth2Helper:
    class TokenRefreshError(Exception):
        pass

    @staticmethod
    def get_oauth2_credentials(username, password, reload_remote_accounts=True):
        """Using the given username (i.e., email address) and password, reads account details from AppConfig and
        handles OAuth 2.0 token request and renewal, saving the updated details back to AppConfig (or removing them
        if invalid). Returns either (True, '[OAuth2 string for authentication]') or (False, '[Error message]')"""

        # we support broader catch-all account names (e.g., `@domain.com` / `@`) if enabled
        config_accounts = AppConfig.accounts()
        valid_accounts = [username in config_accounts]
        if AppConfig.get_global('allow_catch_all_accounts', fallback=False):
            user_domain = '@%s' % username.split('@')[-1]
            valid_accounts.extend([account in config_accounts for account in [user_domain, '@']])

        if not any(valid_accounts):
            Log.error('Proxy config file entry missing for account', username, '- aborting login')
            return (False, '%s: No config file entry found for account %s - please add a new section with values '
                           'for permission_url, token_url, oauth2_scope, redirect_uri, client_id and '
                           'client_secret' % (APP_NAME, username))

        config = AppConfig.get()

        def get_account_with_catch_all_fallback(option):
            fallback = None
            if AppConfig.get_global('allow_catch_all_accounts', fallback=False):
                fallback = config.get(user_domain, option, fallback=config.get('@', option, fallback=None))
            return config.get(username, option, fallback=fallback)

        permission_url = get_account_with_catch_all_fallback('permission_url')
        token_url = get_account_with_catch_all_fallback('token_url')
        oauth2_scope = get_account_with_catch_all_fallback('oauth2_scope')
        oauth2_flow = get_account_with_catch_all_fallback('oauth2_flow')
        redirect_uri = get_account_with_catch_all_fallback('redirect_uri')
        redirect_listen_address = get_account_with_catch_all_fallback('redirect_listen_address')
        client_id = get_account_with_catch_all_fallback('client_id')
        client_secret = get_account_with_catch_all_fallback('client_secret')
        client_secret_encrypted = get_account_with_catch_all_fallback('client_secret_encrypted')

        # note that we don't require permission_url here because it is not needed for the client credentials grant flow,
        # and likewise for client_secret here because it can be optional for Office 365 configurations
        if not (token_url and oauth2_scope and redirect_uri and client_id):
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

        current_time = int(time.time())
        access_token = config.get(username, 'access_token', fallback=None)
        access_token_expiry = config.getint(username, 'access_token_expiry', fallback=current_time)
        refresh_token = config.get(username, 'refresh_token', fallback=None)

        # try reloading remotely cached tokens if possible
        if not access_token and CACHE_STORE != CONFIG_FILE_PATH and reload_remote_accounts:
            AppConfig.unload()
            return OAuth2Helper.get_oauth2_credentials(username, password, reload_remote_accounts=False)

        cryptographer = Cryptographer(config, username, password)
        rotatable_values = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'client_secret_encrypted': client_secret_encrypted
        }
        if any(value and cryptographer.requires_rotation(value) for value in rotatable_values.values()):
            Log.info('Rotating stored secrets for account', username, 'to use new cryptographic parameters')
            for key, value in rotatable_values.items():
                if value:
                    config.set(username, key, cryptographer.rotate(value))

            config.set(username, 'token_iterations', str(cryptographer.iterations))
            AppConfig.save()

        try:
            # if both secret values are present we use the unencrypted version (as it may have been user-edited)
            if client_secret_encrypted and not client_secret:
                client_secret = cryptographer.decrypt(client_secret_encrypted)

            if access_token or refresh_token:  # if possible, refresh the existing token(s)
                if not access_token or access_token_expiry - current_time < TOKEN_EXPIRY_MARGIN:
                    if refresh_token:
                        response = OAuth2Helper.refresh_oauth2_access_token(token_url, client_id, client_secret,
                                                                            cryptographer.decrypt(refresh_token))

                        access_token = response['access_token']
                        config.set(username, 'access_token', cryptographer.encrypt(access_token))
                        config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))
                        if 'refresh_token' in response:
                            config.set(username, 'refresh_token', cryptographer.encrypt(response['refresh_token']))
                        AppConfig.save()

                    else:
                        # we used to keep tokens until the last possible moment here, but it is simpler to just obtain a
                        # new one within TOKEN_EXPIRY_MARGIN, particularly when in CCG or ROPCG flow modes where getting
                        # a new token involves no user interaction (note that in interactive mode it would be better to
                        # request a new token via the user before discarding the existing one, but since this happens
                        # very infrequently, we don't add the extra complexity for just 10 extra minutes of token life)
                        access_token = None  # avoid trying invalid (or soon to be) tokens
                else:
                    access_token = cryptographer.decrypt(access_token)

            if not access_token:
                auth_result = None
                if permission_url:  # O365 CCG and ROPCG flows skip the authorisation step; no permission_url
                    oauth2_flow = 'authorization_code'
                    permission_url = OAuth2Helper.construct_oauth2_permission_url(permission_url, redirect_uri,
                                                                                  client_id, oauth2_scope, username)

                    # note: get_oauth2_authorisation_code is a blocking call (waiting on user to provide code)
                    success, auth_result = OAuth2Helper.get_oauth2_authorisation_code(permission_url, redirect_uri,
                                                                                      redirect_listen_address, username)

                    if not success:
                        Log.info('Authorisation result error for', username, '- aborting login.', auth_result)
                        return False, '%s: Login failed for account %s: %s' % (APP_NAME, username, auth_result)

                if not oauth2_flow:
                    oauth2_flow = 'client_credentials'  # default to CCG over ROPCG if not set (ROPCG is `password`)
                response = OAuth2Helper.get_oauth2_authorisation_tokens(token_url, redirect_uri, client_id,
                                                                        client_secret, auth_result, oauth2_scope,
                                                                        oauth2_flow, username, password)

                access_token = response['access_token']
                if username not in config.sections():
                    config.add_section(username)  # in catch-all mode the section may not yet exist
                    REQUEST_QUEUE.put(MENU_UPDATE)  # make sure the menu shows the newly-added account
                config.set(username, 'token_salt', cryptographer.salt)
                config.set(username, 'token_iterations', str(cryptographer.iterations))
                config.set(username, 'access_token', cryptographer.encrypt(access_token))
                config.set(username, 'access_token_expiry', str(current_time + response['expires_in']))

                if 'refresh_token' in response:
                    config.set(username, 'refresh_token', cryptographer.encrypt(response['refresh_token']))
                elif permission_url:  # ignore this situation with client credentials flow - it is expected
                    Log.info('Warning: no refresh token returned for', username, '- you will need to re-authenticate',
                             'each time the access token expires (does your `oauth2_scope` value allow `offline` use?)')

                if AppConfig.get_global('encrypt_client_secret_on_first_use', fallback=False):
                    if client_secret:
                        # note: save to the `username` entry even if `user_domain` exists, avoiding conflicts when using
                        # incompatible `encrypt_client_secret_on_first_use` and `allow_catch_all_accounts` options
                        config.set(username, 'client_secret_encrypted', cryptographer.encrypt(client_secret))
                        config.remove_option(username, 'client_secret')

                AppConfig.save()

            # send authentication command to server (response checked in ServerConnection) - note: we only support
            # single-trip authentication (SASL) without actually checking the server's capabilities - improve?
            oauth2_string = OAuth2Helper.construct_oauth2_string(username, access_token)
            return True, oauth2_string

        except OAuth2Helper.TokenRefreshError as e:
            # always clear access tokens - can easily request another via the refresh token (with no user interaction)
            has_access_token = True if config.get(username, 'access_token', fallback=None) else False
            config.remove_option(username, 'access_token')
            config.remove_option(username, 'access_token_expiry')

            if not has_access_token:
                # if this is already a second failure, remove the refresh token as well, and force re-authentication
                config.remove_option(username, 'token_salt')
                config.remove_option(username, 'token_iterations')
                config.remove_option(username, 'refresh_token')

            AppConfig.save()

            Log.info('Retrying login due to exception while refreshing OAuth 2.0 tokens for', username,
                     '(attempt %d):' % (1 if has_access_token else 2), Log.error_string(e))
            return OAuth2Helper.get_oauth2_credentials(username, password, reload_remote_accounts=False)

        except InvalidToken as e:
            if AppConfig.get_global('delete_account_token_on_password_error', fallback=True):
                config.remove_option(username, 'access_token')
                config.remove_option(username, 'access_token_expiry')
                config.remove_option(username, 'token_salt')
                config.remove_option(username, 'token_iterations')
                config.remove_option(username, 'refresh_token')
                AppConfig.save()

                Log.info('Retrying login due to exception while decrypting OAuth 2.0 credentials for', username,
                         '(invalid password):', Log.error_string(e))
                return OAuth2Helper.get_oauth2_credentials(username, password, reload_remote_accounts=False)

            Log.error('Invalid password to decrypt', username, 'credentials - aborting login:', Log.error_string(e))
            return False, '%s: Login failed - the password for account %s is incorrect' % (APP_NAME, username)

        except Exception as e:
            # note that we don't currently remove cached credentials here, as failures on the initial request are before
            # caching happens, and the assumption is that refresh token request exceptions are temporal (e.g., network
            # errors: URLError(OSError(50, 'Network is down'))) - access token 400 Bad Request HTTPErrors with messages
            # such as 'authorisation code was already redeemed' are caused by our support for simultaneous requests,
            # and will work from the next request; however, please report an issue if you encounter problems here
            Log.info('Caught exception while requesting OAuth 2.0 credentials for %s:' % username, Log.error_string(e))
            return False, '%s: Login failed for account %s - please check your internet connection and retry' % (
                APP_NAME, username)

    @staticmethod
    def oauth2_url_escape(text):
        return urllib.parse.quote(text, safe='~-._')  # see https://tools.ietf.org/html/rfc3986#section-2.3

    @staticmethod
    def oauth2_url_unescape(text):
        return urllib.parse.unquote(text)

    @staticmethod
    def match_redirect_uri(config, received):
        parsed_config = urllib.parse.urlparse(config)
        parsed_received = urllib.parse.urlparse(received)
        # match host:port and path (except trailing slashes), but allow mismatch of the scheme (i.e., http/https) (#96)
        return parsed_config.netloc == parsed_received.netloc and parsed_config.path.rstrip(
            '/') == parsed_received.path.rstrip('/')

    @staticmethod
    def start_redirection_receiver_server(token_request):
        """Starts a local WSGI web server to receive OAuth responses"""
        redirect_listen_type = 'redirect_listen_address' if token_request['redirect_listen_address'] else 'redirect_uri'
        parsed_uri = urllib.parse.urlparse(token_request[redirect_listen_type])
        parsed_port = 80 if parsed_uri.port is None else parsed_uri.port
        Log.debug('Local server auth mode (%s): starting server to listen for authentication response' %
                  Log.format_host_port((parsed_uri.hostname, parsed_port)))

        class LoggingWSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
            def log_message(self, _format_string, *args):
                Log.debug('Local server auth mode (%s): received authentication response' % Log.format_host_port(
                    (parsed_uri.hostname, parsed_port)), *args)

        class RedirectionReceiverWSGIApplication:
            def __call__(self, environ, start_response):
                start_response('200 OK', [('Content-type', 'text/html; charset=utf-8')])
                token_request['response_url'] = '/'.join(token_request['redirect_uri'].split('/')[0:3]) + environ.get(
                    'PATH_INFO') + '?' + environ.get('QUERY_STRING')
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
            with contextlib.suppress(socket.error):
                redirection_server.server_close()

            if 'response_url' in token_request:
                Log.debug('Local server auth mode (%s): closing local server and returning response' %
                          Log.format_host_port((parsed_uri.hostname, parsed_port)), token_request['response_url'])
            else:
                # failed, likely because of an incorrect address (e.g., https vs http), but can also be due to timeout
                Log.info('Local server auth mode (%s):' % Log.format_host_port((parsed_uri.hostname, parsed_port)),
                         'request failed - if this error reoccurs, please check `%s` for' % redirect_listen_type,
                         token_request['username'], 'is not specified as `https` mistakenly. See the sample '
                                                    'configuration file for documentation')
                token_request['expired'] = True

        except socket.error as e:
            Log.error('Local server auth mode (%s):' % Log.format_host_port((parsed_uri.hostname, parsed_port)),
                      'unable to start local server. Please check that `%s` for %s is unique across accounts, '
                      'specifies a port number, and is not already in use. See the documentation in the proxy\'s '
                      'sample configuration file.' % (redirect_listen_type, token_request['username']),
                      Log.error_string(e))
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
        param_pairs = ['%s=%s' % (param, OAuth2Helper.oauth2_url_escape(value)) for param, value in params.items()]
        return '%s?%s' % (permission_url, '&'.join(param_pairs))

    @staticmethod
    def get_oauth2_authorisation_code(permission_url, redirect_uri, redirect_listen_address, username):
        """Submit an authorisation request to the parent app and block until it is provided (or the request fails)"""
        token_request = {'permission_url': permission_url, 'redirect_uri': redirect_uri,
                         'redirect_listen_address': redirect_listen_address, 'username': username, 'expired': False}
        REQUEST_QUEUE.put(token_request)
        response_queue_reference = RESPONSE_QUEUE  # referenced locally to avoid inserting into the new queue on restart
        wait_time = 0
        while True:
            try:
                data = response_queue_reference.get(block=True, timeout=1)
            except queue.Empty:
                wait_time += 1
                if wait_time < AUTHENTICATION_TIMEOUT:
                    continue

                token_request['expired'] = True
                REQUEST_QUEUE.put(token_request)  # re-insert the request as expired so the parent app can remove it
                return False, 'Authorisation request timed out'

            if data is QUEUE_SENTINEL:  # app is closing
                response_queue_reference.put(QUEUE_SENTINEL)  # make sure all watchers exit
                return False, '%s is shutting down' % APP_NAME

            if data['permission_url'] == permission_url and data['username'] == username:  # a response meant for us
                # to improve no-GUI mode we also support the use of a local redirection receiver server or terminal
                # entry to authenticate; this result is a timeout, wsgi request error/failure, or terminal auth ctrl+c
                if 'expired' in data and data['expired']:
                    return False, 'No-GUI authorisation request failed or timed out'

                if 'local_server_auth' in data:
                    threading.Thread(target=OAuth2Helper.start_redirection_receiver_server, args=(data,),
                                     name='EmailOAuth2Proxy-auth-%s' % data['username'], daemon=True).start()

                else:
                    if 'response_url' in data and OAuth2Helper.match_redirect_uri(token_request['redirect_uri'],
                                                                                  data['response_url']):
                        # parse_qsl not parse_qs because we only ever care about non-array values; extra dict formatting
                        # as IntelliJ has a bug incorrectly detecting parse_qs/l as returning a dict with byte-type keys
                        response = {str(key): value for key, value in
                                    urllib.parse.parse_qsl(urllib.parse.urlparse(data['response_url']).query)}
                        if 'code' in response and response['code']:
                            authorisation_code = OAuth2Helper.oauth2_url_unescape(response['code'])
                            if authorisation_code:
                                return True, authorisation_code
                            return False, 'No OAuth 2.0 authorisation code returned'
                        if 'error' in response:
                            message = 'OAuth 2.0 authorisation error: %s' % response['error']
                            message += '; %s' % response['error_description'] if 'error_description' in response else ''
                            return False, message
                        return False, 'OAuth 2.0 authorisation response has no code or error message'
                    return False, 'OAuth 2.0 authorisation response is missing or does not match `redirect_uri`'

            else:  # not for this thread - put back into queue
                response_queue_reference.put(data)
                time.sleep(1)

    @staticmethod
    def get_oauth2_authorisation_tokens(token_url, redirect_uri, client_id, client_secret, authorisation_code,
                                        oauth2_scope, oauth2_flow, username, password):
        """Requests OAuth 2.0 access and refresh tokens from token_url using the given client_id, client_secret,
        authorisation_code and redirect_uri, returning a dict with 'access_token', 'expires_in', and 'refresh_token'
        on success, or throwing an exception on failure (e.g., HTTP 400)"""
        params = {'client_id': client_id, 'client_secret': client_secret, 'code': authorisation_code,
                  'redirect_uri': redirect_uri, 'grant_type': oauth2_flow}
        if not client_secret:
            del params['client_secret']  # client secret can be optional for O365, but we don't want a None entry
        if oauth2_flow != 'authorization_code':
            del params['code']  # CCG/ROPCG flows have no code, but we need the scope and (for ROPCG) username+password
            params['scope'] = oauth2_scope
            if oauth2_flow == 'password':
                params['username'] = username
                params['password'] = password
        try:
            response = urllib.request.urlopen(
                urllib.request.Request(token_url, data=urllib.parse.urlencode(params).encode('utf-8'),
                                       headers={'User-Agent': APP_NAME})).read()
            return json.loads(response)
        except urllib.error.HTTPError as e:
            e.message = json.loads(e.read())
            Log.debug('Error requesting access token - received invalid response:', e.message)
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
            response = urllib.request.urlopen(
                urllib.request.Request(token_url, data=urllib.parse.urlencode(params).encode('utf-8'),
                                       headers={'User-Agent': APP_NAME})).read()
            return json.loads(response)
        except urllib.error.HTTPError as e:
            e.message = json.loads(e.read())
            Log.debug('Error refreshing access token - received invalid response:', e.message)
            if e.code == 400:  # 400 Bad Request typically means re-authentication is required (token expired)
                raise OAuth2Helper.TokenRefreshError from e
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
            return text[1:-1].replace(r'\"', '"')  # also need to fix any escaped quotes within the string
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
    def __init__(self, connection_socket=None, socket_map=None):
        asyncore.dispatcher_with_send.__init__(self, sock=connection_socket, map=socket_map)
        self.ssl_handshake_errors = (ssl.SSLWantReadError, ssl.SSLWantWriteError,
                                     ssl.SSLEOFError, ssl.SSLZeroReturnError)
        self.ssl_connection, self.ssl_handshake_attempts, self.ssl_handshake_completed = self._reset()

    def _reset(self, is_ssl=False):
        self.ssl_connection = is_ssl
        self.ssl_handshake_attempts = 0
        self.ssl_handshake_completed = not is_ssl
        return self.ssl_connection, self.ssl_handshake_attempts, self.ssl_handshake_completed

    def info_string(self):
        return 'SSLDispatcher'  # override in subclasses to provide more detailed connection information

    def set_ssl_connection(self, is_ssl=False):
        # note that the actual SSLContext.wrap_socket (and associated unwrap()) are handled outside this class
        if not self.ssl_connection and is_ssl:
            self._reset(True)
            if is_ssl:
                # we don't start negotiation here because a failed handshake in __init__ means remove_client also fails
                Log.debug(self.info_string(), '<-> [ Starting TLS handshake ]')

        elif self.ssl_connection and not is_ssl:
            self._reset()

    def _ssl_handshake(self):
        if not isinstance(self.socket, ssl.SSLSocket):
            Log.error(self.info_string(), 'Unable to initiate handshake with a non-SSL socket; aborting')
            raise ssl.SSLError(-1, APP_PACKAGE)

        # attempting to connect insecurely to a secure socket could loop indefinitely here - we set a maximum attempt
        # count and catch in handle_error() when `ssl_handshake_attempts` expires, but there's not much else we can do
        self.ssl_handshake_attempts += 1
        if 0 < MAX_SSL_HANDSHAKE_ATTEMPTS < self.ssl_handshake_attempts:
            Log.error(self.info_string(), 'SSL socket handshake failed (reached `MAX_SSL_HANDSHAKE_ATTEMPTS`)')
            raise ssl.SSLError(-1, APP_PACKAGE)

        # see: https://github.com/python/cpython/issues/54293
        try:
            self.socket.do_handshake()
        except ssl.SSLWantReadError:
            select.select([self.socket], [], [], 0.01)  # wait for the socket to be readable (10ms timeout)
        except ssl.SSLWantWriteError:
            select.select([], [self.socket], [], 0.01)  # wait for the socket to be writable (10ms timeout)
        except self.ssl_handshake_errors:  # also includes SSLWant[Read/Write]Error, but already handled above
            self.close()
        else:
            if not self.ssl_handshake_completed:  # only notify once (we may need to repeat the handshake later)
                Log.debug(self.info_string(), '<-> [', self.socket.version(), 'handshake complete ]')
            self.ssl_handshake_attempts = 0
            self.ssl_handshake_completed = True

    def handle_read_event(self):
        # additional Exceptions are propagated to handle_error(); no need to handle here
        if not self.ssl_handshake_completed:
            self._ssl_handshake()
        else:
            # on the first connection event to a secure server we need to handle SSL handshake events (because we don't
            # have a 'not_currently_ssl_but_will_be_once_connected'-type state) - a version of this class that didn't
            # have to deal with both unsecured, wrapped *and* STARTTLS-type sockets would only need this in recv/send
            try:
                super().handle_read_event()
            except self.ssl_handshake_errors:
                self._ssl_handshake()

    def handle_write_event(self):
        # additional Exceptions are propagated to handle_error(); no need to handle here
        if not self.ssl_handshake_completed:
            self._ssl_handshake()
        else:
            # as in handle_read_event, we need to handle SSL handshake events
            try:
                super().handle_write_event()
            except self.ssl_handshake_errors:
                self._ssl_handshake()

    def recv(self, buffer_size):
        # additional Exceptions are propagated to handle_error(); no need to handle here
        try:
            return super().recv(buffer_size)
        except self.ssl_handshake_errors:
            self._ssl_handshake()
        return b''

    def send(self, byte_data):
        # additional Exceptions are propagated to handle_error(); no need to handle here
        try:
            return super().send(byte_data)  # buffers before sending via the socket, so failure is okay; will auto-retry
        except self.ssl_handshake_errors:
            self._ssl_handshake()
        return 0

    def handle_error(self):
        if self.ssl_connection:
            # OSError 0 ('Error') and SSL errors here are caused by connection handshake failures or timeouts
            # APP_PACKAGE is used when we throw our own SSLError on handshake timeout or socket misconfiguration
            ssl_errors = ['SSLV3_ALERT_BAD_CERTIFICATE', 'PEER_DID_NOT_RETURN_A_CERTIFICATE', 'WRONG_VERSION_NUMBER',
                          'CERTIFICATE_VERIFY_FAILED', 'TLSV1_ALERT_PROTOCOL_VERSION', 'TLSV1_ALERT_UNKNOWN_CA',
                          'UNSUPPORTED_PROTOCOL', APP_PACKAGE]
            error_type, value = Log.get_last_error()
            if error_type == OSError and value.errno == 0 or issubclass(error_type, ssl.SSLError) and \
                    any(i in value.args[1] for i in ssl_errors):
                Log.error('Caught connection error in', self.info_string(), ':', error_type, 'with message:', value)
                if hasattr(self, 'custom_configuration') and hasattr(self, 'proxy_type'):
                    if self.proxy_type == 'SMTP':
                        Log.error('Is the server\'s `starttls` setting correct? Current value: %s' %
                                  self.custom_configuration['starttls'])
                    if self.custom_configuration['local_certificate_path'] and \
                            self.custom_configuration['local_key_path']:
                        Log.error('You have set `local_certificate_path` and `local_key_path`: is your client using a',
                                  'secure connection? github.com/FiloSottile/mkcert is highly recommended for local',
                                  'self-signed certificates, but these may still need an exception in your client')
                Log.error('If you encounter this error repeatedly, please check that you have correctly configured',
                          'python root certificates; see: https://github.com/simonrob/email-oauth2-proxy/issues/14')
                self.close()
            else:
                super().handle_error()
        else:
            super().handle_error()


class OAuth2ClientConnection(SSLAsyncoreDispatcher):
    """The base client-side connection that is subclassed to handle IMAP/POP/SMTP client interaction (note that there
    is some protocol-specific code in here, but it is not essential, and only used to avoid logging credentials)"""

    def __init__(self, proxy_type, connection_socket, socket_map, proxy_parent, custom_configuration):
        SSLAsyncoreDispatcher.__init__(self, connection_socket=connection_socket, socket_map=socket_map)
        self.receive_buffer = b''
        self.proxy_type = proxy_type
        self.server_connection = None
        self.proxy_parent = proxy_parent
        self.local_address = proxy_parent.local_address
        self.server_address = proxy_parent.server_address
        self.custom_configuration = custom_configuration
        self.debug_address_string = '%s-{%s}-%s' % tuple(map(Log.format_host_port, (
            connection_socket.getpeername(), connection_socket.getsockname(), self.server_address)))

        self.censor_next_log = False  # try to avoid logging credentials
        self.authenticated = False

        self.set_ssl_connection(
            bool(custom_configuration['local_certificate_path'] and custom_configuration['local_key_path']))

    def info_string(self):
        debug_string = self.debug_address_string if Log.get_level() == logging.DEBUG else \
            Log.format_host_port(self.local_address)
        account = '; %s' % self.server_connection.authenticated_username if \
            self.server_connection and self.server_connection.authenticated_username else ''
        return '%s (%s%s)' % (self.proxy_type, debug_string, account)

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
                    log_data = re.sub(b'(%s) (LOGIN) (.*)\r\n' % tag_pattern,
                                      br'\1 \2 ' + CENSOR_MESSAGE + b'\r\n', line, flags=re.IGNORECASE)
                    log_data = re.sub(b'(PASS) (.*)\r\n',
                                      br'\1 ' + CENSOR_MESSAGE + b'\r\n', log_data, flags=re.IGNORECASE)
                    log_data = re.sub(b'(%s)?( )?(AUTH)(ENTICATE)? (PLAIN|LOGIN) (.*)\r\n' % tag_pattern,
                                      br'\1\2\3\4 \5 ' + CENSOR_MESSAGE + b'\r\n', log_data, flags=re.IGNORECASE)

                Log.debug(self.info_string(), '-->', log_data if CENSOR_CREDENTIALS else line)
                try:
                    self.process_data(line)
                except AttributeError:  # AttributeError("'NoneType' object has no attribute 'username'"), etc
                    Log.info(self.info_string(),
                             'Caught client exception in subclass; server connection closed before data could be sent')
                    self.close()
                    break

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
        error_type, value = Log.get_last_error()
        if error_type and value:
            message = 'Caught connection error (client)'
            if error_type == ConnectionResetError:
                message = '%s [ Are you attempting an encrypted connection to a non-encrypted server? ]' % message
            Log.info(self.info_string(), message, '-', error_type.__name__, ':', value)
        self.close()

    def close(self):
        if self.server_connection:
            self.server_connection.client_connection = None
            with contextlib.suppress(AttributeError):
                self.server_connection.close()
            self.server_connection = None
        self.proxy_parent.remove_client(self)
        with contextlib.suppress(OSError):
            Log.debug(self.info_string(), '<-- [ Server disconnected ]')
            super().close()


class IMAPOAuth2ClientConnection(OAuth2ClientConnection):
    """The client side of the connection - intercept LOGIN/AUTHENTICATE commands and replace with OAuth 2.0 SASL"""

    def __init__(self, connection_socket, socket_map, proxy_parent, custom_configuration):
        super().__init__('IMAP', connection_socket, socket_map, proxy_parent, custom_configuration)
        self.authentication_tag = None
        self.authentication_command = None
        self.awaiting_credentials = False
        self.login_literal_length_awaited = 0
        self.login_literal_username = None

    def process_data(self, byte_data, censor_server_log=False):
        str_data = byte_data.decode('utf-8', 'replace').rstrip('\r\n')

        # LOGIN data can be sent as quoted text or string literals (https://tools.ietf.org/html/rfc9051#section-4.3)
        if self.login_literal_length_awaited > 0:
            if not self.login_literal_username:
                split_string = str_data.split(' ')
                literal_match = IMAP_LITERAL_MATCHER.match(split_string[-1])
                if literal_match and len(byte_data) > self.login_literal_length_awaited + 2:
                    # could be the username and another literal for password (+2: literal length doesn't include \r\n)
                    # note: plaintext password could end with a string such as ` {1}` that is a valid literal length
                    self.login_literal_username = ' '.join(split_string[:-1])  # handle username space errors elsewhere
                    self.login_literal_length_awaited = int(literal_match.group('length'))
                    self.censor_next_log = True
                    if not literal_match.group('continuation'):
                        self.send(b'+ \r\n')  # request data (RFC 7888's non-synchronising literals don't require this)
                elif len(split_string) > 1:
                    # credentials as a single literal doesn't seem to be valid (RFC 9051), but some clients do this
                    self.login_literal_length_awaited = 0
                    self.authenticate_connection(split_string[0], ' '.join(split_string[1:]))
                else:
                    super().process_data(byte_data)  # probably an invalid command, but just let the server handle it

            else:
                # no need to check length - can only be password; no more literals possible (unless \r\n *in* password)
                self.login_literal_length_awaited = 0
                self.authenticate_connection(self.login_literal_username, str_data)

        # AUTHENTICATE PLAIN can be a two-stage request - handle credentials if they are separate from command
        elif self.awaiting_credentials:
            self.awaiting_credentials = False
            username, password = OAuth2Helper.decode_credentials(str_data)
            self.authenticate_connection(username, password, 'authenticate')

        else:
            match = IMAP_AUTHENTICATION_REQUEST_MATCHER.match(str_data)
            if not match:  # probably an invalid command, but just let the server handle it
                super().process_data(byte_data)
                return

            self.authentication_command = match.group('command').lower()
            client_flags = match.group('flags')
            if self.authentication_command == 'login':
                # string literals are sent as a separate message from the client - note that while length is specified
                # we don't actually check this, instead relying on \r\n as usual (technically, as per RFC 9051 (4.3) the
                # string literal value can itself contain \r\n, but since the proxy only cares about usernames/passwords
                # and it is highly unlikely these will contain \r\n, it is probably safe to avoid this extra complexity)
                split_flags = client_flags.split(' ')
                literal_match = IMAP_LITERAL_MATCHER.match(split_flags[-1])
                if literal_match:
                    self.authentication_tag = match.group('tag')
                    if len(split_flags) > 1:
                        # email addresses will not contain spaces, but let error checking elsewhere handle that - the
                        # important thing is any non-literal here *must* be the username (else no need for a literal)
                        self.login_literal_username = ' '.join(split_flags[:-1])
                    self.login_literal_length_awaited = int(literal_match.group('length'))
                    self.censor_next_log = True
                    if not literal_match.group('continuation'):
                        self.send(b'+ \r\n')  # request data (RFC 7888's non-synchronising literals don't require this)

                # technically only double-quoted strings are allowed here according to RFC 9051 (4.3), but some clients
                # do not obey this - we mandate email addresses as usernames (i.e., no spaces), so can be more flexible
                elif len(split_flags) > 1:
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
                        self.authenticate_connection(username, password, command=self.authentication_command)
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
            super().process_data(b'%s\r\n' % OAuth2Helper.encode_oauth2_string(result), censor_server_log=True)

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

    def __init__(self, connection_socket, socket_map, proxy_parent, custom_configuration):
        super().__init__('POP', connection_socket, socket_map, proxy_parent, custom_configuration)
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

    def __init__(self, connection_socket, socket_map, proxy_parent, custom_configuration):
        super().__init__('SMTP', connection_socket, socket_map, proxy_parent, custom_configuration)
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

    def __init__(self, proxy_type, connection_socket, socket_map, proxy_parent, custom_configuration):
        SSLAsyncoreDispatcher.__init__(self, socket_map=socket_map)  # note: establish connection later due to STARTTLS
        self.receive_buffer = b''
        self.proxy_type = proxy_type
        self.client_connection = None
        self.proxy_parent = proxy_parent
        self.local_address = proxy_parent.local_address
        self.server_address = proxy_parent.server_address
        self.custom_configuration = custom_configuration
        self.debug_address_string = '%s-{%s}-%s' % tuple(map(Log.format_host_port, (
            connection_socket.getpeername(), connection_socket.getsockname(), self.server_address)))

        self.authenticated_username = None  # used only for showing last activity in the menu
        self.last_activity = 0

        self.create_socket()
        self.connect(self.server_address)

    def create_socket(self, socket_family=socket.AF_UNSPEC, socket_type=socket.SOCK_STREAM):
        # connect to whichever resolved IPv4 or IPv6 address is returned first by the system
        for a in socket.getaddrinfo(self.server_address[0], self.server_address[1], socket_family, socket.SOCK_STREAM):
            super().create_socket(a[0], socket.SOCK_STREAM)
            return

    def info_string(self):
        debug_string = self.debug_address_string if Log.get_level() == logging.DEBUG else \
            Log.format_host_port(self.local_address)
        account = '; %s' % self.authenticated_username if self.authenticated_username else ''
        return '%s (%s%s)' % (self.proxy_type, debug_string, account)

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
                try:
                    self.process_data(line)
                except AttributeError:  # AttributeError("'NoneType' object has no attribute 'connection_state'"), etc
                    Log.info(self.info_string(),
                             'Caught server exception in subclass; client connection closed before data could be sent')
                    self.close()
                    break

    def process_data(self, byte_data):
        try:
            self.client_connection.send(byte_data)  # by default we just send everything straight to the client
        except AttributeError:  # AttributeError("'NoneType' object has no attribute 'send'")
            Log.info(self.info_string(), 'Caught server exception; client connection closed before data could be sent')
            self.close()

    def send(self, byte_data, censor_log=False):
        if not self.client_connection.authenticated:  # after authentication these are identical to server-side logs
            Log.debug(self.info_string(), '    -->',
                      b'%s\r\n' % CENSOR_MESSAGE if CENSOR_CREDENTIALS and censor_log else byte_data)
        return super().send(byte_data)

    def handle_error(self):
        error_type, value = Log.get_last_error()
        if error_type == TimeoutError and value.errno == errno.ETIMEDOUT or \
                issubclass(error_type, ConnectionError) and value.errno in [errno.ECONNRESET, errno.ECONNREFUSED] or \
                error_type == OSError and value.errno in [0, errno.ENETDOWN, errno.EHOSTDOWN, errno.EHOSTUNREACH]:
            # TimeoutError 60 = 'Operation timed out'; ConnectionError 54 = 'Connection reset by peer', 61 = 'Connection
            # refused;  OSError 0 = 'Error' (typically network failure), 50 = 'Network is down', 64 = 'Host is down';
            # 65 = 'No route to host'
            Log.info(self.info_string(), 'Caught network error (server) - is there a network connection?',
                     'Error type', error_type, 'with message:', value)
            self.close()
        else:
            super().handle_error()

    def log_info(self, message, message_type='info'):
        # override to redirect error messages to our own log
        if message_type not in self.ignore_log_types:
            Log.info(self.info_string(), 'Caught asyncore info message (server) -', message_type, ':', message)

    def handle_close(self):
        error_type, value = Log.get_last_error()
        if error_type and value:
            message = 'Caught connection error (server)'
            if error_type == OSError and value.errno in [errno.ENOTCONN, 10057]:
                # OSError 57 or 10057 = 'Socket is not connected'
                message = '%s [ Client attempted to send command without waiting for server greeting ]' % message
            Log.info(self.info_string(), message, '-', error_type.__name__, ':', value)
        self.close()

    def close(self):
        if self.client_connection:
            self.client_connection.server_connection = None
            with contextlib.suppress(AttributeError):
                self.client_connection.close()
            self.client_connection = None
        with contextlib.suppress(OSError):
            Log.debug(self.info_string(), '--> [ Client disconnected ]')
            super().close()


class IMAPOAuth2ServerConnection(OAuth2ServerConnection):
    """The IMAP server side - watch for the OK AUTHENTICATE response, then ignore all subsequent data"""

    # IMAP: https://tools.ietf.org/html/rfc3501
    # IMAP SASL-IR: https://tools.ietf.org/html/rfc4959
    def __init__(self, connection_socket, socket_map, proxy_parent, custom_configuration):
        super().__init__('IMAP', connection_socket, socket_map, proxy_parent, custom_configuration)

    def process_data(self, byte_data):
        # note: there is no reason why IMAP STARTTLS (https://tools.ietf.org/html/rfc2595) couldn't be supported here
        # as with SMTP, but all well-known servers provide a non-STARTTLS variant, so left unimplemented for now
        str_response = byte_data.decode('utf-8', 'replace').rstrip('\r\n')

        # if authentication succeeds (or fails), remove our proxy from the client and ignore all further communication
        # don't use a regex here as the tag must match exactly; RFC 3501 specifies uppercase 'OK', so startswith is fine
        if str_response.startswith('%s OK' % self.client_connection.authentication_tag):
            Log.info(self.info_string(), '[ Successfully authenticated IMAP connection - releasing session ]')
            self.client_connection.authenticated = True
        elif str_response.startswith('%s NO' % self.client_connection.authentication_tag):
            super().process_data(byte_data)  # an error occurred - just send to the client and exit
            self.close()
            return

        # intercept pre-auth CAPABILITY response to advertise only AUTH=PLAIN (+SASL-IR) and re-enable LOGIN if required
        if IMAP_CAPABILITY_MATCHER.match(str_response):
            capability = r'[!#$&\'+-\[^-z|}~]+'  # https://ietf.org/rfc/rfc9051.html#name-formal-syntax
            updated_response = re.sub('( AUTH=%s)+' % capability, ' AUTH=PLAIN', str_response, flags=re.IGNORECASE)
            if not re.search(' AUTH=PLAIN', updated_response, re.IGNORECASE):
                # cannot just replace e.g., one 'CAPABILITY ' match because IMAP4 must be first if present (RFC 1730)
                updated_response = re.sub('(CAPABILITY)( IMAP%s)?' % capability, r'\1\2 AUTH=PLAIN', updated_response,
                                          count=1, flags=re.IGNORECASE)
            updated_response = updated_response.replace(' AUTH=PLAIN', '', updated_response.count(' AUTH=PLAIN') - 1)
            if not re.search(' SASL-IR', updated_response, re.IGNORECASE):
                updated_response = updated_response.replace(' AUTH=PLAIN', ' AUTH=PLAIN SASL-IR')
            updated_response = re.sub(' LOGINDISABLED', '', updated_response, count=1, flags=re.IGNORECASE)
            byte_data = (b'%s\r\n' % updated_response.encode('utf-8'))

        super().process_data(byte_data)


class POPOAuth2ServerConnection(OAuth2ServerConnection):
    """The POP server side - submit credentials, then watch for +OK and ignore subsequent data"""

    # POP3: https://tools.ietf.org/html/rfc1939
    # POP3 CAPA: https://tools.ietf.org/html/rfc2449
    # POP3 AUTH: https://tools.ietf.org/html/rfc1734
    # POP3 SASL: https://tools.ietf.org/html/rfc5034
    def __init__(self, connection_socket, socket_map, proxy_parent, custom_configuration):
        super().__init__('POP', connection_socket, socket_map, proxy_parent, custom_configuration)
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
                Log.info(self.info_string(), '[ Successfully authenticated POP connection - releasing session ]')
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

    def __init__(self, connection_socket, socket_map, proxy_parent, custom_configuration):
        super().__init__('SMTP', connection_socket, socket_map, proxy_parent, custom_configuration)
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
            updated_response = re.sub('250([ -])AUTH( [!-*,-<>-~]+)+', r'250\1AUTH PLAIN LOGIN', str_data,
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
                    self.send(b'%s\r\n' % OAuth2Helper.encode_oauth2_string(result), censor_log=True)

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
                Log.info(self.info_string(), '[ Successfully authenticated SMTP connection - releasing session ]')
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
        return '%s server at %s (%s) proxying %s (%s)' % (
            self.proxy_type, Log.format_host_port(self.local_address),
            'TLS' if self.ssl_connection else 'unsecured', Log.format_host_port(self.server_address),
            'STARTTLS' if self.custom_configuration['starttls'] else 'SSL/TLS')

    def handle_accept(self):
        Log.debug('New incoming connection to', self.info_string())
        connected_address = self.accept()
        if connected_address:
            self.handle_accepted(*connected_address)
        else:
            Log.debug('Ignoring incoming connection to', self.info_string(), '- no connection information')

    def handle_accepted(self, connection_socket, address):
        if MAX_CONNECTIONS <= 0 or len(self.client_connections) < MAX_CONNECTIONS:
            new_server_connection = None
            try:
                Log.info('Accepting new connection from', Log.format_host_port(connection_socket.getpeername()),
                         'to', self.info_string())
                socket_map = {}
                server_class = globals()['%sOAuth2ServerConnection' % self.proxy_type]
                new_server_connection = server_class(connection_socket, socket_map, self, self.custom_configuration)
                client_class = globals()['%sOAuth2ClientConnection' % self.proxy_type]
                new_client_connection = client_class(connection_socket, socket_map, self, self.custom_configuration)
                new_server_connection.client_connection = new_client_connection
                new_client_connection.server_connection = new_server_connection
                self.client_connections.append(new_client_connection)

                threading.Thread(target=OAuth2Proxy.run_server, args=(new_client_connection, socket_map),
                                 name='EmailOAuth2Proxy-connection-%d' % address[1], daemon=True).start()

            except Exception:
                connection_socket.close()
                if new_server_connection:
                    new_server_connection.close()
                raise
        else:
            error_text = '%s rejecting new connection above MAX_CONNECTIONS limit of %d' % (
                self.info_string(), MAX_CONNECTIONS)
            Log.error(error_text)
            connection_socket.send(b'%s\r\n' % self.bye_message(error_text).encode('utf-8'))
            connection_socket.close()

    @staticmethod
    def run_server(client, socket_map):
        try:
            asyncore.loop(map=socket_map)  # loop for a single connection thread
        except Exception as e:
            if not EXITING:
                # OSError 9 = 'Bad file descriptor', thrown when closing connections after network interruption
                if isinstance(e, OSError) and e.errno == errno.EBADF:
                    Log.debug(client.info_string(), '[ Connection failed ]')
                else:
                    Log.info(client.info_string(), 'Caught asyncore exception in thread loop:', Log.error_string(e))

    def start(self):
        Log.info('Starting', self.info_string())
        self.create_socket()
        self.set_reuse_addr()
        self.bind(self.local_address)
        self.listen(5)

    def create_socket(self, socket_family=socket.AF_UNSPEC, socket_type=socket.SOCK_STREAM):
        # listen using both IPv4 and IPv6 where possible (python 3.8 and later)
        socket_family = socket.AF_INET6 if socket_family == socket.AF_UNSPEC else socket_family
        if socket_family != socket.AF_INET:
            try:
                socket.getaddrinfo(self.local_address[0], self.local_address[1], socket_family, socket.SOCK_STREAM)
            except OSError:
                socket_family = socket.AF_INET
        new_socket = socket.socket(socket_family, socket_type)
        if socket_family == socket.AF_INET6 and getattr(socket, 'has_dualstack_ipv6', False):
            new_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        new_socket.setblocking(False)

        if self.ssl_connection:
            # noinspection PyTypeChecker
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            try:
                ssl_context.load_cert_chain(certfile=self.custom_configuration['local_certificate_path'],
                                            keyfile=self.custom_configuration['local_key_path'])
            except FileNotFoundError as e:
                raise FileNotFoundError('Unable to open `local_certificate_path` and/or `local_key_path`') from e

            # suppress_ragged_eofs=True: see test_ssl.py documentation in https://github.com/python/cpython/pull/5266
            self.set_socket(ssl_context.wrap_socket(new_socket, server_side=True, suppress_ragged_eofs=True,
                                                    do_handshake_on_connect=False))
        else:
            self.set_socket(new_socket)

    def remove_client(self, client):
        if client in self.client_connections:  # remove closed clients
            self.client_connections.remove(client)
        else:
            Log.info('Warning:', self.info_string(), 'unable to remove orphan client connection', client)

    def bye_message(self, error_text=None):
        if self.proxy_type == 'IMAP':
            return '* BYE %s' % ('Server shutting down' if error_text is None else error_text)
        if self.proxy_type == 'POP':
            return '+OK Server signing off' if error_text is None else ('-ERR %s' % error_text)
        if self.proxy_type == 'SMTP':
            return '221 %s' % ('2.0.0 Service closing transmission channel' if error_text is None else error_text)
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
        error_type, value = Log.get_last_error()
        if error_type == socket.gaierror and value.errno in [-2, 8, 11001] or \
                error_type == TimeoutError and value.errno == errno.ETIMEDOUT or \
                issubclass(error_type, ConnectionError) and value.errno in [errno.ECONNRESET, errno.ECONNREFUSED] or \
                error_type == OSError and value.errno in [0, errno.EINVAL, errno.ENETDOWN, errno.EHOSTUNREACH]:
            # gaierror -2 or 8 = 'nodename nor servname provided, or not known' / 11001 = 'getaddrinfo failed' (caused
            # by getpeername() failing due to no connection); TimeoutError 60 = 'Operation timed out'; ConnectionError
            # 54 = 'Connection reset by peer', 61 = 'Connection refused; OSError 0 = 'Error' (local SSL failure),
            # 22 = 'Invalid argument' (same cause as gaierror 11001), 50 = 'Network is down', 65 = 'No route to host'
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
        error_type, value = Log.get_last_error()
        if error_type and value:
            Log.info(self.info_string(), 'Caught connection error -', error_type.__name__, ':', value)
        Log.info('Unexpected close of proxy connection - restarting', self.info_string())
        try:
            self.restart()
        except Exception as e:
            Log.error('Abandoning restart of', self.info_string(), 'due to repeated exception:', Log.error_string(e))


if sys.platform == 'darwin':
    # noinspection PyUnresolvedReferences,PyMethodMayBeStatic,PyPep8Naming
    class ProvisionalNavigationBrowserDelegate:
        """Used to give pywebview the ability to navigate to unresolved local URLs (only required for macOS)"""

        # note: there is also webView_didFailProvisionalNavigation_withError_ as a broader alternative to these two
        # callbacks, but using that means that window.get_current_url() returns None when the loaded handler is called
        def webView_didStartProvisionalNavigation_(self, web_view, _nav):
            # called when a user action (i.e., clicking our external authorisation mode submit button) redirects locally
            browser_view_instance = webview.platforms.cocoa.BrowserView.get_instance('webkit', web_view)
            if browser_view_instance:
                browser_view_instance.loaded.set()

        def webView_didReceiveServerRedirectForProvisionalNavigation_(self, web_view, _nav):
            # called when the server initiates a local redirect
            browser_view_instance = webview.platforms.cocoa.BrowserView.get_instance('webkit', web_view)
            if browser_view_instance:
                browser_view_instance.loaded.set()

        def performKeyEquivalent_(self, event):
            # modify the popup's default cmd+q behaviour to close the window rather than inadvertently exiting the proxy
            if event.type() == AppKit.NSKeyDown and event.modifierFlags() & AppKit.NSCommandKeyMask and \
                    event.keyCode() == 12 and self.window().firstResponder():
                self.window().performClose_(event)
                return True
            return webview.platforms.cocoa.BrowserView.WebKitHost.performKeyEquivalentBase_(self, event)

if sys.platform == 'darwin':
    # noinspection PyUnresolvedReferences
    class UserNotificationCentreDelegate(AppKit.NSObject):
        # noinspection PyPep8Naming,PyMethodMayBeStatic
        def userNotificationCenter_shouldPresentNotification_(self, _notification_centre, _notification):
            # the notification centre often decides that notifications shouldn't be presented; we want to override that
            return AppKit.YES

        # noinspection PyPep8Naming
        def userNotificationCenter_didActivateNotification_(self, _notification_centre, notification):
            notification_text = notification.informativeText()
            if 'Please authorise your account ' in notification_text:  # hacky, but all we have is the text
                self._click(notification_text.split('account ')[-1].split(' ')[0])

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

            # we add a small icon to show whether the local connection uses SSL; non-secured servers have a blank space
            half_thickness = int(self._status_bar.thickness()) / 2  # half of menu bar size (see _assert_image() below)
            locked_image_data = AppKit.NSData(base64.b64decode(SECURE_SERVER_ICON))
            self._refresh_delegate._locked_image = AppKit.NSImage.alloc().initWithData_(locked_image_data)
            self._refresh_delegate._locked_image.setSize_((half_thickness, half_thickness))
            self._refresh_delegate._locked_image.setTemplate_(AppKit.YES)
            self._refresh_delegate._unlocked_image = AppKit.NSImage.alloc().init()
            self._refresh_delegate._unlocked_image.setSize_((half_thickness, half_thickness))

            super()._mark_ready()

        # noinspection PyUnresolvedReferences
        class MenuDelegate(AppKit.NSObject):
            # noinspection PyMethodMayBeStatic,PyProtectedMember,PyPep8Naming
            def menuNeedsUpdate_(self, sender):
                # add an icon to highlight which local connections are secured (only if at least one is present), and
                # update account menu items' last activity times from config cache - it would be better to delegate this
                # entirely to App.create_config_menu() via update_menu(), but can't replace the menu while creating it
                config_accounts = AppConfig.accounts()
                menu_items = sender._itemArray()

                has_local_ssl = False  # only add hints if at least one local server uses a secure connection
                ssl_string = '    '
                for item in menu_items:
                    if 'Y_SSL    ' in item.title():
                        has_local_ssl = True
                        ssl_string = ''
                        break

                for item in menu_items:
                    item_title = item.title()
                    if '_SSL    ' in item_title:  # need to use a placeholder because we only have the title to match
                        if has_local_ssl:
                            item.setImage_(self._locked_image if 'Y_SSL    ' in item_title else self._unlocked_image)
                        item.setTitle_(item_title.replace('N_SSL    ', ssl_string).replace('Y_SSL    ', ssl_string))
                        continue

                    for account in config_accounts:
                        account_title = '    %s (' % account  # needed to avoid matching other menu items
                        if account_title in item_title:
                            item.setTitle_(App.get_last_activity(account))
                            break

        def _assert_image(self):
            # pystray does some scaling which breaks macOS retina icons - we replace that with the actual menu bar size
            bytes_image = io.BytesIO()
            self.icon.save(bytes_image, 'png')
            data = AppKit.NSData(bytes_image.getvalue())
            self._icon_image = AppKit.NSImage.alloc().initWithData_(data)

            thickness = int(self._status_bar.thickness())  # macOS menu bar size: default = 22px, but can be scaled
            self._icon_image.setSize_((thickness, thickness))
            self._icon_image.setTemplate_(AppKit.YES)  # so macOS applies default shading + inverse on click
            self._status_item.button().setImage_(self._icon_image)


class App:
    """Manage the menu bar icon, server loading, authorisation and notifications, and start the main proxy thread"""

    def __init__(self, args=None):
        global CONFIG_FILE_PATH, CACHE_STORE
        parser = argparse.ArgumentParser(description='%s: transparently add OAuth 2.0 support to IMAP/POP/SMTP client '
                                                     'applications, scripts or any other email use-cases that don\'t '
                                                     'support this authentication method.' % APP_NAME, add_help=False,
                                         epilog='Full readme and guide: https://github.com/simonrob/email-oauth2-proxy')
        group_gui = parser.add_argument_group(title='appearance')
        group_gui.add_argument('--no-gui', action='store_false', dest='gui',
                               help='start the proxy without a menu bar icon (note: account authorisation requests '
                                    'will fail unless a pre-authorised `--config-file` is used, or you use '
                                    '`--external-auth` or `--local-server-auth` and monitor log/terminal output)')
        group_auth = parser.add_argument_group('authentication methods')
        group_auth.add_argument('--external-auth', action='store_true',
                                help='handle authorisation externally: rather than intercepting `redirect_uri`, the '
                                     'proxy will wait for you to paste the result into either its popup window (GUI '
                                     'mode) or the terminal (no-GUI mode; requires `prompt_toolkit`)')
        group_auth.add_argument('--local-server-auth', action='store_true',
                                help='handle authorisation by printing request URLs to the log and starting a local '
                                     'web server on demand to receive responses')
        group_config = parser.add_argument_group('server, account and runtime configuration')
        group_config.add_argument('--config-file', default=None,
                                  help='the full path to the proxy\'s configuration file (optional; default: `%s` in '
                                       'the same directory as the proxy script)' % os.path.basename(CONFIG_FILE_PATH))
        group_config.add_argument('--cache-store', default=None,
                                  help='the full path to a local file to use for credential caching (optional; '
                                       'default: save to `--config-file`); alternatively, an external store such as a '
                                       'secrets manager can be used - see readme for instructions and requirements')
        group_debug = parser.add_argument_group('logging, debugging and help')
        group_debug.add_argument('--log-file', default=None,
                                 help='the full path to a file where log output should be sent (optional; default log '
                                      'behaviour varies by platform - see readme for details)')
        group_debug.add_argument('--debug', action='store_true',
                                 help='enable debug mode, sending all client<->proxy<->server communication to the '
                                      'proxy\'s log')
        group_debug.add_argument('--version', action='version', version='%s %s' % (APP_NAME, __version__),
                                 help='show the proxy\'s version string and exit')
        group_debug.add_argument('-h', '--help', action='help', help='show this help message and exit')

        self.args = parser.parse_args(args)

        Log.initialise(self.args.log_file)
        self.toggle_debug(self.args.debug, log_message=False)

        if self.args.config_file:
            CONFIG_FILE_PATH = CACHE_STORE = self.args.config_file
        if self.args.cache_store:
            CACHE_STORE = self.args.cache_store

        self.proxies = []
        self.authorisation_requests = []

        self.web_view_started = False
        self.macos_web_view_queue = queue.Queue()  # authentication window events (macOS only)

        self.init_platforms()

        if not self.args.gui and self.args.external_auth:
            try:
                # prompt_toolkit is a relatively recent dependency addition that is only required in no-GUI external
                # authorisation mode, but may not be present if only the proxy script itself has been updated
                import prompt_toolkit
            except ImportError:
                Log.error('Unable to load prompt_toolkit, which is a requirement when using `--external-auth` in',
                          '`--no-gui` mode. Please run `python -m pip install -r requirements-core.txt`')
                self.exit(None)
                return

        if self.args.gui and len(MISSING_GUI_REQUIREMENTS) > 0:
            Log.error('Unable to load all GUI requirements:', MISSING_GUI_REQUIREMENTS, '- did you mean to run in',
                      '`--no-gui` mode? If not, please run `python -m pip install -r requirements-gui.txt`')
            self.exit(None)
            return

        if self.args.gui:
            self.icon = self.create_icon()
            try:
                self.icon.run(self.post_create)
            except NotImplementedError:
                Log.error('Unable to initialise icon - did you mean to run in `--no-gui` mode?')
                self.exit(None)
                # noinspection PyProtectedMember
                self.icon._Icon__queue.put(False)  # pystray sets up the icon thread even in dummy mode; need to exit
        else:
            self.icon = None
            self.post_create(None)

    # PyAttributeOutsideInit inspection suppressed because init_platforms() is itself called from __init__()
    # noinspection PyUnresolvedReferences,PyAttributeOutsideInit
    def init_platforms(self):
        if sys.platform == 'darwin' and self.args.gui:
            # hide dock icon (but not LSBackgroundOnly as we need input via webview)
            info = AppKit.NSBundle.mainBundle().infoDictionary()
            info['LSUIElement'] = '1'

            # need to delegate and override to show both "authenticate now" and "authentication success" notifications
            self.macos_user_notification_centre_delegate = UserNotificationCentreDelegate.alloc().init()
            setattr(self.macos_user_notification_centre_delegate, '_click', lambda m: self.authorise_account(None, m))

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

            # on macOS, catching SIGINT/SIGTERM/SIGQUIT/SIGHUP while in pystray's main loop needs a Mach signal handler
            PyObjCTools.MachSignals.signal(signal.SIGINT, lambda _signum: self.exit(self.icon))
            PyObjCTools.MachSignals.signal(signal.SIGTERM, lambda _signum: self.exit(self.icon))
            PyObjCTools.MachSignals.signal(signal.SIGQUIT, lambda _signum: self.exit(self.icon))
            PyObjCTools.MachSignals.signal(signal.SIGHUP, lambda _signum: self.load_and_start_servers(self.icon))
            PyObjCTools.MachSignals.signal(signal.SIGUSR1, lambda _: self.toggle_debug(Log.get_level() == logging.INFO))

        else:
            # for other platforms, or in no-GUI mode, just try to exit gracefully if SIGINT/SIGTERM/SIGQUIT is received
            signal.signal(signal.SIGINT, lambda _signum, _frame: self.exit(self.icon))
            signal.signal(signal.SIGTERM, lambda _signum, _frame: self.exit(self.icon))
            if hasattr(signal, 'SIGQUIT'):  # not all signals exist on all platforms (e.g., Windows)
                signal.signal(signal.SIGQUIT, lambda _signum, _frame: self.exit(self.icon))
            if hasattr(signal, 'SIGHUP'):
                # allow config file reloading without having to stop/start - e.g.: pkill -SIGHUP -f emailproxy.py
                # (we don't use linux_restart() here as it exits then uses nohup to restart, which may not be desirable)
                signal.signal(signal.SIGHUP, lambda _signum, _frame: self.load_and_start_servers(self.icon))
            if hasattr(signal, 'SIGUSR1'):
                # use SIGUSR1 as a toggle for debug mode (e.g.: pkill -USR1 -f emailproxy.py) - please note that the
                # proxy's handling of this signal may change in future if other actions are seen as more suitable
                signal.signal(signal.SIGUSR1, lambda _signum, _fr: self.toggle_debug(Log.get_level() == logging.INFO))

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

    # noinspection PyDeprecation
    def create_icon(self):
        # fix pystray <= 0.19.4 incompatibility with PIL 10.0.0+; resolved in 0.19.5 and later via pystray PR #147
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            pystray_version = pkg_resources.get_distribution('pystray').version
            pillow_version = pkg_resources.get_distribution('pillow').version
            if pkg_resources.parse_version(pystray_version) <= pkg_resources.parse_version('0.19.4') and \
                    pkg_resources.parse_version(pillow_version) >= pkg_resources.parse_version('10.0.0'):
                Image.ANTIALIAS = Image.LANCZOS
        icon_class = RetinaIcon if sys.platform == 'darwin' else pystray.Icon
        return icon_class(APP_NAME, App.get_image(), APP_NAME, menu=pystray.Menu(
            pystray.MenuItem('Servers and accounts', pystray.Menu(self.create_config_menu)),
            pystray.MenuItem('Authorise account', pystray.Menu(self.create_authorisation_menu)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Start at login', self.toggle_start_at_login, checked=self.started_at_login),
            pystray.MenuItem('Debug mode', lambda _, item: self.toggle_debug(not item.checked),
                             checked=lambda _: Log.get_level() == logging.DEBUG),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quit %s' % APP_NAME, self.exit)))

    @staticmethod
    def get_image():
        # we use an icon font for better multiplatform compatibility and icon size flexibility
        icon_colour = 'white'  # see below: colour is handled differently per-platform
        icon_character = 'e'
        icon_background_width = 44
        icon_background_height = 44
        icon_width = 40  # to allow for padding between icon and background image size

        # the colour value is irrelevant on macOS - we configure the menu bar icon as a template to get the platform's
        # colours - but on Windows (and in future potentially Linux) we need to set based on the current theme type
        if sys.platform == 'win32':
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize')
                icon_colour = 'black' if winreg.QueryValueEx(key, 'SystemUsesLightTheme')[0] else 'white'
            except FileNotFoundError:
                pass

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
        # noinspection PyDeprecation
        if pkg_resources.parse_version(
                pkg_resources.get_distribution('pillow').version) < pkg_resources.parse_version('9.2.0'):
            font_width, font_height = font.getsize(text)
            return font, font_width, font_height

        _left, _top, right, bottom = font.getbbox(text)
        return font, right, bottom

    def create_config_menu(self):
        items = []
        if len(self.proxies) <= 0:
            # note that we don't actually allow no servers when loading the config, so no need to generate a menu
            return items  # (avoids creating and then immediately regenerating the menu when servers are loaded)
        else:
            for server_type in ['IMAP', 'POP', 'SMTP']:
                items.extend(App.get_config_menu_servers(self.proxies, server_type))

        config_accounts = AppConfig.accounts()
        items.append(pystray.MenuItem('Accounts (+ last authenticated activity):', None, enabled=False))
        if len(config_accounts) <= 0:
            items.append(pystray.MenuItem('    No accounts configured', None, enabled=False))
        else:
            catch_all_enabled = AppConfig.get_global('allow_catch_all_accounts', fallback=False)
            catch_all_accounts = []
            for account in config_accounts:
                if account.startswith('@') and catch_all_enabled:
                    catch_all_accounts.append(account)
                else:
                    items.append(pystray.MenuItem(App.get_last_activity(account), None, enabled=False))
            if len(catch_all_accounts) > 0:
                items.append(pystray.Menu.SEPARATOR)
                items.append(pystray.MenuItem('Catch-all accounts:', None, enabled=False))
                for account in catch_all_accounts:
                    items.append(pystray.MenuItem('    %s' % account, None, enabled=False))
            if sys.platform != 'darwin':
                items.append(pystray.MenuItem('    Refresh activity data', self.icon.update_menu))
        items.append(pystray.Menu.SEPARATOR)

        items.append(pystray.MenuItem('Edit configuration file...', lambda: self.system_open(CONFIG_FILE_PATH)))

        # asyncore sockets on Linux have a shutdown delay (the time.sleep() call in asyncore.poll), which means we can't
        # easily reload the server configuration without exiting the script and relying on daemon threads to be stopped
        items.append(pystray.MenuItem('Reload configuration file', self.linux_restart if sys.platform.startswith(
            'linux') else self.load_and_start_servers))
        return items

    @staticmethod
    def get_config_menu_servers(proxies, server_type):
        items = []
        heading_appended = False
        for proxy in filter(lambda p: p.proxy_type == server_type, proxies):
            if not heading_appended:
                items.append(pystray.MenuItem('%s servers:' % server_type, None, enabled=False))
                heading_appended = True
            items.append(pystray.MenuItem('%s    %s ➝ %s' % (
                ('Y_SSL' if proxy.ssl_connection else 'N_SSL') if sys.platform == 'darwin' else '',
                Log.format_host_port(proxy.local_address), Log.format_host_port(proxy.server_address)),
                                          None, enabled=False))
        if heading_appended:
            items.append(pystray.Menu.SEPARATOR)
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
    def system_open(path):
        AppConfig.save()  # so we are always editing the most recent version of the file
        if sys.platform == 'darwin':
            result = subprocess.call(['open', path])
            if result != 0:  # no default editor found for this file type; open as a text file
                subprocess.call(['open', '-t', path])
        elif sys.platform == 'win32':
            os.startfile(path)
        elif sys.platform.startswith('linux'):
            subprocess.call(['xdg-open', path])
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
                    self.macos_web_view_queue.put(request)  # future requests need to use the same thread
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
        # noinspection PyDeprecation
        if pkg_resources.parse_version(
                pkg_resources.get_distribution('pywebview').version) < pkg_resources.parse_version('3.6'):
            # noinspection PyUnresolvedReferences
            authorisation_window.loaded += self.authorisation_window_loaded
        else:
            authorisation_window.events.loaded += self.authorisation_window_loaded

    def handle_authorisation_windows(self):
        if sys.platform != 'darwin':
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
        try:
            setattr(webview.platforms.cocoa.BrowserView.WebKitHost, 'performKeyEquivalentBase_',
                    webview.platforms.cocoa.BrowserView.WebKitHost.performKeyEquivalent_)
            setattr(webview.platforms.cocoa.BrowserView.WebKitHost, 'performKeyEquivalent_',
                    ProvisionalNavigationBrowserDelegate.performKeyEquivalent_)
        except TypeError:
            pass

        # also needed only on macOS because otherwise closing the last remaining webview window exits the application
        dummy_window = webview.create_window('%s hidden (dummy) window' % APP_NAME, html='<html></html>', hidden=True)
        dummy_window.hide()  # hidden=True (above) doesn't seem to work in all cases

        while True:
            data = self.macos_web_view_queue.get()  # note: blocking call
            if data is QUEUE_SENTINEL:  # app is closing
                break
            self.create_authorisation_window(data)

    def authorisation_window_loaded(self):
        for window in webview.windows[:]:  # iterate over a copy; remove (in destroy()) from original
            if not hasattr(window, 'get_title'):
                continue  # skip dummy window

            url = window.get_current_url()
            # noinspection PyUnresolvedReferences
            username = window.get_title(window).split(' ')[-1]  # see note above: title *must* match this format
            if not url or not username:
                continue  # skip any invalid windows

            # respond to both the original request and any duplicates in the list
            completed_request = None
            for request in self.authorisation_requests[:]:  # iterate over a copy; remove from original
                if request['username'] == username and OAuth2Helper.match_redirect_uri(request['redirect_uri'], url):
                    Log.info('Returning authorisation request result for', request['username'])
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
            self.notify(APP_NAME, 'Authentication completed for %s' % completed_request['username'])
            if len(self.authorisation_requests) > 0:
                self.notify(APP_NAME, 'Please authorise your account %s from the menu' % self.authorisation_requests[0][
                    'username'])

    def toggle_start_at_login(self, icon, force_rewrite=False):
        # we reuse this function to force-overwrite the startup file when changing the external auth option, but pystray
        # verifies actions have a maximum of two parameters (_assert_action()), so we must use 'item' and check its type
        recreate_login_file = False if isinstance(force_rewrite, pystray.MenuItem) else force_rewrite

        start_command = self.get_script_start_command(quote_args=sys.platform != 'darwin')  # plistlib handles quoting

        if sys.platform == 'darwin':
            if recreate_login_file or not PLIST_FILE_PATH.exists():
                # need to create and load the plist
                plist = {
                    'Label': APP_PACKAGE,
                    'RunAtLoad': True
                }
            else:
                # just toggle the disabled value rather than loading/unloading, so we don't need to restart the proxy
                with open(PLIST_FILE_PATH, mode='rb') as plist_file:
                    plist = plistlib.load(plist_file)
                plist['Disabled'] = True if 'Disabled' not in plist else not plist['Disabled']

            plist['Program'] = start_command[0]
            plist['ProgramArguments'] = start_command

            os.makedirs(PLIST_FILE_PATH.parent, exist_ok=True)
            with open(PLIST_FILE_PATH, mode='wb') as plist_file:
                plistlib.dump(plist, plist_file)

            # if loading, need to exit so we're not running twice (also exits the terminal instance for convenience)
            if not self.macos_launchctl('list'):
                self.exit(icon, restart_callback=lambda: self.macos_launchctl('load'))
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
                windows_start_command = 'start "" %s' % ' '.join(start_command)  # first quoted start arg = window title

                os.makedirs(CMD_FILE_PATH.parent, exist_ok=True)
                with open(CMD_FILE_PATH, mode='w', encoding='utf-8') as cmd_file:
                    cmd_file.write(windows_start_command)

                # on Windows we don't have a service to run, but it is still useful to exit the terminal instance
                if sys.stdin and sys.stdin.isatty() and not recreate_login_file:
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
                with open(AUTOSTART_FILE_PATH, mode='w', encoding='utf-8') as desktop_file:
                    desktop_file.write('[Desktop Entry]\n')
                    for key, value in xdg_autostart.items():
                        desktop_file.write('%s=%s\n' % (key, value))

                # like on Windows we don't have a service to run, but it is still useful to exit the terminal instance
                if sys.stdin and sys.stdin.isatty() and not recreate_login_file:
                    AppConfig.save()  # because linux_restart needs to unload to prevent saving on exit
                    self.linux_restart(icon)
            else:
                os.remove(AUTOSTART_FILE_PATH)

        else:
            pass  # nothing we can do

    def get_script_start_command(self, quote_args=True):
        python_command = sys.executable
        if sys.platform == 'win32':
            # pythonw to avoid a terminal when background launching on Windows
            python_command = 'pythonw.exe'.join(python_command.rsplit('python.exe', 1))

        script_command = [python_command]
        if not getattr(sys, 'frozen', False):  # no need for the script path if using pyinstaller
            script_command.append(os.path.realpath(__file__))

        # preserve any arguments - note that some are configurable in the GUI, so sys.argv may not be their actual state
        script_command.extend(arg for arg in sys.argv[1:] if arg not in ('--debug', '--external-auth'))
        if Log.get_level() == logging.DEBUG:
            script_command.append('--debug')
        if self.args.external_auth:
            script_command.append('--external-auth')

        return ['"%s"' % arg.replace('"', r'\"') if quote_args and ' ' in arg else arg for arg in script_command]

    def linux_restart(self, icon):
        # Linux restarting is separate because it is used for reloading the configuration file as well as start at login
        AppConfig.unload()  # so that we don't overwrite the just-updated file when exiting
        command = ' '.join(self.get_script_start_command())
        self.exit(icon, restart_callback=lambda: subprocess.call('nohup %s </dev/null >/dev/null 2>&1 &' % command,
                                                                 shell=True))

    @staticmethod
    def macos_launchctl(command):
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
                    with open(PLIST_FILE_PATH, mode='rb') as plist_file:
                        plist = plistlib.load(plist_file)
                    if 'Disabled' in plist:
                        return not plist['Disabled']
                    return True  # job is loaded and is not disabled

        elif sys.platform == 'win32':
            return CMD_FILE_PATH.exists()  # we assume that the file's contents are correct

        elif sys.platform.startswith('linux'):
            return AUTOSTART_FILE_PATH.exists()  # we assume that the file's contents are correct

        return False

    def toggle_debug(self, enable_debug_mode, log_message=True):
        Log.set_level(logging.DEBUG if enable_debug_mode else logging.INFO)
        if log_message:
            Log.info('Setting debug mode:', Log.get_level() == logging.DEBUG)
        if hasattr(self, 'icon') and self.icon:
            self.icon.update_menu()

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
                    notification_centre.setDelegate_(self.macos_user_notification_centre_delegate)
                    notification_centre.deliverNotification_(user_notification)
                except Exception:
                    for replacement in (('\\', r'\\'), ('"', r'\"')):  # osascript approach requires sanitisation
                        text = text.replace(*replacement)
                        title = title.replace(*replacement)
                    subprocess.call(['osascript', '-e', 'display notification "%s" with title "%s"' % (text, title)])

            elif self.icon.HAS_NOTIFICATION:
                self.icon.remove_notification()
                self.icon.notify('%s: %s' % (title, text))

            else:
                Log.info(title, text)  # last resort
        else:
            Log.info(title, text)

    def stop_servers(self):
        global RESPONSE_QUEUE
        RESPONSE_QUEUE.put(QUEUE_SENTINEL)  # watchers use a local reference so won't re-insert into the new queue
        RESPONSE_QUEUE = queue.Queue()  # recreate so existing queue closes watchers but we don't have to wait here
        while True:
            try:
                REQUEST_QUEUE.get(block=False)  # remove any pending requests (unlikely any exist, but safest)
            except queue.Empty:
                break
        for proxy in self.proxies:
            with contextlib.suppress(Exception):
                proxy.stop()
        self.proxies = []
        self.authorisation_requests = []  # these requests are no-longer valid

    def load_and_start_servers(self, icon=None, reload=True):
        # we allow reloading, so must first stop any existing servers
        self.stop_servers()
        Log.info('Initialising', APP_NAME,
                 '(version %s)%s' % (__version__, ' in debug mode' if Log.get_level() == logging.DEBUG else ''),
                 'from config file', CONFIG_FILE_PATH)
        if reload:
            AppConfig.unload()
        config = AppConfig.get()

        # load server types and configurations
        server_load_error = False
        server_start_error = False
        for section in AppConfig.servers():
            match = CONFIG_SERVER_MATCHER.match(section)
            server_type = match.group('type')

            local_address = config.get(section, 'local_address', fallback='::')
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
                    Log.error('Error: unable to start', match.string, 'server:', Log.error_string(e))
                    server_start_error = True

        if server_start_error or server_load_error or len(self.proxies) <= 0:
            if server_start_error:
                Log.error('Abandoning setup as one or more servers failed to start - is the proxy already running?')
            else:
                error_text = 'Invalid' if len(AppConfig.servers()) > 0 else 'No'
                Log.error(error_text, 'server configuration(s) found in', CONFIG_FILE_PATH, '- exiting')
                if not os.path.exists(CONFIG_FILE_PATH):
                    Log.error(APP_NAME, 'config file not found - see https://github.com/simonrob/email-oauth2-proxy',
                              'for full documentation and example configurations to help get started')
                self.notify(APP_NAME, error_text + ' server configuration(s) found. ' +
                            'Please verify your account and server details in %s' % CONFIG_FILE_PATH)
            AppConfig.unload()  # so we don't overwrite the invalid file with a blank configuration
            self.exit(icon)
            return False

        if icon:
            icon.update_menu()  # force refresh the menu to show running proxy servers

        threading.Thread(target=App.run_proxy, name='EmailOAuth2Proxy-main', daemon=True).start()
        Log.info('Initialised', APP_NAME, '- listening for authentication requests. Connect your email client to begin')
        return True

    @staticmethod
    def terminal_external_auth_input(prompt_session, prompt_stop_event, data):
        with contextlib.suppress(Exception):  # cancel any other prompts; thrown if there are none to cancel
            # noinspection PyUnresolvedReferences
            prompt_toolkit.application.current.get_app().exit(exception=EOFError)
            time.sleep(1)  # seems to be needed to allow prompt_toolkit to clean up between prompts

        # noinspection PyUnresolvedReferences
        with prompt_toolkit.patch_stdout.patch_stdout():
            open_time = 0
            response_url = None
            Log.info('Please visit the following URL to authenticate account %s: %s' % (
                data['username'], data['permission_url']))
            # noinspection PyUnresolvedReferences
            style = prompt_toolkit.styles.Style.from_dict({'url': 'underline'})
            prompt = [('', '\nCopy+paste or press [↵ Return] to visit the following URL and authenticate account %s: ' %
                       data['username']), ('class:url', data['permission_url']), ('', ' then paste here the full '),
                      ('', 'post-authentication URL from the browser\'s address bar (it should start with %s): ' %
                       data['redirect_uri'])]
            while True:
                try:
                    response_url = prompt_session.prompt(prompt, style=style)
                except (KeyboardInterrupt, EOFError):
                    break
                if not response_url:
                    if time.time() - open_time > 1:  # don't open many windows on key repeats
                        App.system_open(data['permission_url'])
                        open_time = time.time()
                else:
                    break

            prompt_stop_event.set()  # cancel the timeout thread

            result = {'permission_url': data['permission_url'], 'username': data['username']}
            if response_url:
                Log.debug('No-GUI external auth mode: returning response', response_url)
                result['response_url'] = response_url
            else:
                Log.debug('No-GUI external auth mode: no response provided; cancelling authorisation request')
                result['expired'] = True
            RESPONSE_QUEUE.put(result)

    @staticmethod
    def terminal_external_auth_timeout(prompt_session, prompt_stop_event):
        prompt_time = 0
        while prompt_time < AUTHENTICATION_TIMEOUT and not prompt_stop_event.is_set():
            time.sleep(1)
            prompt_time += 1

        if not prompt_stop_event.is_set():
            with contextlib.suppress(Exception):  # thrown if the prompt session has already exited
                prompt_session.app.exit(exception=EOFError)
                time.sleep(1)  # seems to be needed to allow prompt_toolkit to clean up between prompts

    def terminal_external_auth_prompt(self, data):
        # noinspection PyUnresolvedReferences
        prompt_session = prompt_toolkit.PromptSession()
        prompt_stop_event = threading.Event()
        threading.Thread(target=self.terminal_external_auth_input, args=(prompt_session, prompt_stop_event, data),
                         daemon=True).start()
        threading.Thread(target=self.terminal_external_auth_timeout, args=(prompt_session, prompt_stop_event),
                         daemon=True).start()

    def post_create(self, icon):
        if EXITING:
            return  # to handle launch in pystray 'dummy' mode without --no-gui option (partial initialisation failure)

        if icon:
            icon.visible = True

        if not self.load_and_start_servers(icon, reload=False):
            return

        while True:
            data = REQUEST_QUEUE.get()  # note: blocking call
            if data is QUEUE_SENTINEL:  # app is closing
                break
            if data is MENU_UPDATE:
                if icon:
                    icon.update_menu()
                continue
            if not data['expired']:
                Log.info('Authorisation request received for', data['username'],
                         '(local server auth mode)' if self.args.local_server_auth else '(external auth mode)' if
                         self.args.external_auth else '(interactive mode)')
                if self.args.local_server_auth:
                    self.notify(APP_NAME, 'Local server auth mode: please authorise a request for account %s' %
                                data['username'])
                    data['local_server_auth'] = True
                    RESPONSE_QUEUE.put(data)  # local server auth is handled by the client/server connections
                elif self.args.external_auth and not self.args.gui:
                    if sys.stdin and sys.stdin.isatty():
                        self.notify(APP_NAME, 'No-GUI external auth mode: please authorise a request for account '
                                              '%s' % data['username'])
                        self.terminal_external_auth_prompt(data)
                    else:
                        Log.error('Not running interactively; unable to handle no-GUI external auth request')
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

        if sys.platform == 'darwin' and self.args.gui:
            # noinspection PyUnresolvedReferences
            SystemConfiguration.SCNetworkReachabilityUnscheduleFromRunLoop(self.macos_reachability_target,
                                                                           SystemConfiguration.CFRunLoopGetCurrent(),
                                                                           SystemConfiguration.kCFRunLoopDefaultMode)

        REQUEST_QUEUE.put(QUEUE_SENTINEL)
        RESPONSE_QUEUE.put(QUEUE_SENTINEL)

        if self.web_view_started:
            self.macos_web_view_queue.put(QUEUE_SENTINEL)
            for window in webview.windows[:]:  # iterate over a copy; remove (in destroy()) from original
                window.show()
                window.destroy()

        for proxy in self.proxies:  # no need to copy - proxies are never removed, we just restart them on error
            with contextlib.suppress(Exception):
                proxy.stop()

        if icon:
            # work around a pystray issue with removing the macOS status bar icon when started from a parent script
            if sys.platform == 'darwin':
                # noinspection PyProtectedMember
                icon._status_item.button().setImage_(None)
            icon.stop()

        # for the 'Start at login' option we need a callback to restart the script the first time this preference is
        # configured (macOS) or every time (other platforms) - note that just as in toggle_start_at_login(), pystray
        # verifies that actions have a maximum of two parameters, so we must override the 'item' one but check its type
        if restart_callback and not isinstance(restart_callback, pystray.MenuItem):
            Log.info('Restarted', APP_NAME, 'as a background task')
            restart_callback()

        # macOS Launch Agents need reloading when changed; unloading exits immediately so this must be our final action
        if sys.platform == 'darwin' and self.args.gui and self.macos_unload_plist_on_exit:
            self.macos_launchctl('unload')

        EXITING = False  # to allow restarting when imported from parent scripts (or an interpreter)


if __name__ == '__main__':
    App()

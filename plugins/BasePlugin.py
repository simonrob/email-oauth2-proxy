"""Extend this class to create Email OAuth 2.0 Proxy plugins that customise IMAP/POP/SMTP client/server behaviour. The
two overridable methods `receive_from_client` and `receive_from_server` give access to raw IMAP/POP/SMTP messages and/or
commands as they are received. The return values from the overridden methods and the two sender methods `send_to_server`
and `send_to_client` allow you to send messages/commands to the client/server (and other chained plugins) in response.
The `log_debug`, `log_info` and `log_error` methods allow you to post messages to the proxy's main log. Note that
plugins are inserted after authentication has finished – you will not receive (or be able to send) anything between the
client or server until that process is complete."""


class BasePlugin:
    def __init__(self):
        """Override this method (and call `super().__init__()`) if your plugin needs to receive setup parameters. Any
        named arguments you specify here can be passed as a dictionary within the proxy's configuration file – see the
        sample file for further details.
        Note: logging/sending methods are not available at creation time; do not use them if overriding `__init__`"""
        self.log_debug = lambda *args: None
        self.log_info = lambda *args: None
        self.log_error = lambda *args: None

        self.server_plugin_chain = []
        self.client_plugin_chain = []
        self.send_to_server_root = lambda _: None
        self.send_to_client_root = lambda _: None

    def _attach_log(self, debug, info, error):
        """Internal only - register log methods. Do not override this method."""
        self.log_debug = debug
        self.log_info = info
        self.log_error = error

    def _register_senders(self, server_plugin_chain, server, client_plugin_chain, client):
        """Internal only - register sender methods and other chained plugins. Do not override this method."""
        self.server_plugin_chain = server_plugin_chain
        self.client_plugin_chain = client_plugin_chain
        self.send_to_server_root = server
        self.send_to_client_root = client

    def send_to_server(self, byte_data):
        """Call `send_to_server` to send messages to the server (and any plugins further down the chain). Use only in
        `receive_from_server`; always handle any client sending needs by returning a value from `receive_from_server`.
        Do not override this method."""
        self.log_debug('-->', byte_data)
        if self.server_plugin_chain:
            for plugin in self.server_plugin_chain:
                byte_data = plugin.receive_from_client(byte_data)
                if not byte_data:
                    break  # this plugin has consumed the message; nothing to pass to any subsequent plugins
        if byte_data:
            self.send_to_server_root(byte_data)

    def send_to_client(self, byte_data):
        """Call `send_to_client` to send messages to the client (and any plugins further up the chain). Use only in
        `receive_from_client`; always handle any server sending needs by returning a value from `receive_from_client`.
        Do not override this method."""
        self.log_debug('<--', byte_data)
        if self.client_plugin_chain:
            for plugin in self.client_plugin_chain:
                byte_data = plugin.receive_from_server(byte_data)
                if not byte_data:
                    break  # this plugin has consumed the message; nothing to pass to any subsequent plugins
        if byte_data:
            self.send_to_client_root(byte_data)

    # noinspection PyMethodMayBeStatic
    def receive_from_client(self, byte_data):
        """Override this method to intercept messages received from the local client. Note that received messages are
        not always split into lines / single commands – if the client is permitted by the IMAP/POP/SMTP protocol to send
        messages in chunks, you may well receive them like this. You will also only ever receive a maximum of
        emailproxy.RECEIVE_BUFFER_SIZE bytes – buffering is advised if you need complete messages (see `handle_read` in
        emailproxy.py).
        Whatever you return here will be sent to the remote server (and any other stacked plugins). This can be either:
          - byte_data (unmodified) to pass through received commands with no changes (the default behaviour)
          - an edited byte string to change command behaviour
          - nothing/None if you do not want to send anything to the remote server in response to the received command
        If you need to send messages back to the local client, call `self.send_to_client(byte_message)`. Do not use
        `send_to_server` from here; always handle any sending requirements by returning a value as outlined above."""
        return byte_data

    # noinspection PyMethodMayBeStatic
    def receive_from_server(self, byte_data):
        """Override this method to intercept messages received from the remote server. Note that received messages are
        not always split into lines / single commands – if the server is permitted by the IMAP/POP/SMTP protocol to send
        messages in chunks, you may well receive them like this. You will also only ever receive a maximum of
        emailproxy.RECEIVE_BUFFER_SIZE bytes – buffering is advised if you need complete messages (see `handle_read` in
        emailproxy.py).
        Whatever you return here will be sent to the local client (and any other stacked plugins). This can be either:
          - byte_data (unmodified) to pass through received commands with no changes (the default behaviour)
          - an edited byte string to change command behaviour
          - nothing/None if you do not want to send anything to the local client in response to the received command
        If you need to send messages back to the remote server, call `self.send_to_server(byte_message)`. Do not use
        `send_to_client` from here; always handle any sending requirements by returning a value as outlined above."""
        return byte_data


class IMAP:
    """Parsing IMAP messages almost always requires matching tags – this regular expression pattern matches the formal
    tag syntax and saves having to reimplement or copy/paste in every new plugin"""
    TAG_PATTERN = r"^(?P<tag>[!#$&',-\[\]-z|}~]+)"  # https://ietf.org/rfc/rfc9051.html#name-formal-syntax

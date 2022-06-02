"""Extend this class to create Email OAuth 2.0 Proxy plugins that customise IMAP/SMTP client/server behaviour. The
overridable methods receive_from_client and receive_from_server give access to the raw IMAP/SMTP messages/commands.
Note that plugins are inserted after authentication has finished – you will not receive (or be able to send) anything
between the client or server until that process is complete."""


class BasePlugin:
    def __init__(self):
        """Override this method if your plugin needs to receive setup parameters. Any named arguments you specify here
        can be passed as a dictionary within the proxy's configuration file – see the sample file for further details.
        Note: logging/sending methods are not available at creation time; do not use them if overriding __init__"""
        self.log_debug = None
        self.log_info = None
        self.log_error = None

        self.send_to_server = None
        self.send_to_client = None

    def _attach_log(self, debug, info, error):
        self.log_debug = debug
        self.log_info = info
        self.log_error = error

    def _register_senders(self, server, client):
        self.send_to_server = server
        self.send_to_client = client

    # noinspection PyMethodMayBeStatic
    def receive_from_client(self, byte_data):
        """Override this method to intercept messages received from the local client. Note that received messages are
        not always split into lines / single commands – if the client is permitted by the IMAP/SMTP protocol to send
        messages in chunks, you may well receive them like this. You will also only ever receive a maximum of
        emailproxy.RECEIVE_BUFFER_SIZE bytes – buffering is advised if you need complete messages (see handle_read in
        emailproxy).
        Whatever value you return here will be sent to the remote server. This can be either:
          - byte_data (unmodified) to pass through received commands with no changes (the default behaviour)
          - an edited byte string to change command behaviour
          - nothing/None if you do not want to send anything to the remote server in response to the received command
        If you need to send messages back to the local client, call self.send_to_client(byte_message). Do not use
        self.send_to_server from here; always handle any sending requirements by returning a value as outlined above."""
        return byte_data

    # noinspection PyMethodMayBeStatic
    def receive_from_server(self, byte_data):
        """Override this method to intercept messages received from the remote server. Note that received messages are
        not always split into lines / single commands – if the server is permitted by the IMAP/SMTP protocol to send
        messages in chunks, you may well receive them like this. You will also only ever receive a maximum of
        emailproxy.RECEIVE_BUFFER_SIZE bytes – buffering is advised if you need complete messages (see handle_read in
        emailproxy).
        Whatever value you return here will be sent to the local client. This can be either:
          - byte_data (unmodified) to pass through received commands with no changes (the default behaviour)
          - an edited byte string to change command behaviour
          - nothing/None if you do not want to send anything to the local client in response to the received command
        If you need to send messages back to the remote server, call self.send_to_server(byte_message). Do not use
        self.send_to_client from here; always handle any sending requirements by returning a value as outlined above."""
        return byte_data

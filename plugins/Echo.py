"""An example Email OAuth 2.0 Proxy IMAP plugin that does nothing except call `log_debug` with all received messages. As
a result, it is not specific to IMAP, POP or SMTP, and can be used with any type of server."""

import plugins.BasePlugin


class Echo(plugins.BasePlugin.BasePlugin):
    def receive_from_client(self, byte_data):
        self.log_debug('receive_from_client:', byte_data)
        return byte_data

    def receive_from_server(self, byte_data):
        self.log_debug('receive_from_server:', byte_data)
        return byte_data

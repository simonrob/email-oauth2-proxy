"""An example Email OAuth 2.0 Proxy IMAP plugin that intercepts a single `CAPABILITY` response and modifies it to remove
support for `LITERAL+` (chosen only as a common example for demonstration purposes; this is not a useful plugin)."""

import re

import plugins.BasePlugin

# note that we can't use the same capability matcher as in the main proxy because we need to be able to handle multiline
# messages, whereas the proxy only needs this pre-authentication (where all messages are single line)
IMAP_CAPABILITY_MATCHER = re.compile(b'(?:\\* |\\* OK \\[)CAPABILITY .*', flags=re.IGNORECASE)  # '* ' *and* '* OK ['


class IMAPCapabilityModifier(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        super().__init__()
        self.capability_modified = False

    def receive_from_server(self, byte_data):
        if not self.capability_modified and IMAP_CAPABILITY_MATCHER.match(byte_data):
            self.log_debug('Detected capability response to modify:', byte_data)
            self.capability_modified = True
            return byte_data.replace(b' LITERAL+', b'')
        return byte_data

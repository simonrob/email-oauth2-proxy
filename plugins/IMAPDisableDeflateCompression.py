"""An example Email OAuth 2.0 Proxy IMAP plugin that looks for client requests to enable compression (RFC 1951 and 4978)
and responds with NO every time, so that other plugins can continue to intercept requests. Place this plugin before any
others if you use a client that automatically tries to enable compression when it finds COMPRESS=DEFLATE in a CAPABILITY
response. An alternative option here if you do not need to actually edit messages is to keep compression enabled, but
decompress within the plugin - see IMAPDecodeDeflateCompression.py."""

import re

import plugins.BasePlugin

IMAP_COMPRESS_MATCHER = re.compile(plugins.BasePlugin.IMAP.TAG_PATTERN.encode('utf-8') + b' COMPRESS DEFLATE\r\n',
                                   flags=re.IGNORECASE)


class IMAPDisableDeflateCompression(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        super().__init__()
        self.deflate_sent = False

    def receive_from_client(self, byte_data):
        if not self.deflate_sent:
            # when receiving a COMPRESS DEFLATE command, respond with NO so that the proxy can continue to intercept
            # messages (use in addition to other plugins if they require access to raw IMAP commands)
            match = IMAP_COMPRESS_MATCHER.match(byte_data)  # in testing, faster than case-insensitive 'in' match
            if match:
                self.deflate_sent = True
                self.log_debug('Received COMPRESS command; responding with NO')

                # note: sending a NO (or BAD) response causes a failure notification to be generated in Thunderbird;
                # we would need to be able to intercept the CAPABILITY string (post-authentication) to prevent this
                self.send_to_client(b'%s NO Compression disabled by IMAPDisableDeflateCompression Email OAuth 2.0 '
                                    b'Proxy plugin\r\n' % match.group('tag'))
                return None

        return byte_data  # pass through all other messages unedited

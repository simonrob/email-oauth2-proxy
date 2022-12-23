"""An example Email OAuth 2.0 Proxy IMAP plugin that looks for `COMPRESS=DEFLATE` in server capability responses (RFC
1951 and 4978) and, unlike IMAPDecodeDeflateCompression.py, handles this entirely within the plugin, keeping an
uncompressed channel to the client, but enabling compressed communication with the server. Place this plugin at the end
of the chain in the proxy's configuration file."""

import re
import zlib

import plugins.BasePlugin

# note that we can't use the same capability matcher as in the main proxy because we need to be able to handle multiline
# messages, whereas the proxy only needs this pre-authentication (where all messages are single line)
IMAP_CAPABILITY_MATCHER = re.compile(b'(?:\\* |\\* OK \\[)CAPABILITY .*', flags=re.IGNORECASE)  # '* ' *and* '* OK ['

IMAP_DEFLATE_TAG = b'EOP1'
IMAP_COMPRESS_RESPONSE_MATCHER = re.compile(b'%s OK.+\r\n' % IMAP_DEFLATE_TAG, flags=re.IGNORECASE)


class IMAPDeflateCompressionRemoteEnabler(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        super().__init__()
        self.capability_count = 0  # normally we would receive up to two capability responses (pre- and post-login)
        self.deflate_capability_command = None

        self.deflate_sent = False
        self.deflate_acknowledged = False

        self.server_decompressor = None
        self.client_compressor = None

    def receive_from_client(self, byte_data):
        if self.deflate_acknowledged:
            compressed_data = self.client_compressor.compress(byte_data)
            compressed_data += self.client_compressor.flush(zlib.Z_SYNC_FLUSH)
            return compressed_data

        return byte_data

    def receive_from_server(self, byte_data):
        if not self.deflate_sent and self.capability_count < 2 and IMAP_CAPABILITY_MATCHER.match(byte_data):
            self.capability_count += 1
            if b' COMPRESS=DEFLATE' in byte_data:
                self.log_debug('Detected deflate compression capability; enabling')
                self.deflate_capability_command = byte_data.replace(b' COMPRESS=DEFLATE', b'')
                self.send_to_server(b'%s COMPRESS DEFLATE\r\n' % IMAP_DEFLATE_TAG)
                self.deflate_sent = True
                return None

        if self.deflate_sent:
            if not self.deflate_acknowledged:
                if IMAP_COMPRESS_RESPONSE_MATCHER.match(byte_data):
                    self.log_debug('Received COMPRESS confirmation; starting de/compressors')

                    self.server_decompressor = zlib.decompressobj(-15)
                    self.client_compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)

                    self.deflate_acknowledged = True
                    return self.deflate_capability_command

                self.deflate_capability_command += byte_data  # make sure messages are not received out of order
                return None

            if self.server_decompressor.unconsumed_tail:
                compressed_data = self.server_decompressor.unconsumed_tail + byte_data
            else:
                compressed_data = byte_data
            return self.server_decompressor.decompress(compressed_data)

        return byte_data

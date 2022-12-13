"""An example Email OAuth 2.0 Proxy IMAP plugin that looks for client requests to enable compression (RFC 1951 and 4978)
and, unlike IMAPDisableDeflateCompression.py, permits compression but decompresses messages within the plugin. This
allows monitoring and editing of compressed incoming and outgoing communication (but only within this plugin, not any
others). A further improvement that would allow message editing in any plugin but keep the benefits of compression would
be to disable compression between the client and proxy, but keep it enabled between the proxy and server."""

import re
import zlib

import plugins.BasePlugin

IMAP_TAG_PATTERN = plugins.BasePlugin.IMAP.TAG_PATTERN
IMAP_COMPRESS_START_MATCHER = re.compile(IMAP_TAG_PATTERN + b' COMPRESS DEFLATE\r\n', flags=re.IGNORECASE)
IMAP_COMPRESS_RESPONSE_MATCHER = re.compile(IMAP_TAG_PATTERN + b' OK.+\r\n', flags=re.IGNORECASE)


class IMAPDecodeDeflateCompression(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        super().__init__()
        self.deflate_sent = False
        self.deflate_acknowledged = False

        self.client_decompressor = None
        self.server_decompressor = None

        self.client_compressor = None
        self.server_compressor = None

    def receive_from_client(self, byte_data):
        if not self.deflate_sent:
            if IMAP_COMPRESS_START_MATCHER.match(byte_data):
                self.deflate_sent = True
                self.log_debug('Received COMPRESS command; waiting for confirmation')

        elif self.deflate_acknowledged:
            if self.client_decompressor.unconsumed_tail:
                compressed_data = self.client_decompressor.unconsumed_tail + byte_data
            else:
                compressed_data = byte_data

            decompressed_data = self.client_decompressor.decompress(compressed_data)
            self.log_debug('-->', decompressed_data)

            # *** Do any editing of client commands here ***

            self.log_debug('    -->', decompressed_data)
            byte_data = self.client_compressor.compress(decompressed_data)
            byte_data += self.client_compressor.flush(zlib.Z_SYNC_FLUSH)

        return byte_data  # pass through all messages unedited

    def receive_from_server(self, byte_data):
        if self.deflate_sent:
            if not self.deflate_acknowledged:
                if IMAP_COMPRESS_RESPONSE_MATCHER.match(byte_data):
                    self.log_debug('Received COMPRESS confirmation; enabling decompressors')

                    self.client_decompressor = zlib.decompressobj(-15)
                    self.server_decompressor = zlib.decompressobj(-15)

                    self.client_compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
                    self.server_compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)

                    self.deflate_acknowledged = True

            else:
                if self.server_decompressor.unconsumed_tail:
                    compressed_data = self.server_decompressor.unconsumed_tail + byte_data
                else:
                    compressed_data = byte_data

                decompressed_data = self.server_decompressor.decompress(compressed_data)
                self.log_debug('    <--', decompressed_data)

                # *** Do any editing of server responses here ***

                self.log_debug('<--', decompressed_data)
                byte_data = self.server_compressor.compress(decompressed_data)
                byte_data += self.server_compressor.flush(zlib.Z_SYNC_FLUSH)

        return byte_data

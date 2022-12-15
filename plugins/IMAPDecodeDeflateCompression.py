"""An example Email OAuth 2.0 Proxy IMAP plugin that looks for client requests to enable compression (RFC 1951 and 4978)
and, unlike IMAPDisableDeflateCompression.py, permits compression but decompresses messages within the plugin. This
allows monitoring and editing of compressed incoming and outgoing communication, but only within this plugin, not any
others (and as a result only other deflate-aware plugins can be chained). A further improvement can be found in
IMAPDeflateCompressionRemoteEnabler.py, which enables compression between the proxy and server, but keeps messages
uncompressed between the client and proxy, improving network efficiency and enabling chaining with any other plugin."""

import re
import zlib

import plugins.BasePlugin

IMAP_TAG_PATTERN = plugins.BasePlugin.IMAP.TAG_PATTERN
IMAP_COMPRESS_START_MATCHER = re.compile(b'%s COMPRESS DEFLATE\r\n' % IMAP_TAG_PATTERN, flags=re.IGNORECASE)
IMAP_COMPRESS_RESPONSE_MATCHER = re.compile(b'%s OK.+\r\n' % IMAP_TAG_PATTERN, flags=re.IGNORECASE)


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
                    self.log_debug('Received COMPRESS confirmation; enabling de/compressors')

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

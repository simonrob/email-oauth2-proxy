"""An example Email OAuth 2.0 Proxy IMAP plugin that looks for Office 365 Advanced Threat Protection links (also known
as Safe Links in Microsoft Defender for Office 365) and replaces them with their original values (i.e., removing the
redirect). As with most of the proxy's plugins, it would be more efficient to handle this on the server side (i.e.,
by disabling link modification), but this is not always possible."""

import base64
import binascii
import quopri
import re
import urllib.parse

import plugins.BasePlugin

# note: these patterns operate on byte-strings to avoid having to parse (and potentially cache) message encodings
IMAP_COMMAND_MATCHER = re.compile(b'^\\* \\d+ FETCH ', flags=re.IGNORECASE)
IMAP_FETCH_REQUEST_MATCHER = re.compile(b'^\\* \\d+ FETCH \\(BODY\\[(?:TEXT|1(?:\\.1|\\.2)?|2)] {(?P<length>\\d+)}\r\n',
                                        flags=re.IGNORECASE)  # https://stackoverflow.com/a/37794152
QUOPRI_MATCH_PATTERN = b'=(?:[A-F\\d]{2}|\r\n)'  # similar to above, we need to guess quoted-printable encoding
O365_ATP_MATCHER = re.compile(b'(?P<atp>https://(?:nam|eur)\\d{2}\\.safelinks\\.protection\\.outlook\\.com/'
                              b'\\?url=.+?reserved=0)', flags=re.IGNORECASE)


class IMAPCleanO365ATPLinks(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        super().__init__()
        (self.fetching, self.fetch_command, self.fetched_message, self.expected_message_length,
         self.received_message_length) = self.reset()

    def reset(self):
        self.fetching = False
        self.fetch_command = b''
        self.fetched_message = b''
        self.expected_message_length = 0
        self.received_message_length = 0
        return (self.fetching, self.fetch_command, self.fetched_message, self.expected_message_length,
                self.received_message_length)

    def receive_from_server(self, byte_data):
        if not self.fetching:
            if IMAP_COMMAND_MATCHER.match(byte_data):  # simplistic initial match to avoid parsing all messages
                match = IMAP_FETCH_REQUEST_MATCHER.match(byte_data)
                if match:
                    self.fetching = True
                    _, start = match.span()
                    self.fetch_command = byte_data[:start]
                    self.expected_message_length = int(match.group('length'))
                    byte_data = byte_data[start:]
                else:
                    return byte_data
            else:
                return byte_data  # pass through all other messages unedited

        if self.fetching:
            self.fetched_message += byte_data
            if len(self.fetched_message) < self.expected_message_length:
                return None  # wait for more data

            # note: currently we only handle a single body part in each buffer (which is fine for O365)
            original_message = self.fetched_message[:self.expected_message_length]
            original_buffer_end = self.fetched_message[self.expected_message_length:]

            original_message_quopri_count = 0
            try:
                # we have to detect base64 encoding as we don't have the message headers
                base64_decoded = base64.decodebytes(original_message)
                is_base64 = base64.encodebytes(base64_decoded) == original_message.replace(b'\r\n', b'\n')
                if is_base64:
                    original_message_decoded = base64_decoded
                else:
                    raise binascii.Error
            except binascii.Error:
                is_base64 = False
                original_message_decoded = quopri.decodestring(original_message)
                original_message_quopri_count = len(re.findall(QUOPRI_MATCH_PATTERN, original_message))

            edited_message = b''
            link_count = 0
            current_position = 0
            for match in O365_ATP_MATCHER.finditer(original_message_decoded):
                start, end = match.span()
                edited_message += original_message_decoded[current_position:start]

                # parse_qsl not parse_qs because we only ever care about non-array values
                atp_url = match.group('atp')
                atp_url_parts = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(atp_url).query))
                if b'url' in atp_url_parts:
                    edited_message += atp_url_parts[b'url']
                    link_count += 1
                else:
                    edited_message += atp_url  # fall back to original

                current_position = end
            edited_message += original_message_decoded[current_position:]

            if link_count > 0:
                self.log_debug('Removed', link_count, 'O365 ATP links from message requested via', self.fetch_command)
                if is_base64:
                    edited_message_encoded = base64.encodebytes(edited_message).replace(b'\n', b'\r\n')
                elif original_message_quopri_count > 0:
                    edited_message_encoded = quopri.encodestring(edited_message.replace(b'\n', b'\r\n'))
                    edited_message_quopri_count = len(re.findall(QUOPRI_MATCH_PATTERN, edited_message_encoded))
                    if original_message_quopri_count < edited_message_quopri_count * 0.8:
                        # probably not quoted-printable encoded (threshold of 80% match to allow for removed link text)
                        edited_message_encoded = edited_message
                else:
                    edited_message_encoded = edited_message
                edited_command = self.fetch_command.replace(b'{%d}' % self.expected_message_length,
                                                            b'{%d}' % len(edited_message_encoded))
                self.reset()
                return edited_command + edited_message_encoded + original_buffer_end

            # no replacements: either no links or potentially some encoding we don't handle - return original
            self.log_debug('No links to remove; returning original message requested via', self.fetch_command)
            original_fetch_response = self.fetch_command + self.fetched_message
            self.reset()
            return original_fetch_response

        return byte_data

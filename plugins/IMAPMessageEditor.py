"""Extend this class to create IMAP plugins that modify the content of received messages. This class abstracts away the
potentially error-prone message decoding process and instead provides a single method - `edit_message` - that is called
whenever an email is loaded."""

import base64
import binascii
import email
import email.policy
import math
import quopri
import re

import plugins.BasePlugin

# note: these patterns operate on byte-strings to avoid having to parse (and potentially cache) message part encodings
IMAP_RESPONSE_MATCHER = re.compile(br'^\* \d+ FETCH ', flags=re.IGNORECASE)

# handle both full message requests and single (text) parts - note: the 1-part regex intentionally matches full messages
# note also that the part pattern is a trade-off between detecting all text parts (when we don't have the full message
# header) and unintentionally replacing the content of text attachments
IMAP_PART_PATTERN = br'(?:TEXT|1(?:\.1|\.2)*|2)?'  # see https://stackoverflow.com/a/37794152
IMAP_FETCH_PATTERN = br'^\* \d+ FETCH \((?:UID \d+ )?BODY\[%s] {(?P<length>\d+)}\r\n'
IMAP_FETCH_PART_REQUEST_MATCHER = re.compile(IMAP_FETCH_PATTERN % IMAP_PART_PATTERN, flags=re.IGNORECASE)  # single part
IMAP_FETCH_ALL_REQUEST_MATCHER = re.compile(IMAP_FETCH_PATTERN % br'', flags=re.IGNORECASE)  # full message

QUOPRI_MATCH_PATTERN = br'=(?:[A-F\d]{2}|%s)' % b'\r\n'  # similar to above, we need to guess quoted-printable encoding
EMAIL_POLICY = email.policy.default.clone(max_line_length=None, refold_source='none', linesep='\r\n')


class IMAPMessageEditor(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        """Override this method (and call `super().__init__()`) if your plugin needs to receive setup parameters. For
        full documentation see the parent method."""
        super().__init__()
        (self.fetching, self.fetch_command, self.fetched_message, self.fetch_full_message,
         self.expected_message_length, self.received_message_length) = self._reset()

    def _reset(self):
        """Internal only - reset state. Do not override this method."""
        self.fetching = False
        self.fetch_command = b''
        self.fetched_message = b''
        self.fetch_full_message = False
        self.expected_message_length = 0
        self.received_message_length = 0
        return (self.fetching, self.fetch_command, self.fetched_message, self.fetch_full_message,
                self.expected_message_length, self.received_message_length)

    def receive_from_server(self, byte_data):
        """Internal only - handle message detection and editing. If your extension to this plugin requires using this
        method, be sure to call `super().receive_from_server()`. For full documentation see the parent method."""
        if not self.fetching:
            if IMAP_RESPONSE_MATCHER.match(byte_data):  # simplistic initial match to avoid parsing all messages
                part_match = IMAP_FETCH_PART_REQUEST_MATCHER.match(byte_data)
                if part_match:
                    if IMAP_FETCH_ALL_REQUEST_MATCHER.match(byte_data):
                        self.fetch_full_message = True
                    self.fetching = True
                    _, start = part_match.span()
                    self.fetch_command = byte_data[:start]
                    self.expected_message_length = int(part_match.group('length'))
                    byte_data = byte_data[start:]
                else:
                    return byte_data
            else:
                return byte_data  # pass through all other messages unedited

        if self.fetching:
            self.fetched_message += byte_data
            if len(self.fetched_message) < self.expected_message_length:
                return None  # wait for more data

            original_message = self.fetched_message[:self.expected_message_length]
            original_buffer_end = self.fetched_message[self.expected_message_length:]

            message_edited = False
            new_message = original_message
            if self.fetch_full_message:
                # we use the built-in email parser to extract multipart sections as close to original form as possible,
                # skipping anything that is not described as text, and ignoring attachment files (via `get_filename()`)
                # note: there seems to be a minor python bug where `as_bytes()` for headers with linebreaks adds a space
                # (': ' rather than just ':') , but this doesn't matter here as we correct message length if editing
                try:
                    parsed_message = email.message_from_bytes(original_message, policy=EMAIL_POLICY)
                    parsed_message_bytes = parsed_message.as_bytes()
                    for part in parsed_message.walk():
                        if part.get_content_type().startswith('text/') and part.get_filename() is None:
                            part_header, original_part_body = part.as_bytes().split(b'\r\n\r\n', maxsplit=1)
                            cte = part['content-transfer-encoding'] if 'content-transfer-encoding' in part else None
                            part_body_edited, new_part_body = self._decode_and_edit_message_part(original_part_body,
                                                                                                 encoding=cte)
                            if part_body_edited:
                                # string replacement seems to be the only way to achieve parsed message part editing
                                message_edited = True
                                parsed_message_bytes = parsed_message_bytes.replace(original_part_body, new_part_body)
                    if message_edited:
                        new_message = parsed_message_bytes
                except UnicodeError:
                    pass  # as_bytes() can fail - see, e.g., https://github.com/python/cpython/issues/90096
            else:
                message_edited, new_message = self._decode_and_edit_message_part(original_message)

            if message_edited:
                edited_command = self.fetch_command.replace(b'{%d}' % self.expected_message_length,
                                                            b'{%d}' % len(new_message))
                self._reset()
                return edited_command + new_message + original_buffer_end

            # no editing - return the original message
            original_fetch_response = self.fetch_command + self.fetched_message
            self._reset()
            return original_fetch_response

        return byte_data

    def _decode_and_edit_message_part(self, byte_part, encoding=None):
        """Internal only - handle message part decoding/editing. Do not override this method; see `edit_message()`."""

        # see w3.org/Protocols/rfc1341/5_Content-Transfer-Encoding.html and summary at stackoverflow.com/a/28531705
        is_base64 = encoding is not None and encoding.lower() == 'base64'
        is_quopri = encoding is not None and encoding.lower() == 'quoted-printable'
        if encoding:
            original_part_decoded = byte_part
            if is_base64:
                original_part_decoded = base64.decodebytes(byte_part)
            elif is_quopri:
                original_part_decoded = quopri.decodestring(byte_part)
        else:
            try:
                # we have to detect base64 encoding as we don't always have the message headers (and need to remove \r\n
                # from the original IMAP-formatted string to enable comparison with \n-only base64-encoded data)
                original_part_decoded = base64.decodebytes(byte_part)
                is_base64 = base64.encodebytes(original_part_decoded) == byte_part.replace(b'\r\n', b'\n')
                if is_base64:
                    # very likely to be an attachment - ignore (note: we cannot always detect text attachments...)
                    if b'BODY[2]' in self.fetch_command or b'\x00\x00' in original_part_decoded:
                        return False, byte_part
                else:
                    raise binascii.Error  # raise rather than if/else because base64 enc/dec can also raise this error
            except binascii.Error:
                # similar for quoted-printable - detect by comparing the re-encoded character count against the original
                original_part_decoded = quopri.decodestring(byte_part)
                dec_count = len(re.findall(QUOPRI_MATCH_PATTERN, byte_part))
                enc_count = len(re.findall(QUOPRI_MATCH_PATTERN, quopri.encodestring(original_part_decoded)))
                is_quopri = dec_count > 0 and enc_count > 0 and math.isclose(dec_count, enc_count, rel_tol=0.05)

                if not is_quopri:
                    # note: due to the way python's quopri works, we need an extra step for some messages because mixed
                    # linebreaks cause issues (e.g., '=0A=\r\n' will get decoded as '\n' and subsequently not detected)
                    replaced_byte_part = byte_part.replace(b'=\r\n', b'=0A').replace(b'=0A', b'\n')
                    replaced_part_decoded = quopri.decodestring(replaced_byte_part)
                    dec_count = len(re.findall(QUOPRI_MATCH_PATTERN, replaced_byte_part))
                    enc_count = len(re.findall(QUOPRI_MATCH_PATTERN, quopri.encodestring(replaced_part_decoded)))
                    is_quopri = dec_count > 0 and enc_count > 0 and math.isclose(dec_count, enc_count, rel_tol=0.3)

                if not is_quopri:
                    original_part_decoded = byte_part
        self.log_debug('Decoded message part:', original_part_decoded)

        new_part = self.edit_message(original_part_decoded)
        part_edited = new_part != original_part_decoded

        new_part_encoded = new_part  # default is no encoding
        if part_edited:
            self.log_debug('Edited content of message part received via', self.fetch_command)
            self.log_debug('Updated message part:', new_part)
            if is_base64:
                # replace original line endings (base64 is \n; we need \r\n for IMAP)
                new_part_encoded = base64.encodebytes(new_part).replace(b'\n', b'\r\n')
            elif is_quopri:
                # see: https://github.com/python/cpython/issues/64320 - quopri guesses at \r\n; replace consistently
                new_part_encoded = quopri.encodestring(
                    new_part.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))

        return part_edited, new_part_encoded

    # noinspection PyMethodMayBeStatic
    def edit_message(self, byte_message):
        """Override this method to edit received emails. The `byte_message` argument provides the original message text
        (which could be plain or html, but is already decoded for you if needed). Whatever you return from this method
        will replace the message's original content."""
        return byte_message

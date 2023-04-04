"""Extend this class to create IMAP plugins that modify the content of received messages. This class abstracts away the
potentially error-prone message decoding process and instead provides a single method - `edit_message` - that is called
whenever an email is loaded."""

import base64
import binascii
import math
import quopri
import re

import plugins.BasePlugin

# note: these patterns operate on byte-strings to avoid having to parse (and potentially cache) message encodings
IMAP_COMMAND_MATCHER = re.compile(br'^\* \d+ FETCH ', flags=re.IGNORECASE)
IMAP_FETCH_REQUEST_MATCHER = re.compile(br'^\* \d+ FETCH \(BODY\[(?:TEXT|1(?:\.1|\.2)*|2)] {(?P<length>\d+)}'
                                        b'\r\n', flags=re.IGNORECASE)  # https://stackoverflow.com/a/37794152
QUOPRI_MATCH_PATTERN = br'=(?:[A-F\d]{2}|%s)' % b'\r\n'  # similar to above, we need to guess quoted-printable encoding


class IMAPMessageEditor(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        """Override this method (and call `super().__init__()`) if your plugin needs to receive setup parameters. For
        full documentation see the parent method."""
        super().__init__()
        (self.fetching, self.fetch_command, self.fetched_message, self.expected_message_length,
         self.received_message_length) = self.reset()

    def reset(self):
        """Internal only - reset state. Do not override this method."""
        self.fetching = False
        self.fetch_command = b''
        self.fetched_message = b''
        self.expected_message_length = 0
        self.received_message_length = 0
        return (self.fetching, self.fetch_command, self.fetched_message, self.expected_message_length,
                self.received_message_length)

    def receive_from_server(self, byte_data):
        """Internal only - handle message detection and decoding. If your extension to this plugin requires using this
        method, be sure to call super().receive_from_server(). For full documentation see the parent method."""
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

            # note: currently we only handle a single body part in each buffer (which is known to be fine for O365)
            original_message = self.fetched_message[:self.expected_message_length]
            original_buffer_end = self.fetched_message[self.expected_message_length:]

            # see w3.org/Protocols/rfc1341/5_Content-Transfer-Encoding.html and summary at stackoverflow.com/a/28531705
            is_base64 = False
            is_quopri = False
            try:
                # we have to detect base64 encoding as we don't have the message headers (and need to remove \r\n
                # from the original IMAP-formatted string to enable comparison with \n-only base64-encoded data)
                original_message_decoded = base64.decodebytes(original_message)
                is_base64 = base64.encodebytes(original_message_decoded) == original_message.replace(b'\r\n', b'\n')
                if not is_base64:
                    raise binascii.Error  # raise rather than if/else because base64 enc/dec can also raise this error
            except binascii.Error:
                original_message_decoded = quopri.decodestring(original_message)
                is_quopri = math.isclose(len(re.findall(QUOPRI_MATCH_PATTERN, original_message)), len(
                    re.findall(QUOPRI_MATCH_PATTERN, quopri.encodestring(original_message_decoded))), rel_tol=0.05)
                if not is_quopri:
                    original_message_decoded = original_message

            edited_message = self.edit_message(original_message_decoded)

            if edited_message != original_message_decoded:
                self.log_debug('Edited content of message received via', self.fetch_command)
                if is_base64:
                    # replace original line endings (base64 is \n; we need \r\n for IMAP)
                    edited_message_encoded = base64.encodebytes(edited_message).replace(b'\n', b'\r\n')
                elif is_quopri:
                    # see: https://github.com/python/cpython/issues/64320 - quopri guesses at \r\n; replace consistently
                    edited_message_encoded = quopri.encodestring(
                        edited_message.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
                else:
                    edited_message_encoded = edited_message
                edited_command = self.fetch_command.replace(b'{%d}' % self.expected_message_length,
                                                            b'{%d}' % len(edited_message_encoded))
                self.reset()
                return edited_command + edited_message_encoded + original_buffer_end

            # no editing - return the original message
            original_fetch_response = self.fetch_command + self.fetched_message
            self.reset()
            return original_fetch_response

        return byte_data

    # noinspection PyMethodMayBeStatic
    def edit_message(self, byte_message):
        """Override this method to edit received emails. The `byte_message` argument provides the original message;
        whatever you return from this method will replace the message's content."""
        return byte_message

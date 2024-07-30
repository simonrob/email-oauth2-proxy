"""An example Email OAuth 2.0 Proxy SMTP plugin that demonstrates removing the headers `User-Agent`, `X-Mailer` and
`X-Originating-IP` from outgoing messages."""

import enum
import re

import plugins.BasePlugin

SMTP_MAIL_FROM_MATCHER = re.compile(b'MAIL FROM:.+\r\n', flags=re.IGNORECASE)
SMTP_RCPT_TO_MATCHER = re.compile(b'RCPT TO:.+\r\n', flags=re.IGNORECASE)
SMTP_BODY_RECIPIENT_MATCHER = re.compile(b'(?:To|Cc):.+\r\n\r\n', flags=re.IGNORECASE)

CONTENT_TYPE_HEADER = b'\r\nContent-Type: '
CONTENT_TYPE_MATCHER = re.compile(CONTENT_TYPE_HEADER, flags=re.IGNORECASE)


class SMTPRemoveClientIdentifiers(plugins.BasePlugin.BasePlugin):
    class STATE(enum.Enum):
        NONE = 1
        MAIL_FROM = 2
        RCPT_TO = 3
        DATA = 4

    def __init__(self):
        super().__init__()
        self.sending_state, self.previous_line_ended, self.header_processed = self.reset()

    def reset(self):
        self.sending_state = self.STATE.NONE
        self.previous_line_ended = False
        self.header_processed = False
        return self.sending_state, self.previous_line_ended, self.header_processed

    def receive_from_client(self, byte_data):
        # SMTP: https://tools.ietf.org/html/rfc2821
        # Headers: https://tools.ietf.org/html/rfc822#appendix-A.3.3
        if self.sending_state == self.STATE.NONE:
            if SMTP_MAIL_FROM_MATCHER.match(byte_data):  # message sender
                self.sending_state = self.STATE.MAIL_FROM
            return byte_data  # pass through unedited

        if len(byte_data) == 6 and byte_data.lower() == b'rset\r\n':  # RSET can be sent at any point; discard state
            self.reset()

        elif self.sending_state == self.STATE.MAIL_FROM:
            if SMTP_RCPT_TO_MATCHER.match(byte_data):  # initial recipient
                self.sending_state = self.STATE.RCPT_TO

        elif self.sending_state == self.STATE.RCPT_TO:
            if byte_data.lower() == b'data\r\n':  # either additional recipients (not checked here) or start of message
                self.sending_state = self.STATE.DATA

        elif self.sending_state == self.STATE.DATA:  # message contents
            if not self.header_processed:
                byte_data_parts = CONTENT_TYPE_MATCHER.split(byte_data, maxsplit=1)
                split_headers = byte_data_parts[0].split(b'\r\n')
                byte_data_parts[0] = b'\r\n'.join([h for h in split_headers if not self.check_identifying_header(h)])
                byte_data = CONTENT_TYPE_HEADER.join(byte_data_parts)
                self.log_debug('Removed identifying headers from outgoing message')

                self.header_processed = True

            if byte_data.endswith(b'\r\n.\r\n') or (self.previous_line_ended and byte_data == b'.\r\n'):  # end of email
                self.reset()
            else:
                self.previous_line_ended = byte_data.endswith(b'\r\n')

        return byte_data

    @staticmethod
    def check_identifying_header(header):
        lowercase_header = header.lower()
        return lowercase_header.startswith(b'user-agent:') or lowercase_header.startswith(
            b'x-mailer:') or lowercase_header.startswith(b'x-originating-ip:')

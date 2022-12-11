"""An example Email OAuth 2.0 Proxy SMTP plugin that accepts incoming email messages but silently discards them without
passing to the remote server. Useful for testing email sending tools with no risk of actually delivering messages."""

import enum
import re

import plugins.BasePlugin

SMTP_MAIL_FROM_MATCHER = re.compile(b'MAIL FROM:.+\r\n', flags=re.IGNORECASE)
SMTP_RCPT_TO_MATCHER = re.compile(b'RCPT TO:.+\r\n', flags=re.IGNORECASE)


class SMTPBlackHole(plugins.BasePlugin.BasePlugin):
    class STATE(enum.Enum):
        NONE = 1
        MAIL_FROM = 2
        RCPT_TO = 3
        DATA = 4

    def __init__(self):
        super().__init__()
        self.sending_state, self.previous_line_ended = self.reset()

    def reset(self):
        self.sending_state = self.STATE.NONE
        self.previous_line_ended = False
        return self.sending_state, self.previous_line_ended

    def receive_from_client(self, byte_data):
        # SMTP: https://tools.ietf.org/html/rfc2821
        if self.sending_state == self.STATE.NONE:
            if SMTP_MAIL_FROM_MATCHER.match(byte_data):  # message sender
                self.log_debug('Received MAIL FROM; acknowledging')
                self.sending_state = self.STATE.MAIL_FROM
                self.send_to_client(b'250 OK\r\n')
                return None
            return byte_data  # pass through all other messages unedited

        if byte_data.lower() == b'rset\r\n':  # RSET can be sent at any point; discard state and reset
            self.log_debug('Received RSET; resetting state')
            self.reset()
            return byte_data

        if self.sending_state == self.STATE.MAIL_FROM:
            if SMTP_RCPT_TO_MATCHER.match(byte_data):  # initial recipient
                self.log_debug('Received RCPT TO; acknowledging')
                self.sending_state = self.STATE.RCPT_TO
                self.send_to_client(b'250 OK\r\n')
            return None

        if self.sending_state == self.STATE.RCPT_TO:
            if SMTP_RCPT_TO_MATCHER.match(byte_data):  # additional recipients
                self.log_debug('Received additional RCPT TO; acknowledging')
                self.send_to_client(b'250 OK\r\n')
            elif byte_data.lower() == b'data\r\n':
                self.log_debug('Received DATA; requesting full message')
                self.sending_state = self.STATE.DATA
                self.send_to_client(b'354 \r\n')
            return None

        if self.sending_state == self.STATE.DATA:  # message contents
            if byte_data.endswith(b'\r\n.\r\n') or (self.previous_line_ended and byte_data == b'.\r\n'):  # end of email
                self.log_debug('Received DATA end: resetting')
                self.reset()
                self.log_info('Received complete outgoing message; discarding')
                self.send_to_client(b'250 OK\r\n')
            else:
                self.previous_line_ended = byte_data.endswith(b'\r\n')
            return None

        return byte_data

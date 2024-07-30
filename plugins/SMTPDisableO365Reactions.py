"""An example Email OAuth 2.0 Proxy SMTP plugin that adds the Outlook-specific email header `x-ms-reactions: disallow`
that disables message reactions. An additional optional parameter 'domain_whitelist' takes an array of recipient
domains (for example, ['your-domain.com', 'example.com']). If any of these domains are present in the recipient list,
the ability to react to this message will be retained. Note that this functionality applies to all recipients - i.e.,
if a single whitelisted recipient is present, all recipients will be able to react to the message. For further details
about disabling reactions, see the Microsoft article: https://techcommunity.microsoft.com/t5/outlook/r/ba-p/3928103."""

import enum
import re

import plugins.BasePlugin

SMTP_MAIL_FROM_MATCHER = re.compile(b'MAIL FROM:.+\r\n', flags=re.IGNORECASE)
SMTP_RCPT_TO_MATCHER = re.compile(b'RCPT TO:.+\r\n', flags=re.IGNORECASE)
SMTP_BODY_RECIPIENT_MATCHER = re.compile(b'(?:To|Cc):.+\r\n\r\n', flags=re.IGNORECASE)

CONTENT_TYPE_HEADER = b'\r\nContent-Type: '
CONTENT_TYPE_MATCHER = re.compile(CONTENT_TYPE_HEADER, flags=re.IGNORECASE)


class SMTPDisableO365Reactions(plugins.BasePlugin.BasePlugin):
    class STATE(enum.Enum):
        NONE = 1
        MAIL_FROM = 2
        RCPT_TO = 3
        DATA = 4

    def __init__(self, domain_whitelist=None):
        super().__init__()
        self.domain_whitelist = [d.encode('utf-8') for d in domain_whitelist] if domain_whitelist else []
        self.sending_state, self.previous_line_ended, self.whitelist_domain, self.header_processed = self.reset()

    def reset(self):
        self.sending_state = self.STATE.NONE
        self.previous_line_ended = False
        self.whitelist_domain = None
        self.header_processed = False
        return self.sending_state, self.previous_line_ended, self.whitelist_domain, self.header_processed

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
                self.whitelist_domain = self.check_whitelisted_domain(byte_data)
                self.sending_state = self.STATE.RCPT_TO

        elif self.sending_state == self.STATE.RCPT_TO:
            if SMTP_RCPT_TO_MATCHER.match(byte_data):  # additional recipients
                self.whitelist_domain = self.check_whitelisted_domain(byte_data)
            if byte_data.lower() == b'data\r\n':
                self.sending_state = self.STATE.DATA

        elif self.sending_state == self.STATE.DATA:  # message contents
            if not self.header_processed:
                if self.whitelist_domain:
                    self.log_debug('Found whitelisted domain `%s`' % self.whitelist_domain.decode('utf-8'),
                                   '- skipping adding `x-ms-reactions: disallow` header to outgoing message')
                else:
                    byte_data_parts = CONTENT_TYPE_MATCHER.split(byte_data, maxsplit=1)
                    byte_data_parts[0] += b'\r\nx-ms-reactions: disallow'
                    byte_data = CONTENT_TYPE_HEADER.join(byte_data_parts)
                    self.log_debug('Added `x-ms-reactions: disallow` header to outgoing message')

                self.header_processed = True

            if byte_data.endswith(b'\r\n.\r\n') or (self.previous_line_ended and byte_data == b'.\r\n'):  # end of email
                self.reset()
            else:
                self.previous_line_ended = byte_data.endswith(b'\r\n')

        return byte_data

    def check_whitelisted_domain(self, recipient):
        recipient_domain = recipient[:-3].split(b'@')[-1]  # last 3 chars = >\r\n
        for whitelisted_domain in self.domain_whitelist:
            if recipient_domain == whitelisted_domain:
                return whitelisted_domain
        return None

"""An example Email OAuth 2.0 Proxy SMTP plugin that replaces specified recipient addresses in outgoing emails with one
or more different recipients. Please note that this is a relatively simplistic example of how such a plugin could work,
and if you try to confuse/break it you will likely succeed (please use a real mailing list if you need to handle this).
However, this approach works well for basic cases - for example, when you often find yourself sending an email to the
same addresses, you can consolidate the group into a single address and never forget any recipients. Note, though, that
unlike typical mailing lists, recipients are inserted into the same field (e.g., To/Cc/Bcc) that the list address is
found. To create a list address, create a configuration file and pass its full path to the plugin (see example below).
Recipients themselves only ever see the real addresses, not your list, so there is no danger of replying to an address
that does not exist. To make even more certain this is the case, it is recommended to use list addresses @example.com
(or non-existent addresses at another domain you control) to ensure they can never be delivered. It is also sensible
to chain with SMTPBlackHole.py and enable debug mode in the proxy at first use to check intended behaviour.

Sample Email OAuth 2.0 Proxy server configuration:
plugins = {'SMTPSimpleMailingList': {'list_file': '/path/to/SMTPSimpleMailingList.config'}}

Sample Email OAuth 2.0 Proxy server configuration with SMTPBlackHole.py for testing:
plugins = {'SMTPSimpleMailingList': {'list_file': '/path/to/SMTPSimpleMailingList.config'}, 'SMTPBlackHole': {}}

Sample SMTPSimpleMailingList.config plugin configuration file (create one section per list; recipients must be indented
and only one per line; including other lists as recipients is not supported):
[my.list@example.com]
recipients =
    recipient@email.com
    another.recipient@email.com
"""

import configparser
import enum
import re

import plugins.BasePlugin

SMTP_MAIL_FROM_MATCHER = re.compile(b'MAIL FROM:.+\r\n', flags=re.IGNORECASE)
SMTP_RCPT_TO_MATCHER = re.compile(b'RCPT TO:.+\r\n', flags=re.IGNORECASE)
SMTP_BODY_RECIPIENT_MATCHER = re.compile(b'(?:To|Cc):.+\r\n\r\n', flags=re.IGNORECASE)


class SMTPSimpleMailingList(plugins.BasePlugin.BasePlugin):
    class STATE(enum.Enum):
        NONE = 1
        MAIL_FROM = 2
        RCPT_TO = 3
        DATA = 4

    def __init__(self, list_file=None):
        super().__init__()
        self.list_addresses = self.parse_list(list_file)
        print(
            b'RCPT TO:<(?P<recipient>' + b'|'.join([a for a in self.list_addresses.keys()]) + b')>\r\n')
        self.list_address_matcher = re.compile(
            b'RCPT TO:<(?P<recipient>' + b'|'.join([a for a in self.list_addresses.keys()]) + b')>\r\n',
            flags=re.IGNORECASE)
        self.sending_state, self.previous_line_ended, self.matched_addresses, self.list_recipients = self.reset()

    def reset(self):
        self.sending_state = self.STATE.NONE
        self.previous_line_ended = False
        self.matched_addresses = []
        self.list_recipients = []
        return self.sending_state, self.previous_line_ended, self.matched_addresses, self.list_recipients

    @staticmethod
    def parse_list(list_file=None):
        list_addresses = {}
        if list_file:
            config_parser = configparser.ConfigParser()
            config_parser.read(list_file)
            sections = config_parser.sections()
            for address in sections:
                recipients = config_parser.get(address, 'recipients')
                list_addresses[address.encode('utf-8')] = list(
                    filter(None, (r.strip().encode('utf-8') for r in recipients.splitlines())))
        return list_addresses

    def receive_from_client(self, byte_data):
        # SMTP: https://tools.ietf.org/html/rfc2821
        if self.sending_state == self.STATE.NONE:
            if SMTP_MAIL_FROM_MATCHER.match(byte_data):  # message sender
                self.sending_state = self.STATE.MAIL_FROM
            return byte_data  # pass through unedited

        elif byte_data.lower() == b'rset\r\n':  # RSET can be sent at any point; discard state and reset
            self.reset()
            return byte_data

        elif self.sending_state == self.STATE.MAIL_FROM:
            if SMTP_RCPT_TO_MATCHER.match(byte_data):  # initial recipient
                self.log_debug('Received RCPT TO; checking lists', byte_data)
                self.sending_state = self.STATE.RCPT_TO
                return self.check_rcpt_to(byte_data)
            return byte_data

        elif self.sending_state == self.STATE.RCPT_TO:
            if SMTP_RCPT_TO_MATCHER.match(byte_data):  # additional recipients
                self.log_debug('Received additional RCPT TO; checking lists', byte_data)
                return self.check_rcpt_to(byte_data)
            elif byte_data.lower() == b'data\r\n':
                self.sending_state = self.STATE.DATA
            return byte_data

        elif self.sending_state == self.STATE.DATA:  # message contents
            for address in self.matched_addresses:
                if address in byte_data:
                    # note: this simplistic replacement assumes there will only be one occurrence of the recipient list,
                    # and will not work with named recipients (e.g., My List<list@example.com>)
                    byte_data = byte_data.replace(address, b', '.join(self.list_addresses[address]), 1)

            if byte_data.endswith(b'\r\n.\r\n') or (self.previous_line_ended and byte_data == b'.\r\n'):  # end of email
                self.reset()
            else:
                self.previous_line_ended = byte_data.endswith(b'\r\n')
            return byte_data

    def check_rcpt_to(self, byte_data):
        match = self.list_address_matcher.match(byte_data)
        if match:
            matched_address = match.group('recipient')
            self.matched_addresses.append(matched_address)
            self.list_recipients = self.list_addresses[matched_address][:]  # clone to allow popping
            self.log_debug('Found RCPT TO list match:', matched_address)
            if len(self.list_recipients) > 0:  # replace the list with the first recipient
                byte_data = b'RCPT TO:<' + self.list_recipients.pop(0) + b'>\r\n'
                self.send_to_server(byte_data)
            return None

        return byte_data

    def receive_from_server(self, byte_data):
        if self.sending_state == self.STATE.RCPT_TO:  # send any additional recipients directly to the server
            if len(self.list_recipients) > 0:
                byte_data = b'RCPT TO:<' + self.list_recipients.pop(0) + b'>\r\n'
                self.send_to_server(byte_data)
                return None

        return byte_data

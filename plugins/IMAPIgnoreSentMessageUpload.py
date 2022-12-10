"""An example Email OAuth 2.0 Proxy IMAP plugin that accepts client requests to upload sent messages to an IMAP mailbox,
but silently discards them without sending to the server. This plugin helps avoid message duplication for servers that
automatically place messages sent via SMTP into the relevant IMAP mailbox. Note that many clients are aware of this
behaviour and provide an option to not upload sent messages – if this is available it is a much more efficient solution
than adding a proxy plugin."""

import re

import plugins.BasePlugin

IMAP_TAG_PATTERN = plugins.BasePlugin.IMAP.TAG_PATTERN
IMAP_COMMAND_MATCHER = re.compile(IMAP_TAG_PATTERN.encode('utf-8') + b' (?P<command>APPEND) ', flags=re.IGNORECASE)
IMAP_APPEND_REQUEST_MATCHER = re.compile(IMAP_TAG_PATTERN.encode('utf-8') + b' (?P<command>APPEND) "(?P<mailbox>.+)" '
                                                                            b'(?P<flags>.+){(?P<length>\\d+)}\r\n',
                                         flags=re.IGNORECASE)


class IMAPIgnoreSentMessageUpload(plugins.BasePlugin.BasePlugin):
    def __init__(self, target_mailboxes=None):
        super().__init__()
        self.target_mailboxes = [m.encode('utf-8') for m in target_mailboxes]
        self.appending, self.append_tag, self.expected_message_length, self.received_message_length = self.reset()

    def reset(self):
        self.appending = False
        self.append_tag = b''
        self.expected_message_length = 0
        self.received_message_length = 0
        return self.appending, self.append_tag, self.expected_message_length, self.received_message_length

    def receive_from_client(self, byte_data):
        if not self.appending:
            # when receiving an APPEND command that matches our target mailbox, instruct the client to go ahead
            # with the message upload (and ignore received data), but don't actually send anything to the server
            if IMAP_COMMAND_MATCHER.match(byte_data):  # simplistic initial match to avoid parsing all messages
                match = IMAP_APPEND_REQUEST_MATCHER.match(byte_data)
                if match and match.group('mailbox') in self.target_mailboxes:
                    self.appending = True
                    self.append_tag = match.group('tag')
                    self.expected_message_length = int(match.group('length'))
                    self.log_debug('Received APPEND command matching mailbox "%s" - intercepting and ignoring message '
                                   'of length %d' % (match.group('mailbox'), self.expected_message_length))
                    self.send_to_client(b'+\r\n')  # request full message data
                    return None

            return byte_data  # pass through all other messages unedited

        else:
            # if we've received the full message length, send an OK message (with the correct tag) to the client (note:
            # received length is two bytes longer than stated (i.e., terminating \r\n), but that doesn't matter here)
            self.received_message_length += len(byte_data)
            if self.received_message_length > self.expected_message_length:
                self.log_debug('Completed APPEND interception; confirming to client and resuming normal communication')
                self.send_to_client(b'%s OK APPEND completed\r\n' % self.append_tag)
                self.reset()

            return None

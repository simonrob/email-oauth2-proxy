"""An example Email OAuth 2.0 Proxy IMAP plugin that modifies search strings to fix O365's inability to handle uppercase
characters in searches. The plugin also changes BODY searches to TEXT to prompt O365 to return flags in the results."""

import re

import plugins.BasePlugin

# note: these patterns operate on byte-strings to avoid having to parse (and potentially cache) message encodings
IMAP_O365_SEARCH_MATCHER = re.compile(b'(?P<prefix>%s SEARCH(?: .+)? (?:BODY|TEXT) )'
                                      br'(?:{(?P<length>\d+)(?P<continuation>\+?)}|"(?P<query>.*)"(?P<suffix>(?: .+)?))'
                                      b'\r\n' % plugins.BasePlugin.IMAP.TAG_PATTERN,
                                      flags=re.IGNORECASE)


class IMAPFixO365SearchQuirks(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        super().__init__()
        self.query_literal_length_awaited = -1
        self.logged_o365_spaces_in_search_warning = False

    def spaced_query_warning(self, query):
        if not self.logged_o365_spaces_in_search_warning and b' ' in query:
            self.log_info('O365 IMAP search string "%s"' % query.decode('utf-8'), 'contains spaces - no results will',
                          'be returned. (This warning will not be repeated.)')
            self.logged_o365_spaces_in_search_warning = True

    def receive_from_client(self, byte_data):
        # O365 requires searches to be lowercase(!); we also change BODY to TEXT so flags are returned with the result
        if self.query_literal_length_awaited >= 0:
            if len(byte_data) >= self.query_literal_length_awaited:  # a string literal search (+ subsequent criteria)
                query = byte_data[0:self.query_literal_length_awaited]
                byte_data = b'%s%s' % (query.lower(), byte_data[self.query_literal_length_awaited:])
                self.spaced_query_warning(query)
                self.query_literal_length_awaited = -1
                self.log_debug('Modifying search query to lowercase; changing type BODY to TEXT')
                return byte_data

            self.spaced_query_warning(byte_data)
            self.query_literal_length_awaited -= len(byte_data)
            return byte_data.lower()

        match = IMAP_O365_SEARCH_MATCHER.match(byte_data)
        if match:
            if match.group('length'):  # this search is provided as a string literal - wait for the actual text
                modified_prefix = re.sub(b'BODY $', b'TEXT ', match.group('prefix'), flags=re.IGNORECASE)
                byte_data = b'%s{%d}\r\n' % (modified_prefix, self.query_literal_length_awaited)
                self.query_literal_length_awaited = int(match.group('length'))
                return byte_data

            query = match.group('query')
            modified_prefix = re.sub(b'BODY $', b'TEXT ', match.group('prefix'), flags=re.IGNORECASE)
            byte_data = b'%s"%s"%s\r\n' % (modified_prefix, query.lower(), match.group('suffix'))
            self.spaced_query_warning(query)
            self.log_debug('Modifying search query to lowercase; changing type BODY to TEXT')

        return byte_data

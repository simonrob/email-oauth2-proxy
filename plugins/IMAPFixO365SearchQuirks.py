"""An example Email OAuth 2.0 Proxy IMAP plugin that modifies search strings to fix O365's inability to handle uppercase
searches. The plugin also changes BODY searches to TEXT to prompt O365 to return flags in the results."""

import re

import plugins.BasePlugin

# note: these patterns operate on byte-strings to avoid having to parse (and potentially cache) message encodings
IMAP_O365_BODY_SEARCH_MATCHER = re.compile(
    b'(?P<prefix>%s SEARCH(?: .+)? BODY ")(?P<query>.*)(?P<suffix>"(?: .+)?\r\n)' % plugins.BasePlugin.IMAP.TAG_PATTERN,
    flags=re.IGNORECASE)


class IMAPFixO365SearchQuirks(plugins.BasePlugin.BasePlugin):
    def __init__(self):
        super().__init__()
        self.logged_o365_spaces_in_search_warning = False

    def receive_from_client(self, byte_data):
        # O365 requires searches to be lowercase(!); we also change BODY to TEXT so flags are returned with the result
        match = IMAP_O365_BODY_SEARCH_MATCHER.match(byte_data)
        if match:
            query = match.group('query')
            if not self.logged_o365_spaces_in_search_warning and b' ' in query:
                self.log_info('O365 IMAP search string "%s"' % query, 'contains spaces - no results will be returned.',
                              '(This warning will not be repeated)')
                self.logged_o365_spaces_in_search_warning = True
            modified_prefix = re.sub(b'BODY "', b'TEXT "', match.group('prefix'), flags=re.IGNORECASE)
            byte_data = b"%s%s%s" % (modified_prefix, query.lower(), match.group('suffix'))
            self.log_debug('Modifying search query to lowercase; changing type BODY to TEXT')
        return byte_data

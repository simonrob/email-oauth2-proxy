r"""An example Email OAuth 2.0 Proxy IMAP plugin that performs regular expression searches and substitutions in received
messages. Please note that this is a relatively simplistic example of how such a plugin could work, and if you try to
confuse/break it you will likely succeed.

Sample Email OAuth 2.0 Proxy server configuration:
plugins = {'IMAPRegexContentReplacer': {'replacements_file': '/path/to/IMAPRegexContentReplacer.config'}}

Sample IMAPRegexContentReplacer.config plugin configuration file (note: searches are case-insensitive, dot matches all
characters, and spaces at the start/end of searches/replacements are ignored):
[IMAPRegexContentReplacer]
Dear = ¿Qué tal?
\r\n\r\n = \r\n
(\d{2})/(\d{2})/(\d{4}) = \g<3>/\g<1>/\g<2>
"""

import configparser
import re

import plugins.IMAPMessageEditor


class IMAPRegexContentReplacer(plugins.IMAPMessageEditor.IMAPMessageEditor):
    def __init__(self, replacements_file=None):
        super().__init__()
        self.replacements = self.parse_replacements(replacements_file)

    @staticmethod
    def parse_replacements(replacements_file=None):
        config_parser = configparser.ConfigParser()
        config_parser.read(replacements_file)

        def decode_string(original):
            # we need the original string as entered, not the backslash-escaped version
            return original.encode('latin-1', 'backslashreplace').decode('unicode-escape').encode('utf-8')

        replacements = {}
        for section in config_parser.sections():
            for search_pattern, replacement_pattern in config_parser.items(section):
                replacements[decode_string(search_pattern)] = decode_string(replacement_pattern)

        return replacements

    def edit_message(self, byte_message):
        for original, replacement in self.replacements.items():
            byte_message = re.sub(original, replacement, byte_message, flags=re.IGNORECASE | re.DOTALL)
        return byte_message

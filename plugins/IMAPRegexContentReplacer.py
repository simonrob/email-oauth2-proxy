r"""An example Email OAuth 2.0 Proxy IMAP plugin that performs regular expression searches and substitutions in received
messages. Please note that this is a relatively simplistic example of how such a plugin could work, and if you try to
confuse/break it you will likely succeed.

Sample Email OAuth 2.0 Proxy server configuration:
plugins = {'IMAPRegexContentReplacer': {'replacements_file': '/path/to/IMAPRegexContentReplacer.config'}}

Sample IMAPRegexContentReplacer.config plugin configuration file. Note that the normal delimiters `:` and `=` have been
replaced by the string `{=rcr=}` to help with regex-based replacements. In addition, it is important to be aware that
searches are not case-sensitive, dot matches all characters (i.e., including newlines), and spaces at the start/end of
searches/replacements are ignored):
[IMAPRegexContentReplacer]
Dear {=rcr=} ¿Qué tal?
\r\n\r\n {=rcr=} \r\n
(\d{2})/(\d{2})/(\d{4}) {=rcr=} \g<3>/\g<1>/\g<2>
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
        config_parser = configparser.ConfigParser(delimiters=('{=rcr=}',), interpolation=None, allow_no_value=True)
        config_parser.read(replacements_file)

        def decode_string(original):
            # we need the original string as entered, not the backslash-escaped version
            if not original:
                return b''
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

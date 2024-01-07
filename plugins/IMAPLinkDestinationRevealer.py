"""An example Email OAuth 2.0 Proxy IMAP plugin that looks for links that appear to show a URL, but whose text doesn't
match the link's actual destination (its `href`), and makes this more visible by replacing the original link destination
with the text, and displaying the original destination alongside. If using with the IMAPCleanO365ATPLinks plugin, place
that plugin later in the list (so it will be executed first on messages received from the server)."""

import re

import plugins.IMAPMessageEditor

LINK_MATCHER = re.compile(
    br'<a (?P<pre_attr>.*?)href="(?P<prefix>https?://)(?P<url>[^"]+)"(?P<post_attr>[^>]*?)>http(?P<text>.*?)</a>',
    flags=re.IGNORECASE)

DESTINATION_MAX_LENGTH = 0  # for the original link display, how many characters after the domain to show (-1 = all)


class IMAPLinkDestinationRevealer(plugins.IMAPMessageEditor.IMAPMessageEditor):
    def edit_message(self, byte_message):
        edited_message = b''
        link_count = 0
        current_position = 0
        for match in LINK_MATCHER.finditer(byte_message):
            start, end = match.span()
            edited_message += byte_message[current_position:start]

            link_pre_attr = match.group('pre_attr')
            link_prefix = match.group('prefix')
            link_url = match.group('url')
            link_post_attr = match.group('post_attr')
            link_text = match.group('text')

            if link_prefix + link_url != b'http' + link_text:
                parts = link_url.split(b'/', 1)
                truncated = b'%s%s' % (link_prefix, parts[0])
                if len(parts) > 0:
                    truncated = (b'%s/%s...' % (
                        truncated, parts[1][:DESTINATION_MAX_LENGTH])) if 0 <= DESTINATION_MAX_LENGTH < len(
                        parts[1]) else b'%s/%s' % (truncated, parts[1])

                edited_message += (b'<a ' + link_pre_attr + b'href="http' + link_text + b'"' + link_post_attr +
                                   b'>http' + link_text + b'</a> <i>[<a ' + link_pre_attr + b'href="' + link_prefix +
                                   link_url + b'"' + link_post_attr + b'>' + truncated + b'</a>]</i>')
                link_count += 1
            else:
                edited_message += byte_message[start:end]

            current_position = end
        edited_message += byte_message[current_position:]

        if link_count > 0:
            self.log_debug('Expanded target for', link_count, 'links from message requested via', self.fetch_command)
            return edited_message
        else:
            # no links to replace (or potentially some encoding not handled by IMAPMessageEditor)
            return byte_message

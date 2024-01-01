"""An example Email OAuth 2.0 Proxy IMAP plugin that looks for Office 365 Advanced Threat Protection links (also known
as Safe Links in Microsoft Defender for Office 365) and replaces them with their original values (i.e., removing the
redirect). As with most of the proxy's plugins, it would be more efficient to handle this on the server side (i.e.,
by disabling link modification), but this is not always possible."""

import re
import urllib.parse

import plugins.IMAPMessageEditor

# github.com/MicrosoftDocs/microsoft-365-docs/blob/public/microsoft-365/includes/microsoft-365-multi-geo-locations.md
O365_GEO_LOCATIONS = '|'.join(['APC', 'AUS', 'BRA', 'CAN', 'EUR', 'FRA', 'DEU', 'IND', 'JPN', 'KOR', 'NAM', 'NOR',
                               'QAT', 'ZAF', 'SWE', 'CHE', 'ARE', 'GBR']).lower().encode('utf-8')
# noinspection RegExpUnnecessaryNonCapturingGroup
O365_ATP_MATCHER = re.compile(br'(?P<atp>https://(?:%s)\d{2}\.safelinks\.protection\.outlook\.com/.*?'
                              br'\?url=.+?reserved=0)' % O365_GEO_LOCATIONS, flags=re.IGNORECASE)


class IMAPCleanO365ATPLinks(plugins.IMAPMessageEditor.IMAPMessageEditor):
    def edit_message(self, byte_message):
        edited_message = b''
        link_count = 0
        current_position = 0
        for match in O365_ATP_MATCHER.finditer(byte_message):
            start, end = match.span()
            edited_message += byte_message[current_position:start]

            atp_url = match.group('atp')
            try:
                # parse_qsl not parse_qs because we only ever care about non-array values
                atp_url_query = urllib.parse.urlparse(atp_url).query
            except UnicodeDecodeError:
                # urlparse assumes ascii encoding which is not always the case; try to recover if possible
                atp_url_query = atp_url.replace(b'&amp;', b'&').rsplit(b'&data', 2)[0].partition(b'?')[2]
            try:
                # parse_qsl not parse_qs because we only ever care about non-array values; extra dict formatting
                # as IntelliJ has a bug incorrectly detecting parse_qs/l as returning a dict with byte-type keys
                atp_url_parts = {str(key): value for key, value in urllib.parse.parse_qsl(atp_url_query)}
            except UnicodeEncodeError:
                # the encoding and errors parameters for parse_qsl are not actually passed to _encode_result, so invalid
                # (or incorrectly hyperlinked) values can cause decoding errors - we temporarily patch as a workaround
                # noinspection PyUnresolvedReferences,PyProtectedMember
                original_encode_result = urllib.parse._encode_result
                urllib.parse._encode_result = lambda obj, encoding='utf-8', err='replace': obj.encode(encoding, err)
                atp_url_parts = {str(key): value for key, value in urllib.parse.parse_qsl(atp_url_query)}
                urllib.parse._encode_result = original_encode_result
            if b'url' in atp_url_parts:
                edited_message += atp_url_parts[b'url']
                link_count += 1
            else:
                edited_message += atp_url  # fall back to original

            current_position = end
        edited_message += byte_message[current_position:]

        if link_count > 0:
            self.log_debug('Removed', link_count, 'O365 ATP links from message requested via', self.fetch_command)
            return edited_message
        else:
            # no links to replace (or potentially some encoding not handled by IMAPMessageEditor)
            return byte_message

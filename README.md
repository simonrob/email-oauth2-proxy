# Email OAuth 2.0 Proxy
An IMAP proxy that adds OAuth 2.0 authentication transparently for clients that don't support it.

## Getting started
First, add details for each account you want to use with the proxy in the file `oauth2proxy.config`. A [sample configuration](oauth2proxy.config) is provided for Office 365, but you will need to [register a new application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) to get started (or use an existing set of credentials).

Next, start the proxy: `python3 emailproxy.py` – a menu bar icon should appear. If you get `ModuleNotFoundError`, use `pip` to install any missing packages.

Finally, open your email client and configure its IMAP details as `localhost` on port `1433` (editable in [emailproxy.py](emailproxy.py) if needed).

The first time your email client makes an IMAP request you should see a notification about authentication. Click the `Authorise account...` option in the menu bar and follow the instructions to log in to your account. After authentication completes you should have IMAP access to your account as normal.

## Running as a service/daemon
Move [the included plist file](ac.robinson.email-oauth2-proxy.plist) to `~/Library/LaunchAgents/`, then edit it to replace `/path/to/python3` and `/path/to/emailproxy.py` with the full paths to your local `python3` and the `emailproxy.py` script. Run `launchctl load ac.robinson.email-oauth2-proxy.plist`, and the menu bar icon should appear. The script will now run at startup.

If needed, you can remove the startup service using `launchctl unload ac.robinson.email-oauth2-proxy.plist`.

## Potential improvements (pull requests welcome)
- Better handling of computer sleep
- Handle (or alert about) server throttling (e.g., responses such as `a01 NO Request is throttled. Suggested Backoff Time: 256625`)
- Testing on different platforms (currently tested only on macOS)
- Better menu bar icon
- Asyncio (or alternative) rather than asyncore
- SMTP server with the same approach ([DavMail](http://davmail.sourceforge.net/) is an alternative for now)

## License
Apache 2.0

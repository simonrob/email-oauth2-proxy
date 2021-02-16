# Email OAuth 2.0 Proxy
An IMAP proxy that adds OAuth 2.0 authentication transparently for clients that don't support it.

## Getting started
First, add details for each account you want to use with the proxy in the file `oauth2proxy.config`. A [sample configuration](oauth2proxy.config) is provided for Office 365, but you will need to [register a new application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) to get started (or use an existing set of credentials).

Next, start the proxy: `python3 main.py` – a menu bar icon will appear. Open your email client and configure its IMAP details as `localhost` on port `1433` (editable in `main.py` if needed).

Once your email client makes a request you should see a notification about authentication. Click the `Authorise account...` option in the menu bar and follow the instructions to log in to your account. After authentication completes you should have IMAP access to your account as normal.

## Potential improvements (pull requests welcome)
- Background app/service rather than terminal script (e.g., via pyinstaller, etc)
- Handle computer sleep
- Handle server throttling (e.g., responses such as `a01 NO Request is throttled. Suggested Backoff Time: 256625`)
- Testing on different platforms (currently tested only on macOS)
- Better icon
- SMTP server with the same approach ([DavMail](http://davmail.sourceforge.net/) is an alternative for now)

## License
Apache 2.0

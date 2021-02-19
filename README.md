# Email OAuth 2.0 Proxy
An IMAP/SMTP proxy that adds OAuth 2.0 authentication transparently for clients that don't support this method.


## Getting started
First, add configuration details for each account you want to use with the proxy in the file `emailproxy.config`. [Sample configurations](emailproxy.config) are provided for Office 365 and Gmail, but you will need to register a new [Microsoft identity](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) or [Google API](https://support.google.com/googleapi/answer/6158849) client to get started (or use an existing client ID and secret).

While you are editing this file, check the default server details and edit appropriately - again, examples are provided for Office 365 and Gmail, but other services that use OAuth 2.0 should also work.

Next, start the proxy: `python3 emailproxy.py` – a menu bar icon should appear. If you get `ModuleNotFoundError`, use `pip` to install any missing packages.

Finally, open your email client and configure its IMAP details to match those set in the configuration file above. Typically this would be `localhost` on port `1433`. The local connection should be unencrypted, but the connection between the proxy and your email server is secure.

The first time your email client makes a request you should see a notification about authentication. Click the `Authorise account...` option in the menu bar and follow the instructions to log in to your account. After authentication completes you should have IMAP/SMTP access to your account as normal.


## Running as a service/daemon
Move [the included plist file](ac.robinson.email-oauth2-proxy.plist) to `~/Library/LaunchAgents/`, then edit it to replace `/path/to/python3` and `/path/to/emailproxy.py` with the full paths to your local `python3` and the `emailproxy.py` script. Run `launchctl load ac.robinson.email-oauth2-proxy.plist`, and the menu bar icon should appear. The script will now run at startup.

If needed, you can remove the startup service using `launchctl unload ac.robinson.email-oauth2-proxy.plist`.


## Motivation and alternatives
Many email services that provide IMAP/SMTP access require OAuth 2.0 to authenticate the connection, but not all native clients support this. This Python script is a simple local proxy that intercepts authentication commands and transparently replaces them with the appropriate OAuth 2.0 credentials.

[DavMail](http://davmail.sourceforge.net/) is an alternative that provides a local IMAP/SMTP server (and more) for Exchange, though it does this by translating these protocols into EWS rather than proxying the connection.


## Potential improvements (pull requests welcome)
- Testing on different platforms and with different providers (currently tested only with Office 365 on macOS)
- Better structure of menu bar icon, authorisation web views and proxies
- Better error handling
- Encrypted local connections?
- Package as .app/.exe etc


## License
Apache 2.0

# Email OAuth 2.0 Proxy
An IMAP/SMTP proxy that transparently adds OAuth 2.0 authentication for clients that don't support this method.


## Motivation, capabilities and alternatives
Many email services that provide IMAP/SMTP access require the use of OAuth 2.0 to authenticate the connection, but not all native clients support this method. This script creates a simple local proxy that intercepts the standard IMAP/SMTP authentication commands and transparently replaces them with the appropriate OAuth 2.0 commands and credentials. Your email client can continue to use the standard `login` or `auth/authenticate` options, with no need to make it aware of OAuth 2.0's existence.

[DavMail](http://davmail.sourceforge.net/) is an alternative that takes the same approach of providing a local IMAP/SMTP server (and more) for Exchange/Office 365, though it does this by translating these protocols into Exchange API calls rather than proxying the connection. That approach is very useful in situations where IMAP/SMTP are not supported, or the full Exchange capabilities are needed, but it has limitations in terms of speed and the number of email messages that can be retrieved. This proxy was developed to work around these limitations for providers that do support IMAP/SMTP natively.


## Getting started
First, add configuration details for each server and account you want to use with the proxy in the file `emailproxy.config`. [Sample account configurations](emailproxy.config) are provided for Office 365 and Gmail, but you will need to register a new [Microsoft identity](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) or [Google API](https://developers.google.com/identity/protocols/oauth2/native-app) desktop app client (or use your existing desktop app's client ID and secret). Make sure your client is set up to use an OAuth scope that will give it permission to access IMAP/SMTP – see the sample configuration file for examples.

You can remove details from the sample configuration file for services you don't use, or add additional ones for any other OAuth 2.0 IMAP/SMTP servers you would like to use with the proxy (note: services other than Office 365 and Gmail have not been tested, but should work – please [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) if not). Multiple accounts with the same provider can share the same server, and the correct server to use with an account is identified using the port number you configure in your client (see below). Account names (i.e., email addresses) must be unique – only one entry is permitted per account in the configuration file. Once the proxy is running, you can view or update the current configuration from its menu (via the `Servers and accounts` option).

Next, from a terminal, install the script's requirements: `pip3 install -r requirements.txt`, and start the proxy: `python3 emailproxy.py` – a menu bar icon should appear. If you are using Linux and instead of the menu you see an error in the terminal that mentions `pywebview` or `pystray` it is likely that your system is missing their dependencies. See the [Known issues](https://github.com/simonrob/email-oauth2-proxy#known-issues) section below to resolve this. Once any missing dependencies have been resolved, starting the proxy should create a menu bar icon.

Finally, open your email client and configure your account's server details to match those you set in the proxy configuration file. For example, using the sample Office 365 details, this would be `localhost` on port `1433` for IMAP and `localhost` on port `1587` for SMTP. The local connection in your email client should be configured as unencrypted to allow the proxy to operate, but the connection between the proxy and your email server is secured (SSL for IMAP; SSL or STARTTLS for SMTP).

The first time your email client makes a request you should see a notification from the proxy about authentication. Click the proxy's menu bar icon, select your account name in the `Authorise account` submenu, and then log in via the popup window that appears. After authentication completes you should have IMAP/SMTP access to your account as normal.


## Starting the proxy automatically
If you are using macOS you can click the proxy's menu bar icon and then select `Start at login`, which will stop the terminal instance and restart the proxy, configuring it to run as a service/daemon each time you log in.

If you stop the service (i.e., `Quit Email OAuth 2.0 Proxy` from the menu bar), you can restart it using `launchctl start ac.robinson.email-oauth2-proxy` from a terminal. You can stop, disable or remove the service from your startup items either via the menu bar icon options, or using `launchctl unload ~/Library/LaunchAgents/ac.robinson.email-oauth2-proxy.plist`.

Linux users should read the Non-GUI mode section below for a similar approach. Pull requests are welcome to improve this functionality or add similar options for other platforms.


## Non-GUI mode
When starting the proxy there are two optional arguments that are particularly helpful if you would like it to run in a background/service mode on Linux.

`--no-gui` will prevent creating a menu bar icon, which allows the proxy to be run as a `systemctl` service as demonstrated in [issue 2](https://github.com/simonrob/email-oauth2-proxy/issues/2#issuecomment-839713677). Please note that this option is only of use if you have already authorised your accounts via the menu bar icon. Accounts that have not yet been authorised (or for whatever reason require reauthorisation) will fail to connect in this mode, and an error will be printed to the log.

`--debug` enables debug mode, printing more verbose output to the log as discussed in the next section. This argument is identical to enabling debug mode from the menu bar icon.


## Troubleshooting
If you encounter problems using the proxy, enabling `Debug mode` from the menu will print all client-proxy-server communication to your system log to help identify the error. This will include all messages to and from the server, and also the content of your email messages. On macOS this can be viewed using Console.app (select `system.log` in the sidebar). On Linux you can use, for example, `tail -f /var/log/syslog | grep "Email OAuth 2.0 Proxy"`.

Please note that Debug mode may also result in your login credentials being printed to the log (though this is avoided where possible). However, it is worth pointing out that because account authorisation is handled entirely through OAuth 2.0 in a web browser, while the username you set in your email client must be correct, the password used can be anything you like, and does not need to be the one you actually use to log in to your account. The password you provide via your email client is used only to encrypt and decrypt the authentication token that the proxy transparently sends to the server on your behalf. Because of this, if you are concerned about Debug mode and security you can use a test password for debugging and then replace it with a secure password (and authenticate again) once set up.

### Dependencies and setup
On macOS the setup and installation instructions above should automatically install all required dependencies. Please [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) if you encounter problems here.

When first launching on Linux you may encounter errors similar to `Namespace […] not available`. This is caused by missing dependencies for [pystray](https://github.com/moses-palmer/pystray/) and [pywebview](https://github.com/r0x0r/pywebview/), which are used to display the menu bar icon and login windows. See the [pywebview dependencies](https://pywebview.flowrl.com/guide/installation.html#dependencies) page and [issue 1](https://github.com/simonrob/email-oauth2-proxy/issues/1#issuecomment-831746642) in this repository for a summary and suggestions about how to resolve this.

A similar issue may occur on Windows with the [pythonnet](https://github.com/pythonnet/pythonnet) package, which is required for pywebview. If you are unable to resolve this by following the [pythonnet installation instructions](https://github.com/pythonnet/pythonnet/wiki/Installation), you may find that installing a [prebuilt wheel](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pythonnet) helps fix the issue.

### Other issues
Please feel free to [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) reporting any bugs you find, or [submit a pull request](https://github.com/simonrob/email-oauth2-proxy/pulls) to help improve this tool.


## Known issues
- On Windows there is a known incompatibility with [pystray](https://github.com/moses-palmer/pystray/) and [pywebview](https://github.com/r0x0r/pywebview/) that will prevent account authentication. Until pywebview is updated, you can fix this issue by editing your local copy of that package to make [a minor change](https://github.com/r0x0r/pywebview/pull/724), which fixes the bug. It is normally easiest to achieve this by using a [Python virtual environment](https://docs.python.org/3/library/venv.html).
- Authentication currently relies on [pywebview](https://github.com/r0x0r/pywebview/) to display the account login page. For reasons that are currently not clear, the system component that pywebview uses can get into a state where the local login completion redirection URL does not load (pywebview simply hangs). A system restart seems to be the only reliable fix for this.


## Potential improvements (pull requests welcome)
- Full feature parity on different platforms (e.g., launch on startup; live menu updating)
- Testing with different providers (currently verified only with Office 365 and Gmail)
- Encrypted local connections?
- Package as .app/.exe etc?


## License
Apache 2.0

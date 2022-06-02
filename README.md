# Email OAuth 2.0 Proxy
Transparently add OAuth 2.0 support to IMAP/SMTP client applications, scripts or any other email use-cases that don't support this authentication method.


## Motivation and capabilities
Email services that support IMAP and/or SMTP access are increasingly requiring the use of OAuth 2.0 to authenticate connections, but not all clients support this method. This script creates a simple local proxy that intercepts the traditional IMAP/SMTP authentication commands and transparently replaces them with the appropriate SASL (X)OAuth 2.0 commands and credentials. Your email client can continue to use the `login` or `auth`/`authenticate` options, with no need to make it aware of OAuth's existence. The proxy works in the background with a menu bar/taskbar helper or as a system service, and is compatible with macOS, Windows and Linux.

### Example use-cases
- You need to use an Office 365 email account, but don't get on with Outlook. The email client you like doesn't support OAuth 2.0.
- You currently use Gmail via IMAP/SMTP with your raw account credentials (i.e., your real password). You've received a notification that Google is disabling this access at the end of May 2022, but you don't want to use an [App Password](https://support.google.com/accounts/answer/185833) (or cannot enable this option).
- You have an account already set up in an email client, and you need to switch it to OAuth 2.0 authentication. You can edit the server details, but the client forces you to delete and re-add the account to enable OAuth 2.0, and you don't want to do this.
- You have made your own script or application that sends or receives email, but it doesn't support OAuth 2.0, and you don't want to have to modify it to implement this.
- You run a server with multiple services that use IMAP/SMTP, and you don't want to have to set up OAuth 2.0 independently for each one.

In all of these cases and more, this proxy script can help. Follow the instructions below to get started, and please [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) with any problems or suggestions.


## Getting started
After cloning or [downloading](https://github.com/simonrob/email-oauth2-proxy/archive/refs/heads/main.zip) the contents of this repository, start by editing the file `emailproxy.config` to add configuration details for each email server and account that you want to use with the proxy. [Documentation and example account configurations](emailproxy.config) are provided for Office 365, Gmail and several other providers, though you will need to insert your own client credentials for each one (see the [documentation below](#oauth-20-client-credentials)). You can remove details from the sample configuration file for services you don't use, or add additional ones for any other OAuth 2.0-authenticated IMAP/SMTP servers you would like to use with the proxy.

Next, from a terminal, install the script's requirements: `python -m pip install -r requirements.txt`, and start the proxy: `python emailproxy.py` – a menu bar/taskbar icon should appear. If instead of the icon you see an error in the terminal, it is likely that your system is missing dependencies for the `pywebview` or `pystray` packages. See the [dependencies and setup](#dependencies-and-setup) section below to resolve this.

Finally, open your email client and configure its server details to match the ones you set in the proxy's configuration file. The correct server to use with an account is identified using the port number you select in your client. For example, to use the sample Office 365 details, this would be `localhost` on port `1993` for IMAP and `localhost` on port `1587` for SMTP. Multiple accounts with the same provider can share the same server. The local connection in your email client should be configured as unencrypted to allow the proxy to operate, but the connection between the proxy and your email server is always secure (implicit SSL/TLS for IMAP; implicit or explicit (STARTTLS) SSL/TLS for SMTP). You can view or update the current configuration from the proxy's menu (via the `Servers and accounts` option).

The first time your email client makes a request you should see a notification from the proxy about authorising your account. (Note that the notification is not itself clickable, but pull requests to improve this are very welcome). Click the proxy's menu bar icon, select your account name in the `Authorise account` submenu, and then log in via the popup browser window that appears. The window will close itself once the process is complete.

After successful authentication and authorisation you should have IMAP/SMTP access to your account as normal. Make sure you keep the proxy running at all times to allow it to authorise your email client's background activity – enable `Start at login` from the proxy's menu, or see the [instructions below](#starting-the-proxy-automatically) about how to configure this in various different setups.

After your accounts are fully set-up and authorised, no further proxy interaction should be required unless your account needs authorising again. It will notify you if this is the case.


### OAuth 2.0 client credentials
As part of the proxy setup process you need to provide an OAuth 2.0 `client_id` and `client_secret` to allow it to authenticate with email servers on your behalf.

If you have an existing client ID and secret for a desktop app, you can use these directly in the proxy. You can also reuse the client ID and secret from any email client that supports IMAP/SMTP OAuth 2.0 authentication with the email server you would like to connect to.

If you do not have access to credentials for an  existing client you will need to register your own. The process to do this is different for each provider, but the registration guides for several common ones are linked below. In all cases, when registering, make sure your client is set up to use an OAuth scope that will give it permission to access IMAP/SMTP – see the sample configuration file for examples.

- Office 365: register a new [Microsoft identity application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- Gmail / Google Workspace: register a [Google API desktop app client](https://developers.google.com/identity/protocols/oauth2/native-app)
- AOL and Yahoo Mail are not currently allowing new client registrations with the OAuth email scope – the only option here is to use the credentials from an existing client that does have this permission.


## Optional arguments and configuration
When starting the proxy there are several optional arguments that can be set to customise its behaviour.

`--external-auth` configures the proxy to present a clickable account authorisation link that opens in an external browser, rather than using its own built-in browser popup. This can be useful in situations where the script's browser window does not have access to some required authentication attribute of your typical setup. Once you have authorised account access using this method, paste the URL from the browser's address bar back into the script's popup window to give it access to transparently proxy your login. You should ignore any browser error message that is shown (e.g., `localhost refused to connect`); the important part is the URL itself. This argument is identical to enabling external authorisation mode from the `Authorise account` submenu of the menu bar icon.

`--no-gui` will launch the proxy without an icon, which allows it to be run as a `systemctl` service as demonstrated in [issue 2](https://github.com/simonrob/email-oauth2-proxy/issues/2#issuecomment-839713677), or with no GUI toolkit present at all as demonstrated in [issue 11](https://github.com/simonrob/email-oauth2-proxy/issues/11#issuecomment-1073855809). Please note that on its own this mode is only of use if you have already authorised your accounts through the proxy. Unless this option is used in conjunction with `--local-server-auth`, accounts that have not yet been authorised (or for whatever reason require reauthorisation) will time out when authenticating, and an error will be printed to the log.

`--local-server-auth` instructs the proxy to print account authorisation links to its log and temporarily start an internal web server to receive responses, rather than displaying a browser popup window or relying on any GUI interaction. This option is useful primarily in conjunction with the `--no-gui` option and some form of log monitoring. The `--external-auth` option is ignored in this mode.

`--config-file` allows you to specify the location of a [configuration file](emailproxy.config) that the proxy should load. If this argument is not provided, the proxy will look for `emailproxy.config` in the same directory as the script itself.

`--debug` enables debug mode, printing more verbose output to the log as [discussed below](#troubleshooting). This argument is identical to enabling debug mode from the menu bar icon.


### Starting the proxy automatically
In order for the proxy to authenticate background requests from your email client it needs to be kept running constantly. The easiest way to do this is to start the script automatically. The proxy has basic support for this built-in: click its menu bar icon and then select `Start at login`, which will stop the terminal instance and restart the script, configuring it to run each time you log in. On macOS, if you are presented with a prompt about file access here, make sure you grant this so that python can run the script in the background. For more advanced configurations, you may want to customise the startup behaviour and edit the script's parameters – see the sections below for further information on how to achieve this using macOS, Windows or Linux.

On macOS, the file `~/Library/LaunchAgents/ac.robinson.email-oauth2-proxy.plist` is used to configure automatic starting of the proxy. If you stop the proxy's service (i.e., `Quit Email OAuth 2.0 Proxy` from the menu bar), you can restart it using `launchctl start ac.robinson.email-oauth2-proxy` from a terminal. You can stop, disable or remove the service from your startup items either via the menu bar icon option, or using `launchctl unload [plist path]`. If you edit the plist file manually, make sure you `unload` and then `load` it to update the system with your changes. If the `Start at login` option appears not to be working for you on macOS, see the [known issues](#known-issues) section below for potential solutions.

On Windows the auto-start functionality is achieved via a shortcut in your user account's startup folder. Pressing the Windows key and `r` and entering `shell:startup` (and then clicking OK) will open this folder – from here you can either double-click the `ac.robinson.email-oauth2-proxy.cmd` file to relaunch the proxy, edit it to configure, or delete this file (either manually or by deselecting the option in the proxy's menu) to remove the script from your startup items.

On Linux this feature assumes that your system supports XDG Autostart. A Desktop Entry file `ac.robinson.email-oauth2-proxy.desktop` will be created in `~/.config/autostart/`. Use the proxy's menu option (or manually remove this file) to prevent it starting when you log in. It is also possible to run the proxy as a service (e.g., via `systemctl`) – see the `--no-gui` mode option above for more details.


## Troubleshooting
If you encounter problems using the proxy, enabling `Debug mode` from the menu or passing `--debug` as a script argument will print all client–proxy–server communication to your system log to help identify the issue. This will include all commands to and responses from the server (and also as a result the content of your email messages).

On macOS this can be viewed using Console.app or `log stream --predicate 'subsystem == "ac.robinson.email-oauth2-proxy"' --level=debug`. On Windows a file `emailproxy.log` will be created in the same location as the proxy script. On Linux you can use, for example, `tail -f /var/log/syslog | grep "Email OAuth 2.0 Proxy"`.

Please note that debug mode may also result in your login credentials being printed to the log (though this is avoided where possible). However, it is worth pointing out that because account authorisation is handled entirely through OAuth 2.0 in a web browser, while the username you set in your email client must be correct, the password used for the IMAP/SMTP connection can be anything you like, and does not need to be the one you actually use to log in to your account. The password you provide via your email client is used only to encrypt and decrypt the authentication token that the proxy transparently sends to the server on your behalf. Because of this, if you are concerned about debug mode and security you can use a test password for debugging and then replace it with a secure password (and authenticate again) once set up.

It is often helpful to be able to view the raw connection details when debugging (i.e., without using your email client). This can be achieved using `telnet`, [Putty](https://www.chiark.greenend.org.uk/~sgtatham/putty/) or similar. For example, to test the Office 365 IMAP server from the [example configuration](emailproxy.config), first open a connection using `telnet localhost 1993`, and then send a login command: `a1 login e@mail.com password`, replacing `e@mail.com` with your email address, and `password` with any value you like during testing (see above for why the password is irrelevant). If you have already authorised your account with the proxy you should see a response starting with `a1 OK`; if not, this command should trigger a notification from the proxy about authorising your account.

### Dependencies and setup
On macOS the setup and installation instructions above should automatically install all required dependencies. Any error messages you may encounter (for example, with your `pip` version and `cryptograpy`, or `pillow` and `imagingft` dependencies, or [macOS SSL failures](https://github.com/simonrob/email-oauth2-proxy/issues/14#issuecomment-1077379254)) normally give clear explanations of the issues and point to instructions for resolving these problems. Please [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) if you encounter any other problems here.

When first launching on Linux you may encounter errors similar to `Namespace […] not available`. This is caused by missing dependencies for [pystray](https://github.com/moses-palmer/pystray/) and [pywebview](https://github.com/r0x0r/pywebview/), which are used to display the menu bar icon and login windows. See the [pywebview dependencies](https://pywebview.flowrl.com/guide/installation.html#dependencies) page and [issue 1](https://github.com/simonrob/email-oauth2-proxy/issues/1#issuecomment-831746642) in this repository for a summary and suggestions about how to resolve this.

A similar issue may occur on Windows with the [pythonnet](https://github.com/pythonnet/pythonnet) package, which is required for pywebview. If you are unable to resolve this by following the [pythonnet installation instructions](https://github.com/pythonnet/pythonnet/wiki/Installation), you may find that installing a [prebuilt wheel](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pythonnet) helps fix the issue. Note that pythonnet can take some time to be compatible with the latest major python release, so it can be worth using a slightly older version of python.

### Known issues
- On more recent macOS versions (10.14 and later), you may find that you need to manually load the proxy's launch agent in order to trigger a file access permission prompt when first running as a service. You will know if intervention is necessary if the proxy exits (rather than restarts) the first time you click `Start at login` from its menu bar icon. To resolve this, exit the proxy and then run `launchctl load ~/Library/LaunchAgents/ac.robinson.email-oauth2-proxy.plist` from a terminal. A permission pop-up should appear requesting file access for python. Once this has been approved, the proxy's menu bar icon will appear as normal. In some cases — particularly when running the proxy in a virtual environment, or using the built-in macOS python, rather than the python.org version, or installations managed by, e.g., homebrew, pyenv, etc — the permission prompt does not appear. If this happens it is worth first trying to `unload` and then `load` the service via `launchctl`. If this still does not cause the prompt to appear, the only currently-known resolution is to run the proxy outside of a virtual environment and manually grant Full Disk Access to your python executable via the privacy settings in the macOS System Preferences. You may also need to edit the proxy's launch agent plist file, which is found at the location given in the command above, to set the path to your python executable – it must be the real path rather than a symlink (the `readlink` command can help here). Fortunately this is a one-time fix, and once the proxy loads successfully via this method you will not need to adjust its startup configuration again (except perhaps when upgrading to a newer major macOS version, in which case just repeat the procedure).
- On Windows, [pywebview](https://github.com/r0x0r/pywebview/) versions prior to 3.5 had a [bug](https://github.com/r0x0r/pywebview/issues/720) which caused a crash when the proxy's authentication window was opened. To fix this, make sure you have version 3.5 or later of pywebview (which is automatic if you use the proxy's `requirements.txt`).

### Other problems
Please feel free to [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) reporting any bugs you find, or [submit a pull request](https://github.com/simonrob/email-oauth2-proxy/pulls) to help improve this tool.


## Advanced / experimental features
The [plugins branch](https://github.com/simonrob/email-oauth2-proxy/tree/plugins) has a semi-experimental new feature that enables the use of separate scripts to modify IMAP/SMTP commands when they are received from the client or server before passing through to the other side of the connection. This allows a wide range of additional capabilities or triggers to be added the proxy. For example, the [IMAPIgnoreSentMessageUpload plugin](https://github.com/simonrob/email-oauth2-proxy/blob/plugins/plugins/IMAPIgnoreSentMessageUpload.py) intercepts any client commands to add emails to the IMAP sent messages mailbox, which resolves message duplication issues for servers that automatically do this when emails are received via SMTP (e.g., Office 365, Gmail, etc). See the documentation and examples in this branch for further details and setup instructions.


## Potential improvements (pull requests welcome)
- Switch to asyncio (asyncore is currently deprecated, but [PEP 594](https://peps.python.org/pep-0594/) will remove it completely in Python 3.12)
- Full feature parity on different platforms (e.g., live menu updating; monitoring network status)
- Clickable account authorisation notifications
- STARTTLS for IMAP?
- POP3?
- Package as .app/.exe etc?


## Alternatives
[DavMail](http://davmail.sourceforge.net/) is an alternative that takes the same approach of providing a local IMAP/SMTP server (and more) for Exchange/Office 365, though it does this by translating these protocols into Exchange API calls rather than proxying the connection. That approach is very useful in situations where server-side IMAP/SMTP is not supported or enabled, or the full Exchange capabilities are needed, but it has limitations in terms of speed and the number of email messages that can be retrieved. This proxy was developed to work around these limitations for providers that do support IMAP/SMTP natively.


## License
[Apache 2.0](LICENSE)

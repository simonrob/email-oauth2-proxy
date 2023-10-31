# Email OAuth 2.0 Proxy
Transparently add OAuth 2.0 support to IMAP/POP/SMTP client applications, scripts or any other email use-cases that don't support this authentication method.


## Motivation and capabilities
Email services that support IMAP, POP and/or SMTP access are increasingly requiring the use of OAuth 2.0 to authenticate connections, but not all clients support this method.
This script creates a simple local proxy that intercepts the traditional IMAP/POP/SMTP authentication commands and transparently replaces them with the appropriate SASL (X)OAuth 2.0 commands and credentials.
Your email client can continue to use the `login` or `auth`/`authenticate` options, with no need to make it aware of OAuth's existence.
The proxy works in the background with a menu bar/taskbar helper or as a system service, and is compatible with macOS, Windows and Linux.

### Example use-cases
- You need to use an Office 365 email account, but don't get on with Outlook.
The email client you like doesn't support OAuth 2.0, which became mandatory [in January 2023](https://techcommunity.microsoft.com/t5/exchange-team-blog/basic-authentication-deprecation-in-exchange-online-september/ba-p/3609437).
- You used to use Gmail via IMAP/POP/SMTP with your raw account credentials (i.e., your real password), but cannot do this now that Google has disabled this method, and don't want to use an [App Password](https://support.google.com/accounts/answer/185833) (or cannot enable this option).
- You have an account already set up in an email client, and you need to switch it to OAuth 2.0 authentication.
You can edit the server details, but the client forces you to delete and re-add the account to enable OAuth 2.0, and you don't want to do this.
- You have made your own script or application that sends or receives email, but it doesn't support OAuth 2.0, and you don't want to have to modify it to implement this.
- You work with multiple services or applications that use IMAP/POP/SMTP, and you don't want to have to set up OAuth 2.0 independently for each one.

In all of these cases and more, this proxy script can help.
Follow the instructions below to get started, and please [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) with any problems or suggestions.
For commercial support or feature requests, please also consider [sponsoring this project](https://github.com/sponsors/simonrob?frequency=one-time).


## Getting started
Begin by downloading the proxy via one of the following methods:

<ol type="A">
  <li>Pick a <a href="https://github.com/simonrob/email-oauth2-proxy/releases/latest">pre-built release</a> for your platform (no installation needed); <i>or</i>,</li>
  <li>Install from <a href="https://pypi.org/project/emailproxy/">PyPI</a>: <code>python -m pip install emailproxy[gui]</code> to set up, then <code>python -m emailproxy</code> to run; <i>or</i>,</li>
  <li>Clone or <a href="https://github.com/simonrob/email-oauth2-proxy/archive/refs/heads/main.zip">download</a> (and star :-) the <a href="https://github.com/simonrob/email-oauth2-proxy/">GitHub repository</a>, then: <code>python -m pip install -r requirements-core.txt -r requirements-gui.txt</code> to install requirements, and <code>python emailproxy.py</code> to run</li>
</ol>

If you choose download option (A) or (B), you should also [download the sample `emailproxy.config` file](https://github.com/simonrob/email-oauth2-proxy/raw/main/emailproxy.config) and place this into the directory you will run the proxy from.
Next, edit the `emailproxy.config` file to add configuration details for each email server and account that you want to use with the proxy.
[Guidance and example account configurations](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) are provided for Office 365, Gmail and several other providers, though you will need to insert your own client credentials for each one (see the [documentation below](https://github.com/simonrob/email-oauth2-proxy/#oauth-20-client-credentials)).
You can remove details from the sample configuration file for services you don't use, or add additional ones for any other OAuth 2.0-authenticated IMAP/POP/SMTP servers you would like to use with the proxy.

You can now start the proxy: depending on which installation option you chose, either open the application or use the appropriate run command listed above.
A menu bar/taskbar icon should appear.
If instead of the icon you see an error notification, it is likely that your system is missing dependencies for the `pywebview` or `pystray` packages.
See the [dependencies and setup](https://github.com/simonrob/email-oauth2-proxy/#dependencies-and-setup) section below for help resolving this, and also the [advanced configuration](https://github.com/simonrob/email-oauth2-proxy/#advanced-configuration) section for additional options (including fully headless deployments and integration with a secrets manager).

Finally, open your email client and configure its server details to match the ones you set in the proxy's configuration file.
The correct server to use with an account is identified using the port number you select in your client – for example, to use the sample Office 365 details, this would be `localhost` on port `1993` for IMAP, port `1995` for POP and port `1587` for SMTP.
The proxy supports multiple accounts simultaneously, and all accounts associated with the same provider can share the same proxy server.
The local connection in your email client should be configured as unencrypted to allow the proxy to operate, but the connection between the proxy and your email server is always secure (implicit SSL/TLS for IMAP and POP; implicit or explicit (STARTTLS) SSL/TLS for SMTP).
See the [sample configuration file](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) for additional documentation about advanced features, including local encryption, account configuration inheritance and support for running in a container.

The first time your email client makes a request you should see a notification from the proxy about authorising your account.
Click the proxy's menu bar icon, select your account name in the `Authorise account` submenu, and then log in via the popup browser window that appears.
The window will close itself once the process is complete.
See the various [optional arguments](https://github.com/simonrob/email-oauth2-proxy/#optional-arguments-and-configuration) below for completing authentication if running without a GUI.

After successful authentication and authorisation you should have IMAP/POP/SMTP access to your account as normal.
Make sure you keep the proxy running at all times to allow it to authorise your email client's background activity – enable `Start at login` from the proxy's menu, or see the [instructions below](https://github.com/simonrob/email-oauth2-proxy/#starting-the-proxy-automatically) about how to configure this in various different setups.

After your accounts are fully set-up and authorised, no further proxy interaction should be required unless your account needs authorising again.
It will notify you if this is the case.

### OAuth 2.0 client credentials
As part of the proxy setup process you need to provide an OAuth 2.0 `client_id` and `client_secret` to allow it to authenticate with email servers on your behalf.

If you have an existing client ID and secret for a desktop app, you can use these directly in the proxy.
If this is not possible, you can also reuse the client ID and secret from any email client that supports IMAP/POP/SMTP OAuth 2.0 authentication with the email server you would like to connect to (such as [the](https://github.com/mozilla/releases-comm-central/blob/812b7c9068ca5cac0580b0ddbea8e34c141cd441/mailnews/base/src/OAuth2Providers.jsm) [various](https://github.com/Foundry376/Mailspring/blob/master/app/internal_packages/onboarding/lib/onboarding-constants.ts) [open](https://gitlab.gnome.org/GNOME/evolution-data-server/-/blob/master/CMakeLists.txt) [source](https://gitlab.gnome.org/GNOME/gnome-online-accounts/-/blob/master/meson_options.txt) [clients](https://github.com/M66B/FairEmail/blob/master/app/src/main/res/xml/providers.xml) with OAuth 2.0 support), but please do this with care and restraint as access through reused tokens will be associated with the token owner rather than your own client.

If you do not have access to credentials for an existing client you will need to register your own.
The process to do this is different for each provider, but the registration guides for several common ones are linked below.
In all cases, when registering, make sure your client is set up to use an OAuth scope that will give it permission to access IMAP/POP/SMTP as desired.
It is also highly recommended to use a scope that will grant "offline" access (i.e., a way to [refresh the OAuth 2.0 authentication token](https://oauth.net/2/refresh-tokens/) without user intervention).
The [sample configuration file](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) provides example scope values for several common providers.

- Office 365: register a new [Microsoft identity application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- Gmail / Google Workspace: register a [Google API desktop app client](https://developers.google.com/identity/protocols/oauth2/native-app)
- AOL and Yahoo Mail (and subproviders such as AT&T) are not currently allowing new client registrations with the OAuth email scope – the only option here is to reuse the credentials from an existing client that does have this permission.

The proxy also supports the [client credentials grant](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow) and [resource owner password credentials grant](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc) OAuth 2.0 flows if needed.
Please note that currently only Office 365 is known to support these methods.
In addition, when using the client credentials grant flow, Office 365 only supports IMAP/POP, [_not_ SMTP](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth#use-client-credentials-grant-flow-to-authenticate-imap-and-pop-connections) (use [smtp2graph](https://github.com/EvanTrow/smtp2graph) instead here).
See the [sample configuration file](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) for further details.


## Optional arguments and configuration
When starting the proxy there are several optional arguments that can be set to customise its behaviour.

- `--no-gui` will launch the proxy without an icon, which allows it to be run as a `systemctl` service as demonstrated in [this example](https://github.com/simonrob/email-oauth2-proxy/issues/2#issuecomment-839713677), or fully headless as demonstrated in [various](https://github.com/michaelstepner/email-oauth2-proxy-aws) [other](https://github.com/blacktirion/email-oauth2-proxy-docker) subprojects.
Please note that on its own this mode is only of use if you have already authorised your accounts through the proxy in GUI mode, or are importing a pre-authorised proxy configuration file from elsewhere.
Unless this option is used in conjunction with `--external-auth` or `--local-server-auth`, accounts that have not yet been authorised (or for whatever reason require re-authorisation) will time out when authenticating, and an error will be printed to the log.

- `--external-auth` configures the proxy to present an account authorisation URL to be opened in an external browser and wait for you to copy+paste the post-authorisation result.
In GUI mode this can be useful in situations where the script's own browser window does not have access to some required authentication attribute of your typical setup.
In no-GUI mode this option allows you to authenticate accounts entirely externally (unlike `--local-server-auth`, which starts a local web server), though you will need to monitor the proxy's log for authentication notifications.

    After visiting the link provided and authorising account access, paste the final URL from your browser's address bar back into the script's popup window (GUI mode) or the terminal (no-GUI mode) to give it access to transparently proxy your login.
You should ignore any browser error message that is shown (e.g., `unable to connect`); the important part is the URL itself.
This argument is identical to enabling external authorisation mode from the `Authorise account` submenu of the proxy's menu bar icon.

- `--local-server-auth` is similar to `--external-auth`, but instead instructs the proxy to temporarily start an internal web server to receive authentication responses.
The `--external-auth` option is ignored in this mode.
To authorise your account, visit the link that is provided, authenticate, and proceed until you are presented with a success webpage from the proxy.
Please note that while authentication links can actually be visited from anywhere to log in and authorise access, by default the final redirection target (i.e., a link starting with your account's `redirect_uri` value) must be accessed from the machine hosting the proxy itself so that the local server can receive the authorisation result.
See the [sample configuration file](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) for advanced options to configure this (via `redirect_listen_address`).

- `--config-file` allows you to specify the location of a [configuration file](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) that the proxy should load.
By default, the proxy also saves its cached OAuth 2.0 tokens back to this file, so it must be writable.
See the `--cache-store` option, if you would rather store configuration and cached values separately.
If this argument is not provided, the proxy will look for `emailproxy.config` in the same directory as the script itself.

- `--cache-store` is used to specify a separate location in which to cache authorised OAuth 2.0 tokens and associated metadata.
The value of this argument can either be the full path to a local file (which must be writable), or an identifier for an external store such as a secrets manager (see the [documentation below](https://github.com/simonrob/email-oauth2-proxy/#advanced-configuration)).
If this argument is not provided, credentials will be cached in the current configuration file.

- `--log-file` allows you to specify the location of a file to send log output to (full path required).
Log files are rotated at 32MB and 10 older log files are kept.
This option overrides the proxy's default behaviour, which varies by platform (see [below](https://github.com/simonrob/email-oauth2-proxy/#troubleshooting) for details).

- `--debug` enables debug mode, printing more verbose output to the log as [discussed below](https://github.com/simonrob/email-oauth2-proxy/#troubleshooting).
This argument is identical to enabling debug mode from the proxy's menu bar icon.

### Advanced configuration
The [example configuration file](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) contains further documentation for various additional features of the proxy, including catch-all (wildcard) accounts, locally-encrypted connections and advanced Office 365 OAuth 2.0 flows.

The proxy caches authenticated OAuth 2.0 tokens and associated metadata back to its own configuration file by default, but can alternatively be configured to use either a separate local file or a secrets manager service for this purpose.
Currently only [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) is supported for remote token storage.
To use this feature, set the [`--cache-store`](https://github.com/simonrob/email-oauth2-proxy/#optional-arguments-and-configuration) parameter to either a full ARN or a secret name, prefixing the value with `aws:` to identify its type to the proxy.
You must also install the AWS SDK for Python: `python -m pip install boto3` and [set up authentication credentials](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html#configuration) (including a region).
The minimum required permissions for the associated AWS IAM user are `secretsmanager:GetSecretValue` and `secretsmanager:PutSecretValue`.
If the named AWS Secret does not yet exist, the proxy will attempt to create it; here, the `secretsmanager:CreateSecret` permission is also required.

If you are using the proxy in a non-GUI environment it is possible to skip installation of dependencies that apply only to the interactive version.
To do this, install the script via `python -m pip install emailproxy` (i.e., without the `[gui]` variant option), and pass the [`--no-gui`](https://github.com/simonrob/email-oauth2-proxy/#optional-arguments-and-configuration) argument when starting the proxy.
Please note that the proxy was designed as a GUI-based tool from the outset due to the inherently interactive nature of OAuth 2.0 authorisation, and there are limits to its ability to support fully no-GUI operation.
See the [optional arguments and configuration](https://github.com/simonrob/email-oauth2-proxy/#optional-arguments-and-configuration) section of this file for further details.

If your network requires connections to use an existing proxy, you can instruct the script to use this by setting the [proxy handler](https://docs.python.org/3/library/urllib.request.html#urllib.request.ProxyHandler) environment variable `https_proxy` (and/or `http_proxy`) – for example, `https_proxy=localhost python emailproxy.py`.

After installing its requirements, the proxy can be packaged as a single self-contained executable using [pyinstaller](https://pyinstaller.org/) if desired: `pyinstaller --onefile emailproxy.py`.
If you are using the GUI version of the proxy, you may need to add `--hidden-import timeago.locales.en_short` until [this `timeago` issue](https://github.com/hustcc/timeago/issues/40) is resolved.

Python 3.6 or later is required to run the proxy.
The [python2 branch](https://github.com/simonrob/email-oauth2-proxy/tree/python2) provides minimal compatibility with python 2.7, but with a limited feature set, and only very occasional maintenance.
See [issue 38](https://github.com/simonrob/email-oauth2-proxy/issues/38) for further discussion.

### Starting the proxy automatically
In order for the proxy to authenticate background requests from your email client it needs to be kept running constantly.
The easiest way to do this is to start the script automatically.
In GUI mode the proxy has basic support for this built-in: click its menu bar icon and then select `Start at login`, which will stop the terminal instance and restart the script, configuring it to run each time you log in.
On macOS, if you are presented with a prompt about file access here, make sure you grant this so that python can run the script in the background.
For more advanced configurations, you may want to customise the startup behaviour and edit the script's parameters – see the sections below for further information on how to achieve this using macOS, Windows or Linux.

On macOS, the file `~/Library/LaunchAgents/ac.robinson.email-oauth2-proxy.plist` is used to configure automatic starting of the proxy.
If you stop the proxy's service (i.e., `Quit Email OAuth 2.0 Proxy` from the menu bar), you can restart it using `launchctl start ac.robinson.email-oauth2-proxy` from a terminal.
You can stop, disable or remove the service from your startup items either via the menu bar icon option, or using `launchctl unload [plist path]`.
If you edit the plist file manually, make sure you `unload` and then `load` it to update the system with your changes.
If the `Start at login` option appears not to be working for you on macOS, see the [known issues](https://github.com/simonrob/email-oauth2-proxy/#known-issues) section below for potential solutions.

On Windows the auto-start functionality is achieved via a shortcut in your user account's startup folder.
Pressing `⊞ Win` + `r` and entering `shell:startup` (and then clicking OK) will open this folder – from here you can either double-click the `ac.robinson.email-oauth2-proxy.cmd` file to relaunch the proxy, edit it to configure, or delete this file (either manually or by deselecting the option in the proxy's menu) to remove the script from your startup items.

On Linux this feature assumes that your system supports XDG Autostart.
A Desktop Entry file `ac.robinson.email-oauth2-proxy.desktop` will be created in `~/.config/autostart/`.
Use the proxy's menu option (or manually remove this file) to prevent it starting when you log in.
It is also possible to run the proxy as a service (e.g., via `systemctl`) – see the `--no-gui` mode option above for more details.


## Troubleshooting
If you encounter problems using the proxy, enabling `Debug mode` from the menu or passing `--debug` as a script argument will print all client–proxy–server communication to your system log to help identify the issue.
This will include all commands to and responses from the server (and also as a result the content of your email messages).

On macOS this can be viewed using Console.app or `log stream --predicate 'subsystem == "ac.robinson.email-oauth2-proxy"' --level=debug`.
On Windows a file `emailproxy.log` will be created in the same location as the proxy script (see also the `--log-file` option).
On Linux you can use, for example, `tail -f /var/log/syslog | grep "Email OAuth 2.0 Proxy"`.

Please note that debug mode may also result in your login credentials being printed to the log (though this is avoided where possible).
However, it is worth pointing out that because account authorisation with the remote email server is handled entirely through OAuth 2.0 in a web browser, while the username you set in your email client must be correct, the password used for the local IMAP/POP/SMTP connection to the proxy can be anything you like, and does not need to be the one you actually use to log in to your account (though it must be the same value each time, or you will be asked to re-authenticate repeatedly by the proxy).
The password you provide via your email client is used only to encrypt and decrypt the OAuth 2.0 authentication token that the proxy transparently sends to the server on your behalf.
Because of this, if you are concerned about debug mode and security you can use a test password for debugging and then replace it with a secure password (and authenticate again) once set up.

It is often helpful to be able to view the raw connection details when debugging (i.e., without using your email client).
This can be achieved using `telnet`, [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/) or similar.
For example, to test the Office 365 IMAP server from the [example configuration](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config), first open a connection using `telnet localhost 1993`, and then send a login command: `a1 login e@mail.com password`, replacing `e@mail.com` with your email address, and `password` with any value you like during testing (see above for why the password is irrelevant).
If you have already authorised your account with the proxy you should see a response starting with `a1 OK`; if not, this command should trigger a notification from the proxy about authorising your account.

If you are using a [secure local connection](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) the interaction with the remote email server is the same as above, but you will need to use a local debugging tool that supports encryption.
The easiest approach here is to use [OpenSSL](https://www.openssl.org/): `openssl s_client -crlf -connect localhost:1993`.

If you are having trouble actually connecting to the proxy, it is always worth double-checking the `local_address` values that you are using.
The [sample configuration file](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) sets this parameter to `127.0.0.1` for all servers.
If you remove this value and do not provide your own, the proxy defaults to `::` – in most cases this resolves to `localhost` for both IPv4 and IPv6 configurations, but it is possible that this differs depending on your environment.
If you are unable to connect to the proxy from your client, it is always worth first specifying this value explicitly – see the [sample configuration file](https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.config) for further details about how to do this.
Please try setting and connecting to both IPv4 (i.e., `127.0.0.1`) and IPv6 (i.e., `::1`) loopback addresses before reporting any connection issues with the proxy.

### Dependencies and setup
On macOS the setup and installation instructions above should automatically install all required dependencies.
Any error messages you may encounter (for example, with your `pip` version and `cryptography`, or `pillow` and `imagingft` dependencies, or [macOS SSL failures](https://github.com/simonrob/email-oauth2-proxy/issues/14#issuecomment-1077379254)) normally give clear explanations of the issues and point to instructions for resolving these problems.
Please [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) if you encounter any other problems here.

When first launching on Linux in GUI mode you may encounter errors similar to `Namespace […] not available`, issues with the task bar icon display, or no browser popup when attempting to authorise your accounts.
This is caused by missing dependencies for [pystray](https://github.com/moses-palmer/pystray/) and [pywebview](https://github.com/r0x0r/pywebview/), which are used to display the menu bar icon and authentication windows.
See the [pywebview dependencies](https://pywebview.flowrl.com/guide/installation.html#dependencies) and [pystray FAQ](https://pystray.readthedocs.io/en/latest/faq.html) pages and [existing](https://github.com/simonrob/email-oauth2-proxy/issues/1#issuecomment-831746642) [closed issues](https://github.com/simonrob/email-oauth2-proxy/issues/136#issuecomment-1430417456) in this repository for a summary and suggestions about how to resolve this.

A similar issue may occur on Windows with the [pythonnet](https://github.com/pythonnet/pythonnet) package, which is required by [pywebview](https://github.com/r0x0r/pywebview).
If you are unable to resolve this by following the [pythonnet installation instructions](https://github.com/pythonnet/pythonnet/wiki/Installation), you may find that installing a [prebuilt wheel](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pythonnet) helps fix the issue.
Note that the public releases of pythonnet can take some time to be compatible with the latest major python release, so it can be worth using a slightly older version of python, or a pre-release version of pythonnet.

### Known issues
- With some combinations of operating systems, web engines and virtual environments, keyboard control or input to the proxy's popup authorisation window may not always work.
On Windows this is normally limited to keyboard shortcuts (i.e., copy/paste), but in some virtual environments on macOS the entire keyboard may not work.
As a workaround, the proxy will enable pywebview's debug mode when you run the proxy in debug mode, which should allow you to use the right-click context menu to copy/paste to enter text.
If you are unable to proceed with popup-based authentication even with this workaround, it is worth trying the proxy's `--external-auth` or `--local-server-auth` options.

- On more recent macOS versions (10.14 and later), you may find that when first running the proxy as a service you need to manually load its launch agent in order to trigger a file access permission prompt.
You will know if intervention is necessary if the proxy exits (rather than restarts) the first time you click `Start at login` from its menu bar icon.
To resolve this, exit the proxy and then run `launchctl load ~/Library/LaunchAgents/ac.robinson.email-oauth2-proxy.plist` from a terminal.
A permission pop-up should appear requesting file access for python.
Once this has been approved, the proxy's menu bar icon will appear as normal.
In some cases — particularly when running the proxy in a virtual environment, or using the built-in macOS python, rather than the python.org version, or installations managed by, e.g., homebrew, pyenv, etc — the permission prompt does not appear.
If this happens it is worth first trying to `unload` and then `load` the service via `launchctl`.
If this still does not cause the prompt to appear, the only currently-known resolution is to run the proxy outside of a virtual environment and manually grant Full Disk Access to your python executable via the privacy settings in the macOS System Preferences.
You may also need to edit the proxy's launch agent plist file, which is found at the location given in the command above, to set the path to your python executable – it must be the real path rather than a symlink (the `readlink` command can help here).
Fortunately this is a one-time fix, and once the proxy loads successfully via this method you will not need to adjust its startup configuration again (except perhaps when upgrading to a newer major macOS version, in which case just repeat the procedure).

### Other problems
Please feel free to [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) reporting any bugs you find, or [submit a pull request](https://github.com/simonrob/email-oauth2-proxy/pulls) to help improve this tool.


## Advanced / experimental features
The [plugins variant](https://github.com/simonrob/email-oauth2-proxy/tree/plugins) has a semi-experimental new feature that enables the use of separate scripts to modify IMAP/POP/SMTP commands when they are received from the client or server before passing through to the other side of the connection.
This allows a wide range of additional capabilities or triggers to be added the proxy.
For example, the [IMAPIgnoreSentMessageUpload plugin](https://github.com/simonrob/email-oauth2-proxy/blob/plugins/plugins/IMAPIgnoreSentMessageUpload.py) intercepts any client commands to add emails to the IMAP sent messages mailbox, which resolves message duplication issues for servers that automatically do this when emails are received via SMTP (e.g., Office 365, Gmail, etc).
The [IMAPCleanO365ATPLinks plugin](https://github.com/simonrob/email-oauth2-proxy/blob/plugins/plugins/IMAPCleanO365ATPLinks.py) restores links modified by Office 365 Advanced Threat Protection to their original URLs.
The [SMTPBlackHole plugin](https://github.com/simonrob/email-oauth2-proxy/blob/plugins/plugins/SMTPBlackHole.py) gives the impression emails are being sent but actually silently discards them, which is useful for testing email sending tools.
See the [documentation and examples](https://github.com/simonrob/email-oauth2-proxy/tree/plugins/plugins) for further details, additional sample plugins and setup instructions.


## Potential improvements (pull requests welcome)
- Switch to asyncio? (asyncore is currently deprecated, but [PEP 594](https://peps.python.org/pep-0594/) will remove it completely in Python 3.12 – currently mitigated by the use of [pyasyncore](https://pypi.org/project/pyasyncore/))
- Full feature parity on different platforms (e.g., live menu updating; monitoring network status; clickable notifications)
- STARTTLS for IMAP/POP?
- Python 2 support? (see [discussion](https://github.com/simonrob/email-oauth2-proxy/issues/38))


## Related projects and alternatives
Michael Stepner has created a [Terraform configuration](https://github.com/michaelstepner/email-oauth2-proxy-aws) that helps run this proxy on a lightweight cloud server (AWS EC2).
Thiago Macieira has provided a [makefile and systemd configuration files](https://github.com/thiagomacieira/email-oauth2-proxy/tree/Add_a_Makefile_and_systemd_configuration_files_to_install_system_wide).
For Docker, blacktirion has an [example configuration](https://github.com/blacktirion/email-oauth2-proxy-docker).

If you already use postfix, the [sasl-xoauth2](https://github.com/tarickb/sasl-xoauth2) plugin is probably a better solution than running this proxy.
Similarly, if you use an application that is able to handle OAuth 2.0 tokens but just cannot retrieve them itself, then [pizauth](https://github.com/ltratt/pizauth), [mailctl](https://github.com/pdobsan/mailctl) or [oauth-helper-office-365](https://github.com/ahrex/oauth-helper-office-365) may be more appropriate.
There are also dedicated helpers available for specific applications (e.g., [mutt_oauth2](https://gitlab.com/muttmua/mutt/-/blob/master/contrib/mutt_oauth2.py)), and several open-source email clients that support OAuth 2.0 natively (e.g., [Thunderbird](https://www.thunderbird.net/), [Mailspring](https://getmailspring.com/), [FairEmail](https://email.faircode.eu/), [Evolution](https://wiki.gnome.org/Apps/Evolution), etc).

[DavMail](http://davmail.sourceforge.net/) is an alternative to this proxy that takes the same approach of providing a local IMAP/POP/SMTP server (and more) for Exchange/Office 365, though it does this by translating these protocols into Exchange API calls rather than proxying the connection.
That approach is very useful in situations where server-side IMAP/POP/SMTP is not supported or enabled, or the full Exchange capabilities are needed, but it has limitations in terms of speed and the number of email messages that can be retrieved.
This proxy was developed to work around these limitations for providers that do support IMAP/POP/SMTP natively.


## License
[Apache 2.0](https://github.com/simonrob/email-oauth2-proxy/blob/main/LICENSE)

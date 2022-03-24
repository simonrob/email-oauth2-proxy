# Email OAuth 2.0 Proxy
An IMAP/SMTP proxy that transparently adds OAuth 2.0 authentication for client applications that don't support this method. The proxy works in the background with a menu bar/taskbar helper or as a system service, and is compatible with macOS, Windows and Linux.


## Motivation and capabilities
Many email services that provide IMAP/SMTP access require the use of OAuth 2.0 to authenticate the connection, but not all clients support this method. This script creates a simple local proxy that intercepts the standard IMAP/SMTP authentication commands and transparently replaces them with the appropriate (X)OAuth 2.0 commands and credentials. Your email client can continue to use the traditional `login` or `auth`/`authenticate` options, with no need to make it aware of OAuth's existence.


## Getting started
After [downloading](https://github.com/simonrob/email-oauth2-proxy/archive/refs/heads/main.zip) the contents of this repository, start by editing the file `emailproxy.config` to add configuration details for each server and account you want to use with the proxy. [Documentation and example account configurations](emailproxy.config) are provided for Office 365 and Gmail, but you will need to register a new [Microsoft identity](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) or [Google API](https://developers.google.com/identity/protocols/oauth2/native-app) desktop app client (or use your existing desktop app's client ID and secret). Make sure your client is set up to use an OAuth scope that will give it permission to access IMAP/SMTP – see the sample configuration file for examples.

You can remove details from the sample configuration file for services you don't use, or add additional ones for any other OAuth 2.0 IMAP/SMTP servers you would like to use with the proxy (note: services other than Office 365 and Gmail have not been tested, but should work – please [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) if not). Multiple accounts with the same provider can share the same server, and the correct server to use with an account is identified using the port number you configure in your client, as explained below. Account names (i.e., email addresses) must be unique – only one entry per account is permitted in the configuration file. Once the proxy is running, you can view or update the current configuration from its menu (via the `Servers and accounts` option).

Next, from a terminal, install the script's requirements: `python3 -m pip install -r requirements.txt`, and start the proxy: `python3 emailproxy.py` – a menu bar/taskbar icon should appear. If instead of the icon you see an error in the terminal, it is likely that your system is missing dependencies for the `pywebview` or `pystray` packages. See the [Dependencies and setup](https://github.com/simonrob/email-oauth2-proxy#dependencies-and-setup) section below to resolve this. Once any missing dependencies have been installed, starting the proxy should create a menu bar icon.

Finally, open your email client and configure your account's server details to match the ones you set in the proxy's configuration file. For example, using the sample Office 365 details, this would be `localhost` on port `1993` for IMAP and `localhost` on port `1587` for SMTP. The local connection in your email client should be configured as unencrypted to allow the proxy to operate, but the connection between the proxy and your email server is secured (implicit SSL/TLS for IMAP; implicit or explicit (STARTTLS) SSL/TLS for SMTP).

The first time your email client makes a request you should see a notification from the proxy about authorising your account. (Note that the notification is not itself clickable, but pull requests to improve this are very welcome). Click the proxy's menu bar icon, select your account name in the `Authorise account` submenu, and then log in via the popup browser window that appears. The window will close itself once the process is complete.

After successful authentication and authorisation you should have IMAP/SMTP access to your account as normal. Make sure you keep the proxy running at all times to allow it to authorise your email client's background activity – see the next section for instructions about how to do this. No further proxy interaction should be required unless your account needs authorising again, but it will notify you if this is the case.


## Starting the proxy automatically
The simplest way to start the proxy automatically is to click its menu bar icon and then select `Start at login`, which will stop the terminal instance and restart the script, configuring it to run each time you log in. A different approach is used to achieve this depending on whether you are using macOS, Windows or Linux.

On macOS, if you stop the proxy's service (i.e., `Quit Email OAuth 2.0 Proxy` from the menu bar), you can restart it using `launchctl start ac.robinson.email-oauth2-proxy` from a terminal. You can stop, disable or remove the service from your startup items either via the menu bar icon options, or using `launchctl unload ~/Library/LaunchAgents/ac.robinson.email-oauth2-proxy.plist`.

On more recent macOS versions (10.14 and later), you may find that you need to manually load the proxy's launch agent in order to trigger a permission prompt when first running as a service. You will know if this is necessary if the proxy exits (rather than restarts) the first time you click `Start at login` from its menu bar icon. To resolve this, exit the proxy and then run `launchctl start ~/Library/LaunchAgents/ac.robinson.email-oauth2-proxy.plist` from a terminal. A permission pop-up should appear requesting access for python. Once this has been approved, the proxy's menu bar icon will appear as normal (though you may need to run the command again). In some cases — particularly when running the proxy in a python virtual environment — the permission prompt does not appear. If this happens it is worth first trying to `unload` and then `load` the service via `launchctl`. If this still does not cause the prompt to appear, the only currently-known resolution is to run the proxy outside of a virtual environment and manually grant Full Disk Access to your python executable via the privacy settings in the macOS System Preferences. You may also need to edit the proxy's launch agent plist file, which is found at the location given in the command above, to set the path to your python executable – it must be the real path rather than a symlink (the `readlink` command can help here). Fortunately this is a one-time fix, and once the proxy loads successfully via this method you will not need to adjust its startup configuration again (except perhaps when upgrading to a newer major macOS version, in which case just repeat the procedure).

On Windows the auto-start functionality is achieved via a shortcut in your user account's startup folder. Pressing the Windows key and `r` and entering `shell:startup` (and then clicking OK) will open this folder – from here you can either double-click the `ac.robinson.email-oauth2-proxy.cmd` file to relaunch the proxy, or delete this file (either manually or by deselecting the option in the proxy's menu) to remove the script from your startup items.

On Linux this feature assumes that your system supports XDG Autostart. A Desktop Entry file `ac.robinson.email-oauth2-proxy.desktop` will be created in `~/.config/autostart/`. Use the proxy's menu option (or manually remove this file) to prevent it starting when you log in. It is also possible to run the proxy as a service (e.g., via `systemctl`) – see the `--no-gui` mode option below for more details.


## Optional arguments
When starting the proxy there are several optional arguments that can be set to customise its behaviour.

`--external-auth` configures the proxy to present a clickable account authorisation link that opens in an external browser, rather than using its own built-in browser popup. This can be useful in situations where the script's browser window does not have access to some required authentication attribute of your typical setup. Once you have authorised account access using this method, paste the URL from the browser's address bar back into the script's popup window to give it access to transparently proxy your login. You should ignore any browser error message that is shown (e.g., `localhost refused to connect`); the important part is the URL itself. This argument is identical to enabling external authorisation mode from the `Authorise account` submenu of the menu bar icon.

`--no-gui` will launch the proxy without an icon, which allows it to be run as a `systemctl` service as demonstrated in [issue 2](https://github.com/simonrob/email-oauth2-proxy/issues/2#issuecomment-839713677), or with no GUI toolkit present at all as demonstrated in [issue 11](https://github.com/simonrob/email-oauth2-proxy/issues/11#issuecomment-1073855809). Please note that on its own this mode is only of use if you have already authorised your accounts through the proxy. Unless this option is used in conjunction with `--local-server-auth`, accounts that have not yet been authorised (or for whatever reason require reauthorisation) will time out when authenticating, and an error will be printed to the log.

`--local-server-auth` instructs the proxy to print account authorisation links to its log (i.e., `syslog`) and temporarily start an internal web server on demand to receive responses, rather than displaying a browser popup window or relying on any GUI interaction. This option is useful primarily in conjunction with the `--no-gui` option and some form of log monitoring. The `--external-auth` option is ignored in this mode.

`--debug` enables debug mode, printing more verbose output to the log as discussed in the next section. This argument is identical to enabling debug mode from the menu bar icon.


## Troubleshooting
If you encounter problems using the proxy, enabling `Debug mode` from the menu or passing `--debug` as a script argument will print all client–proxy–server communication to your system log to help identify the issue. This will include all commands to and responses from the server (and also as a result the content of your email messages).

On macOS this can be viewed using Console.app (select `system.log` in the sidebar). On Windows a file `emailproxy.log` will be created in the same location as the proxy script. On Linux you can use, for example, `tail -f /var/log/syslog | grep "Email OAuth 2.0 Proxy"`.

Please note that debug mode may also result in your login credentials being printed to the log (though this is avoided where possible). However, it is worth pointing out that because account authorisation is handled entirely through OAuth 2.0 in a web browser, while the username you set in your email client must be correct, the password used for the IMAP/SMTP connection can be anything you like, and does not need to be the one you actually use to log in to your account. The password you provide via your email client is used only to encrypt and decrypt the authentication token that the proxy transparently sends to the server on your behalf. Because of this, if you are concerned about debug mode and security you can use a test password for debugging and then replace it with a secure password (and authenticate again) once set up.

It is often helpful to be able to view the raw connection details when debugging (i.e., without using your email client). This can be achieved using `telnet` on macOS/Linux, or [Putty](https://www.chiark.greenend.org.uk/~sgtatham/putty/) on Windows. For example, to test the Office 365 IMAP server from the [example configuration](emailproxy.config), first open a connection using `telnet localhost 1993`, and then send a login command: `a1 login e@mail.com password`, replacing `e@mail.com` with your email address, and `password` with any value you like during testing (see above for why the password is irrelevant). If you have already authorised your account with the proxy you should see a response starting with `a1 OK LOGIN`; if not, this command should trigger a notification from the proxy about authorising your account.

### Dependencies and setup
On macOS the setup and installation instructions above should automatically install all required dependencies. Any error messages you may encounter (for example, with your `pip` version and `cryptograpy`, or `pillow` and `imagingft` dependencies, or [macOS SSL failures](https://github.com/simonrob/email-oauth2-proxy/issues/14#issuecomment-1077379254)) normally give clear explanations of the issues and point to instructions for resolving these problems. Please [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) if you encounter any other problems here.

When first launching on Linux you may encounter errors similar to `Namespace […] not available`. This is caused by missing dependencies for [pystray](https://github.com/moses-palmer/pystray/) and [pywebview](https://github.com/r0x0r/pywebview/), which are used to display the menu bar icon and login windows. See the [pywebview dependencies](https://pywebview.flowrl.com/guide/installation.html#dependencies) page and [issue 1](https://github.com/simonrob/email-oauth2-proxy/issues/1#issuecomment-831746642) in this repository for a summary and suggestions about how to resolve this.

A similar issue may occur on Windows with the [pythonnet](https://github.com/pythonnet/pythonnet) package, which is required for pywebview. If you are unable to resolve this by following the [pythonnet installation instructions](https://github.com/pythonnet/pythonnet/wiki/Installation), you may find that installing a [prebuilt wheel](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pythonnet) helps fix the issue.

### Known issues
- On Windows, [pywebview](https://github.com/r0x0r/pywebview/) versions prior to 3.5 had a bug which caused a crash when the proxy's authentication window was opened. To fix this, make sure you have version 3.5 or later of pywebview (which is automatic if you use the proxy's `requirements.txt`).

### Other problems
Please feel free to [open an issue](https://github.com/simonrob/email-oauth2-proxy/issues) reporting any bugs you find, or [submit a pull request](https://github.com/simonrob/email-oauth2-proxy/pulls) to help improve this tool.


## Potential improvements (pull requests welcome)
- Full feature parity on different platforms (e.g., live menu updating; suspend on sleep)
- Testing with different providers (currently verified only with Office 365 and Gmail)
- Clickable account authorisation notifications
- STARTTLS for IMAP?
- POP3?
- Package as .app/.exe etc?


## Alternatives
[DavMail](http://davmail.sourceforge.net/) is an alternative that takes the same approach of providing a local IMAP/SMTP server (and more) for Exchange/Office 365, though it does this by translating these protocols into Exchange API calls rather than proxying the connection. That approach is very useful in situations where server-side IMAP/SMTP is not supported or enabled, or the full Exchange capabilities are needed, but it has limitations in terms of speed and the number of email messages that can be retrieved. This proxy was developed to work around these limitations for providers that do support IMAP/SMTP natively.


## License
[Apache 2.0](LICENSE)

ifeq ($(AS_USER),)
prefix = /usr/local
configdir = $(prefix)/etc
libdir = $(prefix)/lib
nmdispatcherdir = $(libdir)/NetworkManager/dispatcher.d
systemddir = $(libdir)/systemd/system
sysusersdir = $(libdir)/sysusers.d
else
prefix = $${XDG_CONFIG_DATA-$$HOME/.local}
configdir = $${XDG_CONFIG_HOME-$$HOME/.config}
libdir = $(prefix)
systemddir = $(libdir)/systemd/user
endif

bindir = $(prefix)/bin

INSTALL_FILE = install -m 644 -t
INSTALL_BIN = install -m 755 -t
INSTALL_DIR = install -m 755 -d

install: install-bin install-config install-systemd
install-bin:
	$(INSTALL_DIR) $(INSTALL_ROOT)$(bindir)
	$(INSTALL_BIN) $(INSTALL_ROOT)$(bindir) emailproxy.py

install-config: $(INSTALL_ROOT)$(configdir)/emailproxy/emailproxy.config
$(INSTALL_ROOT)$(configdir)/emailproxy/emailproxy.config:
	$(INSTALL_DIR) $(INSTALL_ROOT)$(configdir)/emailproxy
	$(INSTALL_FILE) $(INSTALL_ROOT)$(configdir)/emailproxy emailproxy.config

install-systemd: emailproxy.service.in
	$(INSTALL_DIR) $(INSTALL_ROOT)$(systemddir)
	bindir=$(bindir) configdir=$(configdir); sed -e "s,@configdir@,$$configdir,g" -e "s,@bindir@,$$bindir,g" < $< > $(INSTALL_ROOT)$(systemddir)/emailproxy.service
ifneq ($(sysusersdir),)
	$(INSTALL_DIR) $(INSTALL_ROOT)$(sysusersdir)
	$(INSTALL_FILE) $(INSTALL_ROOT)$(sysusersdir) sysusers.d/emailproxy.conf

install: install-nm
install-nm:
	$(INSTALL_DIR) $(nminstalldir)
	$(INSTALL_FILE) $(INSTALL_ROOT)$(nminstalldir) NetworkManager-dispatcher/emailproxy.sh
endif

.PHONY: install install-bin install-config install-nm install-systemd

# yindle — install target honoring the FHS perm map.
# `make && make install DESTDIR=…` produces the layout distro packages ship.

PREFIX        ?= /usr
DESTDIR       ?=
BINDIR        ?= $(PREFIX)/bin
SBINDIR       ?= $(PREFIX)/sbin
SERVERBIN     ?= $(PREFIX)/lib/cups
DATADIR       ?= $(PREFIX)/share/cups
DOCDIR        ?= $(PREFIX)/share/doc/yindle
MANDIR        ?= $(PREFIX)/share/man
UNITDIR       ?= $(PREFIX)/lib/systemd/system
SYSCONFDIR    ?= /etc/cups
PAMDIR        ?= /etc/pam.d
SPOOLDIR      ?= /var/spool/cups
LOGDIR        ?= /var/log/cups
CACHEDIR      ?= /var/cache/cups
RUNDIR        ?= /run/cups
USER          ?= lp
GROUP         ?= lp

CARGO         ?= cargo
PROFILE       ?= release
TARGETDIR     ?= target/$(PROFILE)

# The shipped binaries → their install locations (ServerBin layout).
DAEMONS       := cups-deviced cups-driverd
BACKENDS      := socket file ipp lpd snmp usb dnssd serial parallel
BIN_PROGS     := cupsfilter
HELPERS       := cups-exec cups-lpd

.PHONY: all build install uninstall test check-fmt clippy

all: build

build:
	$(CARGO) build --workspace --profile $(PROFILE)

# ---- install -------------------------------------------------------------
# Perm map (upstream cups install):
#   sbin/cupsd        0755 root:root
#   daemon/*          0755 root:root   (cups-deviced/cups-driverd helpers)
#   backend/*         0755 root:root   (usb/parallel stay 0700 historically)
#   filter/ notifier/ 0755 root:root   (empty dirs for site filters)
#   bin/cupsfilter    0755 root:root
#   etc/cups          0755 root:lp     (cupsd.conf 0640, printers.conf 0600)
#   spool/log/cache/run  lp:lp         (see perms below)
install: build
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGETDIR)/cupsd $(DESTDIR)$(SBINDIR)/cupsd
	# ServerBin helpers.
	install -d $(DESTDIR)$(SERVERBIN)/daemon $(DESTDIR)$(SERVERBIN)/backend \
	           $(DESTDIR)$(SERVERBIN)/filter $(DESTDIR)$(SERVERBIN)/notifier \
	           $(DESTDIR)$(SERVERBIN)/driver $(DESTDIR)$(SERVERBIN)/cgi-bin
	for d in $(DAEMONS); do \
	    install -m 0755 $(TARGETDIR)/$$d $(DESTDIR)$(SERVERBIN)/daemon/$$d; done
	for h in $(HELPERS); do \
	    install -m 0755 $(TARGETDIR)/$$h $(DESTDIR)$(SERVERBIN)/daemon/$$h 2>/dev/null || \
	    install -m 0755 $(TARGETDIR)/$$h $(DESTDIR)$(SERVERBIN)/$$h; done
	for b in $(BACKENDS); do \
	    install -m 0755 $(TARGETDIR)/$$b $(DESTDIR)$(SERVERBIN)/backend/$$b 2>/dev/null || true; done
	# usb + parallel backends are mode 0700 upstream (device access).
	chmod 0700 $(DESTDIR)$(SERVERBIN)/backend/usb 2>/dev/null || true
	chmod 0700 $(DESTDIR)$(SERVERBIN)/backend/parallel 2>/dev/null || true
	for b in $(BIN_PROGS); do \
	    install -m 0755 $(TARGETDIR)/$$b $(DESTDIR)$(BINDIR)/$$b; done
	# Data files (mime db, banners, drv, ppd dirs).
	install -d $(DESTDIR)$(DATADIR)/mime $(DESTDIR)$(DATADIR)/banners \
	           $(DESTDIR)$(DATADIR)/drv $(DESTDIR)$(DATADIR)/ppd \
	           $(DESTDIR)$(DATADIR)/data $(DESTDIR)$(DATADIR)/templates \
	           $(DESTDIR)$(DATADIR)/www
	-[ -d data/mime ] && install -m 0644 data/mime/* $(DESTDIR)$(DATADIR)/mime/ || true
	-[ -d data/banners ] && install -m 0644 data/banners/* $(DESTDIR)$(DATADIR)/banners/ || true
	# Config tree.
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR) $(DESTDIR)$(SYSCONFDIR)/ppd \
	           $(DESTDIR)$(SYSCONFDIR)/ssl $(DESTDIR)$(SYSCONFDIR)/interfaces
	-chmod 0700 $(DESTDIR)$(SYSCONFDIR)/ssl
	-[ -f data/cupsd.conf.default ] && \
	    install -m 0640 -g $(GROUP) data/cupsd.conf.default $(DESTDIR)$(SYSCONFDIR)/cupsd.conf || true
	-[ -f data/cups-files.conf.default ] && \
	    install -m 0640 -g $(GROUP) data/cups-files.conf.default $(DESTDIR)$(SYSCONFDIR)/cups-files.conf || true
	# Spool/log/cache/run — lp-owned.
	install -d -m 0710 -o $(USER) -g $(GROUP) $(DESTDIR)$(SPOOLDIR) $(DESTDIR)$(SPOOLDIR)/tmp
	install -d -m 0755 -o $(USER) -g $(GROUP) $(DESTDIR)$(LOGDIR)
	install -d -m 0770 -o $(USER) -g $(GROUP) $(DESTDIR)$(CACHEDIR) $(DESTDIR)$(CACHEDIR)/rss
	install -d -m 0755 -o $(USER) -g $(GROUP) $(DESTDIR)$(RUNDIR) $(DESTDIR)$(RUNDIR)/certs
	# systemd units + PAM.
	install -d $(DESTDIR)$(UNITDIR) $(DESTDIR)$(PAMDIR)
	-for u in data/systemd/*.service data/systemd/*.socket data/systemd/*.path; do \
	    install -m 0644 $$u $(DESTDIR)$(UNITDIR)/; done
	-[ -f packaging/pam/cups ] && install -m 0644 packaging/pam/cups $(DESTDIR)$(PAMDIR)/cups || true
	# Docs.
	install -d $(DESTDIR)$(DOCDIR)
	install -m 0644 README.md docs/conformance.md docs/deviations.md \
	    SECURITY.md CHANGELOG.md $(DESTDIR)$(DOCDIR)/ 2>/dev/null || true

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/cupsd
	-for d in $(DAEMONS) $(HELPERS); do rm -f $(DESTDIR)$(SERVERBIN)/daemon/$$d; done
	-for b in $(BACKENDS); do rm -f $(DESTDIR)$(SERVERBIN)/backend/$$b; done
	-for b in $(BIN_PROGS); do rm -f $(DESTDIR)$(BINDIR)/$$b; done

test:
	$(CARGO) test --workspace

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

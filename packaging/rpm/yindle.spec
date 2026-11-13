Name:           yindle
Version:        0.1.1
Release:        1%{?dist}
Summary:        Memory-safe CUPS-compatible print spooler and IPP scheduler
License:        MIT AND Apache-2.0
URL:            https://example.invalid/yindle
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  avahi-devel
BuildRequires:  systemd-rpm-macros
Requires:       avahi
Provides:       cups
Conflicts:      cups

%description
yindle is a from-scratch reimplementation of the CUPS 2.x print
spooler and IPP scheduler in Rust — driverless IPP first, with a PPD /
legacy-driver layer for parity. It speaks the same IPP on the same
sockets, reads /etc/cups config in place, and keeps the same
filter/backend contracts, so existing clients, queues, and admin tools
work unmodified.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --workspace --release --frozen

%install
%make_install PROFILE=release USER=lp GROUP=lp
install -Dm644 packaging/pam/cups %{buildroot}%{_pamdir}/cups

%pre
getent group lp >/dev/null || groupadd -r lp
getent passwd lp >/dev/null || \
    useradd -r -g lp -d /var/spool/cups -s /sbin/nologin \
        -c "Printing system" lp
getent group lpadmin >/dev/null || groupadd -r lpadmin
usermod -a -G lpadmin lp >/dev/null 2>&1 || :

%post
%systemd_post cups.service cups.socket cups.path
chown -R lp:lp /var/spool/cups /var/log/cups /var/cache/cups /run/cups 2>/dev/null || :
chmod 0700 /etc/cups/ssl 2>/dev/null || :

%preun
%systemd_preun cups.service cups.socket cups.path

%postun
%systemd_postun_with_restart cups.service

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md PLAN.md docs/conformance.md docs/deviations.md SECURITY.md
%{_sbindir}/cupsd
%{_bindir}/cupsfilter
%{_prefix}/lib/cups/
%{_datadir}/cups/
%config(noreplace) %attr(0640,root,lp) /etc/cups/cupsd.conf
%config(noreplace) %attr(0640,root,lp) /etc/cups/cups-files.conf
%dir %attr(0710,lp,lp) /var/spool/cups
%dir %attr(0755,lp,lp) /var/log/cups
%dir %attr(0770,lp,lp) /var/cache/cups
%dir %attr(0755,lp,lp) /run/cups
%{_unitdir}/cups.service
%{_unitdir}/cups.socket
%{_unitdir}/cups.path
%{_unitdir}/cups-lpd@.service
%{_unitdir}/cups-lpd.socket
%config %{_pamdir}/cups

%changelog
* Fri Nov 13 2026 yindle contributors <yindle@example.invalid> - 0.1.1-1
- Rename: presswork is now yindle
* Wed Nov 12 2025 yindle contributors <yindle@example.invalid> - 0.1.0-1
- Initial package

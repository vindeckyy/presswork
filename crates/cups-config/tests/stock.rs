//! Parse the upstream stock `cupsd.conf`/`cups-files.conf` (with
//! configure substitutions applied) the way `cupsd -t` would.

use cups_config::*;

/// The stock cupsd.conf as a configure would emit it on Linux.
const CUPSD_CONF: &str = r"
LogLevel warn
PageLogFormat

MaxLogSize 1m

ErrorPolicy stop-printer

Listen localhost:631
Listen /run/cups/cups.sock

Browsing Yes
BrowseLocalProtocols dnssd

DefaultAuthType Basic

WebInterface Yes

<Location />
  Order allow,deny
</Location>

<Location /admin>
  AuthType Default
  Require user @SYSTEM
  Order allow,deny
</Location>

<Location /admin/conf>
  AuthType Default
  Require user @SYSTEM
  Order allow,deny
</Location>

<Location /admin/log>
  AuthType Default
  Require user @SYSTEM
  Order allow,deny
</Location>

<Policy default>
  JobPrivateAccess default
  JobPrivateValues default
  SubscriptionPrivateAccess default
  SubscriptionPrivateValues default

  <Limit Create-Job Print-Job Print-URI Validate-Job>
    Order deny,allow
  </Limit>

  <Limit Send-Document Send-URI Hold-Job Release-Job Restart-Job Purge-Jobs Set-Job-Attributes Create-Job-Subscriptions Renew-Subscription Cancel-Subscription Get-Notifications Reprocess-Job Cancel-Current-Job Suspend-Current-Job Resume-Job Cancel-My-Jobs Close-Job CUPS-Move-Job CUPS-Get-Document>
    AuthType Default
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  <Limit Set-Printer-Attributes CUPS-Add-Modify-Printer CUPS-Delete-Printer CUPS-Add-Modify-Class CUPS-Delete-Class CUPS-Set-Default CUPS-Get-Devices>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  <Limit Pause-Printer Resume-Printer Enable-Printer Disable-Printer Pause-Printer-After-Current-Job Hold-New-Jobs Release-Held-New-Jobs Deactivate-Printer Activate-Printer Restart-Printer Shutdown-Printer Startup-Printer Promote-Job Schedule-Job-After Cancel-Jobs CUPS-Accept-Jobs CUPS-Reject-Jobs>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  <Limit Cancel-Job>
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  <Limit CUPS-Authenticate-Job>
    AuthType Default
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  <Limit All>
    Order deny,allow
  </Limit>
</Policy>

<Policy authenticated>
  JobPrivateAccess default
  JobPrivateValues default
  SubscriptionPrivateAccess default
  SubscriptionPrivateValues default

  <Limit Create-Job Print-Job Print-URI Validate-Job>
    AuthType Default
    Order deny,allow
  </Limit>

  <Limit Send-Document Send-URI Hold-Job Release-Job Restart-Job Purge-Jobs Set-Job-Attributes Create-Job-Subscriptions Renew-Subscription Cancel-Subscription Get-Notifications Reprocess-Job Cancel-Current-Job Suspend-Current-Job Resume-Job Cancel-My-Jobs Close-Job CUPS-Move-Job CUPS-Get-Document>
    AuthType Default
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  <Limit Set-Printer-Attributes CUPS-Add-Modify-Printer CUPS-Delete-Printer CUPS-Add-Modify-Class CUPS-Delete-Class CUPS-Set-Default>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  <Limit Pause-Printer Resume-Printer Enable-Printer Disable-Printer Pause-Printer-After-Current-Job Hold-New-Jobs Release-Held-New-Jobs Deactivate-Printer Activate-Printer Restart-Printer Shutdown-Printer Startup-Printer Promote-Job Schedule-Job-After Cancel-Jobs CUPS-Accept-Jobs CUPS-Reject-Jobs>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>

  <Limit Cancel-Job>
    AuthType Default
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  <Limit CUPS-Authenticate-Job>
    AuthType Default
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>

  <Limit All>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>
</Policy>
";

const CUPS_FILES_CONF: &str = r"
SystemGroup sys root wheel
FileDevice No
Printcap /run/cups/printcap
PeerCred on
AccessLog /var/log/cups/access_log
ErrorLog /var/log/cups/error_log
PageLog /var/log/cups/page_log
";

#[test]
fn stock_cupsd_conf_parses_clean() {
    let (cfg, diags) = parse_cupsd_conf(CUPSD_CONF.as_bytes(), "cupsd.conf");
    for d in &diags.entries {
        eprintln!("{:?} {}:{} {}", d.severity, d.file, d.line, d.message);
    }
    assert!(
        !diags.has_errors(),
        "stock cupsd.conf must parse without errors"
    );

    // Typed vars
    assert_eq!(cfg.max_log_size, 1024 * 1024);
    assert_eq!(cfg.log_level, LogLevel::Warn);
    assert!(cfg.browsing);
    assert!(cfg.web_interface);
    assert_eq!(cfg.default_auth_type, AuthType::Basic);
    assert_eq!(cfg.error_policy.as_deref(), Some("stop-printer"));
    assert_eq!(cfg.page_log_format, None); // bare directive → NULL

    // Listeners: localhost:631 (may expand to v4+v6) + domain socket.
    assert!(cfg.listeners.iter().any(|l| matches!(
        &l.addr,
        ListenAddr::Tcp(a) if a.ip().is_loopback() && a.port() == 631
    )));
    assert!(cfg.listeners.iter().any(|l| matches!(
        &l.addr,
        ListenAddr::Unix(p) if p == std::path::Path::new("/run/cups/cups.sock")
    )));

    // Locations: /, /admin, /admin/conf, /admin/log
    let paths: Vec<&str> = cfg.locations.iter().map(|l| l.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/admin"));
    assert!(paths.contains(&"/admin/conf"));
    assert!(paths.contains(&"/admin/log"));
    let admin = cfg.locations.iter().find(|l| l.path == "/admin").unwrap();
    assert_eq!(admin.auth_type, AuthType::Default);
    assert_eq!(admin.auth_level, AuthLevel::User);
    assert_eq!(admin.names, vec!["@SYSTEM"]);
    assert_eq!(admin.order, OrderType::Deny);

    // Policies: default + authenticated, op-expanded.
    assert!(cfg.policies.iter().any(|p| p.name == "default"));
    assert!(cfg.policies.iter().any(|p| p.name == "authenticated"));
    let default = cfg.policies.iter().find(|p| p.name == "default").unwrap();
    assert_eq!(default.job_access, vec!["@OWNER", "@SYSTEM"]);
    assert!(default
        .job_values
        .contains(&"job-originating-user-name".to_string()));
    assert!(default
        .sub_values
        .contains(&"notify-recipient-uri".to_string()));
    // Cancel-Job op exists with @OWNER + @SYSTEM.
    let cj = default
        .ops
        .iter()
        .find(|o| o.op == u32::from(ipp_codec::ops::op::CANCEL_JOB))
        .unwrap();
    assert_eq!(cj.loc.names, vec!["@OWNER", "@SYSTEM"]);
    // <Limit All> fallback present.
    assert!(default
        .ops
        .iter()
        .any(|o| o.op == ipp_codec::ops::op::ANY_OPERATION));
}

#[test]
fn stock_cups_files_conf_parses_clean() {
    let (cfg, _fatal, diags) =
        parse_cups_files_conf(CUPS_FILES_CONF.as_bytes(), "cups-files.conf", "/etc/cups");
    for d in &diags.entries {
        eprintln!("{:?} {}:{} {}", d.severity, d.file, d.line, d.message);
    }
    // Unknown groups warn but don't fail without resolver.
    assert!(cfg.file_device.is_none());
    assert_eq!(cfg.peer_cred, PeerCred::On);
    assert_eq!(cfg.access_log.as_deref(), Some("/var/log/cups/access_log"));
}

#[test]
fn typed_var_edge_cases() {
    // Time suffixes
    let (c, _) = parse_cupsd_conf(b"Timeout 5m\n".as_slice(), "x");
    assert_eq!(c.timeout, 300);
    let (c, _) = parse_cupsd_conf(b"MaxHoldTime 2d\n".as_slice(), "x");
    assert_eq!(c.max_hold_time, 2 * 86400);
    // PreserveJobFiles yes → i32::MAX
    let (c, _) = parse_cupsd_conf(b"PreserveJobFiles yes\n".as_slice(), "x");
    assert_eq!(c.preserve_job_files, i32::MAX);
    // Boolean by number
    let (c, _) = parse_cupsd_conf(b"Browsing 0\n".as_slice(), "x");
    assert!(!c.browsing);
    // Size suffixes
    let (c, _) = parse_cupsd_conf(b"LimitRequestBody 2m\n".as_slice(), "x");
    assert_eq!(c.max_request_size, 2 * 1024 * 1024);
    // Octal perms
    let (_f, _fat, _) =
        parse_cups_files_conf(b"ConfigFilePerm 0600\n".as_slice(), "x", "/etc/cups");
}

#[test]
fn bad_directive_fatal_unknown() {
    let (c, d) = parse_cupsd_conf(b"FatalErrors all\nBogusDirective x\n".as_slice(), "x");
    // fatal=all is in cups-files; in cupsd.conf it prints "move" info,
    // so BogusDirective logs error but doesn't abort (UNKNOWN not set).
    assert!(d.has_errors());
    assert_eq!(c.max_clients, 100);
}

#[test]
fn limit_except_inverts() {
    let (c, d) = parse_cupsd_conf(
        b"<Location /x>\n<LimitExcept POST>\nRequire user @SYSTEM\n</LimitExcept>\n</Location>\n"
            .as_slice(),
        "x",
    );
    assert!(!d.has_errors());
    // Two locations: parent (limit minus POST) + child (POST only).
    let x: Vec<&Location> = c.locations.iter().filter(|l| l.path == "/x").collect();
    assert_eq!(x.len(), 2);
    let post = x.iter().find(|l| l.limit == limit::POST);
    let rest = x.iter().find(|l| l.limit == (limit::ALL & !limit::POST));
    assert!(post.is_some() && rest.is_some());
}

#[test]
fn default_policy_synthesized() {
    let p = default_policy();
    assert_eq!(p.name, "default");
    assert!(p
        .ops
        .iter()
        .any(|o| o.op == u32::from(ipp_codec::ops::op::PRINT_JOB)));
    assert!(p
        .ops
        .iter()
        .any(|o| o.op == ipp_codec::ops::op::ANY_OPERATION));
}

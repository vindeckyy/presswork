//! Authorization — `<Location>`/`<Limit>`/`<Policy>` evaluation, a port of
//! `scheduler/auth.c`'s `cupsdCheckAccess`/`is_authorized`.
//!
//! Two layers:
//!  * `permitted(loc, …)` — does a request satisfy one ACL block (host
//!    Allow/Deny + Require + auth level)?
//!  * `op_allowed(policies, name, op, …)` — find the `PolicyOp` for an IPP
//!    op (or the `All` fallback) and evaluate it.

use cups_config::{AuthLevel, Location, OrderType, Policy, Satisfy};
use std::net::IpAddr;

/// Who/what is making the request.
pub struct Subject<'a> {
    /// Authenticated username (`None` = anonymous).
    pub user: Option<&'a str>,
    /// Unix group names the user belongs to.
    pub groups: &'a [String],
    /// Configured `SystemGroup` names — the `@SYSTEM` expansion.
    pub system_groups: &'a [String],
    /// Client address.
    pub addr: IpAddr,
    /// Client hostname (for name-based masks).
    pub host: &'a str,
    /// Is this connection over TLS?
    pub encrypted: bool,
}

/// `cupsdCheckAccess` on one `Location`: Order Deny,Allow / Allow,Deny over
/// host masks, then `Require`/`Auth`/`Satisfy` user checks.
pub fn permitted(loc: &Location, s: &Subject) -> bool {
    // Encryption requirement.
    if matches!(
        loc.encryption,
        cups_config::Encryption::Required | cups_config::Encryption::Always
    ) && !s.encrypted
    {
        return false;
    }

    // Host allow/deny — upstream `cupsdCheckAccess`: when no masks are
    // configured the host side passes, otherwise the `Order` winner decides.
    let allowed = loc
        .allow
        .iter()
        .any(|m| m.matches(&s.addr) || m.matches_name(s.host));
    let denied = loc
        .deny
        .iter()
        .any(|m| m.matches(&s.addr) || m.matches_name(s.host));
    let host_ok = match loc.order {
        // `Order deny,allow` — allow evaluated last, wins ties.
        OrderType::Allow => allowed || !denied,
        // `Order allow,deny` — deny evaluated last, wins ties.
        OrderType::Deny => !denied && allowed,
    };
    if !host_ok && !satisfies_auth(loc, s) {
        return false;
    }
    // Satisfy mode: "all" requires host AND auth, "any" ORs them.
    match loc.satisfy {
        Satisfy::Any => host_ok || satisfies_auth(loc, s),
        Satisfy::All => host_ok && satisfies_auth(loc, s),
    }
}

/// Whether `Require`/`Auth` user constraints pass. Anonymous locations
/// (`auth_level Anon`, no names) always pass the auth side.
fn satisfies_auth(loc: &Location, s: &Subject) -> bool {
    match loc.auth_level {
        AuthLevel::Anon if loc.names.is_empty() => true,
        _ => require_check(loc, s),
    }
}

/// `Require user|group|valid-user|@OWNER|@SYSTEM` evaluation.
fn require_check(loc: &Location, s: &Subject) -> bool {
    if loc.names.is_empty() {
        return matches!(loc.auth_level, AuthLevel::Anon);
    }
    let Some(user) = s.user else {
        return false;
    };
    for n in &loc.names {
        match n.as_str() {
            // valid-user: any authenticated user.
            "valid-user" => return true,
            // @SYSTEM expands to the configured `SystemGroup` names — the
            // user must belong to at least one of them.
            "@SYSTEM" => {
                if s.groups.iter().any(|g| s.system_groups.contains(g)) {
                    return true;
                }
            }
            "@OWNER" => continue, // owner check is per-resource, handled by caller
            g if g.starts_with('@') => {
                // @group → membership
                if s.groups.iter().any(|x| x == &g[1..]) {
                    return true;
                }
            }
            u if u == user => return true,
            _ => {}
        }
        if n == &user {
            return true;
        }
    }
    false
}

/// Find the policy op limit for `op` in `policy`, falling back to `All`.
pub fn policy_op<'a>(policy: &'a Policy, op: u32) -> Option<&'a Location> {
    policy
        .ops
        .iter()
        .find(|p| p.op == op)
        .or_else(|| policy.ops.iter().find(|p| p.op == u32::MAX))
        .map(|p| &p.loc)
}

/// Evaluate an IPP op against a named policy in `policies`.
/// `None` policy name → `default`. Missing policy → deny (fail closed).
pub fn op_allowed(policies: &[Policy], policy_name: Option<&str>, op: u32, s: &Subject) -> bool {
    let name = policy_name.unwrap_or("default");
    let Some(pol) = policies.iter().find(|p| p.name == name) else {
        return false;
    };
    match policy_op(pol, op) {
        Some(loc) => permitted(loc, s),
        None => true, // no limit defined → default policy permits
    }
}

//! IPP event subscriptions + notifications — a port of
//! `scheduler/subscriptions.c` + `scheduler/event.c`.
//!
//! A [`Subscriptions`] table holds `Create-{Printer,Job}-Subscriptions`
//! objects. State changes call [`Subscriptions::push`], which queues a
//! [`Notification`] on every subscription whose `notify-events` mask covers
//! the event. `Get-Notifications` (ippget pull) drains the queue.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// IPP `notify-events` keywords (`cupsdEventName`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    PrinterAdded,
    PrinterDeleted,
    PrinterModified,
    PrinterState,
    PrinterStateChanged,
    PrinterConfigChanged,
    PrinterChanged,
    JobCreated,
    JobCompleted,
    JobStopped,
    JobStateChanged,
    JobConfigChanged,
    JobProgress,
    ServerRestarted,
    ServerStarted,
    ServerStopped,
    ServerAudit,
    /// `all` — matches every event.
    All,
}

impl Event {
    /// RFC `notify-events` keyword.
    pub fn name(self) -> &'static str {
        match self {
            Self::PrinterAdded => "printer-added",
            Self::PrinterDeleted => "printer-deleted",
            Self::PrinterModified => "printer-modified",
            Self::PrinterState => "printer-state",
            Self::PrinterStateChanged => "printer-state-changed",
            Self::PrinterConfigChanged => "printer-config-changed",
            Self::PrinterChanged => "printer-changed",
            Self::JobCreated => "job-created",
            Self::JobCompleted => "job-completed",
            Self::JobStopped => "job-stopped",
            Self::JobStateChanged => "job-state-changed",
            Self::JobConfigChanged => "job-config-changed",
            Self::JobProgress => "job-progress",
            Self::ServerRestarted => "server-restarted",
            Self::ServerStarted => "server-started",
            Self::ServerStopped => "server-stopped",
            Self::ServerAudit => "server-audit",
            Self::All => "all",
        }
    }

    /// Parse a `notify-events` keyword. `None` if unknown.
    pub fn from_name(n: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.name() == n)
    }

    const ALL: &'static [Self] = &[
        Self::PrinterAdded,
        Self::PrinterDeleted,
        Self::PrinterModified,
        Self::PrinterState,
        Self::PrinterStateChanged,
        Self::PrinterConfigChanged,
        Self::PrinterChanged,
        Self::JobCreated,
        Self::JobCompleted,
        Self::JobStopped,
        Self::JobStateChanged,
        Self::JobConfigChanged,
        Self::JobProgress,
        Self::ServerRestarted,
        Self::ServerStarted,
        Self::ServerStopped,
        Self::ServerAudit,
        Self::All,
    ];

    /// Does `sub`'s mask (containing this or `All`) cover `ev`?
    fn covered(mask: &[Self], ev: Self) -> bool {
        mask.contains(&ev) || mask.contains(&Self::All)
    }
}

/// A queued event notification for the `ippget` pull.
#[derive(Clone, Debug)]
pub struct Notification {
    pub seq: i32,
    pub event: Event,
    pub time: i64,
    pub printer: Option<String>,
    pub job_id: Option<i32>,
    pub job_state: Option<i32>,
    pub text: String,
}

/// One subscription (`cupsd_subscription_t`).
#[derive(Clone, Debug)]
pub struct Subscription {
    pub id: i32,
    /// Printer scope — `None` = all printers.
    pub printer: Option<String>,
    /// Job scope — `None` = printer/system subscription.
    pub job_id: Option<i32>,
    pub events: Vec<Event>,
    pub owner: String,
    /// Absolute lease expiry (epoch secs); `i64::MAX` = never.
    pub lease: i64,
    /// `notify-lease-duration` requested, for `Renew`.
    pub lease_duration: i32,
    pub user_data: Option<Vec<u8>>,
    next_seq: i32,
    queue: std::collections::VecDeque<Notification>,
}

/// Default `notify-lease-duration` (seconds) — upstream `DefaultLeaseDuration`.
const DEFAULT_LEASE: i32 = 86400;
/// `notify-lease-duration` meaning "never expire".
pub const NEVER_EXPIRE: i32 = 0;

/// The subscription table (`Subscriptions` global).
#[derive(Default)]
pub struct Subscriptions {
    subs: BTreeMap<i32, Subscription>,
    next_id: i32,
}

impl Subscriptions {
    pub fn new() -> Self {
        Self {
            subs: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// `cupsdAddSubscription` — returns the new subscription id.
    pub fn add(
        &mut self,
        printer: Option<String>,
        job_id: Option<i32>,
        events: Vec<Event>,
        owner: String,
        lease_duration: i32,
        user_data: Option<Vec<u8>>,
    ) -> i32 {
        let id = self.next_id;
        self.next_id += 1;
        let lease = if lease_duration == NEVER_EXPIRE {
            i64::MAX
        } else {
            now() + i64::from(lease_duration.max(DEFAULT_LEASE.min(lease_duration)))
        };
        self.subs.insert(
            id,
            Subscription {
                id,
                printer,
                job_id,
                events,
                owner,
                lease,
                lease_duration,
                user_data,
                next_seq: 1,
                queue: std::collections::VecDeque::new(),
            },
        );
        id
    }

    /// `cupsdExpireSubscriptions` — drop expired subs; call on each op.
    pub fn expire(&mut self) {
        let t = now();
        self.subs.retain(|_, s| s.lease > t);
    }

    /// Push an event — queues a [`Notification`] on every covering sub.
    /// `printer`/`job_id` scope the event; a sub matches when its scope is
    /// `None` (any) or equal.
    pub fn push(
        &mut self,
        event: Event,
        printer: Option<&str>,
        job_id: Option<i32>,
        job_state: Option<i32>,
        text: String,
    ) {
        self.expire();
        for s in self.subs.values_mut() {
            if !Event::covered(&s.events, event) {
                continue;
            }
            if s.printer.as_deref().is_some_and(|p| Some(p) != printer) {
                continue;
            }
            if s.job_id.is_some() && s.job_id != job_id {
                continue;
            }
            let seq = s.next_seq;
            s.next_seq += 1;
            s.queue.push_back(Notification {
                seq,
                event,
                time: now(),
                printer: printer.map(str::to_string),
                job_id,
                job_state,
                text: text.clone(),
            });
            // Bound the queue (upstream MaxNotifications ~ default 100).
            while s.queue.len() > 100 {
                s.queue.pop_front();
            }
        }
    }

    pub fn find(&self, id: i32) -> Option<&Subscription> {
        self.subs.get(&id)
    }
    pub fn find_mut(&mut self, id: i32) -> Option<&mut Subscription> {
        self.subs.get_mut(&id)
    }
    pub fn remove(&mut self, id: i32) -> Option<Subscription> {
        self.subs.remove(&id)
    }
    /// Renew a subscription's lease (`Renew-Subscription`).
    pub fn renew(&mut self, id: i32) -> bool {
        if let Some(s) = self.subs.get_mut(&id) {
            s.lease = if s.lease_duration == NEVER_EXPIRE {
                i64::MAX
            } else {
                now() + i64::from(s.lease_duration)
            };
            true
        } else {
            false
        }
    }
    /// All subscriptions, optionally filtered to a printer/owner.
    pub fn list(&self, printer: Option<&str>, owner: Option<&str>) -> Vec<&Subscription> {
        self.subs
            .values()
            .filter(|s| {
                (printer.is_none() || s.printer.as_deref() == printer)
                    && (owner.is_none() || s.owner == owner.unwrap_or(""))
            })
            .collect()
    }
    /// Drain `id`'s pending queue for `Get-Notifications` (ippget pull).
    /// When `wait` is false, returns whatever is queued now.
    pub fn drain(&mut self, id: i32) -> Vec<Notification> {
        self.subs
            .get_mut(&id)
            .map(|s| s.queue.drain(..).collect())
            .unwrap_or_default()
    }
}

/// `Subscription` helpers for building IPP attrs.
impl Subscription {
    /// `notify-lease-duration` remaining (0 = expired/never).
    pub fn lease_remaining(&self) -> i32 {
        if self.lease == i64::MAX {
            0
        } else {
            (self.lease - now()).max(0) as i32
        }
    }
    /// Queued notification count.
    pub fn pending(&self) -> usize {
        self.queue.len()
    }
    /// Re-queue `n` (no-op ordering).
    pub fn event_names(&self) -> Vec<String> {
        self.events.iter().map(|e| e.name().to_string()).collect()
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_scope_and_drain() {
        let mut t = Subscriptions::new();
        let a = t.add(Some("p1".into()), None, vec![Event::PrinterStateChanged], "u".into(), 0, None);
        let _b = t.add(Some("p2".into()), None, vec![Event::All], "u".into(), 0, None);
        t.push(Event::PrinterStateChanged, Some("p1"), None, None, "x".into());
        assert_eq!(t.find(a).unwrap().pending(), 1);
        assert_eq!(t.drain(a).len(), 1);
        assert_eq!(t.drain(a).len(), 0); // drained
    }

    #[test]
    fn all_matches_everything() {
        assert!(Event::covered(&[Event::All], Event::JobProgress));
        assert!(!Event::covered(&[Event::JobCreated], Event::JobCompleted));
    }

    #[test]
    fn names_round_trip() {
        for e in Event::ALL {
            assert_eq!(Event::from_name(e.name()), Some(*e));
        }
    }

    #[test]
    fn job_scope_filters() {
        let mut t = Subscriptions::new();
        let a = t.add(None, Some(7), vec![Event::JobStateChanged], "u".into(), 0, None);
        t.push(Event::JobStateChanged, None, Some(8), None, "wrong job".into());
        t.push(Event::JobStateChanged, None, Some(7), None, "right".into());
        assert_eq!(t.find(a).unwrap().pending(), 1);
    }
}

//! Case-insensitive ordered header collection.
//!
//! Upstream keeps headers in `http_t` fields (`httpFields()`); we keep
//! an ordered vec — ordered because `Connection: Upgrade` +
//! `Upgrade:` pairing is order-relevant in some clients, and IPP
//! responses sometimes carry repeated headers.

/// An ordered, case-insensitive header list.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the first occurrence (case-insensitive).
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let v = value.into();
        for e in &mut self.entries {
            if e.0.eq_ignore_ascii_case(name) {
                e.1 = v;
                return;
            }
        }
        self.entries.push((name.to_string(), v));
    }

    /// Append without replacing (for multi-instance headers).
    pub fn push(&mut self, name: &str, value: impl Into<String>) {
        self.entries.push((name.to_string(), value.into()));
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.0.eq_ignore_ascii_case(name))
            .map(|e| e.1.as_str())
    }

    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Iterate `(name, value)` in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|e| (e.0.as_str(), e.1.as_str()))
    }

    /// `Connection` token check — handles `keep-alive`, `close`,
    /// `Upgrade` and comma-lists.
    #[must_use]
    pub fn connection_has(&self, token: &str) -> bool {
        self.get("connection")
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }
}

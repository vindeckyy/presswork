//! `sys` — the only crate in the workspace permitted to use `unsafe`.
//! Everything else builds on these wrappers: privilege dropping, fd
//! plumbing for filter/backend pipes, rlimits, exec, and syslog.
//!
//! See PLAN.md §4 ("FFI boundary").

#![allow(unsafe_code)]

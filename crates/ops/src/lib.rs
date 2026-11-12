//! `ops` — the IPP operation dispatcher, ported from `scheduler/ipp.c`
//! (`cupsdProcessIPPRequest` + the ~50 per-op handlers).
//!
//! Structure mirrors upstream: `dispatch()` runs the fixed validation
//! preamble (version, request-id, group order, required
//! charset/language/uri attrs), then the giant op switch. Each handler
//! returns the response `IppMessage` with `code` = status.
//!
//! P1 scope: the read-only ops — `Get-Printer-Attributes`,
//! `CUPS-Get-Default`, `CUPS-Get-Printers`, `CUPS-Get-Classes`,
//! `Get-Printer-Supported-Values`, `Get-Jobs` (empty until the `job`
//! crate lands), `Validate-Job` (accepting-queue check only).
//! Everything else → `server-error-operation-not-supported`, matching
//! upstream's `default:` case exactly.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

mod common;
mod dispatch;

pub use dispatch::{dispatch, Ctx};

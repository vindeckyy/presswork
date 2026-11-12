#![no_main]
//! Fuzz `printers.conf`/`classes.conf` parsing — `Registry::load_printers_conf`
//! must accept any byte stream without panicking, and a save→load round-trip
//! of whatever parsed must also be clean.

use libfuzzer_sys::fuzz_target;
use printer::Registry;

fuzz_target!(|data: &[u8]| {
    let mut reg = Registry::default();
    let _ = reg.load_printers_conf(data);
    // Serializing whatever state parsed must not panic.
    let out = reg.save_printers_conf();
    // A re-parse of our own emitted conf must be clean too.
    let mut reg2 = Registry::default();
    let _ = reg2.load_printers_conf(&out[..]);
});

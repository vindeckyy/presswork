#![no_main]
//! Fuzz `mime-db`: parse fuzzed `mime.types`/`mime.convs` streams, then run
//! type detection and filter-chain resolution over whatever loaded — the
//! magic-rule evaluator and the Dijkstra are the panic surface.

use libfuzzer_sys::fuzz_target;
use mime_db::MimeDb;

fuzz_target!(|data: &[u8]| {
    let mut db = MimeDb::default();
    // Feed the same bytes to both parsers — neither may panic.
    let _ = db.load_types_reader(data);
    let _ = db.load_convs_reader(data);
    // Detect a type for a fuzzed filename + leading bytes.
    let _ = db.detect("doc", data);
    // Resolve chains between arbitrary pairs drawn from the loaded types.
    let names: Vec<String> = db
        .convs
        .iter()
        .flat_map(|c| [c.src.clone(), c.dst.clone()])
        .take(8)
        .collect();
    for s in &names {
        for d in &names {
            let _ = db.filter_chain(s, d, 0);
        }
    }
});

#![no_main]
//! Run the `cupsFileGetConf` lexer + both file parsers over arbitrary
//! bytes; a panic is a bug.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Lexer alone.
    for line in cups_config::conf_lines(data) {
        let _ = line;
    }
    // Full parsers (they exercise the lexer + directive dispatch).
    let _ = cups_config::parse_cupsd_conf(std::io::Cursor::new(data), "fuzz");
    let _ = cups_config::parse_cups_files_conf(std::io::Cursor::new(data), "fuzz", "/tmp");
});

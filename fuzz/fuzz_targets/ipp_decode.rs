#![no_main]
//! Decode arbitrary bytes as IPP; a panic is a bug. On a clean decode we
//! also re-encode and re-decode to exercise the round-trip.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((msg, consumed)) = ipp_codec::decode(data) {
        // `consumed` must never exceed the input length.
        assert!(consumed <= data.len());
        if let Ok(bytes) = ipp_codec::encode(&msg) {
            // Re-encoding then decoding must not panic.
            let _ = ipp_codec::decode(&bytes);
        }
    }
});

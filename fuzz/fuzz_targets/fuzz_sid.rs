#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse arbitrary bytes — must never panic.
    if let Some(sid) = kacs_core::sid::Sid::from_bytes(data) {
        // If parse succeeds, round-trip must produce identical bytes.
        let bytes = sid.to_bytes().unwrap();
        let reparsed = kacs_core::sid::Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid, reparsed);
        assert_eq!(sid.byte_len(), bytes.len());
    }
});

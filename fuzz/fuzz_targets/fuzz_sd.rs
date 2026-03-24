#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse arbitrary bytes — must never panic.
    // SecurityDescriptor rejects inputs > 64KB (SD_MAX_SIZE).
    if let Ok(Some(sd)) = kacs_core::sd::SecurityDescriptor::from_bytes(data) {
        // Round-trip: serialize and re-parse must produce identical bytes.
        let bytes = sd.to_bytes().unwrap();
        let reparsed = kacs_core::sd::SecurityDescriptor::from_bytes(&bytes)
            .unwrap()
            .unwrap();
        let bytes2 = reparsed.to_bytes().unwrap();
        assert_eq!(bytes, bytes2);
    }
});

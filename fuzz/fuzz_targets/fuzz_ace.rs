#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse arbitrary bytes — must never panic.
    if let Some((ace, consumed)) = kacs_core::ace::Ace::from_bytes(data) {
        assert!(consumed <= data.len());
        assert_eq!(consumed % 4, 0); // ACE size is always 4-byte aligned

        // Round-trip: serialize and re-parse must produce identical bytes.
        let bytes = ace.to_bytes().unwrap();
        let (_, consumed2) = kacs_core::ace::Ace::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), consumed2);
    }
});

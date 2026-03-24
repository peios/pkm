#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse arbitrary bytes — must never panic.
    if let Ok(Some(acl)) = kacs_core::acl::Acl::from_bytes(data) {
        // Round-trip: serialize and re-parse must produce identical bytes.
        let bytes = acl.to_bytes().unwrap();
        let reparsed = kacs_core::acl::Acl::from_bytes(&bytes).unwrap().unwrap();
        let bytes2 = reparsed.to_bytes().unwrap();
        assert_eq!(bytes, bytes2);
    }
});

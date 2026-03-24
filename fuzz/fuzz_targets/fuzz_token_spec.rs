#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse arbitrary bytes — must never panic.
    // token_spec is a one-way parser (kernel receives specs from authd),
    // so no round-trip check, just panic-freedom.
    let _ = kacs_core::token_spec::parse_token_spec(data);
});

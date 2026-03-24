#![no_main]
use libfuzzer_sys::fuzz_target;
use kacs_core::access_check::EnrichedToken;
use kacs_core::token::Token;

fuzz_target!(|data: &[u8]| {
    // Create a minimal token for the evaluator context.
    let token = Token::system_token().unwrap();
    let enriched = EnrichedToken {
        token: &token,
        has_owner_rights: false,
        has_principal_self: false,
        principal_self_deny_only: false,
        device_groups_override: None,
    };

    // Feed arbitrary condition bytes — must never panic.
    let _ = kacs_core::conditional::evaluate(
        data,
        &enriched,
        &[],  // no resource attributes
        &[],  // no local claims
        true, // for_allow
    );
});

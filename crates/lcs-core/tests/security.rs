//! lcs-core integration tests: security.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "security/access_mask_bitwise_comparison.rs"]
mod access_mask_bitwise_comparison;
#[path = "security/access_mask_validation.rs"]
mod access_mask_validation;
#[path = "security/audit_payload_schemas.rs"]
mod audit_payload_schemas;
#[path = "security/blanket_tombstone_enumeration_output.rs"]
mod blanket_tombstone_enumeration_output;
#[path = "security/blanket_tombstone_source_dispatch.rs"]
mod blanket_tombstone_source_dispatch;
#[path = "security/effective_enumeration.rs"]
mod effective_enumeration;
#[path = "security/effective_enumeration_conformance.rs"]
mod effective_enumeration_conformance;
#[path = "security/effective_subkey_watch_events.rs"]
mod effective_subkey_watch_events;
#[path = "security/effective_value_watch_events.rs"]
mod effective_value_watch_events;
#[path = "security/orphaned_key_fd_operation_gate.rs"]
mod orphaned_key_fd_operation_gate;
#[path = "security/orphaned_key_last_fd_close.rs"]
mod orphaned_key_last_fd_close;
#[path = "security/security_descriptor_ioctls.rs"]
mod security_descriptor_ioctls;
#[path = "security/sid_binary_comparison.rs"]
mod sid_binary_comparison;
#[path = "security/tombstone_internal_boundary.rs"]
mod tombstone_internal_boundary;

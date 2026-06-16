//! lcs-core integration tests: key.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "key/key_create_dual_records.rs"]
mod key_create_dual_records;
#[path = "key/key_fd_capabilities.rs"]
mod key_fd_capabilities;
#[path = "key/key_fd_orphan_errno.rs"]
mod key_fd_orphan_errno;
#[path = "key/key_guid_assignment.rs"]
mod key_guid_assignment;
#[path = "key/key_lookup_casefold.rs"]
mod key_lookup_casefold;
#[path = "key/key_name_component_rules.rs"]
mod key_name_component_rules;
#[path = "key/key_open_access_planning.rs"]
mod key_open_access_planning;
#[path = "key/key_open_audit_msgpack.rs"]
mod key_open_audit_msgpack;
#[path = "key/key_path_mutation_errno.rs"]
mod key_path_mutation_errno;
#[path = "key/key_path_mutation_planning.rs"]
mod key_path_mutation_planning;
#[path = "key/key_path_transaction_log_entries.rs"]
mod key_path_transaction_log_entries;
#[path = "key/key_semantics.rs"]
mod key_semantics;
#[path = "key/subkey_enumeration_results.rs"]
mod subkey_enumeration_results;

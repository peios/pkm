//! lcs-core integration tests: value.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "value/value_delete_blanket_planning.rs"]
mod value_delete_blanket_planning;
#[path = "value/value_enumeration_results.rs"]
mod value_enumeration_results;
#[path = "value/value_layer_admission.rs"]
mod value_layer_admission;
#[path = "value/value_layer_cap_errno.rs"]
mod value_layer_cap_errno;
#[path = "value/value_mutation_errno.rs"]
mod value_mutation_errno;
#[path = "value/value_mutation_semantics.rs"]
mod value_mutation_semantics;
#[path = "value/value_name_boundary.rs"]
mod value_name_boundary;
#[path = "value/value_payload_opacity_and_bounds.rs"]
mod value_payload_opacity_and_bounds;
#[path = "value/value_resolution_conformance.rs"]
mod value_resolution_conformance;
#[path = "value/value_security_boundary.rs"]
mod value_security_boundary;
#[path = "value/value_tombstone_read_errno.rs"]
mod value_tombstone_read_errno;
#[path = "value/value_transaction_log_entries.rs"]
mod value_transaction_log_entries;
#[path = "value/value_type_set.rs"]
mod value_type_set;
#[path = "value/value_write_sequencing.rs"]
mod value_write_sequencing;
#[path = "value/value_write_source_dispatch.rs"]
mod value_write_source_dispatch;

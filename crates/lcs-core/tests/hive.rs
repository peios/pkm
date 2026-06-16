//! lcs-core integration tests: hive.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "hive/hive_name_registration_rules.rs"]
mod hive_name_registration_rules;
#[path = "hive/hive_root_delete_hide_gate.rs"]
mod hive_root_delete_hide_gate;
#[path = "hive/hive_route_errno.rs"]
mod hive_route_errno;
#[path = "hive/hive_route_failure_classification.rs"]
mod hive_route_failure_classification;
#[path = "hive/hive_route_identity_uniqueness.rs"]
mod hive_route_identity_uniqueness;
#[path = "hive/hive_routing.rs"]
mod hive_routing;
#[path = "hive/hive_source_transaction_scope.rs"]
mod hive_source_transaction_scope;

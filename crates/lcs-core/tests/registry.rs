//! lcs-core integration tests: registry.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "registry/base_layer_invariants.rs"]
mod base_layer_invariants;
#[path = "registry/begin_transaction_fd.rs"]
mod begin_transaction_fd;
#[path = "registry/bootstrap_pre_registration_defaults.rs"]
mod bootstrap_pre_registration_defaults;
#[path = "registry/create_key_resolution.rs"]
mod create_key_resolution;
#[path = "registry/current_user_binary_sid_rewrite.rs"]
mod current_user_binary_sid_rewrite;
#[path = "registry/default_hives_are_dynamic.rs"]
mod default_hives_are_dynamic;
#[path = "registry/duplicate_sequence_malformed_data.rs"]
mod duplicate_sequence_malformed_data;
#[path = "registry/explicit_delete_path_entry_only.rs"]
mod explicit_delete_path_entry_only;
#[path = "registry/flush_planning.rs"]
mod flush_planning;
#[path = "registry/future_sequence_malformed_data.rs"]
mod future_sequence_malformed_data;
#[path = "registry/get_security_erange_plan.rs"]
mod get_security_erange_plan;
#[path = "registry/global_sequence_allocation.rs"]
mod global_sequence_allocation;
#[path = "registry/hidden_path_entries.rs"]
mod hidden_path_entries;
#[path = "registry/internal_self_watch_planning.rs"]
mod internal_self_watch_planning;
#[path = "registry/internal_watch_callback_actions.rs"]
mod internal_watch_callback_actions;
#[path = "registry/internal_watch_lock_discipline.rs"]
mod internal_watch_lock_discipline;
#[path = "registry/lcs_audit_event_vocabulary.rs"]
mod lcs_audit_event_vocabulary;
#[path = "registry/open_desired_access_pre_resolution.rs"]
mod open_desired_access_pre_resolution;
#[path = "registry/open_flags_preflight.rs"]
mod open_flags_preflight;
#[path = "registry/open_pre_resolution_errno.rs"]
mod open_pre_resolution_errno;
#[path = "registry/query_enumeration_errno.rs"]
mod query_enumeration_errno;
#[path = "registry/query_key_info.rs"]
mod query_key_info;
#[path = "registry/query_value_result.rs"]
mod query_value_result;
#[path = "registry/registry_sd_inheritance.rs"]
mod registry_sd_inheritance;
#[path = "registry/remaining_audit_msgpack.rs"]
mod remaining_audit_msgpack;
#[path = "registry/self_configuration_planner.rs"]
mod self_configuration_planner;
#[path = "registry/set_security_commit_effects.rs"]
mod set_security_commit_effects;
#[path = "registry/set_security_rsi_dispatch.rs"]
mod set_security_rsi_dispatch;
#[path = "registry/set_security_transaction_log_entry.rs"]
mod set_security_transaction_log_entry;
#[path = "registry/unknown_layer_policy.rs"]
mod unknown_layer_policy;
#[path = "registry/visible_child_delete_gate.rs"]
mod visible_child_delete_gate;
#[path = "registry/volatile_child_creation_gate.rs"]
mod volatile_child_creation_gate;

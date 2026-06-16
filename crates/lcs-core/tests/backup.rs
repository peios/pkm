//! lcs-core integration tests: backup.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "backup/backup_blanket_tombstone_payload.rs"]
mod backup_blanket_tombstone_payload;
#[path = "backup/backup_header_payload.rs"]
mod backup_header_payload;
#[path = "backup/backup_hidden_cross_layer_topology.rs"]
mod backup_hidden_cross_layer_topology;
#[path = "backup/backup_hidden_section_placement.rs"]
mod backup_hidden_section_placement;
#[path = "backup/backup_key_payload.rs"]
mod backup_key_payload;
#[path = "backup/backup_layer_manifest_authority.rs"]
mod backup_layer_manifest_authority;
#[path = "backup/backup_layer_manifest_payload.rs"]
mod backup_layer_manifest_payload;
#[path = "backup/backup_layer_manifest_set.rs"]
mod backup_layer_manifest_set;
#[path = "backup/backup_path_entry_payload.rs"]
mod backup_path_entry_payload;
#[path = "backup/backup_read_only_transaction_admission.rs"]
mod backup_read_only_transaction_admission;
#[path = "backup/backup_record_framing.rs"]
mod backup_record_framing;
#[path = "backup/backup_restore_fd_mode.rs"]
mod backup_restore_fd_mode;
#[path = "backup/backup_restore_key_set.rs"]
mod backup_restore_key_set;
#[path = "backup/backup_restore_layer_precedence.rs"]
mod backup_restore_layer_precedence;
#[path = "backup/backup_restore_layer_records.rs"]
mod backup_restore_layer_records;
#[path = "backup/backup_restore_non_root_key_create.rs"]
mod backup_restore_non_root_key_create;
#[path = "backup/backup_restore_non_root_key_timestamp.rs"]
mod backup_restore_non_root_key_timestamp;
#[path = "backup/backup_restore_path_entry.rs"]
mod backup_restore_path_entry;
#[path = "backup/backup_restore_path_sequence.rs"]
mod backup_restore_path_sequence;
#[path = "backup/backup_restore_path_target_membership.rs"]
mod backup_restore_path_target_membership;
#[path = "backup/backup_restore_processed_keys.rs"]
mod backup_restore_processed_keys;
#[path = "backup/backup_restore_root_section.rs"]
mod backup_restore_root_section;
#[path = "backup/backup_restore_root_write.rs"]
mod backup_restore_root_write;
#[path = "backup/backup_restore_sequence_remap.rs"]
mod backup_restore_sequence_remap;
#[path = "backup/backup_restore_teardown_drop.rs"]
mod backup_restore_teardown_drop;
#[path = "backup/backup_restore_teardown_path_entries.rs"]
mod backup_restore_teardown_path_entries;
#[path = "backup/backup_restore_teardown_values.rs"]
mod backup_restore_teardown_values;
#[path = "backup/backup_restore_topology.rs"]
mod backup_restore_topology;
#[path = "backup/backup_restore_transaction_gate.rs"]
mod backup_restore_transaction_gate;
#[path = "backup/backup_restore_unknown_dispatch.rs"]
mod backup_restore_unknown_dispatch;
#[path = "backup/backup_scalar_endianness.rs"]
mod backup_scalar_endianness;
#[path = "backup/backup_stream_envelope.rs"]
mod backup_stream_envelope;
#[path = "backup/backup_stream_ordering.rs"]
mod backup_stream_ordering;
#[path = "backup/backup_trailer_payload.rs"]
mod backup_trailer_payload;
#[path = "backup/backup_unknown_version_gate.rs"]
mod backup_unknown_version_gate;
#[path = "backup/backup_value_payload.rs"]
mod backup_value_payload;

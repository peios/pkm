//! lcs-core integration tests: rsi.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "rsi/rsi_all_layer_qualified_data.rs"]
mod rsi_all_layer_qualified_data;
#[path = "rsi/rsi_concrete_source_poll.rs"]
mod rsi_concrete_source_poll;
#[path = "rsi/rsi_delete_layer_orphan_validation.rs"]
mod rsi_delete_layer_orphan_validation;
#[path = "rsi/rsi_delete_layer_response.rs"]
mod rsi_delete_layer_response;
#[path = "rsi/rsi_enum_children_response.rs"]
mod rsi_enum_children_response;
#[path = "rsi/rsi_in_flight_record_insertion.rs"]
mod rsi_in_flight_record_insertion;
#[path = "rsi/rsi_in_flight_teardown_release.rs"]
mod rsi_in_flight_teardown_release;
#[path = "rsi/rsi_key_payloads.rs"]
mod rsi_key_payloads;
#[path = "rsi/rsi_key_request_frame_construction.rs"]
mod rsi_key_request_frame_construction;
#[path = "rsi/rsi_key_value_response_names.rs"]
mod rsi_key_value_response_names;
#[path = "rsi/rsi_late_response_effects.rs"]
mod rsi_late_response_effects;
#[path = "rsi/rsi_late_response_records.rs"]
mod rsi_late_response_records;
#[path = "rsi/rsi_late_success_opcode_classification.rs"]
mod rsi_late_success_opcode_classification;
#[path = "rsi/rsi_lookup_response.rs"]
mod rsi_lookup_response;
#[path = "rsi/rsi_malformed_source_data.rs"]
mod rsi_malformed_source_data;
#[path = "rsi/rsi_path_metadata_completeness.rs"]
mod rsi_path_metadata_completeness;
#[path = "rsi/rsi_path_payloads.rs"]
mod rsi_path_payloads;
#[path = "rsi/rsi_path_request_frame_construction.rs"]
mod rsi_path_request_frame_construction;
#[path = "rsi/rsi_path_response_names.rs"]
mod rsi_path_response_names;
#[path = "rsi/rsi_payload_compat.rs"]
mod rsi_payload_compat;
#[path = "rsi/rsi_query_values_payload_semantics.rs"]
mod rsi_query_values_payload_semantics;
#[path = "rsi/rsi_query_values_response.rs"]
mod rsi_query_values_response;
#[path = "rsi/rsi_read_key_response.rs"]
mod rsi_read_key_response;
#[path = "rsi/rsi_read_poll.rs"]
mod rsi_read_poll;
#[path = "rsi/rsi_resolved_guid_addressing.rs"]
mod rsi_resolved_guid_addressing;
#[path = "rsi/rsi_response_sd_validation.rs"]
mod rsi_response_sd_validation;
#[path = "rsi/rsi_response_sequence_validation.rs"]
mod rsi_response_sequence_validation;
#[path = "rsi/rsi_slot_timeouts.rs"]
mod rsi_slot_timeouts;
#[path = "rsi/rsi_source_poll_mask.rs"]
mod rsi_source_poll_mask;
#[path = "rsi/rsi_source_read_errno.rs"]
mod rsi_source_read_errno;
#[path = "rsi/rsi_source_request_queue.rs"]
mod rsi_source_request_queue;
#[path = "rsi/rsi_source_sd_ace_mask_validation.rs"]
mod rsi_source_sd_ace_mask_validation;
#[path = "rsi/rsi_source_write_admission.rs"]
mod rsi_source_write_admission;
#[path = "rsi/rsi_source_write_errno.rs"]
mod rsi_source_write_errno;
#[path = "rsi/rsi_source_write_failure_classification.rs"]
mod rsi_source_write_failure_classification;
#[path = "rsi/rsi_status.rs"]
mod rsi_status;
#[path = "rsi/rsi_status_errno.rs"]
mod rsi_status_errno;
#[path = "rsi/rsi_status_only_responses.rs"]
mod rsi_status_only_responses;
#[path = "rsi/rsi_timeout_errno.rs"]
mod rsi_timeout_errno;
#[path = "rsi/rsi_transaction_layer_flush_payloads.rs"]
mod rsi_transaction_layer_flush_payloads;
#[path = "rsi/rsi_transaction_layer_flush_request_frame_construction.rs"]
mod rsi_transaction_layer_flush_request_frame_construction;
#[path = "rsi/rsi_transaction_not_supported.rs"]
mod rsi_transaction_not_supported;
#[path = "rsi/rsi_value_payloads.rs"]
mod rsi_value_payloads;
#[path = "rsi/rsi_value_request_frame_construction.rs"]
mod rsi_value_request_frame_construction;
#[path = "rsi/rsi_wire_headers.rs"]
mod rsi_wire_headers;

//! lcs-core integration tests: transaction.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "transaction/transaction_binding.rs"]
mod transaction_binding;
#[path = "transaction/transaction_bound_counter.rs"]
mod transaction_bound_counter;
#[path = "transaction/transaction_commit_retry.rs"]
mod transaction_commit_retry;
#[path = "transaction/transaction_counter_transitions.rs"]
mod transaction_counter_transitions;
#[path = "transaction/transaction_layer_coherency.rs"]
mod transaction_layer_coherency;
#[path = "transaction/transaction_log_ordering.rs"]
mod transaction_log_ordering;
#[path = "transaction/transaction_log_replay_work.rs"]
mod transaction_log_replay_work;
#[path = "transaction/transaction_log_storage.rs"]
mod transaction_log_storage;
#[path = "transaction/transaction_log_watch_contexts.rs"]
mod transaction_log_watch_contexts;
#[path = "transaction/transaction_poll.rs"]
mod transaction_poll;
#[path = "transaction/transaction_poll_mask.rs"]
mod transaction_poll_mask;
#[path = "transaction/transaction_replay_event_stream.rs"]
mod transaction_replay_event_stream;
#[path = "transaction/transaction_replay_generation.rs"]
mod transaction_replay_generation;
#[path = "transaction/transaction_replay_snapshot_batch_scheduling.rs"]
mod transaction_replay_snapshot_batch_scheduling;
#[path = "transaction/transaction_replay_snapshot_failure_recovery.rs"]
mod transaction_replay_snapshot_failure_recovery;
#[path = "transaction/transaction_replay_snapshot_matching.rs"]
mod transaction_replay_snapshot_matching;
#[path = "transaction/transaction_replay_snapshot_queries.rs"]
mod transaction_replay_snapshot_queries;
#[path = "transaction/transaction_replay_snapshot_request_retention.rs"]
mod transaction_replay_snapshot_request_retention;
#[path = "transaction/transaction_replay_snapshot_request_scheduling.rs"]
mod transaction_replay_snapshot_request_scheduling;
#[path = "transaction/transaction_replay_snapshot_request_table.rs"]
mod transaction_replay_snapshot_request_table;
#[path = "transaction/transaction_replay_snapshot_reservation_scheduling.rs"]
mod transaction_replay_snapshot_reservation_scheduling;
#[path = "transaction/transaction_replay_snapshot_resolution.rs"]
mod transaction_replay_snapshot_resolution;
#[path = "transaction/transaction_replay_snapshot_response_matching.rs"]
mod transaction_replay_snapshot_response_matching;
#[path = "transaction/transaction_replay_snapshot_response_payloads.rs"]
mod transaction_replay_snapshot_response_payloads;
#[path = "transaction/transaction_replay_snapshot_result_materialization.rs"]
mod transaction_replay_snapshot_result_materialization;
#[path = "transaction/transaction_replay_snapshot_result_packing.rs"]
mod transaction_replay_snapshot_result_packing;
#[path = "transaction/transaction_replay_snapshot_result_table.rs"]
mod transaction_replay_snapshot_result_table;
#[path = "transaction/transaction_replay_snapshot_rsi_requests.rs"]
mod transaction_replay_snapshot_rsi_requests;
#[path = "transaction/transaction_replay_snapshot_rsi_responses.rs"]
mod transaction_replay_snapshot_rsi_responses;
#[path = "transaction/transaction_replay_snapshot_source_errors.rs"]
mod transaction_replay_snapshot_source_errors;
#[path = "transaction/transaction_replay_snapshot_success_response.rs"]
mod transaction_replay_snapshot_success_response;
#[path = "transaction/transaction_replay_summary.rs"]
mod transaction_replay_summary;
#[path = "transaction/transaction_replay_watch_dispatch.rs"]
mod transaction_replay_watch_dispatch;
#[path = "transaction/transaction_replay_watch_events.rs"]
mod transaction_replay_watch_events;
#[path = "transaction/transaction_replay_watch_inputs.rs"]
mod transaction_replay_watch_inputs;
#[path = "transaction/transaction_replay_watch_queue.rs"]
mod transaction_replay_watch_queue;
#[path = "transaction/transaction_runtime_transitions.rs"]
mod transaction_runtime_transitions;
#[path = "transaction/transaction_state.rs"]
mod transaction_state;
#[path = "transaction/transaction_timeout_errno.rs"]
mod transaction_timeout_errno;
#[path = "transaction/transaction_use_errno.rs"]
mod transaction_use_errno;
#[path = "transaction/transaction_use_errno_x.rs"]
mod transaction_use_errno_x;
#[path = "transaction/transaction_watch_batch.rs"]
mod transaction_watch_batch;
#[path = "transaction/transaction_watch_burst.rs"]
mod transaction_watch_burst;
#[path = "transaction/transaction_watch_queue_application.rs"]
mod transaction_watch_queue_application;
#[path = "transaction/transactional_mutation_sequences.rs"]
mod transactional_mutation_sequences;

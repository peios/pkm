//! lcs-core integration tests: watch.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "watch/watch_dispatch.rs"]
mod watch_dispatch;
#[path = "watch/watch_event_byte_serialization.rs"]
mod watch_event_byte_serialization;
#[path = "watch/watch_notify.rs"]
mod watch_notify;
#[path = "watch/watch_poll_mask.rs"]
mod watch_poll_mask;
#[path = "watch/watch_queue_records.rs"]
mod watch_queue_records;
#[path = "watch/watch_queue_runtime_mutation.rs"]
mod watch_queue_runtime_mutation;
#[path = "watch/watch_read_drain_poll.rs"]
mod watch_read_drain_poll;
#[path = "watch/watch_read_return_plan.rs"]
mod watch_read_return_plan;

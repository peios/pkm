//! lcs-core integration tests: source.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "source/source_device_open.rs"]
mod source_device_open;
#[path = "source/source_errno_helpers.rs"]
mod source_errno_helpers;
#[path = "source/source_identity_isolation.rs"]
mod source_identity_isolation;
#[path = "source/source_lifecycle.rs"]
mod source_lifecycle;
#[path = "source/source_lifecycle_errno.rs"]
mod source_lifecycle_errno;
#[path = "source/source_registration.rs"]
mod source_registration;
#[path = "source/source_registration_errno.rs"]
mod source_registration_errno;
#[path = "source/source_registration_sequence_update.rs"]
mod source_registration_sequence_update;
#[path = "source/source_restart_fd_watch_effects.rs"]
mod source_restart_fd_watch_effects;
#[path = "source/source_restart_watch_effects.rs"]
mod source_restart_watch_effects;
#[path = "source/source_restart_watch_overflow_queue.rs"]
mod source_restart_watch_overflow_queue;

//! lcs-core integration tests: symlink.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "symlink/symlink_creation_authority_gate.rs"]
mod symlink_creation_authority_gate;
#[path = "symlink/symlink_depth_eloop.rs"]
mod symlink_depth_eloop;
#[path = "symlink/symlink_non_link_resolution.rs"]
mod symlink_non_link_resolution;
#[path = "symlink/symlink_open_resolution.rs"]
mod symlink_open_resolution;
#[path = "symlink/symlink_resolution_errno.rs"]
mod symlink_resolution_errno;
#[path = "symlink/symlink_semantics.rs"]
mod symlink_semantics;
#[path = "symlink/symlink_target_payload_routing.rs"]
mod symlink_target_payload_routing;

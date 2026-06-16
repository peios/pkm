//! lcs-core integration tests: path.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "path/canonical_key_locations.rs"]
mod canonical_key_locations;
#[path = "path/case_preserving_folded_names.rs"]
mod case_preserving_folded_names;
#[path = "path/invalid_reg_link_nonmutation.rs"]
mod invalid_reg_link_nonmutation;
#[path = "path/invalid_value_type_errno.rs"]
mod invalid_value_type_errno;
#[path = "path/linux_errno_projection.rs"]
mod linux_errno_projection;
#[path = "path/malformed_layer_name_source_data.rs"]
mod malformed_layer_name_source_data;
#[path = "path/path_entry_semantics.rs"]
mod path_entry_semantics;
#[path = "path/path_entry_source_dispatch.rs"]
mod path_entry_source_dispatch;
#[path = "path/path_resolution_conformance.rs"]
mod path_resolution_conformance;
#[path = "path/relative_depth_bound.rs"]
mod relative_depth_bound;
#[path = "path/semantic_foundation.rs"]
mod semantic_foundation;
#[path = "path/unicode_casefold.rs"]
mod unicode_casefold;
#[path = "path/variable_output_buffers.rs"]
mod variable_output_buffers;

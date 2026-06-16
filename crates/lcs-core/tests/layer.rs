//! lcs-core integration tests: layer.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "layer/layer_admission_errno.rs"]
mod layer_admission_errno;
#[path = "layer/layer_creation_cap_errno.rs"]
mod layer_creation_cap_errno;
#[path = "layer/layer_deletion.rs"]
mod layer_deletion;
#[path = "layer/layer_deletion_orphans.rs"]
mod layer_deletion_orphans;
#[path = "layer/layer_deletion_transaction_abort_selection.rs"]
mod layer_deletion_transaction_abort_selection;
#[path = "layer/layer_lifecycle_composition.rs"]
mod layer_lifecycle_composition;
#[path = "layer/layer_metadata_sd_validation.rs"]
mod layer_metadata_sd_validation;
#[path = "layer/layer_metadata_value_parser.rs"]
mod layer_metadata_value_parser;
#[path = "layer/layer_owner_selection.rs"]
mod layer_owner_selection;
#[path = "layer/layer_publication_atomicity.rs"]
mod layer_publication_atomicity;
#[path = "layer/layer_resolution.rs"]
mod layer_resolution;
#[path = "layer/layer_table_semantics.rs"]
mod layer_table_semantics;
#[path = "layer/layer_write_authorization.rs"]
mod layer_write_authorization;

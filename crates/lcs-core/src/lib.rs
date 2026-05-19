//! Slow-track LCS semantic core.
//!
//! This crate contains pure, reusable PSD-005 validation and normalization
//! primitives. It intentionally does not perform syscalls, source I/O, KACS
//! access checks, fd management, or KMES emission.

#![cfg_attr(feature = "kernel", no_std)]
#![allow(unreachable_pub)]

pub mod access;
pub mod casefold;
pub mod config;
pub mod constants;
pub mod error;
pub mod path;
pub mod resolution;
pub mod sequence;
pub mod string;
pub mod value;

pub use access::{
    NormalizedRegistryAccess, REGISTRY_GENERIC_MAPPING, RegistryGenericMapping,
    map_registry_generic_bits, registry_fd_has_right, validate_registry_ace_mask,
    validate_registry_desired_access,
};
pub use casefold::{
    casefold_cmp, casefold_eq, casefold_eq_bytes, casefold_is, unicode_simple_case_fold,
};
pub use config::{
    ConfigRange, LcsLimits, MAX_BOUND_TRANSACTIONS_PER_SOURCE, MAX_CONCURRENT_RSI_REQUESTS,
    MAX_HIVES_PER_SOURCE, MAX_KEY_DEPTH, MAX_LAYERS_PER_VALUE, MAX_PATH_COMPONENT_LENGTH,
    MAX_PRIVATE_LAYERS_PER_TOKEN, MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE, MAX_REGISTERED_SOURCES,
    MAX_SCOPE_GUIDS_PER_TOKEN, MAX_SUBTREE_WATCH_DEPTH, MAX_TOTAL_LAYERS, MAX_TOTAL_PATH_LENGTH,
    MAX_TRANSACTION_WATCH_EVENT_BURST, MAX_VALUE_SIZE, NOTIFICATION_QUEUE_SIZE, REQUEST_TIMEOUT_MS,
    SYMLINK_DEPTH_LIMIT, TRANSACTION_TIMEOUT_MS, validate_config_value,
};
pub use constants::*;
pub use error::{LcsError, LcsResult};
pub use path::{
    PathKind, PathSummary, is_base_layer_name, is_reserved_current_user_name,
    validate_hive_name_bytes, validate_key_component_bytes, validate_layer_name_bytes,
    validate_registry_path_bytes, validate_registry_path_str, validate_value_name_bytes,
};
pub use resolution::{
    BlanketTombstoneEntry, EnumeratedSubkey, EnumeratedValue, Guid, LayerResolutionContext,
    LayerView, NamedPathEntry, NamedValueEntry, PathEntry, PathResolution, PathTarget,
    ResolvedPathEntry, ResolvedValueEntry, ValueEntry, ValueResolution, for_each_effective_value,
    for_each_visible_subkey, resolve_path_entry, resolve_value,
};
pub use sequence::SequenceCounter;
pub use string::validate_lcs_str;
pub use value::{
    RegistryValueType, ValidatedValueType, validate_value_data_len, validate_value_write_type,
};

/// Returns a stable value from the staged crate so integration build steps can
/// prove the real `lcs-core` module graph compiled and linked.
pub fn kernel_compile_probe() -> usize {
    REG_VALID_DESIRED_ACCESS_MASK as usize
}

use crate::config::LcsLimits;
use crate::error::{LcsError, LcsResult};
use crate::path::{PathKind, PathSummary, validate_registry_path_bytes};
use crate::value::RegistryValueType;

/// Effective default value selected for a symlink key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymlinkDefaultValue<'a> {
    pub value_type: RegistryValueType,
    pub data: &'a [u8],
}

/// Caller-facing errno category for symlink path-resolution failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymlinkResolutionErrno {
    Einval,
    Eloop,
}

/// Symlink default-value resolution result before integer errno translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymlinkDefaultValueResolution<'a> {
    Target(PathSummary<'a>),
    Failed(SymlinkResolutionErrno),
}

/// Validates the effective default value of a symlink key and returns its target path.
pub fn validate_symlink_default_value<'a>(
    limits: &LcsLimits,
    default_value: Option<SymlinkDefaultValue<'a>>,
) -> LcsResult<PathSummary<'a>> {
    let Some(default_value) = default_value else {
        return Err(LcsError::SymlinkDefaultValueMissing);
    };

    if default_value.value_type != RegistryValueType::Link {
        return Err(LcsError::SymlinkDefaultNotRegLink(
            default_value.value_type.code(),
        ));
    }

    validate_symlink_target_bytes(limits, default_value.data)
}

/// Classifies effective default-value validation for ordinary symlink opens.
pub fn classify_symlink_default_value_resolution<'a>(
    limits: &LcsLimits,
    default_value: Option<SymlinkDefaultValue<'a>>,
) -> SymlinkDefaultValueResolution<'a> {
    match validate_symlink_default_value(limits, default_value) {
        Ok(target) => SymlinkDefaultValueResolution::Target(target),
        Err(_) => SymlinkDefaultValueResolution::Failed(SymlinkResolutionErrno::Einval),
    }
}

/// Validates a REG_LINK payload as a length-delimited absolute registry path.
pub fn validate_symlink_target_bytes<'a>(
    limits: &LcsLimits,
    target: &'a [u8],
) -> LcsResult<PathSummary<'a>> {
    validate_registry_path_bytes(target, PathKind::SymlinkTarget, limits)
}

/// Validates and advances the symlink follow depth counter.
pub fn validate_symlink_follow_depth(current_depth: usize, limits: &LcsLimits) -> LcsResult<usize> {
    let next_depth = current_depth.saturating_add(1);
    if next_depth > limits.symlink_depth_limit {
        return Err(LcsError::SymlinkDepthExceeded {
            depth: next_depth,
            max: limits.symlink_depth_limit,
        });
    }
    Ok(next_depth)
}

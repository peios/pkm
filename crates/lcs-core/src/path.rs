use crate::casefold::casefold_is;
use crate::config::LcsLimits;
use crate::constants::BASE_LAYER_NAME;
use crate::error::{LcsError, LcsResult};
use crate::string::validate_lcs_str;

/// Registry path interpretation context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathKind {
    /// Caller supplied an absolute path with a hive component.
    Absolute,
    /// Caller supplied a path relative to an existing key fd.
    Relative,
    /// LCS is validating a REG_LINK symlink target.
    SymlinkTarget,
}

/// Borrowed summary of a validated registry path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathSummary<'a> {
    pub raw: &'a str,
    pub kind: PathKind,
    pub component_count: usize,
    pub first_component: &'a str,
    pub final_component: &'a str,
    pub used_forward_separator: bool,
}

/// Validates a length-delimited byte path.
pub fn validate_registry_path_bytes<'a>(
    bytes: &'a [u8],
    kind: PathKind,
    limits: &LcsLimits,
) -> LcsResult<PathSummary<'a>> {
    let path = validate_lcs_str(bytes, "path")?;
    validate_registry_path_str(path, kind, limits)
}

/// Validates a decoded registry path.
pub fn validate_registry_path_str<'a>(
    path: &'a str,
    kind: PathKind,
    limits: &LcsLimits,
) -> LcsResult<PathSummary<'a>> {
    if path.is_empty() {
        return Err(LcsError::EmptyPath);
    }
    if path.len() > limits.max_total_path_length {
        return Err(LcsError::PathTooLong {
            len: path.len(),
            max: limits.max_total_path_length,
        });
    }

    let bytes = path.as_bytes();
    let mut component_start = 0usize;
    let mut component_len = 0usize;
    let mut component_count = 0usize;
    let mut first_component = None;
    let mut used_forward_separator = false;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if is_separator(byte) {
            if byte == b'/' {
                used_forward_separator = true;
            }
            if component_len == 0 {
                return Err(LcsError::EmptyPathComponent);
            }
            validate_component_len("path_component", component_len, limits)?;

            component_count += 1;
            if component_count > limits.max_key_depth {
                return Err(LcsError::KeyDepthExceeded {
                    depth: component_count,
                    max: limits.max_key_depth,
                });
            }

            let component = &path[component_start..index];
            if first_component.is_none() {
                first_component = Some(component);
            }
            component_start = index + 1;
            component_len = 0;
        } else {
            component_len += 1;
        }
    }

    if component_len == 0 {
        return Err(LcsError::TrailingPathSeparator);
    }
    validate_component_len("path_component", component_len, limits)?;

    component_count += 1;
    if component_count > limits.max_key_depth {
        return Err(LcsError::KeyDepthExceeded {
            depth: component_count,
            max: limits.max_key_depth,
        });
    }

    let component = &path[component_start..];
    if first_component.is_none() {
        first_component = Some(component);
    }

    Ok(PathSummary {
        raw: path,
        kind,
        component_count,
        first_component: first_component.expect("validated non-empty path has first component"),
        final_component: component,
        used_forward_separator,
    })
}

/// Validates one key-name component.
pub fn validate_key_component_bytes<'a>(bytes: &'a [u8], limits: &LcsLimits) -> LcsResult<&'a str> {
    validate_key_like_name(bytes, "key_component", limits)
}

/// Validates a hive name and rejects the kernel-reserved `CurrentUser` alias.
pub fn validate_hive_name_bytes<'a>(bytes: &'a [u8], limits: &LcsLimits) -> LcsResult<&'a str> {
    let name = validate_key_like_name(bytes, "hive_name", limits)?;
    if is_reserved_current_user_name(name) {
        return Err(LcsError::ReservedHiveName);
    }
    Ok(name)
}

/// Validates a layer name. The base-layer name is valid; base-layer deletion
/// and mutation restrictions are enforced by later layer-table code.
pub fn validate_layer_name_bytes<'a>(bytes: &'a [u8], limits: &LcsLimits) -> LcsResult<&'a str> {
    validate_key_like_name(bytes, "layer_name", limits)
}

/// Validates a value name. Empty value names are valid and identify the default
/// value; path separators are ordinary value-name characters.
pub fn validate_value_name_bytes<'a>(bytes: &'a [u8], limits: &LcsLimits) -> LcsResult<&'a str> {
    let name = validate_lcs_str(bytes, "value_name")?;
    validate_component_len("value_name", name.len(), limits)?;
    Ok(name)
}

pub fn is_reserved_current_user_name(name: &str) -> bool {
    casefold_is(name, "CurrentUser")
}

pub fn is_base_layer_name(name: &str) -> bool {
    casefold_is(name, BASE_LAYER_NAME)
}

fn validate_key_like_name<'a>(
    bytes: &'a [u8],
    field: &'static str,
    limits: &LcsLimits,
) -> LcsResult<&'a str> {
    let name = validate_lcs_str(bytes, field)?;
    if name.is_empty() {
        return Err(LcsError::EmptyString { field });
    }
    validate_component_len(field, name.len(), limits)?;
    if name.as_bytes().iter().copied().any(is_separator) {
        return Err(LcsError::NameContainsSeparator { field });
    }
    Ok(name)
}

fn validate_component_len(field: &'static str, len: usize, limits: &LcsLimits) -> LcsResult<()> {
    if len > limits.max_path_component_length {
        return Err(LcsError::NameTooLong {
            field,
            len,
            max: limits.max_path_component_length,
        });
    }
    Ok(())
}

fn is_separator(byte: u8) -> bool {
    byte == b'\\' || byte == b'/'
}

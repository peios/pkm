//! Pure, allocation-free decisions shared by StrataFS's VFS glue and tests.

#![cfg_attr(not(test), no_std)]
#![allow(unreachable_pub)]

/// The implementation limit. PSD-011 requires support for at least eight.
pub const MAX_STRATA: usize = 16;

pub const FLAG_CREATE: u32 = 1 << 0;
pub const FLAG_READ_ONLY: u32 = 1 << 1;
pub const FLAG_ABSENT_MAY: u32 = 1 << 2;
pub const FLAG_MASK: u32 = FLAG_CREATE | FLAG_READ_ONLY | FLAG_ABSENT_MAY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ConfigError {
    Empty = 1,
    TooMany = 2,
    UnknownFlag = 3,
    RepeatedCreate = 4,
    CreateReadOnly = 5,
}

/// Validate the part of a mount configuration that is independent of paths.
pub fn validate_flags(flags: &[u32]) -> Result<Option<usize>, ConfigError> {
    if flags.is_empty() {
        return Err(ConfigError::Empty);
    }
    if flags.len() > MAX_STRATA {
        return Err(ConfigError::TooMany);
    }

    let mut create = None;
    for (index, value) in flags.iter().copied().enumerate() {
        if value & !FLAG_MASK != 0 {
            return Err(ConfigError::UnknownFlag);
        }
        if value & FLAG_CREATE != 0 {
            if value & FLAG_READ_ONLY != 0 {
                return Err(ConfigError::CreateReadOnly);
            }
            if create.replace(index).is_some() {
                return Err(ConfigError::RepeatedCreate);
            }
        }
    }
    Ok(create)
}

/// Highest-precedence present object. Bit zero is the highest stratum.
pub fn provider(present: u64, count: usize) -> Option<usize> {
    if count == 0 || count > MAX_STRATA {
        return None;
    }
    let bounded = present & ((1_u64 << count) - 1);
    (bounded != 0).then(|| bounded.trailing_zeros() as usize)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Route {
    InPlace = 0,
    CopyUp = 1,
    ReadOnly = 2,
}

/// Route one modifying operation under PSD-011 section 5.1.
pub fn route_existing(
    provider: usize,
    provider_accepts: bool,
    create: Option<usize>,
    create_present: bool,
    copyable: bool,
    mount_read_only: bool,
) -> Route {
    if mount_read_only {
        return Route::ReadOnly;
    }
    if provider_accepts {
        return Route::InPlace;
    }
    match create {
        Some(create_index) if copyable && create_present && create_index < provider => {
            Route::CopyUp
        }
        _ => Route::ReadOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_stack_wide_flag_rules() {
        assert_eq!(validate_flags(&[]), Err(ConfigError::Empty));
        assert_eq!(
            validate_flags(&[FLAG_CREATE, FLAG_CREATE]),
            Err(ConfigError::RepeatedCreate)
        );
        assert_eq!(
            validate_flags(&[FLAG_CREATE | FLAG_READ_ONLY]),
            Err(ConfigError::CreateReadOnly)
        );
        assert_eq!(
            validate_flags(&[FLAG_READ_ONLY, FLAG_CREATE, 0]),
            Ok(Some(1))
        );
    }

    #[test]
    fn provider_is_always_highest_precedence() {
        assert_eq!(provider(0b1010, 4), Some(1));
        assert_eq!(provider(0, 4), None);
        assert_eq!(provider(1 << 10, 4), None);
    }

    #[test]
    fn copy_up_only_goes_upward() {
        assert_eq!(
            route_existing(2, false, Some(1), true, true, false),
            Route::CopyUp
        );
        assert_eq!(
            route_existing(1, false, Some(2), true, true, false),
            Route::ReadOnly
        );
        assert_eq!(
            route_existing(1, false, Some(0), false, true, false),
            Route::ReadOnly
        );
        assert_eq!(
            route_existing(1, false, Some(0), true, false, false),
            Route::ReadOnly
        );
    }

    #[test]
    fn in_place_and_mount_read_only_take_precedence() {
        assert_eq!(
            route_existing(1, true, Some(0), true, true, false),
            Route::InPlace
        );
        assert_eq!(
            route_existing(1, true, Some(0), true, true, true),
            Route::ReadOnly
        );
    }
}

//! Allocation compatibility layer.
//!
//! kacs-core compiles for two targets:
//! - **Userspace** (cargo test): standard `alloc`, allocation infallible
//! - **Kernel** (kbuild): kernel alloc, allocation fallible
//!
//! Production code uses:
//! - `compat::Vec<T>` instead of `alloc::vec::Vec<T>`
//! - `compat::String` instead of `alloc::string::String`
//! - `compat::vec_push()`, `vec_extend()`, etc. (all return Result)
//! - `TryClone::try_clone()` instead of `Clone::clone()`
//!
//! In userspace, TryClone blanket-impls over Clone (always Ok).
//! In kernel, TryClone is implemented explicitly with fallible allocation.

/// Allocation error type.
#[derive(Debug, Clone, Copy)]
pub struct AllocError;

impl core::fmt::Display for AllocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "allocation failed")
    }
}

// ── TryClone trait ────────────────────────────────────────────────────────

/// Fallible clone. Used instead of Clone in production code.
pub trait TryClone: Sized {
    fn try_clone(&self) -> Result<Self, AllocError>;
}

// Userspace: blanket impl — anything Clone is TryClone for free.
#[cfg(not(feature = "kernel"))]
impl<T: Clone> TryClone for T {
    #[inline]
    fn try_clone(&self) -> Result<Self, AllocError> {
        Ok(self.clone())
    }
}

// Kernel: implement TryClone for primitives and common types.
// Structs implement TryClone manually (or via the try_clone_derive pattern).
#[cfg(feature = "kernel")]
mod try_clone_prims {
    use super::{AllocError, TryClone};

    macro_rules! impl_try_clone_copy {
        ($($t:ty),*) => {
            $(impl TryClone for $t {
                #[inline]
                fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
            })*
        }
    }

    impl_try_clone_copy!(
        u8, u16, u32, u64, u128, usize,
        i8, i16, i32, i64, i128, isize,
        bool, char, f32, f64
    );

    impl<T: TryClone> TryClone for Option<T> {
        fn try_clone(&self) -> Result<Self, AllocError> {
            match self {
                Some(v) => Ok(Some(v.try_clone()?)),
                None => Ok(None),
            }
        }
    }
}

// ── Vec ───────────────────────────────────────────────────────────────────

#[cfg(not(feature = "kernel"))]
mod vec_inner {
    use super::AllocError;

    pub type Vec<T> = alloc::vec::Vec<T>;

    #[inline]
    pub fn vec_push<T>(v: &mut Vec<T>, val: T) -> Result<(), AllocError> {
        v.push(val);
        Ok(())
    }

    #[inline]
    pub fn vec_with_capacity<T>(cap: usize) -> Result<Vec<T>, AllocError> {
        Ok(Vec::with_capacity(cap))
    }

    #[inline]
    pub fn vec_extend<T: Clone>(v: &mut Vec<T>, s: &[T]) -> Result<(), AllocError> {
        v.extend_from_slice(s);
        Ok(())
    }

    #[inline]
    pub fn slice_to_vec<T: Clone>(s: &[T]) -> Result<Vec<T>, AllocError> {
        Ok(s.to_vec())
    }
}

#[cfg(feature = "kernel")]
mod vec_inner {
    use super::{AllocError, TryClone};
    use core::ops::{Deref, DerefMut};

    /// Vec wrapper around KVec that implements Debug, Hash, PartialEq, Eq.
    pub struct Vec<T>(kernel::alloc::KVec<T>);

    impl<T> Vec<T> {
        pub const fn new() -> Self {
            Vec(kernel::alloc::KVec::new())
        }

        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        pub fn iter(&self) -> core::slice::Iter<'_, T> {
            self.0.iter()
        }

        pub fn as_slice(&self) -> &[T] {
            &self.0
        }

        pub fn pop(&mut self) -> Option<T> {
            self.0.pop()
        }

        pub fn truncate(&mut self, len: usize) {
            self.0.truncate(len)
        }
    }

    impl<'a, T> IntoIterator for &'a Vec<T> {
        type Item = &'a T;
        type IntoIter = core::slice::Iter<'a, T>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter()
        }
    }

    impl<'a, T> IntoIterator for &'a mut Vec<T> {
        type Item = &'a mut T;
        type IntoIter = core::slice::IterMut<'a, T>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter_mut()
        }
    }

    impl<T> Deref for Vec<T> {
        type Target = [T];
        fn deref(&self) -> &[T] {
            &self.0
        }
    }

    impl<T> DerefMut for Vec<T> {
        fn deref_mut(&mut self) -> &mut [T] {
            &mut self.0
        }
    }

    impl<T: core::fmt::Debug> core::fmt::Debug for Vec<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(self.as_slice(), f)
        }
    }

    impl<T: core::hash::Hash> core::hash::Hash for Vec<T> {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.as_slice().hash(state)
        }
    }

    impl<T: PartialEq> PartialEq for Vec<T> {
        fn eq(&self, other: &Self) -> bool {
            self.as_slice() == other.as_slice()
        }
    }

    impl<T: Eq> Eq for Vec<T> {}

    impl<T: TryClone> TryClone for Vec<T> {
        fn try_clone(&self) -> Result<Self, AllocError> {
            let mut new = vec_with_capacity(self.len())?;
            for item in self.iter() {
                vec_push(&mut new, item.try_clone()?)?;
            }
            Ok(new)
        }
    }

    // Default is needed for #[derive(Default)] on AuditResult
    impl<T> Default for Vec<T> {
        fn default() -> Self {
            Vec::new()
        }
    }

    #[inline]
    pub fn vec_push<T>(v: &mut Vec<T>, val: T) -> Result<(), AllocError> {
        v.0.push(val, kernel::alloc::flags::GFP_KERNEL).map_err(|_| AllocError)
    }

    #[inline]
    pub fn vec_with_capacity<T>(cap: usize) -> Result<Vec<T>, AllocError> {
        let inner = kernel::alloc::KVec::with_capacity(cap, kernel::alloc::flags::GFP_KERNEL)
            .map_err(|_| AllocError)?;
        Ok(Vec(inner))
    }

    #[inline]
    pub fn vec_extend<T: TryClone>(v: &mut Vec<T>, s: &[T]) -> Result<(), AllocError> {
        for item in s {
            vec_push(v, item.try_clone()?)?;
        }
        Ok(())
    }

    #[inline]
    pub fn slice_to_vec<T: TryClone>(s: &[T]) -> Result<Vec<T>, AllocError> {
        let mut v = vec_with_capacity(s.len())?;
        for item in s {
            vec_push(&mut v, item.try_clone()?)?;
        }
        Ok(v)
    }
}

pub use vec_inner::*;

// ── String ────────────────────────────────────────────────────────────────

#[cfg(not(feature = "kernel"))]
mod string_inner {
    pub type String = alloc::string::String;
}

#[cfg(feature = "kernel")]
mod string_inner {
    use super::{AllocError, TryClone, vec_push, vec_with_capacity, Vec};

    /// Owned UTF-8 string backed by Vec<u8> (KVec in kernel).
    pub struct String(Vec<u8>);

    impl String {
        pub fn new() -> Self {
            String(Vec::new())
        }

        pub fn push(&mut self, c: char) -> Result<(), AllocError> {
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            for &b in encoded.as_bytes() {
                vec_push(&mut self.0, b)?;
            }
            Ok(())
        }

        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn as_str(&self) -> &str {
            // Safety: we only construct via push(char) which guarantees UTF-8
            unsafe { core::str::from_utf8_unchecked(&self.0) }
        }

        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }

        pub fn to_ascii_lowercase(&self) -> Result<String, AllocError> {
            let mut new = vec_with_capacity(self.0.len())?;
            for &b in self.0.iter() {
                vec_push(&mut new, b.to_ascii_lowercase())?;
            }
            Ok(String(new))
        }
    }

    impl TryClone for String {
        fn try_clone(&self) -> Result<Self, AllocError> {
            let mut new = vec_with_capacity(self.0.len())?;
            for &b in self.0.iter() {
                vec_push(&mut new, b)?;
            }
            Ok(String(new))
        }
    }

    impl core::fmt::Debug for String {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(self.as_str(), f)
        }
    }

    impl core::fmt::Display for String {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Display::fmt(self.as_str(), f)
        }
    }

    impl PartialEq for String {
        fn eq(&self, other: &Self) -> bool {
            self.as_str() == other.as_str()
        }
    }

    impl Eq for String {}

    impl PartialEq<str> for String {
        fn eq(&self, other: &str) -> bool {
            self.as_str() == other
        }
    }

    impl PartialEq<&str> for String {
        fn eq(&self, other: &&str) -> bool {
            self.as_str() == *other
        }
    }

    impl core::ops::Deref for String {
        type Target = str;
        fn deref(&self) -> &str {
            self.as_str()
        }
    }
}

pub use string_inner::String;

// ── Kernel TryClone impls for kacs-core types ─────────────────────────────
//
// In userspace, the blanket `impl<T: Clone> TryClone for T` covers everything.
// In kernel, each type needs an explicit impl.

#[cfg(feature = "kernel")]
mod kernel_try_clone {
    use super::*;

    // Fixed-size arrays used in structs
    impl TryClone for [u8; 6] {
        fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
    }
    impl TryClone for [u8; 8] {
        fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
    }

    impl TryClone for crate::sid::Sid {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::sid::Sid {
                revision: self.revision,
                authority: self.authority,
                sub_authorities: self.sub_authorities.try_clone()?,
            })
        }
    }

    impl TryClone for crate::guid::Guid {
        fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
    }

    impl TryClone for crate::luid::Luid {
        fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
    }

    impl TryClone for crate::group::GroupEntry {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::group::GroupEntry {
                sid: self.sid.try_clone()?,
                attributes: self.attributes,
            })
        }
    }

    impl TryClone for crate::ace::Ace {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::ace::Ace {
                ace_type: self.ace_type,
                flags: self.flags,
                mask: self.mask,
                sid: self.sid.try_clone()?,
                object_type: self.object_type,
                inherited_object_type: self.inherited_object_type,
                condition: self.condition.try_clone()?,
                application_data: self.application_data.try_clone()?,
            })
        }
    }

    impl TryClone for crate::acl::Acl {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::acl::Acl {
                revision: self.revision,
                aces: self.aces.try_clone()?,
            })
        }
    }

    impl TryClone for crate::sd::SecurityDescriptor {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::sd::SecurityDescriptor {
                control: self.control,
                owner: self.owner.try_clone()?,
                group: self.group.try_clone()?,
                dacl: self.dacl.try_clone()?,
                sacl: self.sacl.try_clone()?,
            })
        }
    }

    impl TryClone for crate::privilege::Privileges {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::privilege::Privileges {
                present: self.present,
                enabled: self.enabled,
                enabled_by_default: self.enabled_by_default,
                used: self.used,
            })
        }
    }

    impl TryClone for crate::token::TokenSource {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::token::TokenSource {
                name: self.name,
                source_id: self.source_id,
            })
        }
    }

    impl TryClone for crate::token::ClaimEntry {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::token::ClaimEntry {
                name: self.name.try_clone()?,
                claim_type: self.claim_type,
                flags: self.flags,
                values: self.values.try_clone()?,
            })
        }
    }

    impl TryClone for crate::token::ClaimValues {
        fn try_clone(&self) -> Result<Self, AllocError> {
            use crate::token::ClaimValues;
            match self {
                ClaimValues::Int64(v) => Ok(ClaimValues::Int64(v.try_clone()?)),
                ClaimValues::Uint64(v) => Ok(ClaimValues::Uint64(v.try_clone()?)),
                ClaimValues::String(v) => Ok(ClaimValues::String(v.try_clone()?)),
                ClaimValues::Sid(v) => Ok(ClaimValues::Sid(v.try_clone()?)),
                ClaimValues::Boolean(v) => Ok(ClaimValues::Boolean(v.try_clone()?)),
                ClaimValues::Octet(v) => Ok(ClaimValues::Octet(v.try_clone()?)),
            }
        }
    }

    impl TryClone for crate::token::Token {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::token::Token {
                user_sid: self.user_sid.try_clone()?,
                user_deny_only: self.user_deny_only,
                groups: self.groups.try_clone()?,
                logon_sid: self.logon_sid.try_clone()?,
                restricted_sids: self.restricted_sids.try_clone()?,
                write_restricted: self.write_restricted,
                token_type: self.token_type,
                impersonation_level: self.impersonation_level,
                integrity_level: self.integrity_level,
                mandatory_policy: self.mandatory_policy,
                privileges: self.privileges.try_clone()?,
                elevation_type: self.elevation_type,
                owner_sid_index: self.owner_sid_index,
                primary_group_index: self.primary_group_index,
                token_id: self.token_id,
                auth_id: self.auth_id,
                source: self.source.try_clone()?,
                origin: self.origin,
                interactive_session_id: self.interactive_session_id,
                user_claims: self.user_claims.try_clone()?,
                device_claims: self.device_claims.try_clone()?,
                device_groups: self.device_groups.try_clone()?,
                restricted_device_groups: self.restricted_device_groups.try_clone()?,
                confinement_sid: self.confinement_sid.try_clone()?,
                confinement_capabilities: self.confinement_capabilities.try_clone()?,
                isolation_boundary: self.isolation_boundary,
                confinement_exempt: self.confinement_exempt,
                projected_uid: self.projected_uid,
                projected_gid: self.projected_gid,
                projected_supplementary_gids: self.projected_supplementary_gids.try_clone()?,
                audit_policy: self.audit_policy,
                modified_id: self.modified_id,
            })
        }
    }

    impl TryClone for crate::audit::AuditEvent {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::audit::AuditEvent {
                ace_type: self.ace_type,
                ace_sid: self.ace_sid.try_clone()?,
                ace_mask: self.ace_mask,
                success: self.success,
                desired: self.desired,
                granted: self.granted,
            })
        }
    }

    impl TryClone for crate::audit::AuditResult {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::audit::AuditResult {
                events: self.events.try_clone()?,
                continuous_audit_mask: self.continuous_audit_mask,
            })
        }
    }

    impl TryClone for crate::cap::CentralAccessRule {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::cap::CentralAccessRule {
                applies_to: self.applies_to.try_clone()?,
                effective_dacl: self.effective_dacl.try_clone()?,
                staged_dacl: self.staged_dacl.try_clone()?,
            })
        }
    }

    impl TryClone for crate::cap::CentralAccessPolicy {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::cap::CentralAccessPolicy {
                policy_sid: self.policy_sid.try_clone()?,
                rules: self.rules.try_clone()?,
            })
        }
    }

    // Conditional ACE types
    impl TryClone for crate::conditional::Value {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::conditional::Value {
                vtype: self.vtype.try_clone()?,
                origin: self.origin,
                flags: self.flags,
            })
        }
    }

    impl TryClone for crate::conditional::ValueType {
        fn try_clone(&self) -> Result<Self, AllocError> {
            use crate::conditional::ValueType;
            match self {
                ValueType::Null => Ok(ValueType::Null),
                ValueType::Int64(v) => Ok(ValueType::Int64(*v)),
                ValueType::Uint64(v) => Ok(ValueType::Uint64(*v)),
                ValueType::Boolean(v) => Ok(ValueType::Boolean(*v)),
                ValueType::String(v) => Ok(ValueType::String(v.try_clone()?)),
                ValueType::Sid(v) => Ok(ValueType::Sid(v.try_clone()?)),
                ValueType::Octet(v) => Ok(ValueType::Octet(v.try_clone()?)),
                ValueType::Composite(v) => Ok(ValueType::Composite(v.try_clone()?)),
            }
        }
    }
}

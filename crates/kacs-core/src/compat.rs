//! Allocation compatibility layer for dual-target compilation.
//!
//! kacs-core is a `no_std + alloc` crate that compiles for two targets:
//!
//! - **Userspace** (`cargo test`): links against the standard `alloc` crate.
//!   Allocation is infallible — `Vec::push()` panics on OOM, same as normal
//!   Rust. All the `Result` returns from compat functions are always `Ok`.
//!   The optimizer eliminates the error path entirely.
//!
//! - **Kernel** (`kbuild` with `feature = "kernel"`): links against the
//!   kernel's own allocator via `kernel::alloc::KVec`. Allocation is fallible —
//!   every push, extend, or capacity reservation can fail and returns
//!   `Result<_, AllocError>`. This matches the kernel Rust team's design:
//!   no hidden panics, all allocation failures propagate to the caller.
//!
//! # What production code uses
//!
//! | Instead of                  | Use                                        |
//! |-----------------------------|--------------------------------------------|
//! | `alloc::vec::Vec<T>`        | `compat::Vec<T>`                           |
//! | `alloc::string::String`     | `compat::String`                           |
//! | `v.push(x)`                 | `compat::vec_push(&mut v, x)?`             |
//! | `Vec::with_capacity(n)`     | `compat::vec_with_capacity(n)?`            |
//! | `v.extend_from_slice(s)`    | `compat::vec_extend(&mut v, s)?`           |
//! | `s.to_vec()`                | `compat::slice_to_vec(s)?`                 |
//! | `x.clone()`                 | `x.try_clone()?`                           |
//!
//! # Why TryClone instead of Clone
//!
//! Rust's `Clone::clone()` returns `Self` — there's no way to propagate an
//! allocation failure. The kernel team's `KVec` deliberately doesn't implement
//! `Clone` for this reason. We follow the same principle: production code uses
//! `TryClone::try_clone()` which returns `Result<Self, AllocError>`.
//!
//! In userspace, a blanket impl makes every `Clone` type automatically
//! `TryClone` (by delegating to `clone()` and wrapping in `Ok`). Tests
//! continue to use `#[derive(Clone)]` and `.clone()` normally.
//!
//! In kernel mode, each kacs-core type has an explicit `TryClone` impl that
//! performs fallible field-by-field cloning. Structs use
//! `#[cfg_attr(not(feature = "kernel"), derive(Clone))]` so they only derive
//! `Clone` in userspace.
//!
//! # Why a Vec newtype (kernel mode)
//!
//! The kernel's `KVec<T>` doesn't implement `Clone`, `Hash`, `Debug`, or
//! `PartialEq` — the kernel team intentionally omitted traits that might
//! hide allocation or that they haven't stabilized yet. But kacs-core's
//! structs derive these traits (`#[derive(Debug, PartialEq, Hash)]`).
//!
//! In kernel mode, `compat::Vec<T>` is a newtype around `KVec<T>` that
//! implements the read-only traits (`Debug`, `Hash`, `PartialEq`, `Eq`) by
//! delegating to the underlying slice. These are non-allocating operations
//! so there's no fallibility concern. `TryClone` is implemented separately
//! with proper error propagation.

/// Allocation failure. Returned by all fallible allocation operations.
///
/// In userspace this type is never actually constructed (all allocations
/// succeed or panic via the standard allocator). In kernel mode it
/// represents a `GFP_KERNEL` allocation failure — the caller should
/// propagate it upward until it becomes an `-ENOMEM` at the syscall
/// boundary.
#[derive(Debug, Clone, Copy)]
pub struct AllocError;

impl core::fmt::Display for AllocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "allocation failed")
    }
}

// ── TryClone ──────────────────────────────────────────────────────────────

/// Fallible clone. The kernel-safe replacement for `Clone`.
///
/// All production code uses `x.try_clone()?` instead of `x.clone()`.
/// In userspace, this is a no-op wrapper around `Clone::clone()`.
/// In kernel, this performs fallible field-by-field deep copying.
pub trait TryClone: Sized {
    /// Create a deep copy, returning `Err(AllocError)` if any allocation
    /// fails during the copy.
    fn try_clone(&self) -> Result<Self, AllocError>;
}

/// Userspace blanket impl: anything that implements Clone is TryClone.
/// The `Ok(self.clone())` is optimized away — this compiles to a direct
/// clone with zero overhead.
#[cfg(not(feature = "kernel"))]
impl<T: Clone> TryClone for T {
    #[inline]
    fn try_clone(&self) -> Result<Self, AllocError> {
        Ok(self.clone())
    }
}

/// Kernel TryClone for primitive and Copy types.
/// These never allocate — try_clone is just a bitwise copy.
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

    /// `Option<T>` is TryClone if `T` is — clones the inner value if present.
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

/// Userspace Vec: just a type alias for the standard `alloc::vec::Vec`.
/// All helper functions wrap the infallible API in `Ok(...)`.
#[cfg(not(feature = "kernel"))]
mod vec_inner {
    use super::AllocError;

    /// Standard library Vec. In userspace, allocation panics on OOM.
    pub type Vec<T> = alloc::vec::Vec<T>;

    /// Push a value onto the end.
    #[inline]
    pub fn vec_push<T>(v: &mut Vec<T>, val: T) -> Result<(), AllocError> {
        v.push(val);
        Ok(())
    }

    /// Create a Vec with pre-allocated capacity.
    #[inline]
    pub fn vec_with_capacity<T>(cap: usize) -> Result<Vec<T>, AllocError> {
        Ok(Vec::with_capacity(cap))
    }

    /// Extend a Vec by cloning elements from a slice.
    #[inline]
    pub fn vec_extend<T: Clone>(v: &mut Vec<T>, s: &[T]) -> Result<(), AllocError> {
        v.extend_from_slice(s);
        Ok(())
    }

    /// Clone a slice into a new Vec.
    #[inline]
    pub fn slice_to_vec<T: Clone>(s: &[T]) -> Result<Vec<T>, AllocError> {
        Ok(s.to_vec())
    }
}

/// Kernel Vec: a newtype around `kernel::alloc::KVec<T>`.
///
/// KVec is the kernel's Vec equivalent with fallible allocation — `push()`
/// takes a GFP flags argument and returns `Result`. This newtype wraps it
/// and adds the standard traits (`Debug`, `Hash`, `PartialEq`, `Eq`) that
/// KVec deliberately omits, plus `IntoIterator` for `for x in &vec` loops.
///
/// The newtype is transparent at runtime — same layout as KVec.
#[cfg(feature = "kernel")]
mod vec_inner {
    use super::{AllocError, TryClone};
    use core::ops::{Deref, DerefMut};

    /// Owned growable array. Wraps `kernel::alloc::KVec<T>` in kernel mode.
    pub struct Vec<T>(kernel::alloc::KVec<T>);

    impl<T> Vec<T> {
        /// Create an empty Vec with no allocation.
        pub const fn new() -> Self {
            Vec(kernel::alloc::KVec::new())
        }

        /// Number of elements.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        /// True if empty.
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        /// Iterate over references to elements.
        pub fn iter(&self) -> core::slice::Iter<'_, T> {
            self.0.iter()
        }

        /// View as a slice.
        pub fn as_slice(&self) -> &[T] {
            &self.0
        }

        /// Remove and return the last element, or `None` if empty.
        pub fn pop(&mut self) -> Option<T> {
            self.0.pop()
        }

        /// Shorten the Vec to `len` elements, dropping the rest.
        pub fn truncate(&mut self, len: usize) {
            self.0.truncate(len)
        }
    }

    /// Allow `for x in &vec { ... }` loops.
    impl<'a, T> IntoIterator for &'a Vec<T> {
        type Item = &'a T;
        type IntoIter = core::slice::Iter<'a, T>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter()
        }
    }

    /// Allow `for x in &mut vec { ... }` loops.
    impl<'a, T> IntoIterator for &'a mut Vec<T> {
        type Item = &'a mut T;
        type IntoIter = core::slice::IterMut<'a, T>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter_mut()
        }
    }

    /// Deref to slice — enables indexing, `.len()`, `.iter()`, etc.
    impl<T> Deref for Vec<T> {
        type Target = [T];
        fn deref(&self) -> &[T] {
            &self.0
        }
    }

    /// Mutable deref to slice — enables `vec[i] = x`, `.sort()`, etc.
    impl<T> DerefMut for Vec<T> {
        fn deref_mut(&mut self) -> &mut [T] {
            &mut self.0
        }
    }

    /// Debug-print as a slice: `[item1, item2, ...]`.
    /// Non-allocating — reads only.
    impl<T: core::fmt::Debug> core::fmt::Debug for Vec<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(self.as_slice(), f)
        }
    }

    /// Hash by contents (delegates to slice hash).
    /// Non-allocating — reads only.
    impl<T: core::hash::Hash> core::hash::Hash for Vec<T> {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.as_slice().hash(state)
        }
    }

    /// Compare by element equality.
    impl<T: PartialEq> PartialEq for Vec<T> {
        fn eq(&self, other: &Self) -> bool {
            self.as_slice() == other.as_slice()
        }
    }

    /// Marker: equality is reflexive.
    impl<T: Eq> Eq for Vec<T> {}

    /// Fallible deep copy. Each element is cloned via `TryClone`,
    /// which propagates allocation failures from nested Vecs.
    impl<T: TryClone> TryClone for Vec<T> {
        fn try_clone(&self) -> Result<Self, AllocError> {
            let mut new = vec_with_capacity(self.len())?;
            for item in self.iter() {
                vec_push(&mut new, item.try_clone()?)?;
            }
            Ok(new)
        }
    }

    /// Default is an empty Vec (no allocation).
    /// Needed for `#[derive(Default)]` on structs containing Vec.
    impl<T> Default for Vec<T> {
        fn default() -> Self {
            Vec::new()
        }
    }

    /// Push a value. Allocates with `GFP_KERNEL`.
    #[inline]
    pub fn vec_push<T>(v: &mut Vec<T>, val: T) -> Result<(), AllocError> {
        v.0.push(val, kernel::alloc::flags::GFP_KERNEL).map_err(|_| AllocError)
    }

    /// Create a Vec with pre-allocated capacity. Allocates with `GFP_KERNEL`.
    #[inline]
    pub fn vec_with_capacity<T>(cap: usize) -> Result<Vec<T>, AllocError> {
        let inner = kernel::alloc::KVec::with_capacity(cap, kernel::alloc::flags::GFP_KERNEL)
            .map_err(|_| AllocError)?;
        Ok(Vec(inner))
    }

    /// Extend a Vec by cloning elements from a slice.
    /// Uses `TryClone` (not `Clone`) for kernel-safe deep copying.
    #[inline]
    pub fn vec_extend<T: TryClone>(v: &mut Vec<T>, s: &[T]) -> Result<(), AllocError> {
        for item in s {
            vec_push(v, item.try_clone()?)?;
        }
        Ok(())
    }

    /// Clone a slice into a new Vec.
    /// Uses `TryClone` (not `Clone`) for kernel-safe deep copying.
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

/// Userspace String: just a type alias for `alloc::string::String`.
#[cfg(not(feature = "kernel"))]
mod string_inner {
    /// Standard library String.
    pub type String = alloc::string::String;
}

/// Kernel String: owned UTF-8 string backed by `Vec<u8>` (which wraps KVec).
///
/// The kernel's Rust support doesn't include `alloc::string::String` —
/// the kernel team replaced all infallible alloc types with fallible
/// equivalents, and hasn't shipped a `KString` yet. This type fills
/// the gap with the minimal API that kacs-core's conditional ACE
/// evaluator needs.
///
/// All construction is through `push(char)`, which encodes UTF-8
/// byte-by-byte. The `Deref<Target = str>` impl enables transparent
/// use as `&str` for comparisons, formatting, and indexing.
#[cfg(feature = "kernel")]
mod string_inner {
    use super::{AllocError, TryClone, vec_push, vec_with_capacity, Vec};

    /// Owned UTF-8 string backed by KVec<u8>.
    pub struct String(Vec<u8>);

    impl String {
        /// Create an empty string (no allocation).
        pub fn new() -> Self {
            String(Vec::new())
        }

        /// Append a Unicode character, encoding as UTF-8.
        pub fn push(&mut self, c: char) -> Result<(), AllocError> {
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            for &b in encoded.as_bytes() {
                vec_push(&mut self.0, b)?;
            }
            Ok(())
        }

        /// True if the string contains no characters.
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        /// Byte length of the UTF-8 representation.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        /// View as a `&str`.
        pub fn as_str(&self) -> &str {
            // Safety: construction only through push(char), which guarantees
            // valid UTF-8 encoding.
            unsafe { core::str::from_utf8_unchecked(&self.0) }
        }

        /// View as raw UTF-8 bytes.
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }

        /// Return a new string with all ASCII characters lowercased.
        /// Used by conditional ACE case-insensitive string comparison.
        pub fn to_ascii_lowercase(&self) -> Result<String, AllocError> {
            let mut new = vec_with_capacity(self.0.len())?;
            for &b in self.0.iter() {
                vec_push(&mut new, b.to_ascii_lowercase())?;
            }
            Ok(String(new))
        }
    }

    /// Fallible deep copy of string contents.
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

    /// Transparent deref to `&str` — enables all `str` methods and
    /// comparisons without wrapping.
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
// In userspace, the blanket `impl<T: Clone> TryClone for T` covers all
// types automatically. In kernel mode, each type needs an explicit impl
// that performs fallible field-by-field deep copying.
//
// Types that are `Copy` (primitives, enums without data, Guid, Luid) are
// handled by the `try_clone_prims` module above. Types below contain
// `Vec` or `String` fields and require actual allocation during cloning.

#[cfg(feature = "kernel")]
mod kernel_try_clone {
    use super::*;

    // Fixed-size byte arrays used in Sid::authority and TokenSource::name.
    impl TryClone for [u8; 6] {
        fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
    }
    impl TryClone for [u8; 8] {
        fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
    }

    /// SID: contains `Vec<u32>` for sub-authorities.
    impl TryClone for crate::sid::Sid {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::sid::Sid {
                revision: self.revision,
                authority: self.authority,
                sub_authorities: self.sub_authorities.try_clone()?,
            })
        }
    }

    /// GUID: 16-byte fixed-size, pure Copy.
    impl TryClone for crate::guid::Guid {
        fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
    }

    /// LUID: 8-byte fixed-size, pure Copy.
    impl TryClone for crate::luid::Luid {
        fn try_clone(&self) -> Result<Self, AllocError> { Ok(*self) }
    }

    /// Group entry: SID + attribute flags.
    impl TryClone for crate::group::GroupEntry {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::group::GroupEntry {
                sid: self.sid.try_clone()?,
                attributes: self.attributes,
            })
        }
    }

    /// ACE: contains SID + optional condition/application data (Vec<u8>).
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

    /// ACL: contains Vec<Ace>.
    impl TryClone for crate::acl::Acl {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::acl::Acl {
                revision: self.revision,
                aces: self.aces.try_clone()?,
            })
        }
    }

    /// Security Descriptor: owner/group SIDs + DACL/SACL.
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

    /// Privileges: 4x u64 bitmasks, pure Copy.
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

    /// Token source: 8-byte name + LUID, pure Copy.
    impl TryClone for crate::token::TokenSource {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::token::TokenSource {
                name: self.name,
                source_id: self.source_id,
            })
        }
    }

    /// Claim entry: String name + typed values (for conditional ACEs).
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

    /// Claim values: multi-valued, each variant holds a Vec.
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

    /// Token: the big one. Many Vec and SID fields.
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

    /// Audit event: contains a SID.
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

    /// Audit result: contains Vec<AuditEvent>.
    impl TryClone for crate::audit::AuditResult {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::audit::AuditResult {
                events: self.events.try_clone()?,
                continuous_audit_mask: self.continuous_audit_mask,
            })
        }
    }

    /// Central access rule (§11.18): conditional expression + DACLs.
    impl TryClone for crate::cap::CentralAccessRule {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::cap::CentralAccessRule {
                applies_to: self.applies_to.try_clone()?,
                effective_dacl: self.effective_dacl.try_clone()?,
                staged_dacl: self.staged_dacl.try_clone()?,
            })
        }
    }

    /// Central access policy: SID + rules.
    impl TryClone for crate::cap::CentralAccessPolicy {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::cap::CentralAccessPolicy {
                policy_sid: self.policy_sid.try_clone()?,
                rules: self.rules.try_clone()?,
            })
        }
    }

    /// Conditional ACE value: expression evaluation intermediate.
    impl TryClone for crate::conditional::Value {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(crate::conditional::Value {
                vtype: self.vtype.try_clone()?,
                origin: self.origin,
                flags: self.flags,
            })
        }
    }

    /// Conditional ACE value type: tagged union of possible values.
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

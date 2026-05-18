// libp-sd: Security Descriptor construction + KACS SD syscall wrappers.
//
// Three things:
//
//   - Re-exports of the SD parse types from `peios-uapi` (so consumers
//     have one place to `use` from).
//   - `WellKnownSid` — a typed enum over the well-known SIDs, with
//     `matches` / `to_sid` / `from_sid` / `label`.
//   - Fluent builders (`SdBuilder`, `AclBuilder`, `AceBuilder`) that
//     emit self-relative SECURITY_DESCRIPTOR / ACL / ACE wire bytes.
//   - `get_sd` / `set_sd` syscall wrappers.
//
// `no_std + alloc` by default; the `std` feature adds
// `From<Error> for std::io::Error`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod access_check;
mod build;
mod claims;
mod condition;
mod error;
mod inherit;
mod object_tree;
pub mod raw;
mod sd;
pub mod sddl;
mod wellknown;

pub use access_check::{AccessCheckRequest, AccessDecision, GenericMapping, NodeDecision};
pub use build::{AceBuilder, AclBuilder, SdBuilder};
pub use claims::{ClaimAttribute, ClaimValue};
pub use condition::{CompareOp, Condition, MemberOp, Operand};
pub use error::Error;
pub use inherit::{compute_inherited_aces, reinherit};
pub use object_tree::{ObjectTypeNode, encode_object_tree};
pub use sd::{SdTarget, SecurityInfo, get_sd, set_sd, strip_inherited_aces};
pub use sddl::{AclKind, ParsedAcl, SddlError};
pub use wellknown::WellKnownSid;

/// Re-exported SD parse types — the canonical shapes live in
/// `peios-uapi`; libp-sd does not wrap them.
pub use peios_uapi::sd::{Ace, AceIter, AceRef, Acl, SecurityDescriptor};
pub use peios_uapi::sid::{Sid, SidRef};

/// Re-exported SD constants for callers building/inspecting descriptors.
pub mod consts {
    pub use peios_uapi::sd::{
        ACCESS_DELETE, ACCESS_GENERIC_ALL, ACCESS_GENERIC_EXECUTE, ACCESS_GENERIC_READ,
        ACCESS_GENERIC_WRITE, ACCESS_READ_CONTROL, ACCESS_SYNCHRONIZE, ACCESS_WRITE_DAC,
        ACCESS_WRITE_OWNER, ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_INHERITED,
        ACE_FLAG_NO_PROPAGATE_INHERIT, ACE_FLAG_OBJECT_INHERIT, ACE_TYPE_ACCESS_ALLOWED,
        ACE_TYPE_ACCESS_DENIED, ACE_TYPE_SYSTEM_AUDIT, ACE_TYPE_SYSTEM_MANDATORY_LABEL,
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, SE_DACL_PRESENT, SE_DACL_PROTECTED,
        SE_SACL_PRESENT, SE_SACL_PROTECTED, SE_SELF_RELATIVE,
    };
}

/// Crate-local `Result<T, Error>` alias.
pub type Result<T> = core::result::Result<T, Error>;

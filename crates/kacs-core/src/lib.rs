//! KACS access control engine.
//!
//! Core security evaluation logic for the Peios kernel: AccessCheck,
//! Security Descriptors, tokens, SIDs, privileges, and the full
//! DACL/MIC/PIP/confinement/CAP pipeline.
//!
//! Compiled for two targets:
//! - **Userspace** (`cargo test`): standard allocator, 383 unit tests
//! - **Kernel** (`kbuild`): kernel allocator, linked into the KACS LSM
//!
//! `no_std + alloc`. Kernel-specific allocation handled by [`compat`].

#![no_std]

extern crate alloc;

/// Allocation compatibility layer (Vec, String, TryClone).
pub mod compat;
/// The AccessCheck pipeline (§11) — the core authorization decision.
pub mod access_check;
/// Access Control Entry types, parsing, and serialization (§2.4.4).
pub mod ace;
/// Access Control Lists — ordered collections of ACEs (§2.4.5).
pub mod acl;
/// SACL audit evaluation — determines what gets logged (§17).
pub mod audit;
/// Central Access Policies — organizational override rules (§11.18).
pub mod cap;
/// Conditional ACE expression evaluator — three-value logic (§11.17).
pub mod conditional;
/// Group entries — SID + attribute flags for token group membership.
pub mod group;
/// SD inheritance — computing child SDs from parent ACLs (§9.5).
pub mod inherit;
/// GUID type — 128-bit identifiers for object ACEs and DS rights.
pub mod guid;
/// LUID type — locally unique 64-bit identifiers for tokens/sessions.
pub mod luid;
/// Access mask constants and GenericMapping tables (§2.4.3).
pub mod mask;
/// Privilege bitmask and all 35+ privilege constants (§10).
pub mod privilege;
/// Security Descriptor parsing, building, and binary format (§2.4.6).
pub mod sd;
/// Security Identifier (SID) — hierarchical principal identifiers.
pub mod sid;
/// Token structure — per-thread identity with SIDs, privileges, claims.
pub mod token;
/// Well-known SID constructors (SYSTEM, Administrators, Everyone, etc.).
pub mod well_known;
/// Token specification wire format for kacs_create_token.
pub mod token_spec;

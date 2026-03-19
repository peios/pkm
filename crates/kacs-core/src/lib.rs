#![no_std]

extern crate alloc;

// KACS access control engine.
//
// This crate implements the core security evaluation logic: AccessCheck,
// Security Descriptor parsing/building, token structures, SID types,
// privilege logic, and the full DACL/MIC/PIP/confinement/CAP pipeline.
//
// Compiled for two targets:
//   - Userspace (cargo test): standard allocator, thousands of unit tests
//   - Kernel (kbuild): kernel allocator, linked into the KACS LSM module
//
// The crate is no_std + alloc. Kernel-specific code (RCU, printk) is
// gated behind #[cfg(feature = "kernel")].

pub mod ace;
pub mod group;
pub mod guid;
pub mod luid;
pub mod mask;
pub mod privilege;
pub mod sid;
pub mod token;
pub mod well_known;

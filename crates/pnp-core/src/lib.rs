//! PNP packet-layer semantic core.
//!
//! The pure rules engine of Peios Network Policy: fact snapshot in, verdict
//! and side effects out. No kernel dependencies, no I/O — the same code
//! compiles into the kernel (`feature = "kernel"`, staged by
//! `kernel/stage-rust-core.sh`) and under plain cargo, where the test suite
//! encodes every ratified law of the design (PEI-598, "PNP Rules — Packet
//! Layer Design").

#![cfg_attr(not(test), no_std)]
#![allow(unreachable_pub)]

#[cfg(not(feature = "kernel"))]
extern crate alloc;

/// The action language: parsing and representation.
pub mod action;
/// Match conditions: facts, operators, evaluation.
pub mod condition;
/// Shared error types.
pub mod error;
/// The evaluation algorithm.
pub mod eval;
/// Registry-shaped input -> validated forest.
pub mod ingest;
/// PKM-owned fallible allocation wrappers.
pub mod pkm_alloc;
/// The rule atom and forest.
pub mod rule;
/// The immutable fact snapshot.
pub mod snapshot;
/// Small string helpers over the fallible string type.
pub mod strutil;
/// Neutral registry value representation.
pub mod value;

/// Returns a stable value from the staged crate so kernel bring-up can prove
/// the real `pnp-core` module graph compiled and linked.
pub fn kernel_compile_probe() -> usize {
    action::MAX_PROMPT_CHAIN
}

pub use action::{parse_action, Action, Fallback, TagOp, Verdict, MAX_PROMPT_CHAIN};
pub use condition::{AddrPattern, CondKey, CondOp, Condition, FactFamily, FactId, IntPattern};
pub use error::{ActionParseError, AllocError, BuildError, LintKind, LintWarning};
pub use eval::{evaluate, Effect, EvalContext, Evaluation, VerdictCandidate};
pub use ingest::{build_forest, BuildOutput, RuleInput};
pub use rule::{Forest, Layer, Rule};
pub use snapshot::{tcp_flags, Direction, FlowState, Snapshot, TimeFacts};
pub use value::RegValue;

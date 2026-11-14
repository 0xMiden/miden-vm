//! Constraint compiler for independently authored native Miden AIR relations.
//!
//! Hand-written constraint definitions are captured once into an immutable
//! [`ir::CapturedProgram`]. Its owned symbolic assertions preserve authored operations
//! for Rust emission; its derived arithmetic [`ir::Graph`] serves ACE and algebraic analyses.
//! Target-specific backends live with their targets; the remaining backends live here.
//!
//! # Invariants
//!
//! 1. **Capture that feeds artifacts or oracle anchors consumes only hand-written definitions** — a
//!    generated artifact as capture input makes regeneration self-referential and severs the chain
//!    back to the source of truth. Capturing generated code is legitimate only as the subject under
//!    test (drift tests compare it against a hand-written capture).
//! 2. **IR node ids are internal.** Ids are deterministic (dense, in walk order) but not part of
//!    any artifact contract. Digest-visible ordering, such as ACE `DagBuilder` interning order, is
//!    owned by each backend.
//! 3. **Determinism.** The same AIR always produces the same captured program, and a backend
//!    always emits byte-identical output for the same program and backend options.
//!
//! Backend output is never trusted by inspection: each backend is validated
//! against the hand-written source by oracles living with its consumers.

pub mod backend;
pub mod ir;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

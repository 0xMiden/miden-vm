//! Constraint compiler for Plonky3-based Miden AIRs.
//!
//! Hand-written constraint definitions — plain Rust `eval` implementations, the
//! auditable source of truth — are captured symbolically into a hash-consed,
//! class-aware IR ([`ir::Graph`]). Analyses and code-generation backends consume
//! that graph. A backend with target-specific machinery lives with its target
//! (the ACE circuit backend in `miden-ace-codegen`); the rest live here.
//!
//! # Invariants
//!
//! 1. **Capture consumes only hand-written definitions.** Generated artifacts are never inputs to
//!    capture; otherwise regeneration is self-referential and the chain back to the source of truth
//!    is lost.
//! 2. **IR node ids are internal.** Ids are deterministic (dense, in walk order) but not part of
//!    any artifact contract. Digest-visible ordering, such as ACE `DagBuilder` interning order, is
//!    owned by each backend.
//! 3. **Determinism.** The same AIR always captures to the same graph, and a backend always emits
//!    byte-identical output for the same graph.
//!
//! Backend output is never trusted by inspection: each backend is validated
//! against the hand-written source by oracles living with its consumers.

pub mod backend;
pub mod ir;

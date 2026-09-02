//! Transcript chiplets.
//!
//! The commitment machinery that content-addresses the precompile transcript DAG. The [`nodes`]
//! module defines operation discriminants within registered node constructions. The [`eidos`]
//! module owns the transcript's native
//! 32-row [`EidosCompressionAir`](eidos::EidosCompressionAir), which proves the raw compression
//! used by the framed Eidos construction and emits the transcript's input/output relations
//! directly. The [`chunk`](crate::hash::chunk) chiplet drives it to content-commit hasher inputs;
//! the [`eval`] chiplet folds truthy bindings into the public transcript root.
//! Uint / group leaf + eval arms join as the language grows.

pub mod binding;
pub mod eidos;
pub mod eval;
pub mod nodes;

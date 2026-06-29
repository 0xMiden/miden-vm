//! Transcript chiplets.
//!
//! The commitment machinery that content-addresses the precompile
//! transcript DAG. The [`nodes`] registry pins the protocol's node
//! tags and version; the [`poseidon2`] permutation is the
//! transcript's own hash, which the [`chunk`](crate::hash::chunk)
//! chiplet drives to content-commit hasher inputs; the [`eval`]
//! chiplet folds truthy bindings into the public transcript root.
//! Uint / group leaf + eval arms join as the language grows.

pub mod binding;
pub mod deferred_tags;
pub mod eval;
pub mod nodes;
pub mod poseidon2;

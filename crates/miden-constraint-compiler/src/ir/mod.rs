//! The constraint IR: a hash-consed expression graph with structural identity,
//! plus the symbolic-capture frontend that builds it and analyses over it.
//!
//! Import capture functions, graph types, and [`op_counts`] from this module. Capture produces
//! a [`Graph`] and [`CapturedConstraints`] for code-generation backends; [`auxiliary`] analyzes
//! affine auxiliary identities over the same graph.

pub(crate) mod analyze;
pub mod auxiliary;
mod capture;
mod graph;

pub use analyze::{OpCounts, op_counts};
pub use capture::{CapturedConstraints, capture, capture_into, capture_into_with};
pub use graph::{Class, Graph, GraphBuilder, Leaf, Node, NodeId, OpKind};

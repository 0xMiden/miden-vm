//! The constraint IR: a hash-consed expression graph with structural identity,
//! plus the symbolic-capture frontend that builds it and analyses over it.

pub mod analyze;
pub mod auxiliary;
pub mod capture;
pub mod graph;

pub(crate) use analyze::ChallengeDependencies;
pub use analyze::{OpCounts, op_counts};
pub use capture::{
    CapturedConstraints, capture, capture_into, capture_into_with, capture_kernel_native_into,
    capture_native, capture_native_into, capture_native_into_with,
};
pub use graph::{Class, Graph, GraphBuilder, Leaf, Node, NodeId, OpKind};

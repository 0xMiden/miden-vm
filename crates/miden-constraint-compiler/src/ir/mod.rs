//! The constraint IR: a hash-consed expression graph with structural identity,
//! plus the symbolic-capture frontend that builds it and analyses over it.

pub mod analyze;
pub mod capture;
pub mod graph;

pub use analyze::{OpCounts, op_counts};
pub use capture::{CapturedConstraints, capture, capture_into};
pub use graph::{Class, Graph, GraphBuilder, Leaf, Node, NodeId, OpKind};

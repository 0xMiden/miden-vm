//! Owned authored expressions, their derived arithmetic graphs,
//! native symbolic capture, and algebraic analyses.

pub mod analyze;
pub mod auxiliary;
pub mod capture;
pub mod graph;
pub mod program;

pub use program::CapturedProgram;

pub use analyze::{OpCounts, op_counts};
pub use capture::{
    CapturedConstraints, capture_kernel_native_into, capture_native, capture_native_into,
    capture_native_into_with, capture_program_native_with_descriptor,
};
pub use graph::{Class, Graph, GraphBuilder, Leaf, Node, NodeId, OpKind};

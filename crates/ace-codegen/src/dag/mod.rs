//! DAG IR for ACE circuit generation.
//!
//! This module lowers captured AIR constraints (`miden-constraint-compiler` IR)
//! into a DAG that mirrors the verifier evaluation order: constraints are folded
//! with the composition challenge, divided by the vanishing polynomial, and then
//! compared against the recomposed quotient. Auxiliary/quotient openings are
//! provided as base coordinates and merged into extension elements inside the
//! DAG. The original symbolic-tree lowering remains, test-gated, as the
//! differential anchor (`lower`).

mod builder;
mod ir;
#[cfg(any(test, feature = "testing"))]
mod lower;
mod lower_ir;
mod periodic;

pub use builder::DagBuilder;
pub use ir::{AceDag, DagSnapshot, NodeId, NodeKind, PeriodicColumnData};
#[cfg(any(test, feature = "testing"))]
pub use lower::build_verifier_dag;
pub use lower_ir::build_verifier_dag_from_ir;

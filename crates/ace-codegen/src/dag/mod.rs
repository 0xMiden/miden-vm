//! DAG IR for ACE circuit generation.
//!
//! This module lowers symbolic AIR constraints into a DAG that matches the
//! verifier evaluation order: constraints are folded with the composition
//! challenge, divided by the vanishing polynomial, and then compared against
//! the recomposed quotient. Auxiliary/quotient openings are provided as base
//! coordinates and merged into extension elements inside the DAG.

mod builder;
mod ir;
mod lower;
#[cfg(any(test, feature = "testing"))]
mod lower_ir;

pub use builder::DagBuilder;
pub use ir::{AceDag, DagSnapshot, NodeId, NodeKind, PeriodicColumnData};
pub use lower::build_verifier_dag;
#[cfg(any(test, feature = "testing"))]
pub use lower_ir::build_verifier_dag_from_ir;

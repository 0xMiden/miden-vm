//! DAG IR for ACE circuit generation.
//!
//! This module lowers captured AIR constraints (`miden-constraint-compiler` IR)
//! into a DAG that mirrors the verifier evaluation order: constraints are folded
//! with the composition challenge, divided by the vanishing polynomial, and then
//! compared against the recomposed quotient. Auxiliary/quotient openings are
//! provided as base coordinates and merged into extension elements inside the
//! DAG. Authored source evaluation supplies the independent scalar reference.

mod builder;
mod ir;
mod lower_ir;
mod normalize;
mod periodic;

pub use builder::DagBuilder;
#[cfg(test)]
pub(crate) use ir::PeriodicColumn;
pub use ir::{AceDag, DagSnapshot, NodeId, NodeKind, PeriodicColumnData};
pub use lower_ir::build_verifier_dag_from_ir;
pub(crate) use normalize::normalize_dag;

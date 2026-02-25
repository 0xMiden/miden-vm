//! DAG IR for ACE circuit generation.
//!
//! This module lowers symbolic AIR constraints into a DAG that mirrors the
//! verifier evaluation order: constraints are folded with the composition
//! challenge, divided by the vanishing polynomial, and then compared against
//! the recomposed quotient. Auxiliary/quotient openings are provided as base
//! coordinates and merged into extension elements inside the DAG.

mod builder;
mod ir;
mod lower;

pub use builder::DagBuilder;
pub use ir::{AceDag, NodeId, NodeKind};
pub use lower::{build_periodic_data, build_verifier_dag};

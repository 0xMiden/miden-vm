//! ACE circuit codegen for Plonky3-based Miden AIRs.
//!
//! The pipeline is:
//! 1. Record AIR constraints with `RecordingAirBuilder`.
//! 2. Lower symbolic expressions into a DAG that mirrors verifier constraints evaluation.
//! 3. Emit an ACE circuit plus an `InputLayout` describing the MASM ACE-READ section order.
//!
//! Quick start:
//! ```ignore
//! use miden_ace_codegen::{AceConfig, LayoutKind, build_ace_circuit_for_air};
//! use miden_air::ProcessorAir;
//! use miden_core::{Felt, field::QuadFelt};
//!
//! let air = ProcessorAir::default();
//! let config = AceConfig { num_quotient_chunks: 8, num_vlpi_groups: 1, layout: LayoutKind::Masm };
//! let circuit = build_ace_circuit_for_air::<_, Felt, QuadFelt>(&air, config)?;
//! ```
//!
//! Module map (data flow):
//! - `pipeline`: public entry points that orchestrate layout + DAG + circuit emission.
//! - `builder`: AIR recorder that captures symbolic constraints.
//! - `dag`: verifier-style DAG IR and lowering helpers.
//! - `circuit`: off-VM circuit representation (inputs/constants/ops/root).
//! - `layout`: READ-section layout and index mapping.
//! - `encode`: ACE stream encoding + padding rules.
//! - `randomness`: challenge input planning for layouts + DAG lowering.
//! - `quotient`: barycentric quotient recomposition helpers (used by DAG + tests).

// Symbolic types (Entry, SymVar, SymExpr).
mod symbolic;

// Core IR and lowering.
mod builder;
mod circuit;
mod dag;

// Input layout and encoding.
mod encode;
mod layout;
mod quotient;
mod randomness;

// High-level orchestration.
mod pipeline;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

/// Extension field degree (quadratic extension for Miden VM).
pub const EXT_DEGREE: usize = 2;

/// Errors returned by ACE codegen.
#[derive(Debug, thiserror::Error)]
pub enum AceError {
    #[error("invalid input length: expected {expected}, got {got}")]
    InvalidInputLength { expected: usize, got: usize },
    #[error("invalid input layout: {message}")]
    InvalidInputLayout { message: String },
}

pub use crate::{
    circuit::{AceCircuit, emit_circuit},
    dag::{AceDag, DagBuilder, NodeId},
    layout::{InputKey, InputLayout},
    pipeline::{
        AceArtifacts, AceConfig, LayoutKind, build_ace_circuit_for_air, build_ace_dag_for_air,
    },
};

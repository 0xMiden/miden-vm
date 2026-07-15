//! High-level ACE codegen pipeline helpers.
//!
//! This module ties together the major layers:
//! - build a verifier-style DAG from AIR constraints,
//! - choose a READ layout for inputs,
//! - emit a circuit that matches verifier evaluation.

use miden_constraint_compiler::ir::capture;
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::stark::air::LiftedAir;

use crate::{
    AceError,
    circuit::{AceCircuit, emit_circuit},
    dag::{AceDag, PeriodicColumnData, build_verifier_dag_from_ir},
    layout::{InputCounts, InputLayout},
};

/// Layout strategy for arranging ACE inputs.
#[derive(Debug, Clone, Copy)]
pub enum LayoutKind {
    /// Minimal layout used for off-VM evaluation.
    Native,
    /// MASM-aligned layout used by the recursive verifier.
    Masm,
}

/// Configuration for building an ACE DAG and its input layout.
#[derive(Debug, Clone, Copy)]
pub struct AceConfig {
    /// Number of quotient chunks used by the AIR.
    pub num_quotient_chunks: usize,
    /// Layout policy.
    pub layout: LayoutKind,
    /// Number of AIRs represented by the circuit layout.
    ///
    /// `1` builds the plain single-AIR layout. Values greater than one reserve the extra
    /// stark-var slots needed by a caller-owned multi-AIR composition circuit.
    pub num_airs: usize,
}

/// Output of the ACE codegen pipeline.
#[derive(Debug)]
pub struct AceArtifacts<EF> {
    /// Input layout describing the READ section order.
    pub layout: InputLayout,
    /// DAG that matches verifier evaluation.
    pub dag: AceDag<EF>,
}

/// Build a verifier-equivalent ACE circuit for the provided AIR.
///
/// This builds the constraint-evaluation DAG, validates layout invariants, and
/// emits the off-VM circuit representation. The circuit performs the constraint
/// evaluation check at the out-of-domain point z.
///
/// The constraints are captured from `air.eval`: callers producing production
/// artifacts must pass an AIR whose `eval` routes to the hand-written
/// definitions (e.g. `HandwrittenMidenAir`).
pub fn build_ace_circuit_for_air<A>(
    air: &A,
    config: AceConfig,
) -> Result<AceCircuit<QuadFelt>, AceError>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let artifacts = build_ace_dag_for_air(air, config)?;
    emit_circuit(&artifacts.dag, artifacts.layout)
}

/// Build a verifier-equivalent DAG and layout for the provided AIR.
///
/// See [`build_ace_circuit_for_air`] for the capture invariant on `air`.
pub fn build_ace_dag_for_air<A>(
    air: &A,
    config: AceConfig,
) -> Result<AceArtifacts<QuadFelt>, AceError>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    if config.num_airs == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "num_airs must be at least 1".into(),
        });
    }

    let periodic_columns = air.periodic_columns();
    let counts = input_counts_for_air(air, config)?;
    let layout = match (config.layout, config.num_airs >= 2) {
        (LayoutKind::Native, false) => InputLayout::new(counts),
        (LayoutKind::Masm, false) => InputLayout::new_masm(counts),
        (LayoutKind::Native, true) => InputLayout::new_multi_air(counts, config.num_airs),
        (LayoutKind::Masm, true) => InputLayout::new_masm_multi_air(counts, config.num_airs),
    };
    layout.validate();

    let (graph, constraints) = capture(air);
    let periodic_data = (!periodic_columns.is_empty())
        .then(|| PeriodicColumnData::from_periodic_columns::<Felt>(periodic_columns.to_vec()));
    let dag = build_verifier_dag_from_ir(&graph, &constraints, &layout, periodic_data.as_ref());

    Ok(AceArtifacts { layout, dag })
}

fn input_counts_for_air<A>(air: &A, config: AceConfig) -> Result<InputCounts, AceError>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    if config.num_quotient_chunks == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "num_quotient_chunks must be > 0".into(),
        });
    }
    if air.preprocessed_trace().is_some() {
        return Err(AceError::InvalidInputLayout {
            message: "preprocessed trace inputs are not supported".into(),
        });
    }

    let num_randomness = air.num_randomness();
    if num_randomness != 2 {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "AIR must declare exactly 2 randomness challenges (alpha, beta), got {num_randomness}"
            ),
        });
    }

    Ok(InputCounts {
        width: air.width(),
        aux_width: air.aux_width(),
        num_aux_boundary: air.num_aux_values(),
        num_public: air.num_public_values(),
        num_randomness,
        num_quotient_chunks: config.num_quotient_chunks,
    })
}

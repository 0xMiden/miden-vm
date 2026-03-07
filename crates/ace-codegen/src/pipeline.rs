//! High-level ACE codegen pipeline helpers.
//!
//! This module ties together the major layers:
//! - build a verifier-style DAG from AIR constraints,
//! - choose a READ layout for inputs,
//! - emit a circuit that mirrors verifier evaluation.

use miden_crypto::stark::{
    air::LiftedAir,
    field::{ExtensionField, Field, TwoAdicField},
};

use crate::{
    AceError,
    builder::RecordingAirBuilder,
    circuit::{AceCircuit, emit_circuit},
    dag::{AceDag, PeriodicColumnData, build_verifier_dag},
    layout::{InputCounts, InputLayout},
};

/// Layout strategy for arranging ACE inputs.
///
/// - `Native`: minimal, no alignment/padding; useful for native (off-VM) evaluation.
/// - `Masm`: matches the recursive verifier READ layout (alignment, padding, and randomness
///   ordering).
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
    /// Number of auxiliary inputs reserved in the stark-vars block.
    pub num_aux_inputs: usize,
    /// Layout policy (Native vs Masm).
    pub layout: LayoutKind,
}

/// Output of the ACE codegen pipeline (layout + DAG).
#[derive(Debug)]
pub(crate) struct AceArtifacts<EF> {
    /// Input layout describing the READ section order.
    pub layout: InputLayout,
    /// DAG that mirrors the verifier evaluation.
    pub dag: AceDag<EF>,
}

/// Build a verifier-equivalent ACE circuit for the provided AIR.
///
/// This is the highest-level entry point: it builds the DAG, validates layout
/// invariants, and emits the off-VM circuit representation.
pub fn build_ace_circuit_for_air<A, F, EF>(
    air: &A,
    config: AceConfig,
) -> Result<AceCircuit<EF>, AceError>
where
    A: LiftedAir<F, EF>,
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    let artifacts = build_ace_dag_for_air::<A, F, EF>(air, config)?;
    emit_circuit(&artifacts.dag, artifacts.layout)
}

/// Build the input layout for the provided AIR.
///
/// The returned `InputLayout` is validated and ready for input assembly.
pub fn build_layout_for_air<A, F, EF>(air: &A, config: AceConfig) -> InputLayout
where
    A: LiftedAir<F, EF>,
    F: Field,
    EF: ExtensionField<F>,
{
    let num_periodic = air.periodic_columns().len();
    let counts = input_counts_for_air::<A, F, EF>(air, config, num_periodic);
    let layout = match config.layout {
        LayoutKind::Native => InputLayout::new(counts),
        LayoutKind::Masm => InputLayout::new_masm(counts),
    };
    layout.validate();
    layout
}

/// Build a verifier-equivalent DAG and layout for the provided AIR.
///
/// This is useful when you need the DAG for off-VM checks and want to
/// assemble inputs separately.
pub(crate) fn build_ace_dag_for_air<A, F, EF>(
    air: &A,
    config: AceConfig,
) -> Result<AceArtifacts<EF>, AceError>
where
    A: LiftedAir<F, EF>,
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    let periodic_columns = air.periodic_columns();
    let counts = input_counts_for_air::<A, F, EF>(air, config, periodic_columns.len());
    let layout = match config.layout {
        LayoutKind::Native => InputLayout::new(counts),
        LayoutKind::Masm => InputLayout::new_masm(counts),
    };
    layout.validate();
    let mut builder = RecordingAirBuilder::<F, EF>::new(
        0,
        counts.width,
        counts.aux_width,
        counts.num_randomness,
        counts.num_public,
        counts.num_periodic,
        air.num_aux_values(),
    );
    air.eval(&mut builder);
    let periodic_data = (!periodic_columns.is_empty())
        .then(|| PeriodicColumnData::from_periodic_columns::<F>(periodic_columns.to_vec()));
    let dag = build_verifier_dag::<F, EF>(builder.constraints(), &layout, periodic_data.as_ref());

    Ok(AceArtifacts { layout, dag })
}

fn input_counts_for_air<A, F, EF>(air: &A, config: AceConfig, num_periodic: usize) -> InputCounts
where
    A: LiftedAir<F, EF>,
    F: Field,
    EF: ExtensionField<F>,
{
    assert!(config.num_quotient_chunks > 0, "num_quotient_chunks must be > 0");
    assert!(
        air.preprocessed_trace().is_none(),
        "preprocessed trace inputs are not supported"
    );

    let num_randomness = air.num_randomness();
    assert!(num_randomness > 0, "AIR must declare at least one randomness challenge");

    InputCounts {
        width: air.width(),
        aux_width: air.aux_width(),
        num_public: air.num_public_values(),
        num_randomness,
        num_periodic,
        num_aux_inputs: config.num_aux_inputs,
        num_quotient_chunks: config.num_quotient_chunks,
    }
}

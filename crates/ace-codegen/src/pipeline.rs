//! High-level ACE codegen pipeline helpers.
//!
//! This module ties together the major layers:
//! - build a verifier-style DAG from AIR constraints,
//! - choose a READ layout for inputs,
//! - emit a circuit that mirrors verifier evaluation.

use miden_crypto::{
    field::{Algebra, ExtensionField, Field, TwoAdicField},
    stark::air::{
        LiftedAir,
        symbolic::{AirLayout, SymbolicAirBuilder, SymbolicExpressionExt},
    },
};

use crate::{
    AceError,
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
    /// Number of variable-length public input groups.
    /// Each group produces one reduced extension field element.
    /// The layout policy handles alignment (e.g., MASM word-aligns each group to
    /// 2 EF slots; Native uses 1 EF slot per group).
    pub num_vlpi_groups: usize,
    /// Layout policy (Native vs Masm).
    pub layout: LayoutKind,
    /// When `true`, quotient chunk openings are extension-field elements (1 EF slot
    /// per chunk) and reconstruction uses power-sum: Q(z) = sum_j chunk_j * z^{j * segment_len}.
    /// When `false` (default), they are flattened to base-field coordinates
    /// (2 slots per chunk) and reconstruction uses barycentric Lagrange interpolation.
    pub quotient_extension: bool,
    /// Segment length for power-sum quotient reconstruction (only used when
    /// `quotient_extension = true`). Each quotient chunk polynomial has degree
    /// < segment_len.
    pub quotient_segment_len: usize,
}

/// Output of the ACE codegen pipeline (layout + DAG).
#[derive(Debug)]
pub struct AceArtifacts<EF> {
    /// Input layout describing the READ section order.
    pub layout: InputLayout,
    /// DAG that mirrors the verifier evaluation.
    pub dag: AceDag<EF>,
}

/// Build a verifier-equivalent ACE circuit for the provided AIR.
///
/// This builds the constraint-evaluation DAG, validates layout invariants, and
/// emits the off-VM circuit representation. The circuit performs the constraint
/// evaluation check at the out-of-domain point z.
pub fn build_ace_circuit_for_air<A, F, EF>(
    air: &A,
    config: AceConfig,
) -> Result<AceCircuit<EF>, AceError>
where
    A: LiftedAir<F, EF>,
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SymbolicExpressionExt<F, EF>: Algebra<EF>,
{
    let artifacts = build_ace_dag_for_air::<A, F, EF>(air, config)?;
    emit_circuit(&artifacts.dag, artifacts.layout)
}

/// Build a verifier-equivalent DAG and layout for the provided AIR.
pub fn build_ace_dag_for_air<A, F, EF>(
    air: &A,
    config: AceConfig,
) -> Result<AceArtifacts<EF>, AceError>
where
    A: LiftedAir<F, EF>,
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SymbolicExpressionExt<F, EF>: Algebra<EF>,
{
    let periodic_columns = air.periodic_columns();
    let counts = input_counts_for_air::<A, F, EF>(air, config, periodic_columns.len());
    let layout = match config.layout {
        LayoutKind::Native => InputLayout::new(counts),
        LayoutKind::Masm => InputLayout::new_masm(counts),
    };
    layout.validate();

    let air_layout = AirLayout {
        preprocessed_width: 0,
        main_width: counts.width,
        num_public_values: counts.num_public,
        permutation_width: counts.aux_width,
        num_permutation_challenges: counts.num_randomness,
        num_permutation_values: air.num_aux_values(),
        num_periodic_columns: counts.num_periodic,
    };
    let mut builder = SymbolicAirBuilder::<F, EF>::new(air_layout);
    air.eval(&mut builder);
    let constraint_layout = builder.constraint_layout();
    let base_constraints = builder.base_constraints();
    let ext_constraints = builder.extension_constraints();

    let periodic_data = (!periodic_columns.is_empty())
        .then(|| PeriodicColumnData::from_periodic_columns::<F>(periodic_columns.to_vec()));
    let dag = build_verifier_dag::<F, EF>(
        &base_constraints,
        &ext_constraints,
        &constraint_layout,
        &layout,
        periodic_data.as_ref(),
    );

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
    assert!(
        num_randomness == 2,
        "AIR must declare exactly 2 randomness challenges (alpha, beta), got {num_randomness}"
    );

    // Convert logical VLPI groups to EF slots based on layout policy.
    // MASM word-aligns each group (4 base felts = 2 EF slots per group).
    // Native uses 1 EF slot per group (no padding).
    let num_vlpi = match config.layout {
        LayoutKind::Masm => config.num_vlpi_groups * 2,
        LayoutKind::Native => config.num_vlpi_groups,
    };

    InputCounts {
        width: air.width(),
        aux_width: air.aux_width(),
        num_public: air.num_public_values(),
        num_vlpi,
        num_randomness,
        num_periodic,
        num_quotient_chunks: config.num_quotient_chunks,
        quotient_extension: config.quotient_extension,
        quotient_segment_len: config.quotient_segment_len,
    }
}

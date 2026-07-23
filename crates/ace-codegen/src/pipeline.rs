//! High-level ACE codegen pipeline helpers.
//!
//! This module ties together the major layers:
//! - build a verifier-style DAG from AIR constraints,
//! - choose a READ layout for inputs,
//! - emit a circuit that matches verifier evaluation.

use miden_crypto::{
    field::{Algebra, ExtensionField, Field, TwoAdicField},
    stark::air::{
        BaseAir, LiftedAir,
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
    if config.num_airs == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "num_airs must be at least 1".into(),
        });
    }

    let periodic_columns = air.periodic_columns();
    let shared_period = max_period(&periodic_columns);
    build_ace_dag_for_air_with_periodic_columns(air, config, periodic_columns, shared_period)
}

/// Build verifier-equivalent DAGs and layouts for the provided AIRs.
#[allow(dead_code)]
pub(crate) fn build_ace_dags_for_airs<A, F, EF>(
    airs: &[A],
    config: AceConfig,
) -> Result<Vec<AceArtifacts<EF>>, AceError>
where
    A: LiftedAir<F, EF>,
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SymbolicExpressionExt<F, EF>: Algebra<EF>,
{
    if config.num_airs == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "num_airs must be at least 1".into(),
        });
    }

    let periodic_columns_by_air: Vec<_> = airs.iter().map(BaseAir::periodic_columns).collect();
    let shared_period = periodic_columns_by_air
        .iter()
        .map(|columns| max_period(columns))
        .max()
        .unwrap_or(1);

    airs.iter()
        .zip(periodic_columns_by_air)
        .map(|(air, periodic_columns)| {
            build_ace_dag_for_air_with_periodic_columns(
                air,
                config,
                periodic_columns,
                shared_period,
            )
        })
        .collect()
}

fn build_ace_dag_for_air_with_periodic_columns<A, F, EF>(
    air: &A,
    config: AceConfig,
    periodic_columns: Vec<Vec<F>>,
    shared_period: usize,
) -> Result<AceArtifacts<EF>, AceError>
where
    A: LiftedAir<F, EF>,
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SymbolicExpressionExt<F, EF>: Algebra<EF>,
{
    let counts = input_counts_for_air::<A, F, EF>(air, config)?;
    let layout = match (config.layout, config.num_airs >= 2) {
        (LayoutKind::Native, false) => InputLayout::new(counts),
        (LayoutKind::Masm, false) => InputLayout::new_masm(counts),
        (LayoutKind::Native, true) => InputLayout::new_multi_air(counts, config.num_airs),
        (LayoutKind::Masm, true) => InputLayout::new_masm_multi_air(counts, config.num_airs),
    };
    layout.validate();

    let air_layout = AirLayout {
        preprocessed_width: counts.preprocessed_width,
        main_width: counts.width,
        num_public_values: counts.num_public,
        permutation_width: counts.aux_width,
        num_permutation_challenges: counts.num_randomness,
        num_permutation_values: air.num_aux_values(),
        num_periodic_columns: periodic_columns.len(),
    };
    let mut builder = SymbolicAirBuilder::<F, EF>::new(air_layout);
    air.eval(&mut builder);
    let constraint_layout = builder.constraint_layout();
    let base_constraints = builder.base_constraints();
    let ext_constraints = builder.extension_constraints();

    let periodic_data = (!periodic_columns.is_empty())
        .then(|| PeriodicColumnData::from_periodic_columns::<F>(periodic_columns));
    let dag = build_verifier_dag::<F, EF>(
        &base_constraints,
        &ext_constraints,
        &constraint_layout,
        &layout,
        periodic_data.as_ref(),
        shared_period,
    );

    Ok(AceArtifacts { layout, dag })
}

fn max_period<F>(periodic_columns: &[Vec<F>]) -> usize {
    periodic_columns.iter().map(Vec::len).max().unwrap_or(1)
}

fn input_counts_for_air<A, F, EF>(air: &A, config: AceConfig) -> Result<InputCounts, AceError>
where
    A: LiftedAir<F, EF>,
    F: Field,
    EF: ExtensionField<F>,
{
    if config.num_quotient_chunks == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "num_quotient_chunks must be > 0".into(),
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
        preprocessed_width: air.preprocessed_width(),
        width: air.width(),
        aux_width: air.aux_width(),
        num_aux_boundary: air.num_aux_values(),
        num_public: air.num_public_values(),
        num_randomness,
        num_quotient_chunks: config.num_quotient_chunks,
    })
}

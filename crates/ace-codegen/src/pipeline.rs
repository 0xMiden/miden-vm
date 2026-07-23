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
    AceError, EXT_DEGREE,
    circuit::{AceCircuit, emit_circuit},
    dag::{AceDag, DagBuilder, NodeId, NodeKind, PeriodicColumnData, build_verifier_dag},
    layout::{InputCounts, InputKey, InputLayout},
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

/// Build one ACE circuit for several AIR instances.
///
/// `airs` defines stable instance indices, while `proof_order` controls trace-region placement and
/// the beta-Horner fold. `trace_width_alignment` is the base-field alignment used for each AIR's
/// preprocessed, main, and auxiliary trace regions.
pub fn build_multi_air_ace_circuit<A, F, EF>(
    airs: &[A],
    proof_order: &[usize],
    config: AceConfig,
    trace_width_alignment: usize,
) -> Result<AceCircuit<EF>, AceError>
where
    A: LiftedAir<F, EF>,
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SymbolicExpressionExt<F, EF>: Algebra<EF>,
{
    let num_airs = airs.len();
    if num_airs == 0 || config.num_airs != num_airs {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "multi-AIR composition requires a nonempty airs slice and matching num_airs; got \
                 {} AIRs and num_airs {}",
                num_airs, config.num_airs
            ),
        });
    }

    let mut seen = vec![false; num_airs];
    if proof_order.len() != num_airs
        || proof_order
            .iter()
            .any(|&index| index >= num_airs || core::mem::replace(&mut seen[index], true))
    {
        return Err(AceError::InvalidInputLayout {
            message: format!("proof_order must be a permutation of 0..{num_airs}"),
        });
    }
    if trace_width_alignment == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "trace width alignment must be nonzero".into(),
        });
    }

    let sub_config = AceConfig { num_airs: 1, ..config };
    let artifacts = build_ace_dags_for_airs::<A, F, EF>(airs, sub_config)?;
    let shared = artifacts[0].layout.counts;
    if artifacts.iter().any(|air| air.layout.counts.num_public != shared.num_public) {
        return Err(AceError::InvalidInputLayout {
            message: "all AIRs must use the same public-value window".into(),
        });
    }

    let mut offsets = vec![TraceOffsets::default(); num_airs];
    let mut totals = TraceOffsets::default();
    for &air_index in proof_order {
        offsets[air_index] = totals;
        let counts = artifacts[air_index].layout.counts;
        totals.preprocessed += counts.preprocessed_width.next_multiple_of(trace_width_alignment);
        totals.main += counts.width.next_multiple_of(trace_width_alignment);
        let aligned_aux = (counts.aux_width * EXT_DEGREE).next_multiple_of(trace_width_alignment);
        if !aligned_aux.is_multiple_of(EXT_DEGREE) {
            return Err(AceError::InvalidInputLayout {
                message: "aligned auxiliary width must be divisible by the extension degree".into(),
            });
        }
        totals.aux += aligned_aux / EXT_DEGREE;
        totals.boundary += counts.num_aux_boundary;
    }

    let counts = InputCounts {
        preprocessed_width: totals.preprocessed,
        width: totals.main,
        aux_width: totals.aux,
        num_aux_boundary: totals.boundary,
        num_public: shared.num_public,
        num_randomness: shared.num_randomness,
        num_quotient_chunks: shared.num_quotient_chunks,
    };
    let layout = match config.layout {
        LayoutKind::Native => InputLayout::new_multi_air(counts, num_airs),
        LayoutKind::Masm => InputLayout::new_masm_multi_air(counts, num_airs),
    };

    // Re-emit in stable instance order; only placement and the final fold follow proof order.
    let mut builder = DagBuilder::new();
    let mut roots = Vec::with_capacity(num_airs);
    for (air_index, artifacts) in artifacts.iter().enumerate() {
        roots.push(reemit_air_root(&mut builder, &artifacts.dag, air_index, offsets[air_index]));
    }
    let quotient_binding = roots[0].1;
    if roots.iter().any(|&(_, binding)| binding != quotient_binding) {
        return Err(AceError::InvalidInputLayout {
            message: "all AIR quotient bindings must use the same q*v node".into(),
        });
    }

    let beta = builder.input(InputKey::MultiAirFoldBeta);
    let mut ordered = proof_order.iter().map(|&index| roots[index].0);
    let mut accumulator = ordered.next().expect("multi-AIR composition is nonempty");
    for next in ordered {
        let scaled = builder.mul(accumulator, beta);
        accumulator = builder.add(scaled, next);
    }

    // The encoded ACE circuit treats the final operation as its root.
    let root = builder.sub(accumulator, quotient_binding);
    let mut dag = builder.build(root);
    dag.compact();
    emit_circuit(&dag, layout)
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

/// Build verifier-equivalent DAGs against one shared periodic-column basis.
fn build_ace_dags_for_airs<A, F, EF>(
    airs: &[A],
    config: AceConfig,
) -> Result<Vec<AceArtifacts<EF>>, AceError>
where
    A: LiftedAir<F, EF>,
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SymbolicExpressionExt<F, EF>: Algebra<EF>,
{
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

#[derive(Clone, Copy, Default)]
struct TraceOffsets {
    preprocessed: usize,
    main: usize,
    aux: usize,
    boundary: usize,
}

fn reemit_air_root<EF: Field>(
    builder: &mut DagBuilder<EF>,
    source: &AceDag<EF>,
    air_index: usize,
    offsets: TraceOffsets,
) -> (NodeId, NodeId) {
    debug_assert_eq!(source.root().index() + 1, source.nodes.len());
    let NodeKind::Sub(accumulator, quotient_binding) = source.nodes[source.root().index()] else {
        unreachable!("build_verifier_dag always emits an accumulator - q*v root")
    };

    let mut translated = Vec::with_capacity(source.nodes.len() - 1);
    for node in &source.nodes[..source.root().index()] {
        let id = match *node {
            NodeKind::Input(key) => {
                let key = match key {
                    InputKey::Preprocessed { offset, index } => InputKey::Preprocessed {
                        offset,
                        index: index + offsets.preprocessed,
                    },
                    InputKey::Main { offset, index } => {
                        InputKey::Main { offset, index: index + offsets.main }
                    },
                    InputKey::AuxCoord { offset, index, coord } => InputKey::AuxCoord {
                        offset,
                        index: index + offsets.aux,
                        coord,
                    },
                    InputKey::AuxBusBoundary(index) => {
                        InputKey::AuxBusBoundary(index + offsets.boundary)
                    },
                    InputKey::IsFirst => InputKey::IsFirstAir(air_index),
                    InputKey::IsLast => InputKey::IsLastAir(air_index),
                    InputKey::IsTransition => InputKey::IsTransitionAir(air_index),
                    other => other,
                };
                builder.input(key)
            },
            NodeKind::Constant(value) => builder.constant(value),
            NodeKind::Add(a, b) => builder.add(translated[a.index()], translated[b.index()]),
            NodeKind::Sub(a, b) => builder.sub(translated[a.index()], translated[b.index()]),
            NodeKind::Mul(a, b) => builder.mul(translated[a.index()], translated[b.index()]),
            NodeKind::Neg(a) => builder.neg(translated[a.index()]),
        };
        translated.push(id);
    }

    (translated[accumulator.index()], translated[quotient_binding.index()])
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

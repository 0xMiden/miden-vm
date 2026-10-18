//! High-level ACE codegen pipeline helpers.
//!
//! This module ties together the major layers:
//! - capture AIR constraints into the compiler IR,
//! - build a verifier-style DAG from that IR,
//! - choose a READ layout for inputs,
//! - emit a circuit that matches verifier evaluation.

use miden_constraint_compiler::ir::capture;
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::stark::air::{BaseAir, LiftedAir};

use crate::{
    EXT_DEGREE,
    circuit::{AceCircuit, emit_circuit},
    dag::{
        AceDag, DagBuilder, NodeId, NodeKind, PeriodicColumnData, build_verifier_dag_from_ir,
        normalize_dag,
    },
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
/// Invalid compiler configuration or inconsistent authored AIR/layout metadata panics.
pub fn build_ace_circuit_for_air<A>(air: &A, config: AceConfig) -> AceCircuit<QuadFelt>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let artifacts = build_ace_dag_for_air(air, config);
    emit_circuit(&artifacts.dag, artifacts.layout)
}

/// Build a verifier-equivalent DAG and layout for the provided AIR.
///
/// See [`build_ace_circuit_for_air`] for the capture invariant on `air`.
pub fn build_ace_dag_for_air<A>(air: &A, config: AceConfig) -> AceArtifacts<QuadFelt>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let periodic_columns = air.periodic_columns();
    let shared_period = max_period(&periodic_columns);
    build_ace_dag_for_air_with_periodic_columns(
        air,
        config,
        periodic_columns.into_owned(),
        shared_period,
    )
}

/// Build verifier-equivalent DAGs against one shared periodic-column basis.
fn build_ace_dags_for_airs<A>(airs: &[A], config: AceConfig) -> Vec<AceArtifacts<QuadFelt>>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let periodic_columns_by_air: Vec<_> =
        airs.iter().map(BaseAir::<Felt>::periodic_columns).collect();
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
                periodic_columns.into_owned(),
                shared_period,
            )
        })
        .collect()
}

fn build_ace_dag_for_air_with_periodic_columns<A>(
    air: &A,
    config: AceConfig,
    periodic_columns: Vec<Vec<Felt>>,
    shared_period: usize,
) -> AceArtifacts<QuadFelt>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let counts = input_counts_for_air(air, config);
    let layout = match config.layout {
        LayoutKind::Native => InputLayout::new(counts),
        LayoutKind::Masm => InputLayout::new_masm(counts),
    };
    layout.validate();

    let (graph, constraints) = capture(air);
    let periodic_data = (!periodic_columns.is_empty())
        .then(|| PeriodicColumnData::from_periodic_columns::<Felt>(periodic_columns));
    let dag = build_verifier_dag_from_ir(
        &graph,
        &constraints,
        &layout,
        periodic_data.as_ref(),
        shared_period,
    );

    AceArtifacts { layout, dag }
}

fn max_period<F>(periodic_columns: &[Vec<F>]) -> usize {
    periodic_columns.iter().map(Vec::len).max().unwrap_or(1)
}

#[derive(Clone, Copy, Debug, Default)]
struct TraceOffsets {
    preprocessed: usize,
    main: usize,
    aux: usize,
    boundary: usize,
}

fn reemit_air_root(
    builder: &mut DagBuilder<QuadFelt>,
    source: &AceDag<QuadFelt>,
    air_index: usize,
    offsets: TraceOffsets,
) -> (NodeId, NodeId) {
    assert_eq!(source.root().index() + 1, source.nodes.len(), "verifier root must be final");
    // The right operand is `Mul(q, v)` over quotient inputs, which AIR constraints cannot
    // reference. It is therefore neither equal nor structurally related to the accumulator,
    // so none of `DagBuilder::sub`'s simplifications can remove the final `Sub` node.
    let NodeKind::Sub(accumulator, quotient_binding) = source.nodes[source.root().index()] else {
        unreachable!("verifier DAGs always emit an accumulator - q*v root")
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

fn input_counts_for_air<A>(air: &A, config: AceConfig) -> InputCounts
where
    A: LiftedAir<Felt, QuadFelt>,
{
    assert!(config.num_quotient_chunks > 0, "num_quotient_chunks must be > 0");
    let num_randomness = air.num_randomness();
    assert_eq!(
        num_randomness, 2,
        "AIR must declare exactly 2 randomness challenges (alpha, beta)"
    );

    InputCounts {
        preprocessed_width: air.preprocessed_width(),
        width: air.width(),
        aux_width: air.aux_width(),
        num_aux_boundary: air.num_aux_values(),
        num_public: air.num_public_values(),
        num_randomness,
        num_quotient_chunks: config.num_quotient_chunks,
    }
}

/// Builds one order-invariant ACE circuit for a nonempty AIR set.
///
/// Each AIR reads trace inputs at its canonical instance offset and its fold coefficient from
/// [`InputKey::MultiAirFoldCoeff`]. The caller must scatter proof-ordered trace segments to those
/// offsets and stage `beta^(N - 1 - k)` for the AIR at proof position `k`, where `N = airs.len()`.
/// Trace and committed quotient widths are padded to `trace_width_alignment` base-field elements.
/// Quotient recomposition reads only the configured logical chunks.
/// Empty AIR sets, invalid alignment, overflow or inconsistent compiler metadata panic.
pub fn build_canonical_multi_air_ace_circuit<A>(
    airs: &[A],
    config: AceConfig,
    trace_width_alignment: usize,
) -> AceCircuit<QuadFelt>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let num_airs = airs.len();
    assert!(num_airs > 0, "multi-AIR composition requires a nonempty AIR set");
    assert!(trace_width_alignment > 0, "trace width alignment must be nonzero");

    let artifacts = build_ace_dags_for_airs(airs, config);
    let shared = artifacts[0].layout.counts;
    assert!(
        artifacts.iter().all(|air| air.layout.counts.num_public == shared.num_public),
        "all AIRs must use the same public-value window"
    );

    let mut offsets = Vec::with_capacity(num_airs);
    let mut totals = TraceOffsets::default();
    for artifact in &artifacts {
        let counts = artifact.layout.counts;
        // Aux widths count EF columns; alignment is in base coordinates.
        let aligned_aux = counts
            .aux_width
            .checked_mul(EXT_DEGREE)
            .and_then(|width| width.checked_next_multiple_of(trace_width_alignment))
            .expect("aligned auxiliary width overflows");
        assert!(
            aligned_aux.is_multiple_of(EXT_DEGREE),
            "aligned auxiliary width must be divisible by the extension degree"
        );
        offsets.push(totals);
        let add_aligned = |total: usize, width: usize| {
            width
                .checked_next_multiple_of(trace_width_alignment)
                .and_then(|width| total.checked_add(width))
                .expect("aligned trace width overflows")
        };
        totals.preprocessed = add_aligned(totals.preprocessed, counts.preprocessed_width);
        totals.main = add_aligned(totals.main, counts.width);
        totals.aux = totals
            .aux
            .checked_add(aligned_aux / EXT_DEGREE)
            .expect("aggregate auxiliary width overflows");
        totals.boundary = totals
            .boundary
            .checked_add(counts.num_aux_boundary)
            .expect("aggregate boundary width overflows");
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
        LayoutKind::Native => InputLayout::new_multi_air_with_quotient_alignment(
            counts,
            num_airs,
            trace_width_alignment,
        ),
        LayoutKind::Masm => InputLayout::new_masm_multi_air_with_quotient_alignment(
            counts,
            num_airs,
            trace_width_alignment,
        ),
    };

    // Re-emit in stable instance order, each AIR placed at its canonical trace offset and scaled
    // by the fold coefficient it reads from its own slot.
    let mut builder = DagBuilder::<QuadFelt>::new();
    let mut roots = Vec::with_capacity(num_airs);
    for (air_index, artifacts) in artifacts.iter().enumerate() {
        roots.push(reemit_air_root(&mut builder, &artifacts.dag, air_index, offsets[air_index]));
    }
    let quotient_binding = roots[0].1;
    assert!(
        roots.iter().all(|&(_, binding)| binding == quotient_binding),
        "all AIR quotient bindings must use the same q*v node"
    );

    let mut accumulator = None;
    for (air_index, &(acc, _)) in roots.iter().enumerate() {
        let coeff = builder.input(InputKey::MultiAirFoldCoeff(air_index));
        let scaled = builder.mul(acc, coeff);
        accumulator = Some(match accumulator {
            None => scaled,
            Some(previous) => builder.add(previous, scaled),
        });
    }
    let accumulator = accumulator.expect("multi-AIR composition is nonempty");

    // The encoded ACE circuit treats the final operation as its root.
    let root = builder.sub(accumulator, quotient_binding);
    let mut dag = builder.build(root);
    dag.compact();
    let dag = normalize_dag(dag);

    emit_circuit(&dag, layout)
}

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
    proof_order::MAX_ORDER_AIRS,
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
    /// Number of AIRs reserved by the single-AIR builder's layout.
    /// Multi-AIR builders derive this count from their AIR slice.
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
pub fn build_ace_circuit_for_air<A>(air: &A, config: AceConfig) -> AceCircuit<QuadFelt>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let artifacts = build_ace_dag_for_air(air, config);
    emit_circuit(&artifacts.dag, artifacts.layout)
}

/// Build one ACE circuit for several AIR instances.
///
/// `airs` defines stable instance indices, while `proof_order` controls trace-region placement and
/// the beta-Horner fold. `trace_width_alignment` is the base-field alignment used for each AIR's
/// preprocessed, main, and auxiliary trace regions.
///
/// As with [`build_ace_circuit_for_air`], each AIR's `eval` must route to the hand-written
/// definitions when this function produces a committed artifact.
pub fn build_multi_air_ace_circuit<A>(
    airs: &[A],
    proof_order: &[usize],
    config: AceConfig,
    trace_width_alignment: usize,
) -> AceCircuit<QuadFelt>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let num_airs = airs.len();
    let (artifacts, blocks) = build_multi_air_artifacts(airs, config, trace_width_alignment);

    let mut seen = vec![false; num_airs];
    assert!(
        proof_order.len() == num_airs
            && proof_order
                .iter()
                .all(|&index| index < num_airs && !core::mem::replace(&mut seen[index], true)),
        "proof_order must be a permutation of 0..{num_airs}"
    );
    let (offsets, totals) = accumulate_block_offsets(&blocks, proof_order.iter().copied());

    let counts = InputCounts {
        preprocessed_width: totals.preprocessed,
        width: totals.main,
        aux_width: totals.aux,
        num_aux_boundary: totals.boundary,
        ..artifacts[0].layout.counts
    };
    let layout = match config.layout {
        LayoutKind::Native => InputLayout::new_multi_air(counts, num_airs),
        LayoutKind::Masm => InputLayout::new_masm_multi_air(counts, num_airs),
    };

    // Re-emit in stable instance order; only placement and the final fold follow proof order.
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
    let dag = normalize_dag(dag);
    emit_circuit(&dag, layout)
}

/// Build a verifier-equivalent DAG and layout for the provided AIR.
///
/// See [`build_ace_circuit_for_air`] for the capture invariant on `air`.
pub fn build_ace_dag_for_air<A>(air: &A, config: AceConfig) -> AceArtifacts<QuadFelt>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    assert_ne!(config.num_airs, 0, "num_airs must be at least 1");

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
    let layout = match (config.layout, config.num_airs >= 2) {
        (LayoutKind::Native, false) => InputLayout::new(counts),
        (LayoutKind::Masm, false) => InputLayout::new_masm(counts),
        (LayoutKind::Native, true) => InputLayout::new_multi_air(counts, config.num_airs),
        (LayoutKind::Masm, true) => InputLayout::new_masm_multi_air(counts, config.num_airs),
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
    assert_eq!(source.root().index() + 1, source.nodes.len(), "verifier DAG root must be last");
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
    assert_ne!(config.num_quotient_chunks, 0, "num_quotient_chunks must be > 0");
    let num_randomness = air.num_randomness();
    assert_eq!(
        num_randomness, 2,
        "AIR must declare exactly 2 randomness challenges (alpha, beta), got {num_randomness}"
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

/// Canonical (order-invariant) variant of [`build_multi_air_ace_circuit`].
///
/// Every AIR's trace regions sit at its canonical (instance-order) offset, and every AIR reads
/// its fold coefficient straight from [`InputKey::MultiAirFoldCoeff`] instead of receiving it
/// from a proof-order Horner chain. The resulting circuit is therefore the same for every proof
/// order: the caller is responsible for landing each proof-ordered trace segment on its canonical
/// address and for staging the AIR at proof position `k` with the coefficient `beta^(N - 1 - k)`.
///
/// Unlike [`build_multi_air_ace_circuit`] there is no per-order construction: this returns one
/// complete, ready-to-encode [`AceCircuit`] serving every proof order.
pub fn build_canonical_multi_air_ace_circuit<A>(
    airs: &[A],
    config: AceConfig,
    trace_width_alignment: usize,
) -> AceCircuit<QuadFelt>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let num_airs = airs.len();
    let (artifacts, blocks) = build_multi_air_artifacts(airs, config, trace_width_alignment);
    let (offsets, totals) = accumulate_block_offsets(&blocks, 0..num_airs);

    let counts = InputCounts {
        preprocessed_width: totals.preprocessed,
        width: totals.main,
        aux_width: totals.aux,
        num_aux_boundary: totals.boundary,
        ..artifacts[0].layout.counts
    };
    let layout = match config.layout {
        LayoutKind::Native => InputLayout::new_canonical_multi_air(counts, num_airs),
        LayoutKind::Masm => InputLayout::new_masm_canonical_multi_air(counts, num_airs),
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

/// Build each AIR against the shared periodic basis and derive its aligned trace blocks.
fn build_multi_air_artifacts<A>(
    airs: &[A],
    config: AceConfig,
    trace_width_alignment: usize,
) -> (Vec<AceArtifacts<QuadFelt>>, Vec<TraceOffsets>)
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let num_airs = airs.len();
    assert!(
        (1..=MAX_ORDER_AIRS).contains(&num_airs),
        "multi-AIR composition requires 1..={MAX_ORDER_AIRS} AIRs, got {num_airs}"
    );
    assert_ne!(trace_width_alignment, 0, "trace width alignment must be nonzero");
    let artifacts = build_ace_dags_for_airs(airs, AceConfig { num_airs: 1, ..config });
    let num_public = artifacts[0].layout.counts.num_public;
    assert!(
        artifacts.iter().all(|air| air.layout.counts.num_public == num_public),
        "all AIRs must use the same public-value window"
    );

    let blocks = artifacts
        .iter()
        .map(|artifact| {
            let counts = artifact.layout.counts;
            let aligned_aux = counts
                .aux_width
                .checked_mul(EXT_DEGREE)
                .and_then(|width| width.checked_next_multiple_of(trace_width_alignment))
                .expect("aligned auxiliary width overflows");
            assert!(
                aligned_aux.is_multiple_of(EXT_DEGREE),
                "aligned auxiliary width must be divisible by the extension degree"
            );
            TraceOffsets {
                preprocessed: counts
                    .preprocessed_width
                    .checked_next_multiple_of(trace_width_alignment)
                    .expect("aligned preprocessed width overflows"),
                main: counts
                    .width
                    .checked_next_multiple_of(trace_width_alignment)
                    .expect("aligned main width overflows"),
                aux: aligned_aux / EXT_DEGREE,
                boundary: counts.num_aux_boundary,
            }
        })
        .collect();
    (artifacts, blocks)
}

/// Prefix-sum the per-AIR block widths in `order`; the result is indexed by instance index.
fn accumulate_block_offsets(
    blocks: &[TraceOffsets],
    order: impl IntoIterator<Item = usize>,
) -> (Vec<TraceOffsets>, TraceOffsets) {
    let mut offsets = vec![TraceOffsets::default(); blocks.len()];
    let mut totals = TraceOffsets::default();
    for air_index in order {
        offsets[air_index] = totals;
        let block = blocks[air_index];
        totals.preprocessed = totals
            .preprocessed
            .checked_add(block.preprocessed)
            .expect("total preprocessed width overflows");
        totals.main = totals.main.checked_add(block.main).expect("total main width overflows");
        totals.aux = totals.aux.checked_add(block.aux).expect("total aux width overflows");
        totals.boundary = totals
            .boundary
            .checked_add(block.boundary)
            .expect("total boundary width overflows");
    }
    (offsets, totals)
}

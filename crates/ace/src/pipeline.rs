//! High-level ACE codegen pipeline helpers.
//!
//! This module ties together the major layers:
//! - capture AIR constraints into the compiler IR,
//! - build a verifier-style DAG from that IR,
//! - choose a READ layout for inputs,
//! - emit a circuit that matches verifier evaluation.

use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::LiftedAir;

use crate::{
    AceError, CapturedAir, CompiledRelation, EXT_DEGREE,
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
/// definitions (e.g. `miden_air_definitions::vm::MidenAir`).
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
    let air = CapturedAir::new(air)?;
    let shared_period = air.max_periodic_length.max(1);
    build_ace_dag_from_capture(&air, config, shared_period)
}

fn build_ace_dag_from_capture(
    air: &CapturedAir,
    config: AceConfig,
    shared_period: usize,
) -> Result<AceArtifacts<QuadFelt>, AceError> {
    if config.num_quotient_chunks == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "num_quotient_chunks must be > 0".into(),
        });
    }
    let counts = InputCounts {
        num_quotient_chunks: config.num_quotient_chunks,
        ..air.counts
    };
    let layout = match config.layout {
        LayoutKind::Native => InputLayout::new(counts),
        LayoutKind::Masm => InputLayout::new_masm(counts),
    };
    layout.validate();
    let periodic_data = (!air.periodic_columns.is_empty())
        .then(|| PeriodicColumnData::from_periodic_columns::<Felt>(air.periodic_columns.clone()));
    let dag = build_verifier_dag_from_ir(
        &air.graph,
        &air.constraints,
        &layout,
        periodic_data.as_ref(),
        shared_period,
    );
    Ok(AceArtifacts { layout, dag })
}

#[derive(Clone, Copy, Debug, Default)]
struct TraceOffsets {
    public: usize,
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
    debug_assert_eq!(source.root().index() + 1, source.nodes.len());
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
                    InputKey::Public(index) => InputKey::Public(index + offsets.public),
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

/// Builds one order-invariant ACE circuit for a nonempty AIR set.
///
/// Each AIR reads public and trace inputs at its canonical instance offset and its fold coefficient
/// from [`InputKey::MultiAirFoldCoeff`]. The caller must scatter proof-ordered trace segments to
/// those offsets and stage `beta^(N - 1 - k)` for the AIR at proof position `k`, where `N =
/// airs.len()`. Trace widths are padded to `trace_width_alignment` base-field elements before
/// concatenation.
pub fn build_canonical_multi_air_ace_circuit<A>(
    airs: &[A],
    config: AceConfig,
    trace_width_alignment: usize,
) -> Result<AceCircuit<QuadFelt>, AceError>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let captured = airs.iter().map(CapturedAir::new).collect::<Result<Vec<_>, _>>()?;
    let captured = captured.iter().collect::<Vec<_>>();
    let relation = CompiledRelation::with_quotient_chunks(
        &captured,
        trace_width_alignment,
        Some(config.num_quotient_chunks),
    )?;
    build_circuit_for_relation(&relation, config)
}

pub(crate) fn build_circuit_for_relation(
    relation: &CompiledRelation<'_>,
    config: AceConfig,
) -> Result<AceCircuit<QuadFelt>, AceError> {
    let num_airs = relation.airs.len();
    let artifacts = relation
        .airs
        .iter()
        .map(|air| build_ace_dag_from_capture(air, config, relation.geometry.shared_period))
        .collect::<Result<Vec<_>, _>>()?;
    let offsets: Vec<_> = relation
        .geometry
        .airs
        .iter()
        .map(|air| TraceOffsets {
            public: air.public_offset,
            preprocessed: air.preprocessed.offset,
            main: air.main.offset,
            aux: air.aux.offset / EXT_DEGREE,
            boundary: air.aux_boundary_offset,
        })
        .collect();
    let layout = InputLayout::for_relation(
        relation.geometry.input_counts(),
        num_airs,
        relation.geometry.quotient_width,
        matches!(config.layout, LayoutKind::Masm),
    );
    layout.validate();

    // Re-emit in stable instance order, each AIR placed at its canonical trace offset and scaled
    // by the fold coefficient it reads from its own slot.
    let mut builder = DagBuilder::<QuadFelt>::new();
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

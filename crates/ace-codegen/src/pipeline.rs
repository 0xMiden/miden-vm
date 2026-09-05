//! High-level ACE codegen pipeline helpers.
//!
//! This module ties together the major layers:
//! - capture AIR constraints into the compiler IR,
//! - build a verifier-style DAG from that IR,
//! - choose a READ layout for inputs,
//! - emit a circuit that matches verifier evaluation.

use miden_constraint_compiler::ir::capture;
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::Field,
    stark::air::{BaseAir, LiftedAir},
};

use crate::{
    AceError, EXT_DEGREE,
    circuit::{AceCircuit, emit_circuit},
    dag::{
        AceDag, DagBuilder, NodeId, NodeKind, PeriodicColumnData, build_verifier_dag_from_ir,
        normalize_dag,
    },
    factored::{FactoredAceCircuit, ShuffleEncodeBuffer, emit_factored_circuit},
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
) -> Result<AceCircuit<QuadFelt>, AceError>
where
    A: LiftedAir<Felt, QuadFelt>,
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
    let artifacts = build_ace_dags_for_airs(airs, sub_config)?;
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
    let shared_period = max_period(&periodic_columns);
    build_ace_dag_for_air_with_periodic_columns(
        air,
        config,
        periodic_columns.into_owned(),
        shared_period,
    )
}

/// Build verifier-equivalent DAGs against one shared periodic-column basis.
fn build_ace_dags_for_airs<A>(
    airs: &[A],
    config: AceConfig,
) -> Result<Vec<AceArtifacts<QuadFelt>>, AceError>
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
) -> Result<AceArtifacts<QuadFelt>, AceError>
where
    A: LiftedAir<Felt, QuadFelt>,
{
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
        .then(|| PeriodicColumnData::from_periodic_columns::<Felt>(periodic_columns));
    let dag = build_verifier_dag_from_ir(
        &graph,
        &constraints,
        &layout,
        periodic_data.as_ref(),
        shared_period,
    );

    Ok(AceArtifacts { layout, dag })
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

fn input_counts_for_air<A>(air: &A, config: AceConfig) -> Result<InputCounts, AceError>
where
    A: LiftedAir<Felt, QuadFelt>,
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

/// Multi-AIR ACE circuit factored into a per-order shuffle section and an order-invariant
/// common section.
///
/// The common section is emitted once from the canonical (instance-order) DAG, which is what
/// makes its encoding — and therefore `H(common)` — well-defined across proof orders; see the
/// `factored` module for the section layout.
#[derive(Debug, Clone)]
pub struct FactoredMultiAirCircuit<EF> {
    factored: FactoredAceCircuit<EF>,
    /// Per-AIR aligned trace-block widths (the per-AIR increments of the offset accumulation),
    /// indexed by instance index.
    blocks: Vec<TraceOffsets>,
}

impl<EF: Field> FactoredMultiAirCircuit<EF> {
    /// Return the input layout shared by every proof order.
    pub fn layout(&self) -> &InputLayout {
        self.factored.layout()
    }

    /// Number of shuffle-section ops (also the section length in stream felts).
    pub fn num_shuffle_ops(&self) -> usize {
        self.factored.num_shuffle_ops()
    }

    /// Number of AIR instances in the composition.
    pub fn num_airs(&self) -> usize {
        self.blocks.len()
    }

    /// Encode only this proof order's shuffle section into `buffer`.
    ///
    /// This is the registry path: it skips circuit assembly and the order-invariant
    /// remainder of the stream, so a caller enumerating every ordering touches only the
    /// per-order bytes. `buffer` may be reused across calls; the returned slice borrows it
    /// (the borrow checker rules out overlapping calls), so hash the felts, then encode
    /// the next order.
    pub fn encode_shuffle_section_for_order<'a>(
        &self,
        proof_order: &[usize],
        buffer: &'a mut ShuffleEncodeBuffer,
    ) -> Result<&'a [Felt], AceError> {
        let (srcs, exponents) = buffer.order_scratch();
        self.shuffle_and_exponents(proof_order, srcs, exponents)?;
        self.factored.encode_shuffle_section(buffer)
    }

    /// Fill `srcs` and `exponents` for one proof order, reusing their allocations.
    fn shuffle_and_exponents(
        &self,
        proof_order: &[usize],
        srcs: &mut Vec<usize>,
        exponents: &mut Vec<usize>,
    ) -> Result<(), AceError> {
        let num_airs = self.blocks.len();
        if proof_order.len() != num_airs {
            return Err(AceError::InvalidInputLayout {
                message: format!("proof_order must be a permutation of 0..{num_airs}"),
            });
        }

        exponents.clear();
        exponents.resize(num_airs, usize::MAX);
        for (position, &air_index) in proof_order.iter().enumerate() {
            let Some(exponent) = exponents.get_mut(air_index) else {
                return Err(AceError::InvalidInputLayout {
                    message: format!("proof_order must be a permutation of 0..{num_airs}"),
                });
            };
            if *exponent != usize::MAX {
                return Err(AceError::InvalidInputLayout {
                    message: format!("proof_order must be a permutation of 0..{num_airs}"),
                });
            }
            // The AIR at proof position `k` carries `beta^(N - 1 - k)` in the Horner fold.
            *exponent = num_airs - 1 - position;
        }

        let proof_offsets = accumulate_block_offsets(&self.blocks, proof_order);
        shuffled_slots(self.factored.layout(), &self.blocks, &proof_offsets, srcs)?;
        Ok(())
    }

    /// Assemble the full circuit for one proof order.
    ///
    /// `proof_order` must be a permutation of `0..num_airs` listing instance indices in the
    /// committed (height-sorted) trace order.
    pub fn circuit_for_order(&self, proof_order: &[usize]) -> Result<AceCircuit<EF>, AceError> {
        let mut srcs = Vec::new();
        let mut coeff_exponents = Vec::new();
        self.shuffle_and_exponents(proof_order, &mut srcs, &mut coeff_exponents)?;
        self.factored.assemble(&srcs, &coeff_exponents)
    }
}

/// Factored variant of [`build_multi_air_ace_circuit`].
///
/// Builds the canonical (instance-order) composition once; per-proof-order circuits are then
/// assembled from it via [`FactoredMultiAirCircuit::circuit_for_order`]. The assembled circuit
/// for a given proof order evaluates to the same value as the one produced by
/// [`build_multi_air_ace_circuit`] for that order: the shuffle section routes proof-order READ
/// slots and fold coefficients onto the canonical wires.
pub fn build_factored_multi_air_ace_circuit<A>(
    airs: &[A],
    config: AceConfig,
    trace_width_alignment: usize,
) -> Result<FactoredMultiAirCircuit<QuadFelt>, AceError>
where
    A: LiftedAir<Felt, QuadFelt>,
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
    if trace_width_alignment == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "trace width alignment must be nonzero".into(),
        });
    }

    let sub_config = AceConfig { num_airs: 1, ..config };
    let artifacts = build_ace_dags_for_airs(airs, sub_config)?;
    let shared = artifacts[0].layout.counts;
    if artifacts.iter().any(|air| air.layout.counts.num_public != shared.num_public) {
        return Err(AceError::InvalidInputLayout {
            message: "all AIRs must use the same public-value window".into(),
        });
    }

    let mut blocks = Vec::with_capacity(num_airs);
    for artifact in &artifacts {
        let counts = artifact.layout.counts;
        let aligned_aux = (counts.aux_width * EXT_DEGREE).next_multiple_of(trace_width_alignment);
        if !aligned_aux.is_multiple_of(EXT_DEGREE) {
            return Err(AceError::InvalidInputLayout {
                message: "aligned auxiliary width must be divisible by the extension degree".into(),
            });
        }
        blocks.push(TraceOffsets {
            preprocessed: counts.preprocessed_width.next_multiple_of(trace_width_alignment),
            main: counts.width.next_multiple_of(trace_width_alignment),
            aux: aligned_aux / EXT_DEGREE,
            boundary: counts.num_aux_boundary,
        });
    }

    let canonical_order: Vec<usize> = (0..num_airs).collect();
    let offsets = accumulate_block_offsets(&blocks, &canonical_order);
    let totals = blocks.iter().fold(TraceOffsets::default(), |mut totals, block| {
        totals.preprocessed += block.preprocessed;
        totals.main += block.main;
        totals.aux += block.aux;
        totals.boundary += block.boundary;
        totals
    });

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

    // Re-emit in stable instance order; placement is canonical, and the fold coefficients are
    // per-order shuffle-section gates rather than a structural Horner fold.
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

    let mut shuffle_dsts = Vec::new();
    shuffled_slots(&layout, &blocks, &offsets, &mut shuffle_dsts)?;
    let factored = emit_factored_circuit(&dag, layout, shuffle_dsts, num_airs)?;
    Ok(FactoredMultiAirCircuit { factored, blocks })
}

/// Prefix-sum the per-AIR block widths in `order`; the result is indexed by instance index.
fn accumulate_block_offsets(blocks: &[TraceOffsets], order: &[usize]) -> Vec<TraceOffsets> {
    let mut offsets = vec![TraceOffsets::default(); blocks.len()];
    let mut totals = TraceOffsets::default();
    for &air_index in order {
        offsets[air_index] = totals;
        let block = blocks[air_index];
        totals.preprocessed += block.preprocessed;
        totals.main += block.main;
        totals.aux += block.aux;
        totals.boundary += block.boundary;
    }
    offsets
}

/// Enumerate the global input indices of every shuffled READ slot, per-AIR blocks placed at
/// `offsets`, AIRs visited in canonical order.
///
/// Called with canonical offsets this yields the shuffle destinations; called with a proof
/// order's offsets it yields the sources aligned element-wise with those destinations.
fn shuffled_slots(
    layout: &InputLayout,
    blocks: &[TraceOffsets],
    offsets: &[TraceOffsets],
    slots: &mut Vec<usize>,
) -> Result<(), AceError> {
    slots.clear();
    let mut push = |key: InputKey| -> Result<(), AceError> {
        let index = layout.index(key).ok_or_else(|| AceError::InvalidInputLayout {
            message: format!("shuffled slot {key:?} is missing from the layout"),
        })?;
        slots.push(index);
        Ok(())
    };

    for row_offset in 0..2 {
        for (block, air_offsets) in blocks.iter().zip(offsets) {
            for column in 0..block.preprocessed {
                push(InputKey::Preprocessed {
                    offset: row_offset,
                    index: air_offsets.preprocessed + column,
                })?;
            }
        }
    }
    for row_offset in 0..2 {
        for (block, air_offsets) in blocks.iter().zip(offsets) {
            for column in 0..block.main {
                push(InputKey::Main {
                    offset: row_offset,
                    index: air_offsets.main + column,
                })?;
            }
        }
    }
    for row_offset in 0..2 {
        for (block, air_offsets) in blocks.iter().zip(offsets) {
            for column in 0..block.aux {
                for coord in 0..EXT_DEGREE {
                    push(InputKey::AuxCoord {
                        offset: row_offset,
                        index: air_offsets.aux + column,
                        coord,
                    })?;
                }
            }
        }
    }
    for (block, air_offsets) in blocks.iter().zip(offsets) {
        for value in 0..block.boundary {
            push(InputKey::AuxBusBoundary(air_offsets.boundary + value))?;
        }
    }

    Ok(())
}

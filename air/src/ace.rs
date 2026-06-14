//! ACE circuit integration for the Miden multi-AIR proof.
//!
//! This module extends the constraint-evaluation DAG produced by
//! `build_ace_dag_for_air` with the LogUp auxiliary-trace boundary check:
//!
//! ```text
//! 0  =  weighted_sum(aux_bound[0..NUM_LOGUP_COMMITTED_FINALS])
//!         + c_block_hash
//!         + c_log_precompile
//!         + c_kernel_rom
//! ```
//!
//! Most AIRs commit raw LogUp boundary sums. Wrapped-centered AIRs commit `sum / trace_len`; their
//! boundary slot is therefore scaled by the corresponding trace length before it enters the
//! cross-AIR identity.
//!
//! Two of the three corrections depend only on fixed-length public inputs
//! (`c_bh`, `c_lp`), so they are rebuilt directly inside the DAG as rational
//! fractions `(n, d)` and folded into a running rational `(N, D)` without any
//! in-circuit inversion. The kernel-ROM correction depends on the variable-
//! length kernel digest list which the circuit can't walk, so MASM computes
//! it (one final `ext2inv`) and hands it in as a single scalar via the
//! existing `VlpiReduction(0)` input. The final boundary check is the quadratic identity
//! `(weighted_aux_sum + c_kr) * D + N = 0`.

use alloc::{format, vec::Vec};

use miden_ace_codegen::{
    AceArtifacts, AceCircuit, AceConfig, AceDag, AceError, DagBuilder, InputCounts, InputKey,
    InputLayout, NodeId, NodeKind, build_ace_dag_for_air,
};
use miden_core::{Felt, field::ExtensionField};
use miden_crypto::{
    field::{Algebra, Field},
    stark::air::{BaseAir, LiftedAir, symbolic::SymbolicExpressionExt},
};

use crate::{
    AIRS, MIDEN_AIR_COUNT, MidenAir, MidenAirId, ProofOrder, lookup::LookupAccumulatorMode,
};

mod logup_boundary;

pub use logup_boundary::{
    AuxBoundaryTerm, BusFraction, LogUpBoundaryConfig, MessageElement, Sign,
    batch_logup_boundary_into_builder, multi_air_logup_boundary_config,
};

#[derive(Copy, Clone)]
struct SlotOffsets {
    /// Preprocessed-trace column offset of this AIR in the combined proof-order layout.
    preprocessed: usize,
    /// Main-trace column offset of this AIR in the combined proof-order layout.
    main: usize,
    /// Aux-trace column offset of this AIR in the combined proof-order layout.
    aux: usize,
    /// Aux-bus-boundary slot offset of this AIR in the combined proof-order layout.
    boundary: usize,
}

/// Per-AIR verifier DAG plus the layout data needed to place it in a combined circuit.
struct AirSubDag<EF> {
    /// Semantic AIR id. This is independent of proof order.
    id: MidenAirId,
    /// Single-AIR verifier DAG emitted by `build_ace_dag_for_air`.
    dag: AceDag<EF>,
    /// Single-AIR input counts from the source DAG layout.
    counts: InputCounts,
    /// Preprocessed-trace width rounded to the LMCS matrix alignment.
    aligned_preprocessed: usize,
    /// Main-trace width rounded to the LMCS matrix alignment.
    aligned_main: usize,
    /// Aux-trace width rounded to the LMCS matrix alignment.
    aligned_aux: usize,
    /// Number of aux-bus-boundary slots contributed by this AIR.
    aux_values: usize,
    /// Maximum period length among this AIR's periodic columns.
    periodic_max: usize,
}

/// Combined trace layout induced by one proof order.
///
/// Offsets are indexed by semantic AIR id for cheap rewrites, while `ids` preserves
/// the proof-order sequence for digest-sensitive ACE serialization.
struct ProofOrderLayout {
    ids: [MidenAirId; MIDEN_AIR_COUNT],
    offsets_by_air: [SlotOffsets; MIDEN_AIR_COUNT],
}

impl ProofOrderLayout {
    fn new<EF>(sub_dags_by_air: &[AirSubDag<EF>], order: &ProofOrder) -> Self {
        debug_assert_eq!(order.ids().len(), MIDEN_AIR_COUNT);

        let ids = core::array::from_fn(|idx| order.ids()[idx]);
        let mut offsets_by_air = [SlotOffsets {
            preprocessed: 0,
            main: 0,
            aux: 0,
            boundary: 0,
        }; MIDEN_AIR_COUNT];
        let mut preprocessed = 0usize;
        let mut main = 0usize;
        let mut aux = 0usize;
        let mut boundary = 0usize;

        for id in ids {
            let air = &sub_dags_by_air[id.instance_index()];
            debug_assert_eq!(air.id, id);
            offsets_by_air[id.instance_index()] = SlotOffsets { preprocessed, main, aux, boundary };
            preprocessed += air.aligned_preprocessed;
            main += air.aligned_main;
            aux += air.aligned_aux;
            boundary += air.aux_values;
        }

        Self { ids, offsets_by_air }
    }

    fn ids(&self) -> impl Iterator<Item = MidenAirId> + '_ {
        self.ids.iter().copied()
    }

    fn offset(&self, id: MidenAirId) -> SlotOffsets {
        self.offsets_by_air[id.instance_index()]
    }
}

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Build the combined ACE circuit for the Miden multi-AIR proof in instance order.
///
/// This is the instance-order circuit. Recursive verification
/// uses [`build_multi_air_ace_circuit_for_order`] to emit one circuit per proof order.
pub fn build_multi_air_ace_circuit<EF>(config: AceConfig) -> Result<AceCircuit<EF>, AceError>
where
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    build_multi_air_ace_circuit_for_order(config, &ProofOrder::instance_order())
}

/// Build the combined ACE circuit for the supplied proof order.
///
/// The output circuit evaluates `combined + gamma * boundary = 0`.
///
/// `combined` is the beta-folded sum of the per-AIR constraint roots.
/// `boundary` is the cross-AIR LogUp identity over all aux-bus-boundary slots,
/// plus the open-bus rational corrections and the kernel-ROM scalar correction.
///
/// Implementation strategy:
/// 1. Build per-AIR sub-DAGs with their own (single-AIR) layouts via [`build_ace_dag_for_air`].
///    These DAGs encode each AIR's alpha-folded constraints referencing layout-relative
///    `InputKey::Main`/`AuxCoord`/`AuxBusBoundary` slots.
/// 2. Re-emit each sub-DAG's nodes into a fresh `DagBuilder` configured for the combined layout.
///    Main, aux-coordinate, and aux-boundary slots are rewritten according to `order`.
/// 3. Beta-fold the per-AIR roots in proof order with the single multi-AIR beta challenge.
/// 4. Apply the shared boundary via [`batch_logup_boundary_into_builder`] using a
///    [`LogUpBoundaryConfig`] whose aux terms cover every AIR's boundary slot.
///
/// Returns the combined `AceCircuit` ready for emission to the MASM ACE chip.
pub fn build_multi_air_ace_circuit_for_order<EF>(
    config: AceConfig,
    order: &ProofOrder,
) -> Result<AceCircuit<EF>, AceError>
where
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    assert!(
        config.is_multi_air,
        "build_multi_air_ace_circuit requires AceConfig::is_multi_air = true"
    );

    // Step 1: per-AIR sub-DAGs. Each is built with its OWN single-AIR layout (no
    // multi-air slot) so the symbolic eval references plain `InputKey` variants.
    let sub_config = AceConfig { is_multi_air: false, ..config };

    // LMCS opens each per-AIR matrix in aligned chunks. The wire OOD data
    // concatenates those aligned per-AIR widths, so the combined ACE layout
    // must keep the same padding slots even when an AIR does not reference them.
    const LMCS_ALIGNMENT: usize = 8;

    let mut sub_dags = Vec::with_capacity(AIRS.len());
    for spec in AIRS {
        let artifacts = build_ace_dag_for_air::<MidenAir, Felt, EF>(&spec.air, sub_config)?;
        sub_dags.push(build_air_sub_dag::<EF>(spec.id, spec.air, artifacts, LMCS_ALIGNMENT));
    }

    let global_periodic_max = sub_dags.iter().map(|air| air.periodic_max).max().unwrap_or(0);
    validate_periodic_embedding(&sub_dags, global_periodic_max)?;

    let combined_preprocessed_w: usize = sub_dags.iter().map(|air| air.aligned_preprocessed).sum();
    let combined_main_w: usize = sub_dags.iter().map(|air| air.aligned_main).sum();
    let combined_aux_w: usize = sub_dags.iter().map(|air| air.aligned_aux).sum();
    let total_aux_values: usize = sub_dags.iter().map(|air| air.aux_values).sum();
    let total_periodic_columns: usize = sub_dags.iter().map(|air| air.counts.num_periodic).sum();

    let reference_counts =
        sub_dags
            .first()
            .map(|air| air.counts)
            .ok_or_else(|| AceError::InvalidInputLayout {
                message: "multi-AIR circuit requires at least one AIR".into(),
            })?;
    for air in &sub_dags {
        if air.counts.num_public != reference_counts.num_public
            || air.counts.num_vlpi != reference_counts.num_vlpi
            || air.counts.num_quotient_chunks != reference_counts.num_quotient_chunks
        {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "{} AIR has incompatible public/VLPI/quotient counts",
                    air.id.name()
                ),
            });
        }
    }

    // Step 2: combined input counts.
    //
    // - Trace widths sum the LMCS-aligned per-AIR widths so the codegen layout matches the wire
    //   byte order exactly. Padding slots inside each AIR subregion are unreferenced by that AIR's
    //   constraints.
    // - `num_aux_boundary` sums each AIR's boundary slot count.
    // - `num_periodic` is metadata for the combined layout. Periodic columns were already
    //   lowered inside each sub-DAG as polynomials in that AIR's `z_k`.
    let combined_counts = InputCounts {
        preprocessed_width: combined_preprocessed_w,
        width: combined_main_w,
        aux_width: combined_aux_w,
        num_aux_boundary: total_aux_values,
        num_public: reference_counts.num_public,
        num_vlpi: reference_counts.num_vlpi,
        num_randomness: 2,
        num_periodic: total_periodic_columns,
        num_quotient_chunks: config.num_quotient_chunks,
    };

    // Build combined layout via the multi-air constructors so the stark-vars region
    // includes the multi-AIR beta coefficients and per-AIR selector slots.
    let combined_layout = match config.layout {
        miden_ace_codegen::LayoutKind::Native => {
            InputLayout::new_multi_air_for_airs(combined_counts, MIDEN_AIR_COUNT)
        },
        miden_ace_codegen::LayoutKind::Masm => {
            InputLayout::new_masm_multi_air_for_airs(combined_counts, MIDEN_AIR_COUNT)
        },
    };

    let mut builder = DagBuilder::<EF>::new();
    let proof_layout = ProofOrderLayout::new(&sub_dags, order);
    let mut acc_by_air = [None; MIDEN_AIR_COUNT];
    let mut shared_qv = None;

    // Step 3: re-emit each sub-DAG with proof-order offsets. The source root is
    // `Sub(acc, q*v)`; the combined circuit uses every AIR's `acc` but one shared `q*v`.
    for air in &sub_dags {
        let translation = reemit_dag_with_rewrite(
            &mut builder,
            &air.dag,
            |builder, key| {
                rewrite_air_input(
                    builder,
                    key,
                    air.id,
                    proof_layout.offset(air.id),
                    air.periodic_max,
                    global_periodic_max,
                )
            },
            true,
        );

        let (acc, qv) = translated_acc_and_qv(air.id, &air.dag, &translation)?;
        if let Some(previous_qv) = shared_qv {
            if previous_qv != qv {
                return Err(AceError::InvalidInputLayout {
                    message: "all AIR quotient bindings must share the same q*v node".into(),
                });
            }
        } else {
            shared_qv = Some(qv);
        }
        acc_by_air[air.id.instance_index()] = Some(acc);
    }
    let shared_qv = shared_qv.ok_or_else(|| AceError::InvalidInputLayout {
        message: "multi-AIR circuit did not emit any AIR roots".into(),
    })?;

    let beta = builder.input(InputKey::MultiAirBeta);
    let acc_for_air = |id: MidenAirId| {
        acc_by_air[id.instance_index()]
            .unwrap_or_else(|| panic!("missing translated acc for {}", id.name()))
    };

    let mut ordered_ids = proof_layout.ids();
    let first_id = ordered_ids.next().ok_or_else(|| AceError::InvalidInputLayout {
        message: "proof order must contain at least one AIR".into(),
    })?;
    let mut combined_acc = acc_for_air(first_id);
    for id in ordered_ids {
        let scaled = builder.mul(combined_acc, beta);
        combined_acc = builder.add(scaled, acc_for_air(id));
    }
    let combined_constraint = builder.sub(combined_acc, shared_qv);

    // Step 4: combined LogUp boundary.
    let combined_boundary_config =
        multi_air_logup_boundary_config(aux_boundary_terms(&sub_dags, &proof_layout));
    let final_root = batch_logup_boundary_into_builder(
        &mut builder,
        combined_constraint,
        &combined_boundary_config,
    );

    let combined_dag = builder.build(final_root);
    miden_ace_codegen::emit_circuit(&combined_dag, combined_layout)
}

fn build_air_sub_dag<EF>(
    id: MidenAirId,
    air: MidenAir,
    artifacts: AceArtifacts<EF>,
    alignment: usize,
) -> AirSubDag<EF>
where
    EF: ExtensionField<Felt>,
{
    let main_width = <MidenAir as BaseAir<Felt>>::width(&air);
    let aux_width = <MidenAir as LiftedAir<Felt, EF>>::aux_width(&air);
    let aux_values = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&air);
    let periodic_columns = <MidenAir as LiftedAir<Felt, EF>>::periodic_columns(&air);
    let periodic_max = periodic_columns.iter().map(Vec::len).max().unwrap_or(0);
    let preprocessed_width = <MidenAir as LiftedAir<Felt, EF>>::preprocessed_width(&air);

    let aligned_aux_coord = (aux_width * miden_ace_codegen::EXT_DEGREE).next_multiple_of(alignment);
    assert!(
        aligned_aux_coord.is_multiple_of(miden_ace_codegen::EXT_DEGREE),
        "aligned aux-coordinate width must be even"
    );

    AirSubDag {
        id,
        dag: artifacts.dag,
        counts: artifacts.layout.counts,
        aligned_preprocessed: preprocessed_width.next_multiple_of(alignment),
        aligned_main: main_width.next_multiple_of(alignment),
        aligned_aux: aligned_aux_coord / miden_ace_codegen::EXT_DEGREE,
        aux_values,
        periodic_max,
    }
}

fn validate_periodic_embedding<EF>(
    sub_dags: &[AirSubDag<EF>],
    global_periodic_max: usize,
) -> Result<(), AceError> {
    for air in sub_dags {
        let local = air.periodic_max;
        if local == 0 {
            continue;
        }
        if global_periodic_max == 0
            || !global_periodic_max.is_multiple_of(local)
            || !global_periodic_max.is_power_of_two()
            || !local.is_power_of_two()
        {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "{} periodic max ({local}) does not embed in global max ({global_periodic_max})",
                    air.id.name()
                ),
            });
        }
    }
    Ok(())
}

fn aux_boundary_terms<EF>(
    sub_dags_by_air: &[AirSubDag<EF>],
    layout: &ProofOrderLayout,
) -> Vec<AuxBoundaryTerm> {
    let total_aux_values: usize = sub_dags_by_air.iter().map(|air| air.aux_values).sum();
    let mut terms = Vec::with_capacity(total_aux_values);
    for id in layout.ids() {
        let air = &sub_dags_by_air[id.instance_index()];
        debug_assert_eq!(air.id, id);
        let offset = layout.offset(id).boundary;
        let scale = aux_boundary_scale(id);
        terms.extend((0..air.aux_values).map(|i| AuxBoundaryTerm { column: offset + i, scale }));
    }
    terms
}

fn aux_boundary_scale(id: MidenAirId) -> Option<InputKey> {
    match id.lookup_accumulator_mode() {
        LookupAccumulatorMode::LastRowIdle => None,
        LookupAccumulatorMode::WrappedCentered => Some(InputKey::TraceLenAir(id.instance_index())),
    }
}

fn rewrite_air_input<EF>(
    builder: &mut DagBuilder<EF>,
    key: InputKey,
    air_id: MidenAirId,
    offsets: SlotOffsets,
    local_periodic_max: usize,
    global_periodic_max: usize,
) -> NodeId
where
    EF: Field,
{
    match key {
        InputKey::Main { offset, index } => {
            builder.input(InputKey::Main { offset, index: index + offsets.main })
        },
        InputKey::Preprocessed { offset, index } => builder.input(InputKey::Preprocessed {
            offset,
            index: index + offsets.preprocessed,
        }),
        InputKey::AuxCoord { offset, index, coord } => builder.input(InputKey::AuxCoord {
            offset,
            index: index + offsets.aux,
            coord,
        }),
        InputKey::AuxBusBoundary(slot) => {
            builder.input(InputKey::AuxBusBoundary(slot + offsets.boundary))
        },
        InputKey::IsFirst => builder.input(InputKey::IsFirstAir(air_id.instance_index())),
        InputKey::IsLast => builder.input(InputKey::IsLastAir(air_id.instance_index())),
        InputKey::IsTransition => builder.input(InputKey::IsTransitionAir(air_id.instance_index())),
        InputKey::ZK if local_periodic_max != 0 && local_periodic_max != global_periodic_max => {
            // The combined circuit uses the global max period. An AIR with a shorter period
            // evaluates its periodic columns at the corresponding power of global z_k.
            let mut z = builder.input(InputKey::ZK);
            let ratio = global_periodic_max / local_periodic_max;
            for _ in 0..ratio.ilog2() {
                z = builder.mul(z, z);
            }
            z
        },
        other => builder.input(other),
    }
}

fn translated_acc_and_qv<EF>(
    id: MidenAirId,
    dag: &AceDag<EF>,
    translation: &[NodeId],
) -> Result<(NodeId, NodeId), AceError> {
    match dag.nodes[dag.root().index()] {
        NodeKind::Sub(acc_id, qv_id) => {
            Ok((translation[acc_id.index()], translation[qv_id.index()]))
        },
        _ => Err(AceError::InvalidInputLayout {
            message: format!("{} sub-DAG root must be `Sub(acc, q*v)`", id.name()),
        }),
    }
}

/// Re-emit `source` into `builder`, rewriting each `Input(key)` via `rewrite`.
///
/// Returns a translation table mapping the source DAG's node indices to the
/// corresponding `NodeId`s in `builder`. The source DAG's nodes must be in
/// topological order (which they are by `DagBuilder::intern` construction).
///
/// `skip_root` skips the source DAG's root node (the last node) when re-emitting.
/// Useful when the caller intends to bypass the source's top-level expression and
/// wire up children directly (e.g., extracting `acc` from a `Sub(acc, q*v)` root
/// when the `q*v` subtraction is replaced by a shared one in the combined DAG).
fn reemit_dag_with_rewrite<EF, F>(
    builder: &mut DagBuilder<EF>,
    source: &AceDag<EF>,
    rewrite: F,
    skip_root: bool,
) -> Vec<NodeId>
where
    EF: Field,
    F: Fn(&mut DagBuilder<EF>, InputKey) -> NodeId,
{
    let nodes = &source.nodes;
    let limit = if skip_root && !nodes.is_empty() {
        nodes.len() - 1
    } else {
        nodes.len()
    };
    let mut translation: Vec<NodeId> = Vec::with_capacity(nodes.len());
    for node in nodes.iter().take(limit) {
        let new_id = match *node {
            NodeKind::Input(key) => rewrite(builder, key),
            NodeKind::Constant(v) => builder.constant(v),
            NodeKind::Add(a, b) => builder.add(translation[a.index()], translation[b.index()]),
            NodeKind::Sub(a, b) => builder.sub(translation[a.index()], translation[b.index()]),
            NodeKind::Mul(a, b) => builder.mul(translation[a.index()], translation[b.index()]),
            NodeKind::Neg(a) => builder.neg(translation[a.index()]),
        };
        translation.push(new_id);
    }
    translation
}

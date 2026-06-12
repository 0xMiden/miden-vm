//! ACE circuit integration for the multi-AIR (CoreAir + ChipletsAir) proof.
//!
//! The circuit checks the β-folded constraint composition of the two AIRs. The
//! LogUp auxiliary-trace boundary identity
//!
//! ```text
//! 0  =  Σ aux_bound[0..NUM_LOGUP_COMMITTED_FINALS]
//!         + c_block_hash
//!         + c_log_precompile
//!         + c_kernel_rom
//! ```
//!
//! is *not* part of the circuit: the MASM verifier asserts it directly on the
//! operand stack (see `sys/vm/public_inputs.masm` / `sys/vm/aux_trace.masm`),
//! mirroring the native verifier's [`MidenMultiAir::eval_external`] check.

use alloc::vec::Vec;

use miden_ace_codegen::{
    AceCircuit, AceConfig, AceDag, AceError, DagBuilder, InputKey, NodeId, NodeKind,
    build_ace_dag_for_air,
};
use miden_core::{Felt, field::ExtensionField};
use miden_crypto::{
    field::Algebra,
    stark::air::{BaseAir, LiftedAir, symbolic::SymbolicExpressionExt},
};

use crate::MidenAir;

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Build the combined ACE circuit for the (CoreAir, ChipletsAir) multi-AIR proof.
///
/// The output circuit evaluates
///   `combined = 0`
/// where `combined = chip_acc · β_multi + core_acc - q·v` is the β-folded sum of the per-AIR
/// alpha-folded constraint roots minus the shared quotient binding. The cross-AIR LogUp
/// boundary identity is asserted separately by the MASM verifier (it is not batched into
/// the circuit).
///
/// Implementation strategy:
/// 1. Build per-AIR sub-DAGs with their own (single-AIR) layouts via [`build_ace_dag_for_air`].
///    These DAGs encode each AIR's alpha-folded constraints referencing layout-relative
///    `InputKey::Main`/`AuxCoord`/`AuxBusBoundary` slots.
/// 2. Re-emit each sub-DAG's nodes into a fresh `DagBuilder` configured for the *combined* layout.
///    The chiplets sub-DAG's input keys are rewritten so its main/aux/bus-boundary slot indices
///    land in the chiplets-half of the combined layout. The core sub-DAG passes through unchanged.
/// 3. β-fold: `combined = MultiAirBetaCore · core_acc + MultiAirBetaChip · chip_acc - q·v`, where
///    the verifier sets one coefficient to β and the other to 1 based on proof_order.
///
/// Returns the combined `AceCircuit` ready for emission to the MASM ACE chip.
pub fn build_multi_air_ace_circuit<EF>(config: AceConfig) -> Result<AceCircuit<EF>, AceError>
where
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    assert!(
        config.is_multi_air,
        "build_multi_air_ace_circuit requires AceConfig::is_multi_air = true"
    );

    use miden_ace_codegen::{InputCounts, InputLayout};

    let core_air = MidenAir::CORE;
    let chip_air = MidenAir::CHIPLETS;

    // Step 1: per-AIR sub-DAGs. Each is built with its OWN single-AIR layout (no
    // multi-air slot) so the symbolic eval references plain `InputKey` variants.
    let sub_config = AceConfig { is_multi_air: false, ..config };
    let core_artifacts = build_ace_dag_for_air::<MidenAir, Felt, EF>(&core_air, sub_config)?;
    let chip_artifacts = build_ace_dag_for_air::<MidenAir, Felt, EF>(&chip_air, sub_config)?;

    let core_main_w = <MidenAir as BaseAir<Felt>>::width(&core_air);
    let core_aux_w = <MidenAir as LiftedAir<Felt, EF>>::aux_width(&core_air);
    let core_aux_n = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&core_air);
    let chip_main_w = <MidenAir as BaseAir<Felt>>::width(&chip_air);
    let chip_aux_w = <MidenAir as LiftedAir<Felt, EF>>::aux_width(&chip_air);
    let chip_aux_n = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&chip_air);

    // LMCS commits each per-AIR matrix as a stack and aligns each matrix's column
    // count to the LMCS rate (8 for Poseidon2). The wire OOD opens carry data in
    // *aligned* per-AIR widths concatenated across AIRs. To make the codegen layout
    // line up with the wire format byte-for-byte, the combined layout uses
    // ALIGNED per-AIR widths (with trailing slots being unreferenced padding). This
    // mirrors what `verify_aligned` does internally before truncation.
    const LMCS_ALIGNMENT: usize = 8;
    let aligned_core_main = core_main_w.next_multiple_of(LMCS_ALIGNMENT);
    let aligned_chip_main = chip_main_w.next_multiple_of(LMCS_ALIGNMENT);
    let aligned_core_aux_coord =
        (core_aux_w * miden_ace_codegen::EXT_DEGREE).next_multiple_of(LMCS_ALIGNMENT);
    let aligned_chip_aux_coord =
        (chip_aux_w * miden_ace_codegen::EXT_DEGREE).next_multiple_of(LMCS_ALIGNMENT);

    let combined_main_w = aligned_core_main + aligned_chip_main;
    let combined_aux_coord_w = aligned_core_aux_coord + aligned_chip_aux_coord;
    assert!(
        combined_aux_coord_w.is_multiple_of(miden_ace_codegen::EXT_DEGREE),
        "combined aux coord width must be even"
    );
    let combined_aux_w = combined_aux_coord_w / miden_ace_codegen::EXT_DEGREE;

    // Step 2: combined input counts.
    //
    // - `width` and `aux_width` sum the LMCS-aligned per-AIR widths so the codegen layout matches
    //   the wire byte order exactly. Padding slots within each AIR's subregion are unreferenced by
    //   the constraints (see eval bodies of CoreAir and ChipletsAir, which only address columns up
    //   to the original width).
    // - `num_aux_boundary` sums each AIR's boundary slot count.
    // - `num_periodic` is taken from chiplets (the only AIR with periodic columns today; the
    //   wrapper exposes them once via the combined `LiftedAir` impl).
    let combined_counts = InputCounts {
        width: combined_main_w,
        aux_width: combined_aux_w,
        num_aux_boundary: core_aux_n + chip_aux_n,
        num_public: core_artifacts.layout.counts.num_public,
        num_vlpi: core_artifacts.layout.counts.num_vlpi,
        num_randomness: 2,
        num_periodic: chip_artifacts.layout.counts.num_periodic,
        num_quotient_chunks: config.num_quotient_chunks,
    };

    // Build combined layout via the multi-air constructors so the stark-vars region
    // includes the multi-AIR β coefficients and per-AIR selector slots.
    let combined_layout = match config.layout {
        miden_ace_codegen::LayoutKind::Native => InputLayout::new_multi_air(combined_counts),
        miden_ace_codegen::LayoutKind::Masm => InputLayout::new_masm_multi_air(combined_counts),
    };

    // Step 3: re-emit the core sub-DAG into a fresh builder. Core's input keys map
    // 1:1 onto the combined layout (its main/aux/boundary slots occupy the leading
    // half of the combined regions).
    let core_dag = core_artifacts.dag;
    let core_root_old = core_dag.root();
    let mut builder = DagBuilder::<EF>::new();

    let core_translation = reemit_dag_with_rewrite(
        &mut builder,
        &core_dag,
        |key| match key {
            InputKey::IsFirst => InputKey::IsFirstCore,
            InputKey::IsLast => InputKey::IsLastCore,
            InputKey::IsTransition => InputKey::IsTransitionCore,
            other => other,
        },
        true, // skip core's `Sub(acc, q*v)` root — combined formula uses a shared q*v
    );
    let _core_root = core_root_old; // unused; we extract `core_acc` from core's root structure below

    // Step 4: re-emit chiplets sub-DAG, rewriting Main/AuxCoord/AuxBusBoundary indices
    // so they land in the chiplets-half of the combined layout.
    let chip_dag = chip_artifacts.dag;
    let chip_root_old = chip_dag.root();
    // Shift chiplets indices by the *aligned* core width, so chiplets's first slot
    // sits exactly where chip_main begins on the wire (after core_main + alignment
    // padding). Padding slots in [core_main_w..aligned_core_main) and
    // [chip_main_w + aligned_core_main..combined_main_w) are unreferenced by the
    // chiplet sub-DAG, so their values can be anything (zeros from the wire).
    // `InputKey::AuxCoord.index` is in EF units (column index). Shift by the
    // *EF-count* of core's aligned aux region so chip's aux EFs land in the
    // chiplets-half of the combined aux region.
    let aligned_core_aux_w = aligned_core_aux_coord / miden_ace_codegen::EXT_DEGREE;
    let chip_translation = reemit_dag_with_rewrite(
        &mut builder,
        &chip_dag,
        |key| match key {
            InputKey::Main { offset, index } => {
                InputKey::Main { offset, index: index + aligned_core_main }
            },
            InputKey::AuxCoord { offset, index, coord } => InputKey::AuxCoord {
                offset,
                index: index + aligned_core_aux_w,
                coord,
            },
            InputKey::AuxBusBoundary(slot) => InputKey::AuxBusBoundary(slot + core_aux_n),
            InputKey::IsFirst => InputKey::IsFirstChip,
            InputKey::IsLast => InputKey::IsLastChip,
            InputKey::IsTransition => InputKey::IsTransitionChip,
            other => other,
        },
        true, // skip chiplets's `Sub(acc, q*v)` root — combined formula uses a shared q*v
    );

    // β-fold: `combined = mab_core · core_acc + mab_chip · chip_acc - q*v`. Verifier
    // picks (β, 1) or (1, β) for (mab_core, mab_chip) per proof_order.
    let (core_acc, core_qv) = match core_dag.nodes[core_root_old.index()] {
        NodeKind::Sub(acc_id, qv_id) => {
            (core_translation[acc_id.index()], core_translation[qv_id.index()])
        },
        _ => panic!("CoreAir sub-DAG root must be `Sub(acc, q*v)`"),
    };
    let (chip_acc, chip_qv) = match chip_dag.nodes[chip_root_old.index()] {
        NodeKind::Sub(acc_id, qv_id) => {
            (chip_translation[acc_id.index()], chip_translation[qv_id.index()])
        },
        _ => panic!("ChipletsAir sub-DAG root must be `Sub(acc, q*v)`"),
    };
    if core_qv != chip_qv {
        return Err(AceError::InvalidInputLayout {
            message: "CoreAir and ChipletsAir quotient bindings must share the same q*v node"
                .into(),
        });
    }

    let mab_core = builder.input(InputKey::MultiAirBetaCore);
    let mab_chip = builder.input(InputKey::MultiAirBetaChip);
    let core_term = builder.mul(mab_core, core_acc);
    let chip_term = builder.mul(mab_chip, chip_acc);
    let combined_acc = builder.add(core_term, chip_term);
    // SAFETY-CRITICAL invariant: this `sub` must be the *last* operation emitted into the
    // builder, since the MASM ACE chip's "is the last op zero?" check evaluates that node
    // as the root.
    let combined_constraint = builder.sub(combined_acc, chip_qv);

    let combined_dag = builder.build(combined_constraint);
    miden_ace_codegen::emit_circuit(&combined_dag, combined_layout)
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
    EF: ExtensionField<Felt>,
    F: Fn(InputKey) -> InputKey,
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
            NodeKind::Input(key) => builder.input(rewrite(key)),
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

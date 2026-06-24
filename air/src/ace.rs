//! ACE circuit integration for the multi-AIR (CoreAir + ChipletsAir) proof.
//!
//! This module extends the constraint-evaluation DAG produced by
//! `build_ace_dag_for_air` with the LogUp auxiliary-trace boundary check:
//!
//! ```text
//! 0  =  Σ aux_bound[0..NUM_LOGUP_COMMITTED_FINALS]
//!         + c_block_hash
//!         + c_log_precompile
//!         + c_kernel_rom
//! ```
//!
//! Two of the three corrections depend only on fixed-length public inputs
//! (`c_bh`, `c_lp`), so they are rebuilt directly inside the DAG as rational
//! fractions `(n, d)` and folded into a running rational `(N, D)` without any
//! in-circuit inversion. The kernel-ROM correction depends on the variable-
//! length kernel digest list which the circuit can't walk, so MASM computes
//! it (one final `ext2inv`) and hands it in as a single scalar via the
//! existing `VlpiReduction(0)` input. The final boundary check is the
//! quadratic identity `(Σ aux_bound + c_kr) · D + N = 0`.

use alloc::{vec, vec::Vec};

use miden_ace_codegen::{
    AceCircuit, AceConfig, AceDag, AceError, DagBuilder, InputKey, NodeId, NodeKind,
    build_ace_dag_for_air,
};
use miden_core::{Felt, field::ExtensionField};
use miden_crypto::{
    field::Algebra,
    stark::air::{BaseAir, LiftedAir, symbolic::SymbolicExpressionExt},
};

use crate::{MidenAir, PV_PROGRAM_HASH, PV_TRANSCRIPT_STATE};

// BATCHING TYPES
// ================================================================================================

/// An element in a bus message encoding.
///
/// Bus messages are encoded as `bus_prefix + sum(beta^i * elements[i])` using the
/// aux randomness challenges. Each element is either a constant base-field value
/// or a reference to a fixed-length public input.
#[derive(Debug, Clone)]
pub enum MessageElement {
    /// A constant base-field value.
    Constant(Felt),
    /// A fixed-length public input value, indexed into the public values array.
    PublicInput(usize),
}

/// Sign applied to a `BusFraction` numerator.
#[derive(Debug, Clone, Copy)]
pub enum Sign {
    Plus,
    Minus,
}

/// A rational `±1 / bus_message` contribution to the LogUp boundary sum.
///
/// The bus message denominator is rebuilt inside the ACE DAG from public inputs
/// and aux randomness, so no external input is needed for this term.
#[derive(Debug, Clone)]
pub struct BusFraction {
    pub sign: Sign,
    pub bus: usize,
    pub message: Vec<MessageElement>,
}

/// Configuration for the LogUp auxiliary-trace boundary batching.
///
/// Consumed by [`batch_logup_boundary_into_builder`] to extend the constraint-check DAG
/// with the per-AIR LogUp boundary identity (the same one checked at runtime via
/// `CoreAir`/`ChipletsAir`'s `boundary_correction`).
#[derive(Debug, Clone)]
pub struct LogUpBoundaryConfig {
    /// Aux-bus-boundary column indices summed as `Σ aux_bound[col]`.
    pub sum_columns: Vec<usize>,
    /// Rational `(±1, d_i)` fractions folded into the running rational `(N, D)`.
    pub fractions: Vec<BusFraction>,
    /// Scalar EF inputs added directly to the aux-boundary sum. Trusted from
    /// MASM (the VM's own constraint system covers the procedure that produced
    /// them). Typically one entry pointing at `VlpiReduction(0)` for `c_kr`.
    pub scalar_corrections: Vec<InputKey>,
}

// BATCHING FUNCTIONS
// ================================================================================================

/// Appends the LogUp auxiliary-trace boundary check into an existing [`DagBuilder`].
///
/// Builds:
///
///   `sum_aux   = Σ AuxBusBoundary(col)  +  Σ scalar_corrections`
///   `(N, D)    = fold((0, 1), fractions)` via `(N', D') = (N·d_i + D·n_i, D·d_i)`
///   `boundary  = sum_aux · D  +  N`
///   `root      = constraint_check  +  γ · boundary`
///
/// Used by the multi-AIR combined builder, where the two per-AIR constraint roots are
/// β-folded before this shared boundary check is appended.
pub fn batch_logup_boundary_into_builder<EF>(
    builder: &mut DagBuilder<EF>,
    constraint_root: NodeId,
    config: &LogUpBoundaryConfig,
) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    // sum_aux = Σ aux_bound[col] + Σ scalar_corrections
    let mut sum_aux = builder.constant(EF::ZERO);
    for &col in &config.sum_columns {
        let node = builder.input(InputKey::AuxBusBoundary(col));
        sum_aux = builder.add(sum_aux, node);
    }
    for &scalar in &config.scalar_corrections {
        let node = builder.input(scalar);
        sum_aux = builder.add(sum_aux, node);
    }

    // Fold all rational fractions into a single (N, D) running rational.
    let mut num = builder.constant(EF::ZERO);
    let mut den = builder.constant(EF::ONE);
    for fraction in &config.fractions {
        let d_i = encode_bus_message(builder, fraction.bus, &fraction.message);
        let sign_value = match fraction.sign {
            Sign::Plus => EF::ONE,
            Sign::Minus => -EF::ONE,
        };
        let n_i = builder.constant(sign_value);

        // (num', den') = (num * d_i + den * n_i, den * d_i)
        let num_d = builder.mul(num, d_i);
        let den_n = builder.mul(den, n_i);
        num = builder.add(num_d, den_n);
        den = builder.mul(den, d_i);
    }

    // boundary = sum_aux · D + N
    let sum_times_den = builder.mul(sum_aux, den);
    let boundary = builder.add(sum_times_den, num);

    // Batch with the constraint root using gamma. SAFETY-CRITICAL invariant: this final
    // `add` must be the *last* operation emitted into the builder, since the MASM ACE
    // chip's "is the last op zero?" check evaluates that node as the root.
    let gamma = builder.input(InputKey::Gamma);
    let gamma_boundary = builder.mul(gamma, boundary);
    builder.add(constraint_root, gamma_boundary)
}

/// Encode a bus message as `bus_prefix[bus] + sum(beta^i * elements[i])`.
///
/// The bus prefix provides domain separation: `bus_prefix[bus] = alpha + (bus+1) * gamma_bus`
/// where `gamma_bus = beta^MIDEN_MAX_MESSAGE_WIDTH`. This matches [`lookup::Challenges::encode`].
fn encode_bus_message<EF>(
    builder: &mut DagBuilder<EF>,
    bus: usize,
    elements: &[MessageElement],
) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    use crate::constraints::lookup::messages::MIDEN_MAX_MESSAGE_WIDTH;

    let alpha = builder.input(InputKey::AuxRandAlpha);
    let beta = builder.input(InputKey::AuxRandBeta);

    // gamma_bus = beta^MIDEN_MAX_MESSAGE_WIDTH.
    let mut gamma_bus = builder.constant(EF::ONE);
    for _ in 0..MIDEN_MAX_MESSAGE_WIDTH {
        gamma_bus = builder.mul(gamma_bus, beta);
    }

    // bus_prefix = alpha + (bus + 1) * gamma_bus
    let scale = builder.constant(EF::from(Felt::from_u32((bus as u32) + 1)));
    let offset = builder.mul(gamma_bus, scale);
    let bus_prefix = builder.add(alpha, offset);

    // acc = bus_prefix + sum(beta^i * elem_i)
    //
    // Beta powers are built incrementally; the DagBuilder is hash-consed, so
    // identical beta^i nodes across multiple message encodings are shared
    // automatically.
    let mut acc = bus_prefix;
    let mut beta_power = builder.constant(EF::ONE);
    for elem in elements {
        let node = match elem {
            MessageElement::Constant(f) => builder.constant(EF::from(*f)),
            MessageElement::PublicInput(idx) => builder.input(InputKey::Public(*idx)),
        };
        let term = builder.mul(beta_power, node);
        acc = builder.add(acc, term);
        beta_power = builder.mul(beta_power, beta);
    }
    acc
}

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Build the combined ACE circuit for the (CoreAir, ChipletsAir) multi-AIR proof.
///
/// The output circuit evaluates
///   `combined + γ · boundary = 0`
/// where `combined = chip_acc · β_multi + core_acc` is the β-folded sum of the per-AIR
/// alpha-folded constraint roots, and `boundary` is the cross-AIR LogUp identity built
/// over both AIRs' aux-bus-boundary slots plus the open-bus rational corrections plus
/// the kernel-ROM scalar correction.
///
/// Implementation strategy:
/// 1. Build per-AIR sub-DAGs with their own (single-AIR) layouts via [`build_ace_dag_for_air`].
///    These DAGs encode each AIR's alpha-folded constraints referencing layout-relative
///    `InputKey::Main`/`AuxCoord`/`AuxBusBoundary` slots.
/// 2. Re-emit each sub-DAG's nodes into a fresh `DagBuilder` configured for the *combined* layout.
///    The chiplets sub-DAG's input keys are rewritten so its main/aux/bus-boundary slot indices
///    land in the chiplets-half of the combined layout. The core sub-DAG passes through unchanged.
/// 3. β-fold: `combined = MultiAirBetaCore · core_acc + MultiAirBetaChip · chip_acc`, where the
///    verifier sets one coefficient to β and the other to 1 based on proof_order.
/// 4. Apply the shared boundary via [`batch_logup_boundary_into_builder`] using a
///    [`LogUpBoundaryConfig`] whose `sum_columns` covers both AIRs' boundary slots.
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
    let combined_constraint = builder.sub(combined_acc, chip_qv);

    // Step 6: combined LogUp boundary.
    let combined_boundary_config = multi_air_logup_boundary_config(core_aux_n, chip_aux_n);
    let final_root = batch_logup_boundary_into_builder(
        &mut builder,
        combined_constraint,
        &combined_boundary_config,
    );

    let combined_dag = builder.build(final_root);
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

/// Build the [`LogUpBoundaryConfig`] for the combined multi-AIR ACE circuit.
///
/// Column indices are mapped into the combined layout: Core's LogUp final lives at slot
/// `0..core_aux_n`, Chiplets's at `core_aux_n..core_aux_n + chip_aux_n`.
pub fn multi_air_logup_boundary_config(
    core_aux_n: usize,
    chip_aux_n: usize,
) -> LogUpBoundaryConfig {
    use MessageElement::{Constant, PublicInput};

    use crate::constraints::lookup::messages::BusId;

    // Three rational corrections feeding the combined boundary identity. The open-bus
    // corrections (block-hash + log-precompile) belong to Core's column 0; the kernel-ROM
    // correction belongs to Chiplets.
    let ph_msg = vec![
        PublicInput(PV_PROGRAM_HASH),
        PublicInput(PV_PROGRAM_HASH + 1),
        PublicInput(PV_PROGRAM_HASH + 2),
        PublicInput(PV_PROGRAM_HASH + 3),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
    ];
    let default_lp_msg = vec![
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
    ];
    let final_lp_msg = vec![
        PublicInput(PV_TRANSCRIPT_STATE),
        PublicInput(PV_TRANSCRIPT_STATE + 1),
        PublicInput(PV_TRANSCRIPT_STATE + 2),
        PublicInput(PV_TRANSCRIPT_STATE + 3),
    ];

    // Sum every per-AIR boundary slot. With `num_aux_values()` returning 1 for both
    // CoreAir and ChipletsAir, this is just `[0, 1]` — Core's LogUp final at slot 0
    // and Chiplets's at slot 1 (after the index rewrite).
    let total_slots = core_aux_n + chip_aux_n;
    let sum_columns: Vec<usize> = (0..total_slots).collect();

    LogUpBoundaryConfig {
        sum_columns,
        fractions: vec![
            BusFraction {
                sign: Sign::Plus,
                bus: BusId::BlockHashTable as usize,
                message: ph_msg,
            },
            BusFraction {
                sign: Sign::Plus,
                bus: BusId::LogPrecompileTranscript as usize,
                message: default_lp_msg,
            },
            BusFraction {
                sign: Sign::Minus,
                bus: BusId::LogPrecompileTranscript as usize,
                message: final_lp_msg,
            },
        ],
        scalar_corrections: vec![InputKey::VlpiReduction(0)],
    }
}

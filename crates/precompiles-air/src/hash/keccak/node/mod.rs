//! Keccak transcript-DAG node chiplet.
//!
//! Ties one chunk-absorption chain + one sponge invocation into one
//! Keccak transcript-DAG node and provides `Binding(H_keccak, True, 0, 0)`.
//! One row per Keccak invocation; sticky-downward `act` flag, no
//! periodic columns.
//!
//! Per row, the chip:
//!
//! 1. Issues `KeccakSponge(sponge_seq_id_head, 4·chunk_seq_id_head, len_bytes)` — pins the
//!    invocation's sponge anchor and chunk-tape base.
//! 2. Consumes a `ChunkChain(chunk_seq_id_head, absorption_id_chunks)` provide from the chunk
//!    chiplet — bundles the chunk chain's two foreign keys.
//! 3. Reads the 4-lane Keccak digest `D` from `Memory64` at the round chiplet's perm-N
//!    digest-output addresses, mult 2 (matching the round chiplet's `dst_mult`).
//! 4. Drives one framed Eidos compression chain to hash `D[8 felts]` (block low = lanes 0-1, block
//!    high = lanes 2-3) under VM `Tag::CHUNKS = [2, 0, 0, 0]` → `H_digest_chunks`.
//! 5. Reads `H_input_chunks` from `EidosOut` at `absorption_id_chunks + n_chunks − 1` — the chunks
//!    chain tail.
//! 6. Drives a second framed Eidos compression chain over `[H_input_chunks | H_digest_chunks]`
//!    (block low = H_input_chunks, block high = H_digest_chunks) under the VM Keccak-256 assertion
//!    tag `[Keccak256Precompile::id(), 0, len_bytes, 0]` → `H_keccak`.
//! 7. Provides `Binding(H_keccak, True, 0, 0)`.
//!
//! Continuity (`+n_chunks` on `chunk_seq_id_head`, `+32·n_sponge_perms`
//! on `sponge_seq_id_head`, gated on `act_next`) prevents per-namespace
//! aliasing and gaps across invocations on the two single-producer
//! namespaces (chunk-tape, sponge rows). `absorption_id_chunks` is
//! bus-pinned per row (`ChunkChain`) but not constrained across rows —
//! Eidos is shared with other callers.
//!
//! See the design notes for the design and
//! the design notes for the binding-bus model.

use alloc::vec::Vec;
use core::array;

use miden_core::{
    Felt,
    deferred::Tag,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use miden_precompiles::Keccak256Precompile;

use crate::{
    hash::{chunk::ChunkChainMsg, keccak::sponge::KeccakSpongeMsg, memory64::Memory64Msg},
    logup::{
        ConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, frac_col,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::BindingMsg,
        eidos::{EidosChainInputMsg, EidosOutMsg},
    },
    utils::{current_main, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================
//
// 30 main witness columns:
//
// - Structural (1):     act.
// - Heads / lengths (6): sponge_seq_id_head, n_sponge_perms, chunk_seq_id_head, n_chunks,
//   absorption_id_chunks, len_bytes.
// - Internal Eidos cycles (2): absorption_id_digest_chunks, absorption_id_keccak.
// - Keccak digest (8):  D, interleaved as (lo, hi) per lane × 4 lanes.
// - Computed hashes (12): H_input_chunks[4] || H_digest_chunks[4] || H_keccak[4].
// - Consumer count (1): out_mult, a plain count pinned by Binding balance.

/// Sticky-downward activity flag. Gates every bus multiplicity.
pub const COL_ACT: usize = 0;

/// Sponge invocation start (= sponge's row counter at the first row of
/// this invocation). Pinned by the `KeccakSponge` provide; continuity
/// `sponge_seq_id_head_next = sponge_seq_id_head + 32·n_sponge_perms`
/// keeps the sponge namespace gap-free across invocations.
pub const COL_SPONGE_SEQ_ID_HEAD: usize = 1;
/// Number of Keccak permutations this invocation occupies on the sponge
/// (= sponge blocks). Free witness; the sponge's `bytes_left` /
/// pad-must-fire pin it to `floor(len_bytes / 136) + 1`.
pub const COL_N_SPONGE_PERMS: usize = 2;
/// Head chunk index of this invocation's chunk chain. Pinned by the
/// `ChunkChain` consume; `chunk_seq_id_head_next = chunk_seq_id_head +
/// n_chunks` keeps the chunk-side namespace contiguous.
pub const COL_CHUNK_SEQ_ID_HEAD: usize = 3;
/// Number of chunks in this invocation's chain. Free witness; chunk-side
/// `ChunkChain` bus balance + sponge's `chunk_ptr` chain pin it to
/// `ceil(17·n_sponge_perms / 4)`.
pub const COL_N_CHUNKS: usize = 4;
/// Eidos cycle at the head of this invocation's chunks-absorption chain.
/// Pinned by the `ChunkChain` consume per row (the FK closes there);
/// *not* constrained to be contiguous across keccak-node rows — other
/// Eidos callers (transcript-node hashing, the digest-chunks / keccak
/// one-shots this chiplet drives, …) interleave with chunk-content absorptions,
/// so successive rows' `absorption_id_chunks` values can have gaps.
pub const COL_ABSORPTION_ID_CHUNKS: usize = 5;
/// Invocation byte length. Pinned by the `KeccakSponge` provide.
/// Folded into the Keccak-node hash's `param_a` chain-context slot.
pub const COL_LEN_BYTES: usize = 6;

/// Eidos cycle used internally to hash `D` as a semantic one-chunk payload.
/// Free witness; Eidos-bus balance pins it to an Eidos chiplet cycle running a
/// 1-block absorption.
pub const COL_ABSORPTION_ID_DIGEST_CHUNKS: usize = 7;
/// Eidos cycle used internally to hash `[H_input_chunks | H_digest_chunks]`
/// into the Keccak node. Free witness; same pinning as
/// `absorption_id_digest_chunks`.
pub const COL_ABSORPTION_ID_KECCAK: usize = 8;

/// First of the 8 Keccak-digest content felts, laid out as
/// `[lo_0, hi_0, lo_1, hi_1, lo_2, hi_2, lo_3, hi_3]`. Lane `j` is
/// `(D[2j], D[2j+1])` on Memory64. The digest-chunks Eidos compression uses
/// `block_lo = D[0..4]` (lanes 0-1) and `block_hi = D[4..8]` (lanes 2-3).
pub const COL_D_BEGIN: usize = 9;
/// Number of digest-content felts.
pub const NUM_D: usize = 8;
/// One past the last digest felt.
pub const COL_D_END: usize = COL_D_BEGIN + NUM_D;

/// Number of felts in each 4-felt hash.
pub const NUM_HASH: usize = 4;

/// First felt of the input chunks-chain digest read out of `EidosOut`
/// at `absorption_id_chunks + n_chunks − 1`. Feeds the first block word of the
/// Keccak-node Eidos compression.
pub const COL_H_INPUT_CHUNKS_BEGIN: usize = COL_D_END;
pub const COL_H_INPUT_CHUNKS_END: usize = COL_H_INPUT_CHUNKS_BEGIN + NUM_HASH;

/// First felt of the digest-chunks hash (output of the digest-chunks Eidos chain). Read from
/// `EidosOut` at `absorption_id_digest_chunks`. Feeds the second block word of the Keccak-node
/// Eidos compression.
pub const COL_H_DIGEST_CHUNKS_BEGIN: usize = COL_H_INPUT_CHUNKS_END;
pub const COL_H_DIGEST_CHUNKS_END: usize = COL_H_DIGEST_CHUNKS_BEGIN + NUM_HASH;

/// First felt of the Keccak-node hash (output of the framed Eidos compression chain).
/// Read from `EidosOut` at `absorption_id_keccak`; provided as the
/// `h` key of `Binding(H_keccak, True, 0, 0)`.
pub const COL_H_KECCAK_BEGIN: usize = COL_H_DIGEST_CHUNKS_END;
pub const COL_H_KECCAK_END: usize = COL_H_KECCAK_BEGIN + NUM_HASH;

/// Witnessed per-row count of downstream consumers of the
/// `Binding(H_keccak, True, 0, 0)` provide — a plain count pinned to the
/// consumer count by `Binding` bus balance (not range-checked; see
/// the design notes) and pinned to 0 on inactive rows by
/// `(1 − act) · out_mult = 0`. Lets a `KeccakNodeRequires` dedupe by
/// Keccak digest and tally consumers without re-emitting the Binding
/// tuple per consumer — true dedup, one row per digest at any count.
pub const COL_OUT_MULT: usize = COL_H_KECCAK_END;

/// Total number of main witness columns.
pub const NUM_MAIN_COLS: usize = COL_OUT_MULT + 1;

// AUX / PUBLIC LAYOUT
// ================================================================================================

/// Seven aux columns, flattened via `frac_col!` so every closing
/// constraint stays at degree ≤ 3 → `log_quotient_degree = 1`:
///
/// - col 0: `KeccakSponge` provide alone.
/// - col 1: `Binding(_, True, 0, 0)` provide + `ChunkChain` consume.
/// - col 2: `EidosOut(H_input_chunks)` consume alone (no partner left to pair).
/// - col 3/4: the four `Memory64` D-limb consumes, paired.
/// - col 5: atomic digest-chunks `EidosIn` + `EidosOut(H_digest_chunks)`.
/// - col 6: atomic keccak-node `EidosIn` + `EidosOut(H_keccak)`.
pub const NUM_AUX_COLS: usize = 7;

pub(crate) const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 2, 1, 2, 2, 2, 2];

// AIR
// ================================================================================================

/// Keccak transcript-DAG node chiplet AIR. Period 1.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeccakNodeAir;

impl BaseAir<Felt> for KeccakNodeAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

// LIFTED AIR — local constraints
// ================================================================================================

impl LiftedAir<Felt, QuadFelt> for KeccakNodeAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        NUM_LOGUP_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        crate::logup::build_logup_aux_trace(&KeccakNodeAir, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        eval_main(builder, 0);

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

/// Evaluate this component's base constraints in a main-trace column band.
pub(crate) fn eval_main<AB>(builder: &mut AB, main_col_offset: usize)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);
    let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), main_col_offset);

    let act: AB::Expr = local[COL_ACT].into();
    let act_next: AB::Expr = next[COL_ACT].into();
    let out_mult: AB::Expr = local[COL_OUT_MULT].into();

    let sponge_seq_id_head: AB::Expr = local[COL_SPONGE_SEQ_ID_HEAD].into();
    let sponge_seq_id_head_next: AB::Expr = next[COL_SPONGE_SEQ_ID_HEAD].into();
    let n_sponge_perms: AB::Expr = local[COL_N_SPONGE_PERMS].into();

    let chunk_seq_id_head: AB::Expr = local[COL_CHUNK_SEQ_ID_HEAD].into();
    let chunk_seq_id_head_next: AB::Expr = next[COL_CHUNK_SEQ_ID_HEAD].into();
    let n_chunks: AB::Expr = local[COL_N_CHUNKS].into();

    // `absorption_id_chunks` is read only by the LookupAir below
    // (no local cross-row constraint — see the comment in the
    // namespace-continuity section).
    let _ = next[COL_ABSORPTION_ID_CHUNKS];

    // Boundary -----------------------------------------------
    // Pin `sponge_seq_id_head` and `chunk_seq_id_head` at row 0 to
    // align the orchestrator's first invocation with the sponge's
    // and chunk chiplet's row-0 anchors. Ungated by `act` — an
    // all-inactive trace's prover sets them to 0 anyway, and the
    // gating cost (one mult) is not worth it.
    builder.when_first_row().assert_zero(sponge_seq_id_head.clone());
    builder.when_first_row().assert_zero(chunk_seq_id_head.clone());

    // Activity -----------------------------------------------
    // Binary, sticky-downward (matches chunk / sponge convention).
    builder.assert_bool(local[COL_ACT]);
    builder
        .when_transition()
        .assert_zero((AB::Expr::ONE - act.clone()) * act_next.clone());

    // out_mult on inactive rows --------------------------------
    // Pin `out_mult = 0` on dead rows so the `Binding` provide
    // (mult = `−out_mult`) contributes 0 on padding. Deg 2.
    builder.assert_zero((AB::Expr::ONE - act) * out_mult);

    // Continuity (gated on `act_next`) -----------------------
    // sponge namespace: 32 sponge rows per perm.
    builder.when_transition().assert_zero(
        act_next.clone()
            * (sponge_seq_id_head_next
                - sponge_seq_id_head
                - AB::Expr::from(Felt::from(32u8)) * n_sponge_perms),
    );
    // chunk namespace.
    builder
        .when_transition()
        .assert_zero(act_next * (chunk_seq_id_head_next - chunk_seq_id_head - n_chunks));
    // No Eidos chunks-absorption namespace continuity. Other Eidos
    // callers (transcript-node hashing, the digest-chunks / keccak
    // one-shots this chiplet drives, …) interleave with chunk-
    // content absorptions, so `absorption_id_chunks` is *not*
    // contiguous across keccak-node rows. The `ChunkChain` bus
    // pins each row's `(chunk_seq_id_head, absorption_id_chunks)`
    // pair to a real chunk-side chain head, which is what closes
    // the FK — see the chunk chiplet's `absorption_id` column doc
    // for the matching shared-namespace argument.
}

// LOOKUP AIR — bus interactions
// ================================================================================================

impl<LB> LookupAir<LB> for KeccakNodeAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);

        let act: LB::Expr = local[COL_ACT].into();
        let sponge_seq_id_head: LB::Expr = local[COL_SPONGE_SEQ_ID_HEAD].into();
        let n_sponge_perms: LB::Expr = local[COL_N_SPONGE_PERMS].into();
        let chunk_seq_id_head: LB::Expr = local[COL_CHUNK_SEQ_ID_HEAD].into();
        let n_chunks: LB::Expr = local[COL_N_CHUNKS].into();
        let absorption_id_chunks: LB::Expr = local[COL_ABSORPTION_ID_CHUNKS].into();
        let len_bytes: LB::Expr = local[COL_LEN_BYTES].into();
        let absorption_id_digest_chunks: LB::Expr = local[COL_ABSORPTION_ID_DIGEST_CHUNKS].into();
        let absorption_id_keccak: LB::Expr = local[COL_ABSORPTION_ID_KECCAK].into();

        let d: [LB::Expr; NUM_D] = array::from_fn(|i| local[COL_D_BEGIN + i].into());
        let h_input_chunks: [LB::Expr; NUM_HASH] =
            array::from_fn(|i| local[COL_H_INPUT_CHUNKS_BEGIN + i].into());
        let h_digest_chunks: [LB::Expr; NUM_HASH] =
            array::from_fn(|i| local[COL_H_DIGEST_CHUNKS_BEGIN + i].into());
        let h_keccak: [LB::Expr; NUM_HASH] =
            array::from_fn(|i| local[COL_H_KECCAK_BEGIN + i].into());

        // Multiplicities.
        let neg_act: LB::Expr = LB::Expr::ZERO - act.clone();
        let pos_act: LB::Expr = act.clone();
        let pos_act_x2: LB::Expr = LB::Expr::from(Felt::from(2u8)) * act;
        let out_mult: LB::Expr = local[COL_OUT_MULT].into();
        let neg_out_mult: LB::Expr = LB::Expr::ZERO - out_mult;

        // Derived addresses / cycles.
        // chunk_ptr_head = 4·chunk_seq_id_head — the bus-side
        // conversion lives here, not in the chunk chiplet.
        let chunk_ptr_head: LB::Expr = LB::Expr::from(Felt::from(4u8)) * chunk_seq_id_head.clone();
        // absorption_id_chunks_tail = absorption_id_chunks + n_chunks − 1.
        let absorption_id_chunks_tail: LB::Expr =
            absorption_id_chunks.clone() + n_chunks - LB::Expr::ONE;
        // Digest-lane Memory64 addresses. Sponge's `addr_squeeze =
        // 100·sponge_seq_id − 99·p_idx + 3072` at the last block's
        // digest rows (`p_idx ∈ [0, 4)` of the last period) reduces to
        // `100·sponge_seq_id_head + 3200·n_sponge_perms − 128 + j`. The
        // round chiplet provides these lanes at `dst_mult = 2`; we are
        // the sole consumer, so the consume mult is `2·act`.
        let digest_addr_base: LB::Expr = LB::Expr::from(Felt::from(100u8)) * sponge_seq_id_head
            + LB::Expr::from(Felt::from(3200u32)) * n_sponge_perms
            - LB::Expr::from(Felt::from(128u8));

        // Eidos chain contexts.
        let chain_context_digest_chunks = Tag::CHUNKS.as_word().map(LB::Expr::from);
        let chain_context_keccak = [
            LB::Expr::from(Keccak256Precompile::id()),
            LB::Expr::from(Felt::from_u32(Keccak256Precompile::ASSERT_TAG_ID)),
            len_bytes.clone(),
            LB::Expr::ZERO,
        ];

        let interaction_deg = Deg { v: 1, u: 1 };
        let provides_deg = Deg { v: 1, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };

        // col 0: KeccakSponge request alone.
        frac_col!(
            builder,
            "handshake-and-chunks-digest",
            provides_deg,
            (
                "ks-request",
                neg_act.clone(),
                KeccakSpongeMsg {
                    sponge_seq_id: local[COL_SPONGE_SEQ_ID_HEAD].into(),
                    chunk_ptr: chunk_ptr_head,
                    len_bytes: len_bytes.clone(),
                },
                interaction_deg
            ),
        );
        // col 1 (paired, lqd-1): Binding truth provide + ChunkChain consume.
        frac_col!(
            builder,
            "handshake-and-chunks-digest",
            pair_deg,
            (
                "binding-truth",
                neg_out_mult,
                BindingMsg::truth(h_keccak.clone()),
                interaction_deg
            ),
            (
                "chunk-chain",
                pos_act.clone(),
                ChunkChainMsg {
                    chunk_seq_id_head: chunk_seq_id_head.clone(),
                    absorption_id_head: absorption_id_chunks,
                },
                interaction_deg
            ),
        );
        // col 2: EidosOut(H_input_chunks) consume alone (no partner
        // left to pair).
        frac_col!(
            builder,
            "handshake-and-chunks-digest",
            provides_deg,
            (
                "p2out-h-input-chunks",
                pos_act.clone(),
                EidosOutMsg {
                    chain_step_id: absorption_id_chunks_tail,
                    digest: h_input_chunks.clone(),
                },
                interaction_deg
            ),
        );

        // ---- col 3/4: 4 Memory64 D-limb consumes, paired -------
        let addr_lane =
            |j: u8| -> LB::Expr { digest_addr_base.clone() + LB::Expr::from(Felt::from(j)) };
        frac_col!(
            builder,
            "memory64-d-limbs",
            pair_deg,
            (
                "d-lane-0",
                pos_act_x2.clone(),
                Memory64Msg {
                    addr: addr_lane(0),
                    lo: d[0].clone(),
                    hi: d[1].clone()
                },
                interaction_deg
            ),
            (
                "d-lane-1",
                pos_act_x2.clone(),
                Memory64Msg {
                    addr: addr_lane(1),
                    lo: d[2].clone(),
                    hi: d[3].clone()
                },
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "memory64-d-limbs",
            pair_deg,
            (
                "d-lane-2",
                pos_act_x2.clone(),
                Memory64Msg {
                    addr: addr_lane(2),
                    lo: d[4].clone(),
                    hi: d[5].clone()
                },
                interaction_deg
            ),
            (
                "d-lane-3",
                pos_act_x2,
                Memory64Msg {
                    addr: addr_lane(3),
                    lo: d[6].clone(),
                    hi: d[7].clone()
                },
                interaction_deg
            ),
        );

        // ---- col 5: one atomic digest-chunks input + its output -------------------------------
        frac_col!(
            builder,
            "digest-chunks-eidos",
            pair_deg,
            (
                "eidos-chain-input",
                pos_act.clone(),
                EidosChainInputMsg::chunks(
                    absorption_id_digest_chunks.clone(),
                    LB::Expr::ONE,
                    d,
                    chain_context_digest_chunks,
                ),
                interaction_deg
            ),
            (
                "eidos-chain-output",
                pos_act.clone(),
                EidosOutMsg {
                    chain_step_id: absorption_id_digest_chunks,
                    digest: h_digest_chunks.clone(),
                },
                interaction_deg
            ),
        );

        // ---- col 6: one atomic keccak-node input + its output ---------------------------------
        frac_col!(
            builder,
            "keccak-eidos",
            pair_deg,
            (
                "eidos-chain-input",
                pos_act.clone(),
                EidosChainInputMsg::node(
                    absorption_id_keccak.clone(),
                    LB::Expr::ONE,
                    array::from_fn(|idx| {
                        if idx < 4 {
                            h_input_chunks[idx].clone()
                        } else {
                            h_digest_chunks[idx - 4].clone()
                        }
                    }),
                    chain_context_keccak,
                ),
                interaction_deg
            ),
            (
                "eidos-chain-output",
                pos_act,
                EidosOutMsg {
                    chain_step_id: absorption_id_keccak,
                    digest: h_keccak
                },
                interaction_deg
            ),
        );
    }
}

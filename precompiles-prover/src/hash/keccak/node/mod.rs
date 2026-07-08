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
//! 2. Consumes a `ChunkChain(chunk_seq_id_head, perm_seq_id_chunks)` provide from the chunk chiplet
//!    — bundles the chunk chain's two foreign keys.
//! 3. Reads the 4-lane Keccak digest `D` from `Memory64` at the round chiplet's perm-N
//!    digest-output addresses, mult 2 (matching the round chiplet's `dst_mult`).
//! 4. Drives one Poseidon2 perm to hash `D[8 felts]` (rate0 = lanes 0-1, rate1 = lanes 2-3) under
//!    VM `Tag::CHUNKS = [2, 0, 0, 0]` → `H_digest_chunks`.
//! 5. Reads `H_input_chunks` from `Poseidon2Out` at `perm_seq_id_chunks + n_chunks − 1` — the
//!    chunks chain tail.
//! 6. Drives a second Poseidon2 perm over `[H_input_chunks | H_digest_chunks]` (rate0 =
//!    H_input_chunks, rate1 = H_digest_chunks) under the VM Keccak-256 assertion tag
//!    `[Keccak256Precompile::id(), 0, len_bytes, 0]` → `H_keccak`.
//! 7. Provides `Binding(H_keccak, True, 0, 0)`.
//!
//! Continuity (`+n_chunks` on `chunk_seq_id_head`, `+32·n_sponge_perms`
//! on `sponge_seq_id_head`, gated on `act_next`) prevents per-namespace
//! aliasing and gaps across invocations on the two single-producer
//! namespaces (chunk-tape, sponge rows). `perm_seq_id_chunks` is
//! bus-pinned per row (`ChunkChain`) but not constrained across rows —
//! P2 is shared with other callers.
//!
//! See `docs/chiplets/keccak-node.md` for the design and
//! `docs/transcript-eval.md` for the binding-bus model.

pub mod trace;

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
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::BindingMsg,
        poseidon2::{Poseidon2InMsg, Poseidon2OutMsg},
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
//   perm_seq_id_chunks, len_bytes.
// - Internal P2 cycles (2): perm_seq_id_digest_chunks, perm_seq_id_keccak.
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
/// P2 cycle at the head of this invocation's chunks-absorption chain.
/// Pinned by the `ChunkChain` consume per row (the FK closes there);
/// *not* constrained to be contiguous across keccak-node rows — other
/// P2 callers (transcript-node hashing, the digest-chunks / keccak
/// one-shots this chiplet drives, …) interleave with chunk-content absorptions,
/// so successive rows' `perm_seq_id_chunks` values can have gaps.
pub const COL_PERM_SEQ_ID_CHUNKS: usize = 5;
/// Invocation byte length. Pinned by the `KeccakSponge` provide.
/// Folded into the Keccak-node hash's `param_a` cap slot.
pub const COL_LEN_BYTES: usize = 6;

/// P2 cycle used internally to hash `D` as a semantic one-chunk payload.
/// Free witness; P2-bus balance pins it to a P2 chiplet cycle running a
/// 1-block absorption.
pub const COL_PERM_SEQ_ID_DIGEST_CHUNKS: usize = 7;
/// P2 cycle used internally to hash `[H_input_chunks | H_digest_chunks]`
/// into the Keccak node. Free witness; same pinning as
/// `perm_seq_id_digest_chunks`.
pub const COL_PERM_SEQ_ID_KECCAK: usize = 8;

/// First of the 8 Keccak-digest content felts, laid out as
/// `[lo_0, hi_0, lo_1, hi_1, lo_2, hi_2, lo_3, hi_3]`. Lane `j` is
/// `(D[2j], D[2j+1])` on Memory64; `rate0 = D[0..4]` (lanes 0-1),
/// `rate1 = D[4..8]` (lanes 2-3) on the digest-chunks P2 perm.
pub const COL_D_BEGIN: usize = 9;
/// Number of digest-content felts.
pub const NUM_D: usize = 8;
/// One past the last digest felt.
pub const COL_D_END: usize = COL_D_BEGIN + NUM_D;

/// Number of felts in each 4-felt hash.
pub const NUM_HASH: usize = 4;

/// First felt of the input chunks-chain digest read out of `Poseidon2Out`
/// at `perm_seq_id_chunks + n_chunks − 1`. Feeds the keccak-node P2 perm
/// as `rate0`.
pub const COL_H_INPUT_CHUNKS_BEGIN: usize = COL_D_END;
pub const COL_H_INPUT_CHUNKS_END: usize = COL_H_INPUT_CHUNKS_BEGIN + NUM_HASH;

/// First felt of the digest-chunks hash (output of the digest-chunks P2
/// perm). Read from `Poseidon2Out` at `perm_seq_id_digest_chunks`. Feeds
/// the keccak-node P2 perm as `rate1`.
pub const COL_H_DIGEST_CHUNKS_BEGIN: usize = COL_H_INPUT_CHUNKS_END;
pub const COL_H_DIGEST_CHUNKS_END: usize = COL_H_DIGEST_CHUNKS_BEGIN + NUM_HASH;

/// First felt of the Keccak-node hash (output of the keccak P2 perm).
/// Read from `Poseidon2Out` at `perm_seq_id_keccak`; provided as the
/// `h` key of `Binding(H_keccak, True, 0, 0)`.
pub const COL_H_KECCAK_BEGIN: usize = COL_H_DIGEST_CHUNKS_END;
pub const COL_H_KECCAK_END: usize = COL_H_KECCAK_BEGIN + NUM_HASH;

/// Witnessed per-row count of downstream consumers of the
/// `Binding(H_keccak, True, 0, 0)` provide — a plain count pinned to the
/// consumer count by `Binding` bus balance (not range-checked; see
/// `docs/lookup-argument.md`) and pinned to 0 on inactive rows by
/// `(1 − act) · out_mult = 0`. Lets a `KeccakNodeRequires` dedupe by
/// Keccak digest and tally consumers without re-emitting the Binding
/// tuple per consumer — true dedup, one row per digest at any count.
pub const COL_OUT_MULT: usize = COL_H_KECCAK_END;

/// Total number of main witness columns.
pub const NUM_MAIN_COLS: usize = COL_OUT_MULT + 1;

// AUX / PUBLIC LAYOUT
// ================================================================================================

/// Four aux columns, each with one group / one batch:
///
/// - col 0: running σ + `KeccakSponge` provide + `Binding(_, True, 0, 0)` provide + `ChunkChain`
///   consume + `Poseidon2Out(H_input_chunks)` consume (4 inserts).
/// - col 1: four `Memory64` D-limb consumes (one per digest lane).
/// - col 2: digest-chunks P2 perm — three `Poseidon2In` consumes (rate0, rate1, cap) + one
///   `Poseidon2Out(H_digest_chunks)` consume.
/// - col 3: keccak-node P2 perm — three `Poseidon2In` consumes + one `Poseidon2Out(H_keccak)`
///   consume.
///
/// All cols keep mults at degree ≤ 1 (× `act` or `out_mult`). The
/// ungated fraction columns (1, 2, 3) land at `4 + 1 = 5`, but col 0
/// hosts the σ-closing, whose last-row close is gated by `is_transition`
/// / `is_last_row` (degree-1 selectors), so its batch of 4 lands at
/// `4 + 2 = 6`. Max constraint deg 6 → `log_quotient_degree = 3` (was
/// deg 5 → lqd 2 under the older ungated σ/n form).
pub const NUM_AUX_COLS: usize = 4;

const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [4, 4, 4, 4];

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
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        trace::build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let act: AB::Expr = local[COL_ACT].into();
        let act_next: AB::Expr = next[COL_ACT].into();
        let out_mult: AB::Expr = local[COL_OUT_MULT].into();

        let sponge_seq_id_head: AB::Expr = local[COL_SPONGE_SEQ_ID_HEAD].into();
        let sponge_seq_id_head_next: AB::Expr = next[COL_SPONGE_SEQ_ID_HEAD].into();
        let n_sponge_perms: AB::Expr = local[COL_N_SPONGE_PERMS].into();

        let chunk_seq_id_head: AB::Expr = local[COL_CHUNK_SEQ_ID_HEAD].into();
        let chunk_seq_id_head_next: AB::Expr = next[COL_CHUNK_SEQ_ID_HEAD].into();
        let n_chunks: AB::Expr = local[COL_N_CHUNKS].into();

        // `perm_seq_id_chunks` is read only by the LookupAir below
        // (no local cross-row constraint — see the comment in the
        // namespace-continuity section).
        let _ = next[COL_PERM_SEQ_ID_CHUNKS];

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
        // No P2 chunks-absorption namespace continuity. Other P2
        // callers (transcript-node hashing, the digest-chunks / keccak
        // one-shots this chiplet drives, …) interleave with chunk-
        // content absorptions, so `perm_seq_id_chunks` is *not*
        // contiguous across keccak-node rows. The `ChunkChain` bus
        // pins each row's `(chunk_seq_id_head, perm_seq_id_chunks)`
        // pair to a real chunk-side chain head, which is what closes
        // the FK — see the chunk chiplet's `perm_seq_id` column doc
        // for the matching shared-namespace argument.

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR — bus interactions
// ================================================================================================

impl<LB> LookupAir<LB> for KeccakNodeAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_AUX_COLS
    }

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
        let perm_seq_id_chunks: LB::Expr = local[COL_PERM_SEQ_ID_CHUNKS].into();
        let len_bytes: LB::Expr = local[COL_LEN_BYTES].into();
        let perm_seq_id_digest_chunks: LB::Expr = local[COL_PERM_SEQ_ID_DIGEST_CHUNKS].into();
        let perm_seq_id_keccak: LB::Expr = local[COL_PERM_SEQ_ID_KECCAK].into();

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
        // perm_seq_id_chunks_tail = perm_seq_id_chunks + n_chunks − 1.
        let perm_seq_id_chunks_tail: LB::Expr =
            perm_seq_id_chunks.clone() + n_chunks - LB::Expr::ONE;
        // Digest-lane Memory64 addresses. Sponge's `addr_squeeze =
        // 100·sponge_seq_id − 99·p_idx + 3072` at the last block's
        // digest rows (`p_idx ∈ [0, 4)` of the last period) reduces to
        // `100·sponge_seq_id_head + 3200·n_sponge_perms − 128 + j`. The
        // round chiplet provides these lanes at `dst_mult = 2`; we are
        // the sole consumer, so the consume mult is `2·act`.
        let digest_addr_base: LB::Expr = LB::Expr::from(Felt::from(100u8)) * sponge_seq_id_head
            + LB::Expr::from(Felt::from(3200u32)) * n_sponge_perms
            - LB::Expr::from(Felt::from(128u8));

        // Capacities.
        let cap_digest_chunks = Tag::CHUNKS.as_word().map(LB::Expr::from);
        let cap_keccak = [
            LB::Expr::from(Keccak256Precompile::id()),
            LB::Expr::from(Felt::from_u32(Keccak256Precompile::ASSERT_TAG_ID)),
            len_bytes.clone(),
            LB::Expr::ZERO,
        ];

        // Rate splits.
        let d_rate0 = [d[0].clone(), d[1].clone(), d[2].clone(), d[3].clone()];
        let d_rate1 = [d[4].clone(), d[5].clone(), d[6].clone(), d[7].clone()];

        let interaction_deg = Deg { v: 1, u: 1 };
        // All aux columns: 1 batch of 4 inserts, each mult deg 1
        // (× act). d = 4, n = 4. Ungated fraction columns (1, 2, 3)
        // land at max(1 + 4, 4) = 5; col 0 carries the σ-closing's
        // `is_transition` / `is_last_row` gate (+1 over the old ungated
        // σ/n form), so it lands at 6. Max constraint deg 6 →
        // log_quotient_degree = 3.
        let aux_deg = Deg { v: 4, u: 4 };

        // ---- col 0: KS + Binding + ChunkChain + P2Out(H_input_chunks) ----
        builder.next_column(
            |col| {
                col.group(
                    "handshake-and-chunks-digest",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "ks-request",
                                    neg_act.clone(),
                                    KeccakSpongeMsg {
                                        sponge_seq_id: local[COL_SPONGE_SEQ_ID_HEAD].into(),
                                        chunk_ptr: chunk_ptr_head,
                                        len_bytes: len_bytes.clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "binding-truth",
                                    neg_out_mult,
                                    BindingMsg::truth(h_keccak.clone()),
                                    interaction_deg,
                                );
                                b.insert(
                                    "chunk-chain",
                                    pos_act.clone(),
                                    ChunkChainMsg {
                                        chunk_seq_id_head: chunk_seq_id_head.clone(),
                                        perm_seq_id_head: perm_seq_id_chunks,
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "p2out-h-input-chunks",
                                    pos_act.clone(),
                                    Poseidon2OutMsg {
                                        perm_seq_id: perm_seq_id_chunks_tail,
                                        digest: h_input_chunks.clone(),
                                    },
                                    interaction_deg,
                                );
                            },
                            aux_deg,
                        );
                    },
                    aux_deg,
                );
            },
            aux_deg,
        );

        // ---- col 1: 4 Memory64 D-limb consumes -----------------
        let addr_lane =
            |j: u8| -> LB::Expr { digest_addr_base.clone() + LB::Expr::from(Felt::from(j)) };
        builder.next_column(
            |col| {
                col.group(
                    "memory64-d-limbs",
                    |g| {
                        g.batch(
                            "lanes",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "d-lane-0",
                                    pos_act_x2.clone(),
                                    Memory64Msg {
                                        addr: addr_lane(0),
                                        lo: d[0].clone(),
                                        hi: d[1].clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "d-lane-1",
                                    pos_act_x2.clone(),
                                    Memory64Msg {
                                        addr: addr_lane(1),
                                        lo: d[2].clone(),
                                        hi: d[3].clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "d-lane-2",
                                    pos_act_x2.clone(),
                                    Memory64Msg {
                                        addr: addr_lane(2),
                                        lo: d[4].clone(),
                                        hi: d[5].clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "d-lane-3",
                                    pos_act_x2,
                                    Memory64Msg {
                                        addr: addr_lane(3),
                                        lo: d[6].clone(),
                                        hi: d[7].clone(),
                                    },
                                    interaction_deg,
                                );
                            },
                            aux_deg,
                        );
                    },
                    aux_deg,
                );
            },
            aux_deg,
        );

        // ---- col 2: digest-chunks P2 perm — 3 P2In + 1 P2Out ------
        builder.next_column(
            |col| {
                col.group(
                    "digest-chunks-p2",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "p2in-rate0",
                                    pos_act.clone(),
                                    Poseidon2InMsg::rate0(
                                        perm_seq_id_digest_chunks.clone(),
                                        d_rate0,
                                    ),
                                    interaction_deg,
                                );
                                b.insert(
                                    "p2in-rate1",
                                    pos_act.clone(),
                                    Poseidon2InMsg::rate1(
                                        perm_seq_id_digest_chunks.clone(),
                                        d_rate1,
                                    ),
                                    interaction_deg,
                                );
                                b.insert(
                                    "p2in-cap",
                                    pos_act.clone(),
                                    Poseidon2InMsg::cap(
                                        perm_seq_id_digest_chunks.clone(),
                                        cap_digest_chunks,
                                    ),
                                    interaction_deg,
                                );
                                b.insert(
                                    "p2out-h-digest-chunks",
                                    pos_act.clone(),
                                    Poseidon2OutMsg {
                                        perm_seq_id: perm_seq_id_digest_chunks,
                                        digest: h_digest_chunks.clone(),
                                    },
                                    interaction_deg,
                                );
                            },
                            aux_deg,
                        );
                    },
                    aux_deg,
                );
            },
            aux_deg,
        );

        // ---- col 3: keccak-node P2 perm — 3 P2In + 1 P2Out -----
        builder.next_column(
            |col| {
                col.group(
                    "keccak-p2",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "p2in-rate0",
                                    pos_act.clone(),
                                    Poseidon2InMsg::rate0(
                                        perm_seq_id_keccak.clone(),
                                        h_input_chunks,
                                    ),
                                    interaction_deg,
                                );
                                b.insert(
                                    "p2in-rate1",
                                    pos_act.clone(),
                                    Poseidon2InMsg::rate1(
                                        perm_seq_id_keccak.clone(),
                                        h_digest_chunks,
                                    ),
                                    interaction_deg,
                                );
                                b.insert(
                                    "p2in-cap",
                                    pos_act.clone(),
                                    Poseidon2InMsg::cap(perm_seq_id_keccak.clone(), cap_keccak),
                                    interaction_deg,
                                );
                                b.insert(
                                    "p2out-h-keccak",
                                    pos_act,
                                    Poseidon2OutMsg {
                                        perm_seq_id: perm_seq_id_keccak,
                                        digest: h_keccak,
                                    },
                                    interaction_deg,
                                );
                            },
                            aux_deg,
                        );
                    },
                    aux_deg,
                );
            },
            aux_deg,
        );
    }
}

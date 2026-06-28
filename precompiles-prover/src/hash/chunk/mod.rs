//! Chunk chiplet.
//!
//! Feeds input-byte chunks to any downstream hasher over the
//! [`Memory64`](super::memory64) bus and content-hashes each
//! invocation's chunks by driving a Poseidon2 absorption chain over
//! the [`Poseidon2In`](crate::relations::BusId::Poseidon2In) bus. One
//! row per 32-byte chunk = 8 u32 felts = one Poseidon2 absorption
//! block (`rate0[4] || rate1[4]`).
//!
//! See [`docs/chiplets/chunk.md`](../../../docs/chiplets/chunk.md) for
//! the design. The chiplet does not read the Poseidon2 digest —
//! `OutRate0` is the downstream digest consumer's to consume.

pub mod message;
pub mod trace;

use core::array;

pub use message::ChunkChainMsg;
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    hash::memory64::{CHUNK_ADDR_BASE, Memory64Msg},
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::poseidon2::Poseidon2InMsg,
    utils::{current_main, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================
//
// 16 main witness columns:
//
// - Structural (3): chunk_seq_id, perm_seq_id, act.
// - Selector (1):   is_head.
// - Content (8):    f[0..8] — the chunk's 8 u32 felts.
// - Capacity (4):   cap[0..4] — Poseidon2 capacity for the chunk chain head.
//
// See `docs/chiplets/chunk.md` §"Columns".

/// Sequential chunk index; +1 per row, row 0 = 0. `4·chunk_seq_id` is
/// the chunk's Memory64 tape base (the chiplet is the sole producer of
/// its `CHUNK_ADDR_BASE` namespace, so global-sequential is sound).
pub const COL_CHUNK_SEQ_ID: usize = 0;
/// Poseidon2 cycle id this row's absorption binds to — a foreign key
/// into the P2 chiplet's shared cycle namespace. Constrained by a
/// within-chain `+1` relaxed at chain heads (not a global sequence);
/// the lockstep with `chunk_seq_id` forces P2's absorption order to
/// match the downstream hasher's Memory64 order.
pub const COL_PERM_SEQ_ID: usize = 1;
/// Sticky-downward activity flag. Gates every bus multiplicity so dead
/// trace-tail rows contribute nothing.
pub const COL_ACT: usize = 2;
/// 1 on the chain-head row of each invocation (its first chunk). Gates
/// the `InCap` consume and determines the P2 chain structure
/// (`is_absorb = 1 − is_head`, tied by the `InCap` bus balance).
pub const COL_IS_HEAD: usize = 3;
/// First of the 8 chunk-content felts. `lane_j = (f[2j], f[2j+1])` on
/// Memory64; `rate0 = f[0..4]`, `rate1 = f[4..8]` on Poseidon2. Every
/// chunk emits all four lanes; per-hasher block-fit (leftover-lane
/// handling, padding) lives downstream, not here.
pub const COL_F_BEGIN: usize = 4;
/// Number of chunk-content felts.
pub const NUM_F: usize = 8;
/// One past the last content felt.
pub const COL_F_END: usize = COL_F_BEGIN + NUM_F;
/// First of the 4 Poseidon2 capacity felts for this invocation.
pub const COL_CAP_BEGIN: usize = COL_F_END;
pub const NUM_CAP: usize = 4;
/// One past the last capacity felt.
pub const COL_CAP_END: usize = COL_CAP_BEGIN + NUM_CAP;

/// Total number of main witness columns.
pub const NUM_MAIN_COLS: usize = COL_CAP_END;

// AUX / PUBLIC LAYOUT
// ================================================================================================

/// Three aux columns, following the `bitwise64` chaining pattern:
/// - col 0: running σ + Memory64 fractions (one group, one batch of 4 product inserts — all four
///   lanes every active row).
/// - col 1: Poseidon2 fractions (one group, one batch of 3 product inserts — rate0/rate1 every row,
///   InCap on chain heads).
/// - col 2: ChunkChain fractions (one group, one batch of 1 insert — chain-head emit, mult
///   `−act·is_head`).
///
/// Col 0 hosts the σ-closing, so its last-row close is gated by
/// `is_transition` / `is_last_row` (degree-1 selectors): a col-0 batch
/// of 4 fractions lands at `4 + 2 = 6`, vs the ungated fraction columns'
/// `k + 1`. Max per-column constraint deg 6 → `log_quotient_degree = 3`
/// (was deg 5 → lqd 2 under the older ungated σ/n form, which closed on
/// the wrap with a degree-0 `σ·inv_n` correction instead of a gate).
pub const NUM_AUX_COLS: usize = 3;

/// Per-column insert counts: col 0 = 4 Memory64 lanes, col 1 = 3
/// Poseidon2In messages (rate0, rate1, cap), col 2 = 1 ChunkChain emit.
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [4, 3, 1];

// The single exposed σ ([`NUM_SIGMA_VALUES`]) follows the VM-wide σ
// contract in [`crate::logup`]; aggregating the Memory64 + Poseidon2In
// residues into one σ is the shared shape, not a chunk-specific choice.
// The shared public values ([`NUM_PUBLIC_VALUES`]) are the transcript
// root alone — declared but not read here; the natural last-row closing
// needs no `inv_n` height input.

// AIR
// ================================================================================================

/// Chunk chiplet AIR. Period 1 (no periodic columns). Provides chunk
/// lanes on [`Memory64`](crate::hash::memory64) and consumes the
/// Poseidon2 rate / chain-head capacity on
/// [`Poseidon2In`](crate::relations::BusId::Poseidon2In).
#[derive(Debug, Default, Clone, Copy)]
pub struct ChunkAir;

impl BaseAir<Felt> for ChunkAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

// LIFTED AIR
// ================================================================================================

impl LiftedAir<Felt, QuadFelt> for ChunkAir {
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
        // Phase 1: local row constraints.
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let chunk_seq_id: AB::Expr = local[COL_CHUNK_SEQ_ID].into();
        let chunk_seq_id_next: AB::Expr = next[COL_CHUNK_SEQ_ID].into();
        let perm_seq_id: AB::Expr = local[COL_PERM_SEQ_ID].into();
        let perm_seq_id_next: AB::Expr = next[COL_PERM_SEQ_ID].into();
        let act: AB::Expr = local[COL_ACT].into();
        let act_next: AB::Expr = next[COL_ACT].into();
        let is_head: AB::Expr = local[COL_IS_HEAD].into();
        let is_head_next: AB::Expr = next[COL_IS_HEAD].into();
        let cap: [AB::Expr; NUM_CAP] = array::from_fn(|i| local[COL_CAP_BEGIN + i].into());

        // Boundary (`when_first_row`) ---------------------------
        // chunk_seq_id starts at 0. perm_seq_id / act / is_head are
        // unpinned at row 0: an all-padding trace is valid, and the
        // first head's P2 cycle is bus-pinned.
        builder.when_first_row().assert_zero(chunk_seq_id.clone());

        // chunk_seq_id chain ------------------------------------
        // +1 per row, globally. `when_transition` leaves the cyclic
        // wrap unconstrained.
        builder
            .when_transition()
            .assert_zero(chunk_seq_id_next - chunk_seq_id - AB::Expr::ONE);

        // perm_seq_id chain -------------------------------------
        // Within an absorption chain (successor not a new head) it
        // increments by 1, in lockstep with chunk_seq_id; at chain
        // heads the gate vanishes and it jumps freely to the new
        // chain's P2 cycle. This lockstep makes P2's absorption order
        // equal the downstream hasher's Memory64 order.
        builder.when_transition().assert_zero(
            (AB::Expr::ONE - is_head_next) * (perm_seq_id_next - perm_seq_id - AB::Expr::ONE),
        );

        // Activity ----------------------------------------------
        builder.assert_bool(local[COL_ACT]);
        builder.when_transition().assert_zero((AB::Expr::ONE - act.clone()) * act_next);

        // Selector ----------------------------------------------
        builder.assert_bool(local[COL_IS_HEAD]);
        builder.assert_zero(is_head.clone() * (AB::Expr::ONE - act.clone()));
        for cap_felt in cap {
            builder.assert_zero((AB::Expr::ONE - act.clone() * is_head.clone()) * cap_felt);
        }

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for ChunkAir
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

        let chunk_seq_id: LB::Expr = local[COL_CHUNK_SEQ_ID].into();
        let perm_seq_id: LB::Expr = local[COL_PERM_SEQ_ID].into();
        let act: LB::Expr = local[COL_ACT].into();
        let is_head: LB::Expr = local[COL_IS_HEAD].into();
        let f: [LB::Expr; NUM_F] = array::from_fn(|i| local[COL_F_BEGIN + i].into());
        let cap_chunk: [LB::Expr; NUM_CAP] = array::from_fn(|i| local[COL_CAP_BEGIN + i].into());

        // Memory64 lane addresses: CHUNK_ADDR_BASE + 4·chunk_seq_id + j.
        let chunk_addr_base =
            Felt::new(CHUNK_ADDR_BASE).expect("CHUNK_ADDR_BASE fits in canonical Goldilocks");
        let addr0 =
            LB::Expr::from(chunk_addr_base) + LB::Expr::from(Felt::from(4u8)) * chunk_seq_id;
        let addr1 = addr0.clone() + LB::Expr::ONE;
        let addr2 = addr0.clone() + LB::Expr::from(Felt::from(2u8));
        let addr3 = addr0.clone() + LB::Expr::from(Felt::from(3u8));

        // Memory64 provide multiplicity (sign −, gated by act): every
        // active row provides all four lanes.
        let neg_act: LB::Expr = LB::Expr::ZERO - act.clone();

        // Poseidon2In consume multiplicities (sign +, gated by act):
        // rate0/rate1 every row; InCap on chain heads.
        let pos_act: LB::Expr = act.clone();
        let pos_act_head: LB::Expr = act * is_head;

        let rate0_chunk = [f[0].clone(), f[1].clone(), f[2].clone(), f[3].clone()];
        let rate1_chunk = [f[4].clone(), f[5].clone(), f[6].clone(), f[7].clone()];
        let interaction_deg = Deg { v: 1, u: 1 };
        // Col 0 Memory64: one batch, 4 product inserts. d = 4; every
        // insert mult is `−act` (deg 1) → n = 1 + 3 = 4.
        let m64_deg = Deg { v: 4, u: 4 };
        // Col 1 Poseidon2In: one batch, 3 product inserts. d = 3; worst
        // insert mult deg 2 (cap) → n = 2 + 2 = 4.
        let p2_deg = Deg { v: 4, u: 3 };
        // Col 2 ChunkChain: one batch, 1 insert. d = 1; insert mult
        // `−act · is_head` (deg 2) → n = 2.
        let chunkchain_deg = Deg { v: 2, u: 1 };

        // ---- col 0: Memory64 lane provides --------------------
        builder.next_column(
            |col| {
                col.group(
                    "memory64",
                    |g| {
                        g.batch(
                            "lanes",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "lane0",
                                    neg_act.clone(),
                                    Memory64Msg {
                                        addr: addr0,
                                        lo: f[0].clone(),
                                        hi: f[1].clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "lane1",
                                    neg_act.clone(),
                                    Memory64Msg {
                                        addr: addr1,
                                        lo: f[2].clone(),
                                        hi: f[3].clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "lane2",
                                    neg_act.clone(),
                                    Memory64Msg {
                                        addr: addr2,
                                        lo: f[4].clone(),
                                        hi: f[5].clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "lane3",
                                    neg_act,
                                    Memory64Msg {
                                        addr: addr3,
                                        lo: f[6].clone(),
                                        hi: f[7].clone(),
                                    },
                                    interaction_deg,
                                );
                            },
                            m64_deg,
                        );
                    },
                    m64_deg,
                );
            },
            m64_deg,
        );

        // ---- col 1: Poseidon2In consumes ----------------------
        builder.next_column(
            |col| {
                col.group(
                    "poseidon2-in",
                    |g| {
                        g.batch(
                            "rate-and-cap",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "rate0",
                                    pos_act.clone(),
                                    Poseidon2InMsg::rate0(perm_seq_id.clone(), rate0_chunk),
                                    interaction_deg,
                                );
                                b.insert(
                                    "rate1",
                                    pos_act,
                                    Poseidon2InMsg::rate1(perm_seq_id.clone(), rate1_chunk),
                                    interaction_deg,
                                );
                                b.insert(
                                    "cap",
                                    pos_act_head.clone(),
                                    Poseidon2InMsg::cap(perm_seq_id.clone(), cap_chunk),
                                    interaction_deg,
                                );
                            },
                            p2_deg,
                        );
                    },
                    p2_deg,
                );
            },
            p2_deg,
        );

        // ---- col 2: ChunkChain provide on chain heads ---------
        // mult = `−act · is_head` (deg 2); message ties this chain's
        // chunk-side index to its P2 absorption-chain head. Consumed by
        // hasher-orchestration chiplets (Keccak node, …).
        let neg_act_head: LB::Expr = LB::Expr::ZERO - pos_act_head;
        builder.next_column(
            |col| {
                col.group(
                    "chunk-chain",
                    |g| {
                        g.batch(
                            "head",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "emit",
                                    neg_act_head,
                                    ChunkChainMsg {
                                        chunk_seq_id_head: local[COL_CHUNK_SEQ_ID].into(),
                                        perm_seq_id_head: perm_seq_id,
                                    },
                                    interaction_deg,
                                );
                            },
                            chunkchain_deg,
                        );
                    },
                    chunkchain_deg,
                );
            },
            chunkchain_deg,
        );
    }
}

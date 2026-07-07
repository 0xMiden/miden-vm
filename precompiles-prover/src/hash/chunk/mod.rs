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

use alloc::vec::Vec;
use core::array;

pub use message::ChunkChainMsg;
use miden_core::{
    Felt,
    deferred::Tag,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    hash::memory64::{CHUNK_ADDR_BASE, Memory64Msg},
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES, frac_col,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::poseidon2::Poseidon2InMsg,
    utils::{current_main, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================
//
// 12 main witness columns:
//
// - Structural (3): chunk_seq_id, perm_seq_id, act.
// - Selector (1):   is_head.
// - Content (8):    f[0..8] — the chunk's 8 u32 felts.
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

/// Total number of main witness columns.
pub const NUM_MAIN_COLS: usize = COL_F_END;

// AUX / PUBLIC LAYOUT
// ================================================================================================

/// Five aux columns, flattened via `frac_col!` so every closing
/// constraint stays at degree ≤ 3 → `log_quotient_degree = 1`:
/// - col 0: `lane0` alone — the gated running-sum anchor.
/// - col 1: `lane1` + `lane2` (Memory64).
/// - col 2: `lane3` (Memory64) + `rate0` (Poseidon2In) — cross-bus pair.
/// - col 3: `rate1` + `cap` (Poseidon2In).
/// - col 4: `emit` alone (ChunkChain, no partner left to pair).
pub const NUM_AUX_COLS: usize = 5;

/// Per-column fraction counts, matching the pairing above.
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 2, 2, 2, 1];

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
        builder.assert_zero(is_head * (AB::Expr::ONE - act));

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
        let cap_chunk = Tag::CHUNKS.as_word().map(LB::Expr::from);

        let interaction_deg = Deg { v: 1, u: 1 };
        let provides_deg = Deg { v: 1, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };

        // col 0: lane0 alone — the gated running-sum anchor.
        frac_col!(
            builder,
            "memory64",
            provides_deg,
            (
                "lane0",
                neg_act.clone(),
                Memory64Msg {
                    addr: addr0,
                    lo: f[0].clone(),
                    hi: f[1].clone()
                },
                interaction_deg
            ),
        );
        // col 1 (paired, lqd-1): lane1 + lane2 (Memory64).
        frac_col!(
            builder,
            "memory64",
            pair_deg,
            (
                "lane1",
                neg_act.clone(),
                Memory64Msg {
                    addr: addr1,
                    lo: f[2].clone(),
                    hi: f[3].clone()
                },
                interaction_deg
            ),
            (
                "lane2",
                neg_act.clone(),
                Memory64Msg {
                    addr: addr2,
                    lo: f[4].clone(),
                    hi: f[5].clone()
                },
                interaction_deg
            ),
        );
        // col 2 (paired, lqd-1): lane3 (Memory64) + rate0 (Poseidon2In).
        frac_col!(
            builder,
            "chunk-flatten",
            pair_deg,
            (
                "lane3",
                neg_act,
                Memory64Msg {
                    addr: addr3,
                    lo: f[6].clone(),
                    hi: f[7].clone()
                },
                interaction_deg
            ),
            (
                "rate0",
                pos_act.clone(),
                Poseidon2InMsg::rate0(perm_seq_id.clone(), rate0_chunk),
                interaction_deg
            ),
        );
        // col 3 (paired, lqd-1): rate1 + cap (Poseidon2In).
        frac_col!(
            builder,
            "poseidon2-in",
            pair_deg,
            (
                "rate1",
                pos_act,
                Poseidon2InMsg::rate1(perm_seq_id.clone(), rate1_chunk),
                interaction_deg
            ),
            (
                "cap",
                pos_act_head.clone(),
                Poseidon2InMsg::cap(perm_seq_id.clone(), cap_chunk),
                interaction_deg
            ),
        );

        // col 4: ChunkChain provide on chain heads, alone (no partner left
        // to pair). mult = `−act · is_head` (deg 2); message ties this
        // chain's chunk-side index to its P2 absorption-chain head.
        // Consumed by hasher-orchestration chiplets (Keccak node, …).
        let neg_act_head: LB::Expr = LB::Expr::ZERO - pos_act_head;
        frac_col!(
            builder,
            "chunk-chain",
            provides_deg,
            (
                "emit",
                neg_act_head,
                ChunkChainMsg {
                    chunk_seq_id_head: local[COL_CHUNK_SEQ_ID].into(),
                    perm_seq_id_head: perm_seq_id,
                },
                interaction_deg
            ),
        );
    }
}

//! ChunkNode chiplet — the chunk chiplet and the Keccak transcript-DAG
//! node chiplet sharing one row range.
//!
//! Both are period-1 (no periodic columns) and their own trace heights
//! are otherwise unrelated, so they run **simultaneously** on the same
//! rows in disjoint column ranges: main columns 0..12 are exactly
//! [`chunk::ChunkAir`]'s own layout (unchanged), columns 12..42 are
//! exactly [`node::KeccakNodeAir`]'s own layout (unchanged, shifted by
//! [`NODE_COL_OFFSET`]). No mode selector, no cross-gating — each side
//! keeps its own constraint degree (`lqd = 1`).
//!
//! Exactly one running-sum column is committed per AIR, so column 0 is
//! chunk's own anchor fraction, unchanged; keccak-node's own anchor
//! fraction becomes an ordinary (non-anchor) column instead of folding
//! into chunk's — both still close into the one shared σ via the
//! standard `acc_next[0] = Σ acc[i]` recurrence, and neither pays the
//! degree cost of physically sharing column 0.
//!
//! The shared height is `max` of what each side natively needs
//! (independently `next_power_of_two`-padded, own padding mechanism),
//! not their sum, since they occupy the same rows.

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
    hash::{
        chunk::{self, ChunkChainMsg},
        keccak::{node, sponge::KeccakSpongeMsg},
        memory64::{CHUNK_ADDR_BASE, Memory64Msg},
    },
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES, frac_col,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::BindingMsg,
        poseidon2::{Poseidon2InMsg, Poseidon2OutMsg},
    },
    utils::{current_main, next_main},
};

// COLUMN LAYOUT
// ================================================================================================

/// Keccak-node's main columns start right after chunk's own 12.
pub const NODE_COL_OFFSET: usize = chunk::NUM_MAIN_COLS;

pub const NUM_MAIN_COLS: usize = chunk::NUM_MAIN_COLS + node::NUM_MAIN_COLS;

/// Aux layout: col 0 = chunk's own anchor fraction (unchanged); cols
/// 1..5 = chunk's original cols 1..4 unchanged; col 5 = keccak-node's
/// original col 0 (its own anchor), now an ordinary column; cols 6..14
/// = keccak-node's original cols 1..8 unchanged.
pub const NUM_AUX_COLS: usize = chunk::NUM_AUX_COLS + node::NUM_AUX_COLS;

const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 2, 2, 2, 1, 1, 2, 1, 2, 2, 2, 2, 2, 2];

// AIR
// ================================================================================================

/// ChunkNode chiplet AIR. Period 1 (no periodic columns).
#[derive(Debug, Default, Clone, Copy)]
pub struct ChunkNodeAir;

impl BaseAir<Felt> for ChunkNodeAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for ChunkNodeAir {
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
        // ---- CHUNK (verbatim from `chunk::ChunkAir::eval`, cols 0..12) ----
        {
            let local: [AB::Var; chunk::NUM_MAIN_COLS] = current_main(builder.main(), 0);
            let next: [AB::Var; chunk::NUM_MAIN_COLS] = next_main(builder.main(), 0);

            let chunk_seq_id: AB::Expr = local[chunk::COL_CHUNK_SEQ_ID].into();
            let chunk_seq_id_next: AB::Expr = next[chunk::COL_CHUNK_SEQ_ID].into();
            let perm_seq_id: AB::Expr = local[chunk::COL_PERM_SEQ_ID].into();
            let perm_seq_id_next: AB::Expr = next[chunk::COL_PERM_SEQ_ID].into();
            let act: AB::Expr = local[chunk::COL_ACT].into();
            let act_next: AB::Expr = next[chunk::COL_ACT].into();
            let is_head: AB::Expr = local[chunk::COL_IS_HEAD].into();
            let is_head_next: AB::Expr = next[chunk::COL_IS_HEAD].into();

            builder.when_first_row().assert_zero(chunk_seq_id.clone());

            builder
                .when_transition()
                .assert_zero(chunk_seq_id_next - chunk_seq_id - AB::Expr::ONE);

            builder.when_transition().assert_zero(
                (AB::Expr::ONE - is_head_next) * (perm_seq_id_next - perm_seq_id - AB::Expr::ONE),
            );

            builder.assert_bool(local[chunk::COL_ACT]);
            builder.when_transition().assert_zero((AB::Expr::ONE - act.clone()) * act_next);

            builder.assert_bool(local[chunk::COL_IS_HEAD]);
            builder.assert_zero(is_head * (AB::Expr::ONE - act));
        }

        // ---- KECCAK-NODE (verbatim from `node::KeccakNodeAir::eval`, cols
        // `NODE_COL_OFFSET`..`NUM_MAIN_COLS`) ----
        {
            let local: [AB::Var; node::NUM_MAIN_COLS] =
                current_main(builder.main(), NODE_COL_OFFSET);
            let next: [AB::Var; node::NUM_MAIN_COLS] = next_main(builder.main(), NODE_COL_OFFSET);

            let act: AB::Expr = local[node::COL_ACT].into();
            let act_next: AB::Expr = next[node::COL_ACT].into();
            let out_mult: AB::Expr = local[node::COL_OUT_MULT].into();

            let sponge_seq_id_head: AB::Expr = local[node::COL_SPONGE_SEQ_ID_HEAD].into();
            let sponge_seq_id_head_next: AB::Expr = next[node::COL_SPONGE_SEQ_ID_HEAD].into();
            let n_sponge_perms: AB::Expr = local[node::COL_N_SPONGE_PERMS].into();

            let chunk_seq_id_head: AB::Expr = local[node::COL_CHUNK_SEQ_ID_HEAD].into();
            let chunk_seq_id_head_next: AB::Expr = next[node::COL_CHUNK_SEQ_ID_HEAD].into();
            let n_chunks: AB::Expr = local[node::COL_N_CHUNKS].into();

            let _ = next[node::COL_PERM_SEQ_ID_CHUNKS];

            builder.when_first_row().assert_zero(sponge_seq_id_head.clone());
            builder.when_first_row().assert_zero(chunk_seq_id_head.clone());

            builder.assert_bool(local[node::COL_ACT]);
            builder
                .when_transition()
                .assert_zero((AB::Expr::ONE - act.clone()) * act_next.clone());

            builder.assert_zero((AB::Expr::ONE - act) * out_mult);

            builder.when_transition().assert_zero(
                act_next.clone()
                    * (sponge_seq_id_head_next
                        - sponge_seq_id_head
                        - AB::Expr::from(Felt::from(32u8)) * n_sponge_perms),
            );
            builder
                .when_transition()
                .assert_zero(act_next * (chunk_seq_id_head_next - chunk_seq_id_head - n_chunks));
        }

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for ChunkNodeAir
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
        // ---- CHUNK (verbatim from `chunk::ChunkAir`'s `LookupAir::eval`, aux cols 0..5) ----
        let local: [LB::Var; chunk::NUM_MAIN_COLS] = current_main(builder.main(), 0);

        let chunk_seq_id: LB::Expr = local[chunk::COL_CHUNK_SEQ_ID].into();
        let perm_seq_id: LB::Expr = local[chunk::COL_PERM_SEQ_ID].into();
        let act: LB::Expr = local[chunk::COL_ACT].into();
        let is_head: LB::Expr = local[chunk::COL_IS_HEAD].into();
        let f: [LB::Expr; chunk::NUM_F] = array::from_fn(|i| local[chunk::COL_F_BEGIN + i].into());

        let chunk_addr_base =
            Felt::new(CHUNK_ADDR_BASE).expect("CHUNK_ADDR_BASE fits in canonical Goldilocks");
        let addr0 =
            LB::Expr::from(chunk_addr_base) + LB::Expr::from(Felt::from(4u8)) * chunk_seq_id;
        let addr1 = addr0.clone() + LB::Expr::ONE;
        let addr2 = addr0.clone() + LB::Expr::from(Felt::from(2u8));
        let addr3 = addr0.clone() + LB::Expr::from(Felt::from(3u8));

        let neg_act: LB::Expr = LB::Expr::ZERO - act.clone();

        let pos_act: LB::Expr = act.clone();
        let pos_act_head: LB::Expr = act * is_head;

        let rate0_chunk = [f[0].clone(), f[1].clone(), f[2].clone(), f[3].clone()];
        let rate1_chunk = [f[4].clone(), f[5].clone(), f[6].clone(), f[7].clone()];
        let cap_chunk = Tag::CHUNKS.as_word().map(LB::Expr::from);

        let interaction_deg = Deg { v: 1, u: 1 };
        let provides_deg = Deg { v: 1, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };

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

        let neg_act_head: LB::Expr = LB::Expr::ZERO - pos_act_head;
        frac_col!(
            builder,
            "chunk-chain",
            provides_deg,
            (
                "emit",
                neg_act_head,
                ChunkChainMsg {
                    chunk_seq_id_head: local[chunk::COL_CHUNK_SEQ_ID].into(),
                    perm_seq_id_head: perm_seq_id,
                },
                interaction_deg
            ),
        );

        // ---- KECCAK-NODE (verbatim from `node::KeccakNodeAir`'s `LookupAir::eval`, aux cols
        // 5..14) ----
        let local: [LB::Var; node::NUM_MAIN_COLS] = current_main(builder.main(), NODE_COL_OFFSET);

        let act: LB::Expr = local[node::COL_ACT].into();
        let sponge_seq_id_head: LB::Expr = local[node::COL_SPONGE_SEQ_ID_HEAD].into();
        let n_sponge_perms: LB::Expr = local[node::COL_N_SPONGE_PERMS].into();
        let chunk_seq_id_head: LB::Expr = local[node::COL_CHUNK_SEQ_ID_HEAD].into();
        let n_chunks: LB::Expr = local[node::COL_N_CHUNKS].into();
        let perm_seq_id_chunks: LB::Expr = local[node::COL_PERM_SEQ_ID_CHUNKS].into();
        let len_bytes: LB::Expr = local[node::COL_LEN_BYTES].into();
        let perm_seq_id_digest_chunks: LB::Expr = local[node::COL_PERM_SEQ_ID_DIGEST_CHUNKS].into();
        let perm_seq_id_keccak: LB::Expr = local[node::COL_PERM_SEQ_ID_KECCAK].into();

        let d: [LB::Expr; node::NUM_D] = array::from_fn(|i| local[node::COL_D_BEGIN + i].into());
        let h_input_chunks: [LB::Expr; node::NUM_HASH] =
            array::from_fn(|i| local[node::COL_H_INPUT_CHUNKS_BEGIN + i].into());
        let h_digest_chunks: [LB::Expr; node::NUM_HASH] =
            array::from_fn(|i| local[node::COL_H_DIGEST_CHUNKS_BEGIN + i].into());
        let h_keccak: [LB::Expr; node::NUM_HASH] =
            array::from_fn(|i| local[node::COL_H_KECCAK_BEGIN + i].into());

        let neg_act: LB::Expr = LB::Expr::ZERO - act.clone();
        let pos_act: LB::Expr = act.clone();
        let pos_act_x2: LB::Expr = LB::Expr::from(Felt::from(2u8)) * act;
        let out_mult: LB::Expr = local[node::COL_OUT_MULT].into();
        let neg_out_mult: LB::Expr = LB::Expr::ZERO - out_mult;

        let chunk_ptr_head: LB::Expr = LB::Expr::from(Felt::from(4u8)) * chunk_seq_id_head.clone();
        let perm_seq_id_chunks_tail: LB::Expr =
            perm_seq_id_chunks.clone() + n_chunks - LB::Expr::ONE;
        let digest_addr_base: LB::Expr = LB::Expr::from(Felt::from(100u8)) * sponge_seq_id_head
            + LB::Expr::from(Felt::from(3200u32)) * n_sponge_perms
            - LB::Expr::from(Felt::from(128u8));

        let cap_digest_chunks = Tag::CHUNKS.as_word().map(LB::Expr::from);
        let cap_keccak = [
            LB::Expr::from(Keccak256Precompile::id()),
            LB::Expr::from(Felt::from_u32(Keccak256Precompile::ASSERT_TAG_ID)),
            len_bytes.clone(),
            LB::Expr::ZERO,
        ];

        let d_rate0 = [d[0].clone(), d[1].clone(), d[2].clone(), d[3].clone()];
        let d_rate1 = [d[4].clone(), d[5].clone(), d[6].clone(), d[7].clone()];

        frac_col!(
            builder,
            "handshake-and-chunks-digest",
            provides_deg,
            (
                "ks-request",
                neg_act.clone(),
                KeccakSpongeMsg {
                    sponge_seq_id: local[node::COL_SPONGE_SEQ_ID_HEAD].into(),
                    chunk_ptr: chunk_ptr_head,
                    len_bytes: len_bytes.clone()
                },
                interaction_deg
            ),
        );
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
                    perm_seq_id_head: perm_seq_id_chunks
                },
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "handshake-and-chunks-digest",
            provides_deg,
            (
                "p2out-h-input-chunks",
                pos_act.clone(),
                Poseidon2OutMsg {
                    perm_seq_id: perm_seq_id_chunks_tail,
                    digest: h_input_chunks.clone()
                },
                interaction_deg
            ),
        );

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

        frac_col!(
            builder,
            "digest-chunks-p2",
            pair_deg,
            (
                "p2in-rate0",
                pos_act.clone(),
                Poseidon2InMsg::rate0(perm_seq_id_digest_chunks.clone(), d_rate0),
                interaction_deg
            ),
            (
                "p2in-rate1",
                pos_act.clone(),
                Poseidon2InMsg::rate1(perm_seq_id_digest_chunks.clone(), d_rate1),
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "digest-chunks-p2",
            pair_deg,
            (
                "p2in-cap",
                pos_act.clone(),
                Poseidon2InMsg::cap(perm_seq_id_digest_chunks.clone(), cap_digest_chunks),
                interaction_deg
            ),
            (
                "p2out-h-digest-chunks",
                pos_act.clone(),
                Poseidon2OutMsg {
                    perm_seq_id: perm_seq_id_digest_chunks,
                    digest: h_digest_chunks.clone()
                },
                interaction_deg
            ),
        );

        frac_col!(
            builder,
            "keccak-p2",
            pair_deg,
            (
                "p2in-rate0",
                pos_act.clone(),
                Poseidon2InMsg::rate0(perm_seq_id_keccak.clone(), h_input_chunks),
                interaction_deg
            ),
            (
                "p2in-rate1",
                pos_act.clone(),
                Poseidon2InMsg::rate1(perm_seq_id_keccak.clone(), h_digest_chunks),
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "keccak-p2",
            pair_deg,
            (
                "p2in-cap",
                pos_act.clone(),
                Poseidon2InMsg::cap(perm_seq_id_keccak.clone(), cap_keccak),
                interaction_deg
            ),
            (
                "p2out-h-keccak",
                pos_act,
                Poseidon2OutMsg {
                    perm_seq_id: perm_seq_id_keccak,
                    digest: h_keccak
                },
                interaction_deg
            ),
        );
    }
}

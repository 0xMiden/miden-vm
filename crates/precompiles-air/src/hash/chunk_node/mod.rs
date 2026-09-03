//! Chunk and Keccak transcript-DAG node bands sharing one row range,
//! composed into the merged hash chiplet by
//! [`crate::hash::chunk_node_sponge::ChunkNodeSpongeAir`].
//!
//! Both are period-1 (no periodic columns) and their own trace heights
//! are otherwise unrelated, so they run **simultaneously** on the same
//! rows in disjoint column ranges: main columns 0..12 are exactly
//! [`chunk::ChunkAir`]'s own layout (unchanged), columns 12..42 are
//! exactly [`node::KeccakNodeAir`]'s own layout (unchanged, shifted by
//! [`NODE_COL_OFFSET`]). No mode selector or cross-gating is introduced.
//!
//! The 18 lookup fractions are repacked into six three-fraction columns.
//! Column 0 contains three degree-1 chunk Memory64 interactions and drives the centered
//! accumulator, keeping its constraint within the composite's degree-5 budget. The remaining
//! columns are ordinary fraction columns.

use core::array;

use miden_core::{Felt, deferred::Tag, field::PrimeCharacteristicRing};
use miden_lifted_air::LiftedAirBuilder;
use miden_precompiles::Keccak256Precompile;

use crate::{
    hash::{
        chunk::{self, ChunkChainMsg},
        keccak::{node, sponge::KeccakSpongeMsg},
        memory64::{CHUNK_ADDR_BASE, Memory64Msg},
    },
    logup::{Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup, frac_col},
    transcript::{
        binding::BindingMsg,
        eidos::{EidosChainInputMsg, EidosOutMsg},
    },
    utils::current_main,
};

// COLUMN LAYOUT
// ================================================================================================

/// Keccak-node's main columns start right after chunk's own 12.
pub const NODE_COL_OFFSET: usize = chunk::NUM_MAIN_COLS;

pub const NUM_MAIN_COLS: usize = chunk::NUM_MAIN_COLS + node::NUM_MAIN_COLS;

/// Six auxiliary columns, each containing three exact lookup fractions.
pub const NUM_AUX_COLS: usize = 6;

pub(crate) const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [3; NUM_AUX_COLS];

// CONSTRAINTS
// ================================================================================================

/// Evaluate this component's base constraints in a main-trace column band.
pub(crate) fn eval_main<AB>(builder: &mut AB, main_col_offset: usize)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    chunk::eval_main(builder, main_col_offset);
    node::eval_main(builder, main_col_offset + NODE_COL_OFFSET);
}

// LOOKUPS
// ================================================================================================

/// Evaluate this component's LogUp columns in a main-trace column band.
pub(crate) fn eval_lookups<LB>(builder: &mut LB, main_col_offset: usize)
where
    LB: LookupBuilder<F = Felt>,
{
    // Chunk lookups.
    let local: [LB::Var; chunk::NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);

    let chunk_seq_id: LB::Expr = local[chunk::COL_CHUNK_SEQ_ID].into();
    let absorption_id: LB::Expr = local[chunk::COL_ABSORPTION_ID].into();
    let act: LB::Expr = local[chunk::COL_ACT].into();
    let is_head: LB::Expr = local[chunk::COL_IS_HEAD].into();
    let f: [LB::Expr; chunk::NUM_F] = array::from_fn(|i| local[chunk::COL_F_BEGIN + i].into());

    let chunk_addr_base =
        Felt::new(CHUNK_ADDR_BASE).expect("CHUNK_ADDR_BASE fits in canonical Goldilocks");
    let addr0 = LB::Expr::from(chunk_addr_base) + LB::Expr::from(Felt::from(4u8)) * chunk_seq_id;
    let addr1 = addr0.clone() + LB::Expr::ONE;
    let addr2 = addr0.clone() + LB::Expr::from(Felt::from(2u8));
    let addr3 = addr0.clone() + LB::Expr::from(Felt::from(3u8));

    let neg_act: LB::Expr = LB::Expr::ZERO - act.clone();

    let pos_act: LB::Expr = act.clone();
    let pos_act_head: LB::Expr = act * is_head.clone();

    let chunk_chain_context = Tag::CHUNKS.as_word().map(LB::Expr::from);

    let interaction_deg = Deg { v: 1, u: 1 };
    let emit_deg = Deg { v: 2, u: 1 };
    let triple_deg = Deg { v: 3, u: 3 };
    let emit_triple_deg = Deg { v: 4, u: 3 };

    // col 0 (running sum): three degree-1 Memory64 interactions. The
    // denominator product has degree 3, leaving one degree for the
    // accumulator and one for the transition/last-row selector.
    frac_col!(
        builder,
        "memory64",
        triple_deg,
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

    let neg_act_head: LB::Expr = LB::Expr::ZERO - pos_act_head;
    // col 1: the remaining chunk interactions. The ChunkChain emission
    // has degree-2 multiplicity, so this ordinary column has numerator
    // degree 4 and denominator degree 3.
    frac_col!(
        builder,
        "chunk-flatten",
        emit_triple_deg,
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
            "eidos-chain-input",
            pos_act.clone(),
            EidosChainInputMsg::chunks(absorption_id.clone(), is_head, f, chunk_chain_context,),
            interaction_deg
        ),
        (
            "emit",
            neg_act_head,
            ChunkChainMsg {
                chunk_seq_id_head: local[chunk::COL_CHUNK_SEQ_ID].into(),
                absorption_id_head: absorption_id,
            },
            emit_deg
        ),
    );

    // Keccak-node lookups.
    let local: [LB::Var; node::NUM_MAIN_COLS] =
        current_main(builder.main(), main_col_offset + NODE_COL_OFFSET);

    let act: LB::Expr = local[node::COL_ACT].into();
    let sponge_seq_id_head: LB::Expr = local[node::COL_SPONGE_SEQ_ID_HEAD].into();
    let n_sponge_perms: LB::Expr = local[node::COL_N_SPONGE_PERMS].into();
    let chunk_seq_id_head: LB::Expr = local[node::COL_CHUNK_SEQ_ID_HEAD].into();
    let n_chunks: LB::Expr = local[node::COL_N_CHUNKS].into();
    let absorption_id_chunks: LB::Expr = local[node::COL_ABSORPTION_ID_CHUNKS].into();
    let len_bytes: LB::Expr = local[node::COL_LEN_BYTES].into();
    let absorption_id_digest_chunks: LB::Expr = local[node::COL_ABSORPTION_ID_DIGEST_CHUNKS].into();
    let absorption_id_keccak: LB::Expr = local[node::COL_ABSORPTION_ID_KECCAK].into();

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
    let absorption_id_chunks_tail: LB::Expr =
        absorption_id_chunks.clone() + n_chunks - LB::Expr::ONE;
    let digest_addr_base: LB::Expr = LB::Expr::from(Felt::from(100u8)) * sponge_seq_id_head
        + LB::Expr::from(Felt::from(3200u32)) * n_sponge_perms
        - LB::Expr::from(Felt::from(128u8));

    let digest_chunks_chain_context = Tag::CHUNKS.as_word().map(LB::Expr::from);
    let keccak_chain_context = [
        LB::Expr::from(Keccak256Precompile::id()),
        LB::Expr::from(Felt::from_u32(Keccak256Precompile::ASSERT_TAG_ID)),
        len_bytes.clone(),
        LB::Expr::ZERO,
    ];
    let addr_lane =
        |j: u8| -> LB::Expr { digest_addr_base.clone() + LB::Expr::from(Felt::from(j)) };

    // col 2: node request, truth binding, and chunk-chain consume.
    frac_col!(
        builder,
        "handshake-and-chunks-digest",
        triple_deg,
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
                absorption_id_head: absorption_id_chunks
            },
            interaction_deg
        ),
    );

    // col 3: the input-chunks digest and the first two D limbs.
    frac_col!(
        builder,
        "input-chunks-and-d-limbs",
        triple_deg,
        (
            "p2out-h-input-chunks",
            pos_act.clone(),
            EidosOutMsg {
                chain_step_id: absorption_id_chunks_tail,
                digest: h_input_chunks.clone()
            },
            interaction_deg
        ),
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

    // col 4: the remaining D limbs and the digest-chunks Eidos input.
    frac_col!(
        builder,
        "d-limbs-and-digest-chunks",
        triple_deg,
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
        (
            "eidos-chain-input",
            pos_act.clone(),
            EidosChainInputMsg::chunks(
                absorption_id_digest_chunks.clone(),
                LB::Expr::ONE,
                d,
                digest_chunks_chain_context,
            ),
            interaction_deg
        ),
    );

    // col 5: the digest-chunks output and the Keccak Eidos input/output.
    frac_col!(
        builder,
        "digest-and-keccak-eidos",
        triple_deg,
        (
            "eidos-chain-output",
            pos_act.clone(),
            EidosOutMsg {
                chain_step_id: absorption_id_digest_chunks,
                digest: h_digest_chunks.clone()
            },
            interaction_deg
        ),
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
                keccak_chain_context,
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

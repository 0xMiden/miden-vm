//! Chunk and Keccak-node records serialized into idle sponge cells.
//!
//! Each 32-row sponge period reserves rows 17 through 23 for one seven-phase node record, row 24
//! for a chunk, and rows 26 through 31 for six more chunks. Six persistent columns carry the node
//! heads/activity and chunk sequence/id/activity. The payload cells are shared with the sponge.
//!
//! Node phases authenticate the request and chunk count (17), permutation count (18), digest
//! lanes and their Eidos block (19..21), input and digest hashes (21..23), then the node hash
//! and truth binding (23). The eight-felt digest and node blocks read four local payload cells
//! and four cells from the next phase. Hold equations keep metadata live through its last use;
//! namespace heads advance only after their last consumer.

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    deferred::DEFERRED_CHUNKS_DOMAIN,
    field::{Algebra, PrimeCharacteristicRing},
};
use miden_precompiles::Keccak256Precompile;
use miden_stark::{
    air::{AirBuilder, LiftedAirBuilder},
    lookup::{Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup},
};

use crate::precompiles::{
    hash::{
        chunk::ChunkChainMsg,
        keccak::{
            node,
            sponge::{self, KeccakSpongeMsg},
        },
        memory64::{CHUNK_ADDR_BASE, Memory64Msg},
    },
    primitives::byte_pair_lut::BytePairLutMsg,
    transcript::{
        binding::BindingMsg,
        eidos::{EidosBlockMsg, EidosInitMsg, EidosOutMsg},
        initial_cv_from_frame,
    },
    utils::{current_main, next_main},
};

pub const NUM_MAIN_COLS: usize = 47;
pub const NUM_AUX_COLS: usize = 2;
pub(crate) const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [3, 3];
pub const COL_NODE_ACT: usize = 40;
pub const COL_SPONGE_HEAD: usize = 41;
pub const COL_CHUNK_HEAD: usize = 42;
pub const COL_CHUNK_SEQ: usize = 43;
pub const COL_CHUNK_ID: usize = 44;
pub const COL_CHUNK_ACT: usize = 45;
pub const COL_NODE_PERMS: usize = 16;
pub const COL_NODE_ID: usize = COL_NODE_PERMS;
pub const COL_NODE_CHUNKS: usize = 17;
pub const COL_INPUT_ID: usize = 18;
pub const COL_OUT_MULT: usize = COL_INPUT_ID;
pub const COL_LEN: usize = 19;
pub const COL_DIGEST_ID: usize = 20;
pub const PAYLOAD: [usize; 4] = [21, 22, 23, 46];
pub const COL_REMAINDER: usize = PAYLOAD[0];
pub const COL_CHUNKS_INV: usize = PAYLOAD[1];
/// ChunkAir's twelve logical columns on the capacity row.
pub const CHUNK_CAPACITY_COLUMNS: [usize; 12] = [43, 44, 45, 16, 17, 18, 19, 20, 21, 22, 23, 46];
/// ChunkAir's twelve logical columns on rows 26 through 31.
pub const CHUNK_LATE_COLUMNS: [usize; 12] = [43, 44, 45, 14, 15, 24, 25, 26, 27, 28, 29, 30];
pub const NODE_ROW_START: usize = 17;
pub const CHUNK_ROWS: [usize; 7] = [24, 26, 27, 28, 29, 30, 31];

const PERIODIC_OFFSET: usize = sponge::NUM_PERIODIC_COLS;
const P_CHUNK_CAPACITY: usize = 7;
const P_CHUNK_LATE: usize = 8;
const P_NEXT_CHUNK: usize = 9;
const _: () = assert!(sponge::NUM_MAIN_COLS == 40 && sponge::SPONGE_PERIOD == 32);

pub(crate) fn periodic_columns() -> Vec<Vec<Felt>> {
    let mut columns = vec![vec![Felt::ZERO; 32]; 10];
    for phase in 0..7 {
        columns[phase][NODE_ROW_START + phase] = Felt::ONE;
    }
    columns[P_CHUNK_CAPACITY][24] = Felt::ONE;
    columns[P_CHUNK_LATE][26..32].fill(Felt::ONE);
    for row in CHUNK_ROWS {
        columns[P_NEXT_CHUNK][row - 1] = Felt::ONE;
    }
    columns
}

pub(crate) fn eval_main<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
    let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
    let p: [AB::Expr; 10] =
        array::from_fn(|i| builder.periodic_values()[PERIODIC_OFFSET + i].into());
    let last: AB::Expr = builder.periodic_values()[sponge::program::COL_LAST].into();
    let v = |i: usize| -> AB::Expr { local[i].into() };
    let nv = |i: usize| -> AB::Expr { next[i].into() };
    let one = AB::Expr::ONE;
    let node_act = v(COL_NODE_ACT);
    builder.assert_bool(local[COL_NODE_ACT]);
    builder
        .when_transition()
        .assert_zero((one.clone() - node_act.clone()) * nv(COL_NODE_ACT));
    builder
        .when_transition()
        .assert_zero((one.clone() - last) * (nv(COL_NODE_ACT) - node_act.clone()));
    for column in [COL_SPONGE_HEAD, COL_CHUNK_HEAD, COL_CHUNK_SEQ] {
        builder.when_first_row().assert_zero(local[column]);
    }
    builder.when_transition().assert_zero(
        nv(COL_SPONGE_HEAD)
            - v(COL_SPONGE_HEAD)
            - p[3].clone() * v(COL_NODE_PERMS) * Felt::from_u8(32),
    );
    builder
        .when_transition()
        .assert_zero(nv(COL_CHUNK_HEAD) - v(COL_CHUNK_HEAD) - p[6].clone() * v(COL_NODE_CHUNKS));

    // Each value is held from its first authenticated use through its last consumer. These
    // intervals stop before the same cells take a new role or become chunk payload.
    for (column, phases) in [
        (COL_NODE_PERMS, &[0, 1, 2, 4, 5][..]),
        (COL_NODE_CHUNKS, &[0, 1, 2, 3, 4, 5][..]),
        (COL_INPUT_ID, &[0, 1, 2, 3][..]),
        (COL_LEN, &[0, 1, 2, 3, 4][..]),
        (COL_DIGEST_ID, &[2, 3, 4][..]),
    ] {
        let hold = phases.iter().map(|&i| p[i].clone()).sum::<AB::Expr>();
        builder.when_transition().assert_zero(hold * (nv(column) - v(column)));
    }
    node::eval_chunk_count(
        builder,
        p[0].clone() * node_act.clone(),
        v(COL_LEN),
        v(COL_NODE_CHUNKS),
        v(COL_CHUNKS_INV),
        v(COL_REMAINDER),
    );
    builder.assert_zero(p[6].clone() * (one.clone() - node_act) * v(COL_OUT_MULT));

    let chunk = p[P_CHUNK_CAPACITY].clone() + p[P_CHUNK_LATE].clone();
    let entering = p[P_NEXT_CHUNK].clone();
    let chunk_act = v(COL_CHUNK_ACT);
    builder.assert_bool(local[COL_CHUNK_ACT]);
    builder
        .when_transition()
        .assert_zero((one.clone() - chunk_act.clone()) * nv(COL_CHUNK_ACT));
    builder
        .when_transition()
        .assert_zero((one.clone() - entering.clone()) * (nv(COL_CHUNK_ACT) - chunk_act.clone()));
    builder
        .when_transition()
        .assert_zero(nv(COL_CHUNK_SEQ) - v(COL_CHUNK_SEQ) - chunk);
    builder
        .when_transition()
        .assert_zero((one.clone() - entering.clone()) * (nv(COL_CHUNK_ID) - v(COL_CHUNK_ID)));
    for (mask, columns, entry_mask) in [
        (p[P_CHUNK_CAPACITY].clone(), CHUNK_CAPACITY_COLUMNS, p[6].clone()),
        (p[P_CHUNK_LATE].clone(), CHUNK_LATE_COLUMNS, entering - p[6].clone()),
    ] {
        let head = v(columns[3]);
        builder.assert_zero(mask.clone() * head.clone() * (head.clone() - one.clone()));
        builder.assert_zero(mask * head * (one.clone() - chunk_act.clone()));
        builder.when_transition().assert_zero(
            entry_mask
                * (one.clone() - nv(columns[3]))
                * (nv(COL_CHUNK_ID) - v(COL_CHUNK_ID) - one.clone()),
        );
    }
}

pub(crate) fn eval_lookups<LB: LookupBuilder<F = Felt>>(builder: &mut LB) {
    let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
    let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
    let p: [LB::Expr; 10] =
        array::from_fn(|i| builder.periodic_values()[PERIODIC_OFFSET + i].into());
    for index in 0..NUM_AUX_COLS {
        let degree = Deg { v: 4 + index, u: 4 };
        builder.next_column(
            |column| {
                column.group(
                    "chunk-and-node",
                    |group| {
                        for (mask, columns) in [
                            (p[P_CHUNK_CAPACITY].clone(), CHUNK_CAPACITY_COLUMNS),
                            (p[P_CHUNK_LATE].clone(), CHUNK_LATE_COLUMNS),
                        ] {
                            group.batch(
                                "chunk",
                                mask,
                                |batch| {
                                    emit_chunk(batch, index, &columns.map(|c| local[c]));
                                },
                                degree,
                            );
                        }
                        if index == 0 {
                            for (phase, mask) in p[..7].iter().enumerate() {
                                let count = if phase < 5 { 3 } else { 2 };
                                let phase_degree = Deg { v: count + 1, u: count + 1 };
                                group.batch(
                                    "node",
                                    mask.clone(),
                                    |batch| {
                                        emit_node(batch, phase, &local, &next);
                                    },
                                    phase_degree,
                                );
                            }
                        }
                    },
                    degree,
                )
            },
            degree,
        );
    }
}

fn emit_chunk<B: LookupBatch, V: Copy + Into<B::Expr>>(batch: &mut B, index: usize, local: &[V; 12])
where
    B::Expr: Algebra<Felt>,
{
    let v = |i: usize| -> B::Expr { local[i].into() };
    let act = v(2);
    let base = B::Expr::from_u64(CHUNK_ADDR_BASE) + v(0) * B::Expr::from_u8(4);
    let linear = Deg { v: 1, u: 1 };
    let lanes = if index == 0 { 0..3 } else { 3..4 };
    for lane in lanes {
        batch.insert(
            "chunk-lane",
            -act.clone(),
            Memory64Msg {
                addr: base.clone() + B::Expr::from_usize(lane),
                lo: v(4 + 2 * lane),
                hi: v(5 + 2 * lane),
            },
            linear,
        );
    }
    if index == 1 {
        batch.insert(
            "chunk-block",
            act.clone(),
            EidosBlockMsg {
                compression_id: v(1),
                block: array::from_fn(|i| v(4 + i)),
            },
            linear,
        );
        batch.insert(
            "chunk-chain",
            -act * v(3),
            ChunkChainMsg {
                chunk_seq_id_head: v(0),
                absorption_id_head: v(1),
            },
            Deg { v: 2, u: 1 },
        );
    }
}

fn emit_node<B: LookupBatch, V: Copy + Into<B::Expr>>(
    batch: &mut B,
    phase: usize,
    local: &[V; NUM_MAIN_COLS],
    next: &[V; NUM_MAIN_COLS],
) where
    B::Expr: Algebra<Felt>,
{
    let v = |i: usize| -> B::Expr { local[i].into() };
    let nv = |i: usize| -> B::Expr { next[i].into() };
    let act = v(COL_NODE_ACT);
    let degree = Deg { v: 1, u: 1 };
    let payload = || PAYLOAD.map(v);
    let chunks_cv = |n| {
        initial_cv_from_frame([
            B::Expr::from(DEFERRED_CHUNKS_DOMAIN),
            n,
            B::Expr::ZERO,
            B::Expr::ZERO,
        ])
    };
    match phase {
        0 => {
            batch.insert(
                "ks-request",
                -act.clone(),
                KeccakSpongeMsg {
                    sponge_seq_id: v(COL_SPONGE_HEAD),
                    chunk_ptr: v(COL_CHUNK_HEAD) * B::Expr::from_u8(4),
                    len_bytes: v(COL_LEN),
                },
                degree,
            );
            batch.insert(
                "chunk-chain",
                act.clone(),
                ChunkChainMsg {
                    chunk_seq_id_head: v(COL_CHUNK_HEAD),
                    absorption_id_head: v(COL_INPUT_ID),
                },
                degree,
            );
            batch.insert(
                "chunk-remainder",
                act,
                BytePairLutMsg::from_xor(
                    v(COL_REMAINDER),
                    B::Expr::from_u8(31) - v(COL_REMAINDER),
                    B::Expr::from_u8(31),
                ),
                degree,
            );
        },
        1 => {
            for message in node::sponge_perm_count_messages(v(COL_LEN), v(COL_NODE_PERMS)) {
                batch.insert("sponge-count", act.clone(), message, degree);
            }
        },
        2 | 3 => {
            let addr = v(COL_SPONGE_HEAD) * B::Expr::from_u8(100)
                + v(COL_NODE_PERMS) * B::Expr::from_u16(3200)
                - B::Expr::from_u8(128);
            for lane in 0..2 {
                batch.insert(
                    "digest-lane",
                    act.clone(),
                    Memory64Msg {
                        addr: addr.clone() + B::Expr::from_usize(2 * (phase - 2) + lane),
                        lo: v(PAYLOAD[2 * lane]),
                        hi: v(PAYLOAD[2 * lane + 1]),
                    },
                    degree,
                );
            }
            if phase == 2 {
                batch.insert(
                    "digest-block",
                    act,
                    EidosBlockMsg {
                        compression_id: v(COL_DIGEST_ID),
                        block: array::from_fn(|i| {
                            if i < 4 { v(PAYLOAD[i]) } else { nv(PAYLOAD[i - 4]) }
                        }),
                    },
                    degree,
                );
            } else {
                batch.insert(
                    "digest-init",
                    act,
                    EidosInitMsg {
                        compression_id: v(COL_DIGEST_ID),
                        initial_cv: chunks_cv(B::Expr::from_u8(8)),
                    },
                    degree,
                );
            }
        },
        4 => {
            batch.insert(
                "input-out",
                act.clone(),
                EidosOutMsg {
                    chain_head_id: v(COL_INPUT_ID),
                    compression_id: v(COL_INPUT_ID) + v(COL_NODE_CHUNKS) - B::Expr::ONE,
                    digest: payload(),
                },
                degree,
            );
            batch.insert(
                "node-block",
                act.clone(),
                EidosBlockMsg {
                    compression_id: v(COL_NODE_ID),
                    block: array::from_fn(
                        |i| {
                            if i < 4 { v(PAYLOAD[i]) } else { nv(PAYLOAD[i - 4]) }
                        },
                    ),
                },
                degree,
            );
            batch.insert(
                "input-init",
                act,
                EidosInitMsg {
                    compression_id: v(COL_INPUT_ID),
                    initial_cv: chunks_cv(v(COL_NODE_CHUNKS) * B::Expr::from_u8(8)),
                },
                degree,
            );
        },
        5 => {
            batch.insert(
                "digest-out",
                act.clone(),
                EidosOutMsg {
                    chain_head_id: v(COL_DIGEST_ID),
                    compression_id: v(COL_DIGEST_ID),
                    digest: payload(),
                },
                degree,
            );
            batch.insert(
                "node-init",
                act,
                EidosInitMsg {
                    compression_id: v(COL_NODE_ID),
                    initial_cv: initial_cv_from_frame([
                        B::Expr::from(Keccak256Precompile::domain().as_felt()),
                        B::Expr::from_u32(Keccak256Precompile::ASSERT_OP_ID),
                        v(COL_LEN),
                        B::Expr::ZERO,
                    ]),
                },
                degree,
            );
        },
        6 => {
            batch.insert(
                "node-out",
                act,
                EidosOutMsg {
                    chain_head_id: v(COL_NODE_ID),
                    compression_id: v(COL_NODE_ID),
                    digest: payload(),
                },
                degree,
            );
            batch.insert("binding-truth", -v(COL_OUT_MULT), BindingMsg::truth(payload()), degree);
        },
        _ => unreachable!(),
    }
}

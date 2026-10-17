//! SHA-256 IO serialized over raw, chaining, digest and assertion rows.

pub mod program;

use alloc::{borrow::Cow, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    deferred::DEFERRED_CHUNKS_DOMAIN,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use miden_precompiles::Sha256Precompile;
use miden_utils_sync::LazyLock;
pub use program::{IO_PERIOD, NUM_PERIODIC_COLS, io_program};

use crate::{
    hash::sha256::compression::{INPUT_ADDR_BASE, OUTPUT_SLOTS, Sha256WordMsg},
    logup::{
        ConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, build_logup_aux_trace,
    },
    primitives::byte_pair_lut::{BytePairLutMsg, Range16Msg},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::BindingMsg,
        eidos::{EidosBlockMsg, EidosInitMsg, EidosOutMsg},
        initial_cv_from_frame,
    },
    utils::{current_main, halves_le, next_main, pack_le},
};

pub const NUM_MAIN_COLS: usize = 28;
pub const NUM_AUX_COLS: usize = 9;
pub const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 2, 2, 2, 2, 2, 2, 2, 1];
pub const COL_ACT: usize = 0;
pub const COL_BLOCK_ID: usize = 1;
pub const COL_FIRST_BLOCK: usize = 2;
pub const COL_FINAL_BLOCK: usize = 3;
pub const COL_BEFORE: usize = 4;
pub const COL_LEFT: usize = 5;
pub const COL_LEFT_LO16: usize = 6;
pub const COL_LEFT_HI16: usize = 7;
pub const COL_LEN: usize = 8;
pub const COL_CHUNK_ACTIVE: usize = 9;
pub const COL_INPUT_EIDOS: usize = 10;
pub const COL_INPUT_HEAD: usize = 11;
pub const COL_RAW_BEGIN: usize = 12;
pub const COL_MSG_BEGIN: usize = 16;
pub const COL_WORD: usize = 20;
/// Oldest to newest of the seven preceding little-endian raw words.
pub const COL_RAW_BUFFER: usize = 21;
// The phases below are disjoint from raw processing and reuse its payload cells.
pub const COL_STATE_HI: usize = 12;
pub const COL_STATE_LO: usize = 13;
pub const COL_DIGEST_BEGIN: usize = 12;
pub const COL_PREVIOUS_DIGEST: usize = 21;
pub const COL_CHUNK_HEAD_DIGEST: usize = 23;
pub const COL_DIGEST_EIDOS: usize = 6;
pub const COL_NODE_EIDOS: usize = 7;
pub const COL_OUT_MULT: usize = 9;
pub const COL_H_INPUT: usize = 12;
pub const COL_H_DIGEST: usize = 16;
pub const H_SHA256_COLS: [usize; 4] = [20, 21, 22, 23];

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256IoAir;

static PERIODIC_COLUMNS: LazyLock<[Vec<Felt>; NUM_PERIODIC_COLS]> = LazyLock::new(io_program);

impl BaseAir<Felt> for Sha256IoAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Borrowed(PERIODIC_COLUMNS.as_slice())
    }
}

impl LiftedAir<Felt, QuadFelt> for Sha256IoAir {
    fn max_periodic_length(&self) -> usize {
        IO_PERIOD
    }

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
        _: &[Felt],
        _: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_logup_aux_trace(self, main, challenges)
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        eval_main(builder, 0, 0);
        let mut lb = ConstraintLookupBuilder::new(builder, self);
        eval_lookups(&mut lb, 0, 0);
        lb.finish();
    }
}

/// Evaluate the local constraints in an independent main/periodic column band.
pub fn eval_main<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);
    let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), main_col_offset);
    let periods = builder.periodic_values();
    let p: [AB::Expr; NUM_PERIODIC_COLS] =
        array::from_fn(|i| periods[periodic_col_offset + i].into());
    let one = AB::Expr::ONE;
    let v = |i: usize| -> AB::Expr { local[i].into() };
    let nv = |i: usize| -> AB::Expr { next[i].into() };
    let act = v(COL_ACT);
    let next_act = nv(COL_ACT);
    let first = v(COL_FIRST_BLOCK);
    let final_block = v(COL_FINAL_BLOCK);
    let last = p[program::P_LAST].clone();
    let end = last.clone() * final_block.clone();
    let carry = next_act.clone() * (one.clone() - end);

    eval_main_rows(builder, &local, &next, &p, one.clone(), carry);

    // These controller constraints belong to the dense standalone wrapper. A composite caller
    // supplies the corresponding block/coverage constraints from the shared compression rows.
    builder.when_first_row().assert_zero(v(COL_BLOCK_ID));
    builder.when_first_row().assert_zero(act.clone() * (first - one.clone()));
    builder
        .when_transition()
        .assert_zero(nv(COL_BLOCK_ID) - v(COL_BLOCK_ID) - last.clone());
    builder
        .when_transition()
        .assert_zero((one.clone() - act.clone()) * next_act.clone());
    builder
        .when_transition()
        .assert_zero((one.clone() - last.clone()) * (next_act.clone() - act.clone()));
    builder
        .when_transition()
        .assert_zero(next_act.clone() * last.clone() * (nv(COL_FIRST_BLOCK) - final_block.clone()));
    builder
        .when_transition()
        .assert_zero((act.clone() - next_act) * last * (one.clone() - final_block.clone()));
    builder.when_last_row().assert_zero(act * (one - final_block));
}

/// `owned` gates reused cells; `carry` also includes non-final block boundaries in standalone IO.
pub(super) fn eval_main_rows<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    local: &[AB::Var; NUM_MAIN_COLS],
    next: &[AB::Var; NUM_MAIN_COLS],
    p: &[AB::Expr; NUM_PERIODIC_COLS],
    owned: AB::Expr,
    carry: AB::Expr,
) {
    let v = |i: usize| -> AB::Expr { local[i].into() };
    let nv = |i: usize| -> AB::Expr { next[i].into() };
    let one = AB::Expr::ONE;
    let act = v(COL_ACT);
    let first = v(COL_FIRST_BLOCK);
    let final_block = v(COL_FINAL_BLOCK);
    let raw = owned.clone() * p[program::P_RAW].clone();
    for column in [COL_ACT, COL_FIRST_BLOCK, COL_FINAL_BLOCK, COL_BEFORE] {
        builder.assert_zero(owned.clone() * v(column) * (one.clone() - v(column)));
    }
    builder.assert_zero(raw.clone() * v(COL_CHUNK_ACTIVE) * (one.clone() - v(COL_CHUNK_ACTIVE)));
    for column in [COL_FIRST_BLOCK, COL_FINAL_BLOCK] {
        builder.when_transition().assert_zero(
            owned.clone() * (one.clone() - p[program::P_LAST].clone()) * (nv(column) - v(column)),
        );
    }
    for column in [COL_LEN, COL_INPUT_HEAD] {
        builder.when_transition().assert_zero(carry.clone() * (nv(column) - v(column)));
    }
    let start = act.clone() * p[program::P_FIRST].clone() * first.clone();
    builder.assert_zero(start.clone() * (v(COL_LEFT) - v(COL_LEN)));
    builder.assert_zero(start.clone() * (v(COL_BEFORE) - one.clone()));
    builder.assert_zero(start * (v(COL_INPUT_HEAD) - v(COL_INPUT_EIDOS)));
    builder.assert_zero(
        act.clone()
            * p[program::P_RAW].clone()
            * (v(COL_LEFT) - v(COL_LEFT_LO16) - v(COL_LEFT_HI16) * Felt::from_u32(1 << 16)),
    );
    let mut sum = AB::Expr::ZERO;
    let mut previous = v(COL_BEFORE);
    let padded: [AB::Expr; 4] = array::from_fn(|i| {
        let msg = v(COL_MSG_BEGIN + i);
        builder.assert_zero(raw.clone() * msg.clone() * (one.clone() - msg.clone()));
        builder.assert_zero(raw.clone() * msg.clone() * (one.clone() - previous.clone()));
        builder.assert_zero(raw.clone() * v(COL_RAW_BEGIN + i) * (one.clone() - msg.clone()));
        let byte = v(COL_RAW_BEGIN + i) + (previous.clone() - msg.clone()) * Felt::from_u8(128);
        sum += msg.clone();
        previous = msg;
        byte
    });
    builder.assert_zero(raw * (one.clone() - previous.clone()) * (v(COL_LEFT) - sum.clone()));
    builder.when_transition().assert_zero(
        carry.clone() * (nv(COL_LEFT) - v(COL_LEFT) + p[program::P_RAW].clone() * sum.clone()),
    );
    builder.when_transition().assert_zero(
        carry.clone()
            * (nv(COL_BEFORE)
                - v(COL_BEFORE)
                - p[program::P_RAW].clone() * (previous - v(COL_BEFORE))),
    );
    builder.assert_zero(
        act.clone() * p[program::P_RAW_LAST].clone() * final_block.clone() * (v(COL_LEFT) - sum),
    );
    // The marker must precede W14/W15 exactly when this block is final.
    builder.assert_zero(
        act.clone()
            * p[program::P_LENGTH].clone()
            * (final_block.clone() + v(COL_BEFORE) - one.clone()),
    );
    let padded_word = padded
        .into_iter()
        .fold(AB::Expr::ZERO, |word, byte| word * Felt::from_u32(256) + byte);
    builder.assert_zero(
        act.clone()
            * (p[program::P_RAW].clone() - final_block.clone() * p[program::P_SUFFIX].clone())
            * (v(COL_WORD) - padded_word),
    );
    builder.assert_zero(
        act.clone()
            * p[program::P_LENGTH].clone()
            * final_block.clone()
            * (nv(COL_WORD) + v(COL_WORD) * Felt::new_unchecked(1u64 << 32)
                - v(COL_LEN) * Felt::from_u8(8)),
    );
    let expected_chunk = v(COL_MSG_BEGIN)
        + p[program::P_FIRST].clone() * first.clone() * (one.clone() - v(COL_MSG_BEGIN));
    builder.assert_zero(
        act.clone() * p[program::P_CHUNK_FIRST].clone() * (v(COL_CHUNK_ACTIVE) - expected_chunk),
    );
    builder.when_transition().assert_zero(
        owned.clone()
            * (p[program::P_RAW].clone() - p[program::P_CHUNK_END].clone())
            * (nv(COL_CHUNK_ACTIVE) - v(COL_CHUNK_ACTIVE)),
    );
    builder.when_transition().assert_zero(
        carry
            * (nv(COL_INPUT_EIDOS)
                - v(COL_INPUT_EIDOS)
                - (p[program::P_CHUNK_ADVANCE].clone() + p[program::P_LAST].clone())
                    * nv(COL_CHUNK_ACTIVE)),
    );
    for i in 0..7 {
        let value = if i < 6 {
            v(COL_RAW_BUFFER + i + 1)
        } else {
            pack_le(&local[COL_RAW_BEGIN..COL_RAW_BEGIN + 4], 256)
        };
        builder.when_transition().assert_zero(
            owned.clone() * p[program::P_RAW_NEXT].clone() * (nv(COL_RAW_BUFFER + i) - value),
        );
    }
    let state = act.clone() * first * p[program::P_STATE].clone();
    builder.assert_zero(state.clone() * (v(COL_STATE_HI) - p[program::P_IV_HI].clone()));
    builder.assert_zero(state * (v(COL_STATE_LO) - p[program::P_IV_LO].clone()));
    let digest: [AB::Var; 8] = array::from_fn(|i| local[COL_DIGEST_BEGIN + i]);
    for (i, half) in halves_le(&digest, 256).into_iter().enumerate() {
        builder.when_transition().assert_zero(
            act.clone()
                * final_block.clone()
                * p[program::P_DIGEST_NEXT].clone()
                * (nv(COL_PREVIOUS_DIGEST + i) - half),
        );
        builder.when_transition().assert_zero(
            act.clone()
                * final_block.clone()
                * p[program::P_DIGEST_SECOND].clone()
                * (nv(COL_CHUNK_HEAD_DIGEST + i) - v(COL_PREVIOUS_DIGEST + i)),
        );
    }
    builder.when_transition().assert_zero(
        act.clone()
            * final_block.clone()
            * p[program::P_DIGEST_CARRY].clone()
            * (nv(COL_DIGEST_EIDOS) - v(COL_DIGEST_EIDOS)),
    );
    builder.assert_zero(act * p[program::P_BIND].clone() * (one - final_block) * v(COL_OUT_MULT));
}

fn chunks_initial_cv<E: Algebra<Felt>>(num_felts: E) -> [E; 4] {
    initial_cv_from_frame([E::from(DEFERRED_CHUNKS_DOMAIN), num_felts, E::ZERO, E::ZERO])
}
fn halves_be<E: Algebra<Felt>, V: Clone + Into<E>>(bytes: &[V; 8]) -> [E; 2] {
    let pack = |s: &[V]| s.iter().fold(E::ZERO, |a, b| a * Felt::from_u32(256) + b.clone().into());
    [pack(&bytes[4..]), pack(&bytes[..4])]
}
fn digest_block<E: Algebra<Felt>, V: Copy + Into<E>>(
    local: &[V; NUM_MAIN_COLS],
    next: &[V; NUM_MAIN_COLS],
) -> [E; 8] {
    let current: [V; 8] = array::from_fn(|i| local[COL_DIGEST_BEGIN + i]);
    let following: [V; 8] = array::from_fn(|i| next[COL_DIGEST_BEGIN + i]);
    let [a, b] = halves_le(&current, 256);
    let [c, d] = halves_le(&following, 256);
    [
        local[COL_CHUNK_HEAD_DIGEST].into(),
        local[COL_CHUNK_HEAD_DIGEST + 1].into(),
        local[COL_PREVIOUS_DIGEST].into(),
        local[COL_PREVIOUS_DIGEST + 1].into(),
        a,
        b,
        c,
        d,
    ]
}

/// Degree after the mutually exclusive row-phase batch flags, including IO activity.
pub(super) fn lookup_column_degree(index: usize, continuation: bool) -> Deg {
    match index {
        0 => Deg { v: 2, u: 3 },
        4 => Deg { v: 5, u: 4 },
        8 => Deg {
            v: 3,
            u: if continuation { 4 } else { 3 },
        },
        _ => Deg { v: 4, u: 4 },
    }
}

#[derive(Clone, Copy)]
enum Batch {
    Word,
    StateHi,
    StateLo,
    Init,
    Out,
    RawBytes(usize),
    DigestBytes(usize),
    NodeIn,
    NodeOut,
    Left,
    RawBlock,
    DigestWords,
    Length,
    DigestBlock,
}

/// Add IO batches to the same group as compression: their row flags are mutually exclusive.
pub(super) fn eval_lookup_group<G, V>(
    group: &mut G,
    index: usize,
    local: &[V; NUM_MAIN_COLS],
    next: &[V; NUM_MAIN_COLS],
    p: &[G::Expr; NUM_PERIODIC_COLS],
    act: G::Expr,
) where
    G: LookupGroup,
    G::Expr: Algebra<Felt>,
    V: Copy + Into<G::Expr>,
{
    use program::*;
    let batches: &[(usize, Batch, Deg)] = match index {
        0 => &[(P_RAW, Batch::Word, Deg { v: 2, u: 3 })],
        1 => &[
            (P_STATE, Batch::StateHi, Deg { v: 4, u: 4 }),
            (P_BIND, Batch::Init, Deg { v: 4, u: 4 }),
        ],
        2 => &[
            (P_STATE, Batch::StateLo, Deg { v: 4, u: 4 }),
            (P_BIND, Batch::Out, Deg { v: 4, u: 4 }),
        ],
        3 => &[
            (P_RAW, Batch::RawBytes(0), Deg { v: 3, u: 4 }),
            (P_DIGEST, Batch::DigestBytes(0), Deg { v: 4, u: 4 }),
            (P_BIND, Batch::NodeIn, Deg { v: 4, u: 4 }),
        ],
        4 => &[
            (P_RAW, Batch::RawBytes(2), Deg { v: 3, u: 4 }),
            (P_DIGEST, Batch::DigestBytes(2), Deg { v: 4, u: 4 }),
            (P_BIND, Batch::NodeOut, Deg { v: 5, u: 4 }),
        ],
        5 => &[
            (P_RAW, Batch::Left, Deg { v: 3, u: 4 }),
            (P_DIGEST, Batch::DigestBytes(4), Deg { v: 4, u: 4 }),
        ],
        6 => &[
            (P_RAW_EMIT, Batch::RawBlock, Deg { v: 3, u: 3 }),
            (P_DIGEST, Batch::DigestBytes(6), Deg { v: 4, u: 4 }),
        ],
        7 => &[
            (P_DIGEST, Batch::DigestWords, Deg { v: 4, u: 4 }),
            (P_LENGTH, Batch::Length, Deg { v: 3, u: 3 }),
        ],
        8 => &[(P_DIGEST_EMIT, Batch::DigestBlock, Deg { v: 3, u: 3 })],
        _ => unreachable!(),
    };
    for &(selector, kind, degree) in batches {
        group.batch(
            "io-phase",
            act.clone() * p[selector].clone(),
            |batch| eval_batch(batch, kind, local, next, p),
            degree,
        );
    }
}
fn eval_batch<B, V>(
    batch: &mut B,
    kind: Batch,
    local: &[V; NUM_MAIN_COLS],
    next: &[V; NUM_MAIN_COLS],
    p: &[B::Expr; NUM_PERIODIC_COLS],
) where
    B: LookupBatch,
    B::Expr: Algebra<Felt>,
    V: Copy + Into<B::Expr>,
{
    let e = |i: usize| -> B::Expr { local[i].into() };
    let final_block = e(COL_FINAL_BLOCK);
    let word = |bid, addr, value| Sha256WordMsg { block_id: bid, addr, value };
    let one = B::Expr::ONE;
    let d0 = Deg { v: 0, u: 1 };
    let d1 = Deg { v: 1, u: 1 };
    match kind {
        Batch::Word => batch.insert(
            "input",
            -one,
            word(
                e(COL_BLOCK_ID),
                B::Expr::from_u32(INPUT_ADDR_BASE) + p[program::P_IDX].clone(),
                e(COL_WORD),
            ),
            d0,
        ),
        Batch::StateHi | Batch::StateLo => {
            let (off, col) = if matches!(kind, Batch::StateHi) {
                (0, COL_STATE_HI)
            } else {
                (1, COL_STATE_LO)
            };
            let addr = p[program::P_STATE_IDX].clone() * Felt::from_u8(2) + B::Expr::from_u32(off);
            batch.insert(
                "incoming",
                -one.clone(),
                word(
                    e(COL_BLOCK_ID),
                    B::Expr::from_u32(INPUT_ADDR_BASE + 16) + addr.clone(),
                    e(col),
                ),
                d0,
            );
            batch.insert(
                "previous",
                one - e(COL_FIRST_BLOCK),
                word(
                    e(COL_BLOCK_ID) - B::Expr::ONE,
                    B::Expr::from_u32(OUTPUT_SLOTS[0]) + addr,
                    e(col),
                ),
                d1,
            );
        },
        Batch::Init => {
            batch.insert(
                "raw-init",
                final_block.clone(),
                EidosInitMsg {
                    compression_id: e(COL_INPUT_HEAD),
                    initial_cv: chunks_initial_cv(
                        (e(COL_INPUT_EIDOS) - e(COL_INPUT_HEAD) + one) * Felt::from_u8(8),
                    ),
                },
                d1,
            );
            batch.insert(
                "digest-init",
                final_block,
                EidosInitMsg {
                    compression_id: e(COL_DIGEST_EIDOS),
                    initial_cv: chunks_initial_cv(B::Expr::from_u8(8)),
                },
                d1,
            );
        },
        Batch::Out => {
            batch.insert(
                "raw-out",
                final_block.clone(),
                EidosOutMsg {
                    chain_head_id: e(COL_INPUT_HEAD),
                    compression_id: e(COL_INPUT_EIDOS),
                    digest: array::from_fn(|i| e(COL_H_INPUT + i)),
                },
                d1,
            );
            batch.insert(
                "digest-out",
                final_block,
                EidosOutMsg {
                    chain_head_id: e(COL_DIGEST_EIDOS),
                    compression_id: e(COL_DIGEST_EIDOS),
                    digest: array::from_fn(|i| e(COL_H_DIGEST + i)),
                },
                d1,
            );
        },
        Batch::NodeIn => {
            let frame = [
                B::Expr::from(Sha256Precompile::domain().as_felt()),
                B::Expr::from_u32(Sha256Precompile::ASSERT_OP_ID),
                e(COL_LEN),
                B::Expr::ZERO,
            ];
            batch.insert(
                "node-init",
                final_block.clone(),
                EidosInitMsg {
                    compression_id: e(COL_NODE_EIDOS),
                    initial_cv: initial_cv_from_frame(frame),
                },
                d1,
            );
            batch.insert(
                "node-block",
                final_block,
                EidosBlockMsg {
                    compression_id: e(COL_NODE_EIDOS),
                    block: array::from_fn(|i| e(COL_H_INPUT + i)),
                },
                d1,
            );
        },
        Batch::NodeOut => {
            let digest = H_SHA256_COLS.map(e);
            batch.insert(
                "node-out",
                final_block.clone(),
                EidosOutMsg {
                    chain_head_id: e(COL_NODE_EIDOS),
                    compression_id: e(COL_NODE_EIDOS),
                    digest: digest.clone(),
                },
                d1,
            );
            batch.insert(
                "truth",
                -final_block * e(COL_OUT_MULT),
                BindingMsg::truth(digest),
                Deg { v: 2, u: 1 },
            );
        },
        Batch::RawBytes(offset) | Batch::DigestBytes(offset) => {
            let is_digest = matches!(kind, Batch::DigestBytes(_));
            let base = if is_digest { COL_DIGEST_BEGIN } else { COL_RAW_BEGIN };
            let mult = if is_digest { final_block } else { one };
            for i in offset..offset + 2 {
                batch.insert(
                    "byte",
                    mult.clone(),
                    BytePairLutMsg::from_xor(B::Expr::ZERO, e(base + i), e(base + i)),
                    if is_digest { d1 } else { d0 },
                );
            }
        },
        Batch::Left => {
            batch.insert("left-low", one.clone(), Range16Msg { w: e(COL_LEFT_LO16) }, d0);
            batch.insert("left-high", one, Range16Msg { w: e(COL_LEFT_HI16) }, d0);
        },
        Batch::RawBlock => batch.insert(
            "raw-block",
            e(COL_CHUNK_ACTIVE),
            EidosBlockMsg {
                compression_id: e(COL_INPUT_EIDOS),
                block: array::from_fn(|i| {
                    if i < 7 {
                        e(COL_RAW_BUFFER + i)
                    } else {
                        pack_le(&local[COL_RAW_BEGIN..COL_RAW_BEGIN + 4], 256)
                    }
                }),
            },
            d1,
        ),
        Batch::DigestWords => {
            let bytes: [V; 8] = array::from_fn(|i| local[COL_DIGEST_BEGIN + i]);
            let [lo, hi] = halves_be(&bytes);
            let addr = B::Expr::from_u32(OUTPUT_SLOTS[0])
                + p[program::P_DIGEST_IDX].clone() * Felt::from_u8(2);
            batch.insert(
                "digest-hi",
                final_block.clone(),
                word(e(COL_BLOCK_ID), addr.clone(), hi),
                d1,
            );
            batch.insert("digest-lo", final_block, word(e(COL_BLOCK_ID), addr + one, lo), d1);
        },
        Batch::Length => {
            batch.insert("length-high", final_block, Range16Msg { w: e(COL_WORD) }, d1)
        },
        Batch::DigestBlock => batch.insert(
            "digest-block",
            final_block,
            EidosBlockMsg {
                compression_id: e(COL_DIGEST_EIDOS),
                block: digest_block(local, next),
            },
            d1,
        ),
    }
}

pub fn eval_lookups<LB: LookupBuilder<F = Felt>>(
    builder: &mut LB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local = current_main(builder.main(), main_col_offset);
    let next = next_main(builder.main(), main_col_offset);
    let p = array::from_fn(|i| builder.periodic_values()[periodic_col_offset + i].into());
    let act: LB::Expr = local[COL_ACT].into();
    for index in 0..NUM_AUX_COLS {
        let degree = lookup_column_degree(index, false);
        builder.next_column(
            |column| {
                column.group(
                    "io",
                    |group| eval_lookup_group(group, index, &local, &next, &p, act.clone()),
                    degree,
                )
            },
            degree,
        );
    }
}
impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for Sha256IoAir {
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
        eval_lookups(builder, 0, 0);
    }
}

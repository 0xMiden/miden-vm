//! SHA-256 padding, chaining, and deferred-assertion binding.
//!
//! Each active block occupies eight rows, one per eight message bytes, which form two big-endian
//! u32 message words. Raw message bytes are committed independently of SHA padding, through
//! framed Eidos compression chains. SHA word messages connect this band to the fixed-program
//! compressor without entering Keccak's namespace.

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
    utils::{current_main, halves_le, next_main},
};

pub const NUM_MAIN_COLS: usize = 51;
pub const NUM_AUX_COLS: usize = 18;
pub const COLUMN_SHAPE: [usize; NUM_AUX_COLS] =
    [2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1];

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
/// Eidos compression ID of the current raw-input chunk; the chain tail on the final row.
pub const COL_INPUT_EIDOS: usize = 10;
/// Eidos compression ID of the digest chain, whose single chunk spans state rows 0..3.
pub const COL_DIGEST_EIDOS: usize = 11;
/// Eidos compression ID of the assertion node.
pub const COL_NODE_EIDOS: usize = 12;
pub const COL_OUT_MULT: usize = 13;
pub const COL_RAW_BEGIN: usize = 14;
pub const COL_MSG_BEGIN: usize = 22;
pub const COL_PREVIOUS_RAW: usize = 30;
/// Message word `W[2i + 1]`, the big-endian value of the row's last four padded bytes.
pub const COL_WORD_LO: usize = 32;
/// Message word `W[2i]`, the big-endian value of the row's first four padded bytes.
pub const COL_WORD_HI: usize = 33;
/// Chaining word `H[2i + 1]` on state row `i`.
pub const COL_STATE_LO: usize = 34;
/// Chaining word `H[2i]` on state row `i`.
pub const COL_STATE_HI: usize = 35;
pub const COL_DIGEST_BEGIN: usize = 36;
pub const COL_PREVIOUS_DIGEST: usize = 44;
/// Eidos compression ID of the raw-input chain head, carried through the invocation.
pub const COL_INPUT_HEAD: usize = 46;
/// Packed raw-input felts of a chunk's first row, carried to the row that emits the chunk.
pub const COL_CHUNK_HEAD_RAW: usize = 47;
/// Packed digest felts of a chunk's first row, carried to the row that emits the chunk.
pub const COL_CHUNK_HEAD_DIGEST: usize = 49;

// The following cells are unused by state/digest extraction on row 7 and hold assertion hashes.
// Every constraint and lookup on their ordinary byte/word meaning is restricted to rows 0..3.
pub const COL_H_INPUT: usize = COL_DIGEST_BEGIN;
pub const COL_H_DIGEST: usize = COL_DIGEST_BEGIN + 4;
pub const H_SHA256_COLS: [usize; 4] =
    [COL_STATE_LO, COL_STATE_HI, COL_PREVIOUS_DIGEST, COL_PREVIOUS_DIGEST + 1];

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

/// Evaluate the row-local IO equations shared by the dense standalone band and the composite
/// SHA-256 layout. `owned` gates interpretations of cells which are only meaningful on IO rows;
/// `carry` gates transport across the next-row boundary.
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
    let last = p[program::P_LAST].clone();
    let end = last.clone() * final_block.clone();

    for index in [COL_ACT, COL_FIRST_BLOCK, COL_FINAL_BLOCK, COL_BEFORE, COL_CHUNK_ACTIVE] {
        builder
            .assert_zero(owned.clone() * local[index].into() * (one.clone() - local[index].into()));
    }

    builder
        .when_transition()
        .assert_zero(carry.clone() * (nv(COL_LEN) - v(COL_LEN)));
    builder
        .when_transition()
        .assert_zero(carry.clone() * (nv(COL_INPUT_HEAD) - v(COL_INPUT_HEAD)));
    for index in [COL_FIRST_BLOCK, COL_FINAL_BLOCK] {
        builder
            .when_transition()
            .assert_zero(owned.clone() * (one.clone() - last.clone()) * (nv(index) - v(index)));
    }
    let start = p[program::P_FIRST].clone() * first.clone();
    builder.assert_zero(act.clone() * start.clone() * (v(COL_LEFT) - v(COL_LEN)));
    builder.assert_zero(act.clone() * start.clone() * (v(COL_BEFORE) - one.clone()));
    builder.assert_zero(act.clone() * start * (v(COL_INPUT_HEAD) - v(COL_INPUT_EIDOS)));
    builder.assert_zero(
        act.clone() * (v(COL_LEFT) - v(COL_LEFT_LO16) - v(COL_LEFT_HI16) * Felt::from_u32(1 << 16)),
    );

    let mut sum_msg = AB::Expr::ZERO;
    let mut previous = v(COL_BEFORE);
    let padded: [AB::Expr; 8] = array::from_fn(|i| {
        let msg = v(COL_MSG_BEGIN + i);
        builder.assert_zero(
            owned.clone() * local[COL_MSG_BEGIN + i].into() * (one.clone() - msg.clone()),
        );
        builder
            .assert_zero(owned.clone() * v(COL_MSG_BEGIN + i) * (one.clone() - previous.clone()));
        builder.assert_zero(owned.clone() * v(COL_RAW_BEGIN + i) * (one.clone() - msg.clone()));
        let byte = v(COL_RAW_BEGIN + i) + (previous.clone() - msg.clone()) * Felt::from_u8(128);
        sum_msg += msg.clone();
        previous = msg;
        byte
    });
    builder.assert_zero(
        act.clone() * (one.clone() - previous.clone()) * (v(COL_LEFT) - sum_msg.clone()),
    );
    builder
        .when_transition()
        .assert_zero(carry.clone() * (nv(COL_LEFT) - v(COL_LEFT) + sum_msg.clone()));
    builder
        .when_transition()
        .assert_zero(carry.clone() * (nv(COL_BEFORE) - previous));
    builder.assert_zero(act.clone() * end.clone() * (v(COL_LEFT) - sum_msg));
    // The 64-bit length suffix fills the last row, so the message and its marker end before it
    // exactly when the block is final.
    builder.assert_zero(
        act.clone() * last.clone() * (final_block.clone() + v(COL_BEFORE) - one.clone()),
    );
    let [word_lo, word_hi]: [AB::Expr; 2] = halves_be(&padded);
    let data_gate = act.clone() * (one.clone() - end.clone());
    builder.assert_zero(data_gate.clone() * (v(COL_WORD_LO) - word_lo));
    builder.assert_zero(data_gate * (v(COL_WORD_HI) - word_hi));
    // Range16(word_hi), together with the compressor's u32 words, prevents an alias at 8*n+p.
    builder.assert_zero(
        act.clone()
            * end.clone()
            * (v(COL_WORD_LO) + v(COL_WORD_HI) * Felt::new_unchecked(1u64 << 32)
                - v(COL_LEN) * Felt::from_u8(8)),
    );

    let expected_chunk =
        v(COL_MSG_BEGIN) + p[program::P_FIRST].clone() * first * (one.clone() - v(COL_MSG_BEGIN));
    builder.assert_zero(
        act.clone() * p[program::P_CHUNK_FIRST].clone() * (v(COL_CHUNK_ACTIVE) - expected_chunk),
    );
    builder.when_transition().assert_zero(
        owned.clone()
            * (one.clone() - p[program::P_CHUNK_LAST].clone())
            * (nv(COL_CHUNK_ACTIVE) - v(COL_CHUNK_ACTIVE)),
    );
    builder.when_transition().assert_zero(
        carry.clone()
            * (nv(COL_INPUT_EIDOS)
                - v(COL_INPUT_EIDOS)
                - p[program::P_CHUNK_LAST].clone() * nv(COL_CHUNK_ACTIVE)),
    );
    // An Eidos block carries a whole chunk. Chunk rows 1 and 2 already see the preceding row's
    // packed felts; row 1 also forwards its predecessor so the emitting row sees all four rows.
    for (head, previous) in [
        (COL_CHUNK_HEAD_RAW, COL_PREVIOUS_RAW),
        (COL_CHUNK_HEAD_DIGEST, COL_PREVIOUS_DIGEST),
    ] {
        for i in 0..2 {
            builder.when_transition().assert_zero(
                owned.clone()
                    * p[program::P_CHUNK_SECOND].clone()
                    * (nv(head + i) - v(previous + i)),
            );
        }
    }
    let raw: [AB::Var; 8] = array::from_fn(|i| local[COL_RAW_BEGIN + i]);
    let raw_le: [AB::Expr; 2] = halves_le(&raw, 256);
    for (i, packed) in raw_le.into_iter().enumerate() {
        builder
            .when_transition()
            .assert_zero(carry.clone() * (nv(COL_PREVIOUS_RAW + i) - packed));
    }

    let state_gate = act.clone() * v(COL_FIRST_BLOCK) * p[program::P_STATE].clone();
    builder.assert_zero(state_gate.clone() * (v(COL_STATE_LO) - p[program::P_IV_LO].clone()));
    builder.assert_zero(state_gate * (v(COL_STATE_HI) - p[program::P_IV_HI].clone()));
    let digest: [AB::Var; 8] = array::from_fn(|i| local[COL_DIGEST_BEGIN + i]);
    let digest_le: [AB::Expr; 2] = halves_le(&digest, 256);
    for (i, packed) in digest_le.into_iter().enumerate() {
        builder.when_transition().assert_zero(
            act.clone()
                * final_block.clone()
                * p[program::P_DIGEST_NEXT].clone()
                * (nv(COL_PREVIOUS_DIGEST + i) - packed),
        );
    }
    // This includes row 6->7: the final EidosOut must refer to the same digest chunk.
    builder.when_transition().assert_zero(
        act.clone() * final_block * (one - last) * (nv(COL_DIGEST_EIDOS) - v(COL_DIGEST_EIDOS)),
    );
    builder.assert_zero((owned - act * end) * v(COL_OUT_MULT));
}

/// The eight packed felts of the chunk whose third row is `local`: the carried first row, the
/// carried second row, and the little-endian halves of `local` and `next`.
fn chunk_block<E: Algebra<Felt>, V: Copy + Into<E>>(
    local: &[V; NUM_MAIN_COLS],
    next: &[V; NUM_MAIN_COLS],
    head: usize,
    previous: usize,
    bytes: usize,
) -> [E; 8] {
    let current: [V; 8] = array::from_fn(|i| local[bytes + i]);
    let following: [V; 8] = array::from_fn(|i| next[bytes + i]);
    let [current_lo, current_hi] = halves_le(&current, 256);
    let [following_lo, following_hi] = halves_le(&following, 256);
    [
        local[head].into(),
        local[head + 1].into(),
        local[previous].into(),
        local[previous + 1].into(),
        current_lo,
        current_hi,
        following_lo,
        following_hi,
    ]
}

/// Initial chaining value of a `DEFERRED_CHUNKS` chain over `num_felts` payload felts.
fn chunks_initial_cv<E: Algebra<Felt>>(num_felts: E) -> [E; 4] {
    initial_cv_from_frame([E::from(DEFERRED_CHUNKS_DOMAIN), num_felts, E::ZERO, E::ZERO])
}

fn halves_be<E: Algebra<Felt>, V: Clone + Into<E>>(bytes: &[V; 8]) -> [E; 2] {
    let pack = |slice: &[V]| {
        slice
            .iter()
            .fold(E::ZERO, |acc, byte| acc * Felt::from_u32(256) + byte.clone().into())
    };
    [pack(&bytes[4..]), pack(&bytes[..4])]
}

/// Append this band's lookup columns to the enclosing AIR's single LogUp recurrence.
pub fn eval_lookups<LB: LookupBuilder<F = Felt>>(
    builder: &mut LB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);
    let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), main_col_offset);
    let periods = builder.periodic_values();
    let p: [LB::Expr; NUM_PERIODIC_COLS] =
        array::from_fn(|i| periods[periodic_col_offset + i].into());
    for index in 0..NUM_AUX_COLS {
        let degree = lookup_batch_degree(index, 1);
        let group = match index {
            0 => "sha256-words",
            1..=2 => "sha256-state",
            3 => "sha256-digest-and-input",
            4..=6 => "sha256-chunks",
            7 => "sha256-assertion",
            8..=15 => "sha256-bytes",
            16..=17 => "sha256-length",
            _ => unreachable!(),
        };
        builder.next_column(
            |col| {
                col.group(
                    group,
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |batch| {
                                eval_lookup_batch(
                                    batch,
                                    index,
                                    &local,
                                    &next,
                                    &p,
                                    local[COL_ACT].into(),
                                    1,
                                );
                            },
                            degree,
                        );
                    },
                    degree,
                );
            },
            degree,
        );
    }
}

/// Return the post-batch degree annotation for one of the fixed IO lookup columns.
pub(super) fn lookup_batch_degree(index: usize, activity_degree: usize) -> Deg {
    debug_assert!(index < NUM_AUX_COLS);
    debug_assert!(activity_degree <= 1);
    let (v, u) = match index {
        0 => (2, 2),
        1 | 2 => (4, 2),
        3 => (5, 3),
        4 => (5, 2),
        5 | 6 => (4, 2),
        7 => (5, 3),
        8..=11 => (2, 2),
        12..=15 => (4, 2),
        16 => (2, 2),
        17 => (3, 1),
        _ => unreachable!(),
    };
    Deg { v: v - (1 - activity_degree), u }
}

/// Emit one fixed IO lookup batch. The caller owns the enclosing column, group, and batch flag.
pub(super) fn eval_lookup_batch<B, V>(
    batch: &mut B,
    index: usize,
    local: &[V; NUM_MAIN_COLS],
    next: &[V; NUM_MAIN_COLS],
    p: &[B::Expr; NUM_PERIODIC_COLS],
    act: B::Expr,
    activity_degree: usize,
) where
    B: LookupBatch,
    B::Expr: Algebra<Felt>,
    V: Copy + Into<B::Expr>,
{
    let e = |i: usize| -> B::Expr { local[i].into() };
    let one = B::Expr::ONE;
    let d = |v: usize, u: usize| Deg { v: v - (1 - activity_degree), u };
    let word = |block_id, addr, value| Sha256WordMsg { block_id, addr, value };
    // Row `i` carries the word pair `(W[2i], W[2i + 1])`, and state row `i` the pair
    // `(H[2i], H[2i + 1])`, at consecutive addresses.
    let pair_addr = |base: u32, offset: u32| {
        p[program::P_IDX].clone() * Felt::from_u8(2) + B::Expr::from_u32(base + offset)
    };
    match index {
        0 => {
            batch.insert(
                "input-hi",
                B::Expr::ZERO - act.clone(),
                word(e(COL_BLOCK_ID), pair_addr(INPUT_ADDR_BASE, 0), e(COL_WORD_HI)),
                d(1, 1),
            );
            batch.insert(
                "input-lo",
                B::Expr::ZERO - act,
                word(e(COL_BLOCK_ID), pair_addr(INPUT_ADDR_BASE, 1), e(COL_WORD_LO)),
                d(1, 1),
            );
        },
        1 | 2 => {
            let (offset, column) = if index == 1 {
                (0, COL_STATE_HI)
            } else {
                (1, COL_STATE_LO)
            };
            let state = act * p[program::P_STATE].clone();
            let previous_state = state.clone() * (one - e(COL_FIRST_BLOCK));
            batch.insert(
                "incoming",
                B::Expr::ZERO - state,
                word(e(COL_BLOCK_ID), pair_addr(INPUT_ADDR_BASE + 16, offset), e(column)),
                d(2, 1),
            );
            batch.insert(
                "previous",
                previous_state,
                word(e(COL_BLOCK_ID) - B::Expr::ONE, pair_addr(OUTPUT_SLOTS[0], offset), e(column)),
                d(3, 1),
            );
        },
        3 => {
            let state = act.clone() * p[program::P_STATE].clone();
            let digest = state * e(COL_FINAL_BLOCK);
            let raw_emit = act * e(COL_CHUNK_ACTIVE) * p[program::P_CHUNK_EMIT].clone();
            let digest_bytes: [V; 8] = array::from_fn(|i| local[COL_DIGEST_BEGIN + i]);
            let digest_expr: [B::Expr; 8] = digest_bytes.map(Into::into);
            let [digest_lo, digest_hi]: [B::Expr; 2] = halves_be(&digest_expr);
            batch.insert(
                "digest-hi",
                digest.clone(),
                word(e(COL_BLOCK_ID), pair_addr(OUTPUT_SLOTS[0], 0), digest_hi),
                d(3, 1),
            );
            batch.insert(
                "digest-lo",
                digest,
                word(e(COL_BLOCK_ID), pair_addr(OUTPUT_SLOTS[0], 1), digest_lo),
                d(3, 1),
            );
            batch.insert(
                "raw-block",
                raw_emit,
                EidosBlockMsg {
                    compression_id: e(COL_INPUT_EIDOS),
                    block: chunk_block(
                        local,
                        next,
                        COL_CHUNK_HEAD_RAW,
                        COL_PREVIOUS_RAW,
                        COL_RAW_BEGIN,
                    ),
                },
                d(3, 1),
            );
        },
        4 => {
            let end = act.clone() * e(COL_FINAL_BLOCK) * p[program::P_LAST].clone();
            let state = act * p[program::P_STATE].clone();
            let digest_emit = state * e(COL_FINAL_BLOCK) * p[program::P_CHUNK_EMIT].clone();
            batch.insert(
                "raw-init",
                end,
                EidosInitMsg {
                    compression_id: e(COL_INPUT_HEAD),
                    initial_cv: chunks_initial_cv(
                        (e(COL_INPUT_EIDOS) - e(COL_INPUT_HEAD) + B::Expr::ONE)
                            * B::Expr::from(Felt::from(8u8)),
                    ),
                },
                d(3, 1),
            );
            batch.insert(
                "digest-block",
                digest_emit,
                EidosBlockMsg {
                    compression_id: e(COL_DIGEST_EIDOS),
                    block: chunk_block(
                        local,
                        next,
                        COL_CHUNK_HEAD_DIGEST,
                        COL_PREVIOUS_DIGEST,
                        COL_DIGEST_BEGIN,
                    ),
                },
                d(4, 1),
            );
        },
        5 => {
            let end = act * e(COL_FINAL_BLOCK) * p[program::P_LAST].clone();
            batch.insert(
                "digest-init",
                end.clone(),
                EidosInitMsg {
                    compression_id: e(COL_DIGEST_EIDOS),
                    initial_cv: chunks_initial_cv(B::Expr::from(Felt::from(8u8))),
                },
                d(3, 1),
            );
            batch.insert(
                "raw-digest",
                end,
                EidosOutMsg {
                    chain_head_id: e(COL_INPUT_HEAD),
                    compression_id: e(COL_INPUT_EIDOS),
                    digest: array::from_fn(|i| e(COL_H_INPUT + i)),
                },
                d(3, 1),
            );
        },
        6 => {
            let end = act * e(COL_FINAL_BLOCK) * p[program::P_LAST].clone();
            let assert_frame = [
                B::Expr::from(Sha256Precompile::domain().as_felt()),
                B::Expr::from(Felt::from_u32(Sha256Precompile::ASSERT_OP_ID)),
                e(COL_LEN),
                B::Expr::ZERO,
            ];
            batch.insert(
                "full-digest",
                end.clone(),
                EidosOutMsg {
                    chain_head_id: e(COL_DIGEST_EIDOS),
                    compression_id: e(COL_DIGEST_EIDOS),
                    digest: array::from_fn(|i| e(COL_H_DIGEST + i)),
                },
                d(3, 1),
            );
            batch.insert(
                "node-init",
                end,
                EidosInitMsg {
                    compression_id: e(COL_NODE_EIDOS),
                    initial_cv: initial_cv_from_frame(assert_frame),
                },
                d(3, 1),
            );
        },
        7 => {
            let end = act * e(COL_FINAL_BLOCK) * p[program::P_LAST].clone();
            let h_sha256 = H_SHA256_COLS.map(e);
            batch.insert(
                "node-block",
                end.clone(),
                EidosBlockMsg {
                    compression_id: e(COL_NODE_EIDOS),
                    block: array::from_fn(|i| {
                        if i < 4 {
                            e(COL_H_INPUT + i)
                        } else {
                            e(COL_H_DIGEST + i - 4)
                        }
                    }),
                },
                d(3, 1),
            );
            batch.insert(
                "node-out",
                end,
                EidosOutMsg {
                    chain_head_id: e(COL_NODE_EIDOS),
                    compression_id: e(COL_NODE_EIDOS),
                    digest: h_sha256.clone(),
                },
                d(3, 1),
            );
            batch.insert(
                "truth",
                B::Expr::ZERO - e(COL_OUT_MULT),
                BindingMsg::truth(h_sha256),
                Deg { v: 1, u: 1 },
            );
        },
        8..=11 => {
            let i = 2 * (index - 8);
            let byte = |offset| {
                BytePairLutMsg::from_xor(
                    B::Expr::ZERO,
                    e(COL_RAW_BEGIN + i + offset),
                    e(COL_RAW_BEGIN + i + offset),
                )
            };
            batch.insert("byte", act.clone(), byte(0), d(1, 1));
            batch.insert("byte", act, byte(1), d(1, 1));
        },
        12..=15 => {
            let i = 2 * (index - 12);
            let state = act * p[program::P_STATE].clone();
            let digest = state * e(COL_FINAL_BLOCK);
            let byte = |offset| {
                BytePairLutMsg::from_xor(
                    B::Expr::ZERO,
                    e(COL_DIGEST_BEGIN + i + offset),
                    e(COL_DIGEST_BEGIN + i + offset),
                )
            };
            batch.insert("byte", digest.clone(), byte(0), d(3, 1));
            batch.insert("byte", digest, byte(1), d(3, 1));
        },
        16 => {
            batch.insert("left-low", act.clone(), Range16Msg { w: e(COL_LEFT_LO16) }, d(1, 1));
            batch.insert("left-high", act, Range16Msg { w: e(COL_LEFT_HI16) }, d(1, 1));
        },
        17 => {
            let end = act * e(COL_FINAL_BLOCK) * p[program::P_LAST].clone();
            batch.insert("length-high", end, Range16Msg { w: e(COL_WORD_HI) }, d(3, 1));
        },
        _ => unreachable!(),
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

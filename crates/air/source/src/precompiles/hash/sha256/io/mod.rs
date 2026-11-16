//! SHA-256 IO serialized over raw, chaining, digest and assertion rows.

pub mod program;

use alloc::{borrow::Cow, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    deferred::DEFERRED_CHUNKS_DOMAIN,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
};
use miden_precompiles::Sha256Precompile;
use miden_stark::{
    air,
    air::LiftedAirBuilder as _,
    lookup::{self, Deg, LookupBatch, LookupColumn, LookupGroup},
};
use miden_utils_sync::LazyLock;
use p3_field::Dup;
pub use program::{IO_PERIOD, NUM_PERIODIC_COLS, io_program};

use crate::precompiles::{
    hash::sha256::compression::{INPUT_ADDR_BASE, OUTPUT_SLOTS, Sha256WordMsg},
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::{BytePairLutMsg, Range16Msg},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::BindingMsg,
        eidos::{EidosBlockMsg, EidosInitMsg, EidosOutMsg},
        initial_cv_from_frame,
    },
    utils::{halves_le, pack_le},
};

pub const NUM_MAIN_COLS: usize = 28;
pub const NUM_AUX_COLS: usize = 4;
pub const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [2; NUM_AUX_COLS];
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
/// XOR witnesses for adjacent digest-byte pairs, live only on rows 20..24.
/// These cells are idle in the digest controller and its incoming next-row references.
pub const COL_DIGEST_XOR: [usize; 4] = [20, 25, 26, 27];
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

impl air::LiftedAir for Sha256IoAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: NUM_AUX_COLS,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(PERIODIC_COLUMNS.as_slice()),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        eval_main(frame, builder, 0, 0);
        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for Sha256IoAir {
    type Error = lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}

/// Evaluate the local constraints in an independent main/periodic column band.
pub fn eval_main<AB: air::LiftedAirBuilder<F = Felt>>(
    frame: &air::Frame<'_, AB>,
    builder: &mut AB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local: &[AB::Expr; NUM_MAIN_COLS] = frame.main.current
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-256 current row band");
    let next: &[AB::Expr; NUM_MAIN_COLS] = frame.main.next
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-256 next row band");
    let p: &[AB::Expr; NUM_PERIODIC_COLS] = frame.periodic
        [periodic_col_offset..periodic_col_offset + NUM_PERIODIC_COLS]
        .try_into()
        .expect("SHA-256 IO periodic band");
    let one = AB::Expr::ONE;
    let v = |i: usize| -> AB::Expr { local[i].dup() };
    let nv = |i: usize| -> AB::Expr { next[i].dup() };
    let act = v(COL_ACT);
    let next_act = nv(COL_ACT);
    let first = v(COL_FIRST_BLOCK);
    let final_block = v(COL_FINAL_BLOCK);
    let last = p[program::P_LAST].dup();
    let end = last.dup() * final_block.dup();
    let carry = next_act.dup() * (one.dup() - end);

    eval_main_rows(frame, builder, local, next, p, one.dup(), carry);

    // These controller constraints belong to the dense standalone wrapper. A composite caller
    // supplies the corresponding block/coverage constraints from the shared compression rows.
    builder.when(frame.first_row()).assert_zero(v(COL_BLOCK_ID));
    builder.when(frame.first_row()).assert_zero(act.dup() * (first - one.dup()));
    builder
        .when(frame.transition())
        .assert_zero(nv(COL_BLOCK_ID) - v(COL_BLOCK_ID) - last.dup());
    builder
        .when(frame.transition())
        .assert_zero((one.dup() - act.dup()) * next_act.dup());
    builder
        .when(frame.transition())
        .assert_zero((one.dup() - last.dup()) * (next_act.dup() - act.dup()));
    builder
        .when(frame.transition())
        .assert_zero(next_act.dup() * last.dup() * (nv(COL_FIRST_BLOCK) - final_block.dup()));
    builder
        .when(frame.transition())
        .assert_zero((act.dup() - next_act) * last * (one.dup() - final_block.dup()));
    builder.when(frame.last_row()).assert_zero(act * (one - final_block));
}

/// `owned` gates reused cells; `carry` also includes non-final block boundaries in standalone IO.
pub(super) fn eval_main_rows<AB: air::LiftedAirBuilder<F = Felt>>(
    frame: &air::Frame<'_, AB>,
    builder: &mut AB,
    local: &[AB::Expr; NUM_MAIN_COLS],
    next: &[AB::Expr; NUM_MAIN_COLS],
    p: &[AB::Expr; NUM_PERIODIC_COLS],
    owned: AB::Expr,
    carry: AB::Expr,
) {
    let v = |i: usize| -> AB::Expr { local[i].dup() };
    let nv = |i: usize| -> AB::Expr { next[i].dup() };
    let one = AB::Expr::ONE;
    let act = v(COL_ACT);
    let first = v(COL_FIRST_BLOCK);
    let final_block = v(COL_FINAL_BLOCK);
    let raw = owned.dup() * p[program::P_RAW].dup();
    for column in [COL_ACT, COL_FIRST_BLOCK, COL_FINAL_BLOCK, COL_BEFORE] {
        builder.assert_zero(owned.dup() * v(column) * (one.dup() - v(column)));
    }
    builder.assert_zero(raw.dup() * v(COL_CHUNK_ACTIVE) * (one.dup() - v(COL_CHUNK_ACTIVE)));
    for column in [COL_FIRST_BLOCK, COL_FINAL_BLOCK] {
        builder.when(frame.transition()).assert_zero(
            owned.dup() * (one.dup() - p[program::P_LAST].dup()) * (nv(column) - v(column)),
        );
    }
    for column in [COL_LEN, COL_INPUT_HEAD] {
        builder
            .when(frame.transition())
            .assert_zero(carry.dup() * (nv(column) - v(column)));
    }
    let start = act.dup() * p[program::P_FIRST].dup() * first.dup();
    builder.assert_zero(start.dup() * (v(COL_LEFT) - v(COL_LEN)));
    builder.assert_zero(start.dup() * (v(COL_BEFORE) - one.dup()));
    builder.assert_zero(start * (v(COL_INPUT_HEAD) - v(COL_INPUT_EIDOS)));
    builder.assert_zero(
        act.dup()
            * p[program::P_RAW].dup()
            * (v(COL_LEFT) - v(COL_LEFT_LO16) - v(COL_LEFT_HI16) * Felt::from_u32(1 << 16)),
    );
    let mut sum = AB::Expr::ZERO;
    let mut previous = v(COL_BEFORE);
    let padded: [AB::Expr; 4] = array::from_fn(|i| {
        let msg = v(COL_MSG_BEGIN + i);
        builder.assert_zero(raw.dup() * msg.dup() * (one.dup() - msg.dup()));
        builder.assert_zero(raw.dup() * msg.dup() * (one.dup() - previous.dup()));
        builder.assert_zero(raw.dup() * v(COL_RAW_BEGIN + i) * (one.dup() - msg.dup()));
        let byte = v(COL_RAW_BEGIN + i) + (previous.dup() - msg.dup()) * Felt::from_u8(128);
        sum += msg.dup();
        previous = msg;
        byte
    });
    builder.assert_zero(raw * (one.dup() - previous.dup()) * (v(COL_LEFT) - sum.dup()));
    builder.when(frame.transition()).assert_zero(
        carry.dup() * (nv(COL_LEFT) - v(COL_LEFT) + p[program::P_RAW].dup() * sum.dup()),
    );
    builder.when(frame.transition()).assert_zero(
        carry.dup()
            * (nv(COL_BEFORE)
                - v(COL_BEFORE)
                - p[program::P_RAW].dup() * (previous - v(COL_BEFORE))),
    );
    builder.assert_zero(
        act.dup() * p[program::P_RAW_LAST].dup() * final_block.dup() * (v(COL_LEFT) - sum),
    );
    // The marker must precede W14/W15 exactly when this block is final.
    builder.assert_zero(
        act.dup() * p[program::P_LENGTH].dup() * (final_block.dup() + v(COL_BEFORE) - one.dup()),
    );
    let padded_word = padded
        .into_iter()
        .fold(AB::Expr::ZERO, |word, byte| word * Felt::from_u32(256) + byte);
    builder.assert_zero(
        act.dup()
            * (p[program::P_RAW].dup() - final_block.dup() * p[program::P_SUFFIX].dup())
            * (v(COL_WORD) - padded_word),
    );
    builder.assert_zero(
        act.dup()
            * p[program::P_LENGTH].dup()
            * final_block.dup()
            * (nv(COL_WORD) + v(COL_WORD) * Felt::new_unchecked(1u64 << 32)
                - v(COL_LEN) * Felt::from_u8(8)),
    );
    let expected_chunk =
        v(COL_MSG_BEGIN) + p[program::P_FIRST].dup() * first.dup() * (one.dup() - v(COL_MSG_BEGIN));
    builder.assert_zero(
        act.dup() * p[program::P_CHUNK_FIRST].dup() * (v(COL_CHUNK_ACTIVE) - expected_chunk),
    );
    builder.when(frame.transition()).assert_zero(
        owned.dup()
            * (p[program::P_RAW].dup() - p[program::P_CHUNK_END].dup())
            * (nv(COL_CHUNK_ACTIVE) - v(COL_CHUNK_ACTIVE)),
    );
    builder.when(frame.transition()).assert_zero(
        carry
            * (nv(COL_INPUT_EIDOS)
                - v(COL_INPUT_EIDOS)
                - (p[program::P_CHUNK_ADVANCE].dup() + p[program::P_LAST].dup())
                    * nv(COL_CHUNK_ACTIVE)),
    );
    for i in 0..7 {
        let value = if i < 6 {
            v(COL_RAW_BUFFER + i + 1)
        } else {
            pack_le(&local[COL_RAW_BEGIN..COL_RAW_BEGIN + 4], 256)
        };
        builder.when(frame.transition()).assert_zero(
            owned.dup() * p[program::P_RAW_NEXT].dup() * (nv(COL_RAW_BUFFER + i) - value),
        );
    }
    let state = act.dup() * first * p[program::P_STATE].dup();
    builder.assert_zero(state.dup() * (v(COL_STATE_HI) - p[program::P_IV_HI].dup()));
    builder.assert_zero(state * (v(COL_STATE_LO) - p[program::P_IV_LO].dup()));
    let digest: &[AB::Expr; 8] = local[COL_DIGEST_BEGIN..COL_DIGEST_BEGIN + 8]
        .try_into()
        .expect("SHA-256 digest byte band");
    for (i, half) in halves_le::<AB::Expr, _>(digest, 256).into_iter().enumerate() {
        builder.when(frame.transition()).assert_zero(
            act.dup()
                * final_block.dup()
                * p[program::P_DIGEST_NEXT].dup()
                * (nv(COL_PREVIOUS_DIGEST + i) - half),
        );
        builder.when(frame.transition()).assert_zero(
            act.dup()
                * final_block.dup()
                * p[program::P_DIGEST_SECOND].dup()
                * (nv(COL_CHUNK_HEAD_DIGEST + i) - v(COL_PREVIOUS_DIGEST + i)),
        );
    }
    builder.when(frame.transition()).assert_zero(
        act.dup()
            * final_block.dup()
            * p[program::P_DIGEST_CARRY].dup()
            * (nv(COL_DIGEST_EIDOS) - v(COL_DIGEST_EIDOS)),
    );
    builder.assert_zero(act * p[program::P_BIND].dup() * (one - final_block) * v(COL_OUT_MULT));
}

fn chunks_initial_cv<E: Algebra<Felt>>(num_felts: E) -> [E; 4] {
    initial_cv_from_frame([E::from(DEFERRED_CHUNKS_DOMAIN), num_felts, E::ZERO, E::ZERO])
}
fn halves_be<E: Algebra<Felt>>(bytes: &[E; 8]) -> [E; 2] {
    let pack = |s: &[E]| s.iter().fold(E::ZERO, |a, b| a * Felt::from_u32(256) + b.dup());
    [pack(&bytes[4..]), pack(&bytes[..4])]
}
fn digest_block<E: Algebra<Felt>>(local: &[E; NUM_MAIN_COLS], next: &[E; NUM_MAIN_COLS]) -> [E; 8] {
    let current: &[E; 8] = local[COL_DIGEST_BEGIN..COL_DIGEST_BEGIN + 8]
        .try_into()
        .expect("SHA-256 current digest band");
    let following: &[E; 8] = next[COL_DIGEST_BEGIN..COL_DIGEST_BEGIN + 8]
        .try_into()
        .expect("SHA-256 next digest band");
    let [a, b] = halves_le(current, 256);
    let [c, d] = halves_le(following, 256);
    [
        local[COL_CHUNK_HEAD_DIGEST].dup(),
        local[COL_CHUNK_HEAD_DIGEST + 1].dup(),
        local[COL_PREVIOUS_DIGEST].dup(),
        local[COL_PREVIOUS_DIGEST + 1].dup(),
        a,
        b,
        c,
        d,
    ]
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
    Resume,
    Continue,
}

impl Batch {
    fn degree(self) -> Deg {
        match self {
            Self::Word => Deg { v: 0, u: 1 },
            Self::StateHi
            | Self::StateLo
            | Self::Init
            | Self::Out
            | Self::NodeIn
            | Self::DigestBytes(_)
            | Self::DigestWords => Deg { v: 2, u: 2 },
            Self::NodeOut => Deg { v: 3, u: 2 },
            Self::RawBytes(_) | Self::Left => Deg { v: 1, u: 2 },
            Self::RawBlock | Self::Length | Self::DigestBlock | Self::Resume | Self::Continue => {
                Deg { v: 1, u: 1 }
            },
        }
    }
}

fn phase_batches(phase: usize, index: usize) -> &'static [Batch] {
    use Batch::*;
    match (phase, index) {
        (0, 0) => &[Word, Resume],
        (1, 0) => &[Word, RawBlock],
        (2, 0) => &[Word, Length],
        (3, 0) => &[Word],
        (0..=3, 1) => &[RawBytes(0)],
        (0..=3, 2) => &[RawBytes(2)],
        (0..=3, 3) => &[Left],
        (4, 0) => &[StateHi],
        (4, 1) => &[StateLo],
        (5 | 6, 0) => &[DigestWords],
        (5 | 6, 1) => &[DigestBytes(0)],
        (5 | 6, 2) => &[DigestBytes(2)],
        (5, 3) => &[DigestBlock],
        (7, 0) => &[Init],
        (7, 1) => &[Out],
        (7, 2) => &[NodeIn],
        (7, 3) => &[NodeOut],
        (8, 0) => &[Continue],
        _ => &[],
    }
}

fn selected_batches(phase: usize, index: usize, continuation: bool) -> impl Iterator<Item = Batch> {
    phase_batches(phase, index)
        .iter()
        .copied()
        .filter(move |b| continuation || !matches!(b, Batch::Resume | Batch::Continue))
}

fn phase_degree(phase: usize, index: usize, continuation: bool) -> Option<Deg> {
    selected_batches(phase, index, continuation)
        .map(Batch::degree)
        .reduce(|a, b| Deg {
            v: (a.v + b.u).max(b.v + a.u),
            u: a.u + b.u,
        })
        .map(|d| Deg { v: d.v + 2, u: d.u + 2 })
}

pub(super) fn lookup_column_degree(index: usize, continuation: bool) -> Deg {
    (0..9)
        .filter_map(|phase| phase_degree(phase, index, continuation))
        .reduce(|a, b| Deg { v: a.v.max(b.v), u: a.u.max(b.u) })
        .unwrap()
}

/// Add IO batches under disjoint fixed row masks. Continuation endpoints replace adjacent-row
/// state transport when the IO rows share a trace with compression.
pub(super) fn eval_lookup_group<G>(
    group: &mut G,
    index: usize,
    local: &[G::Expr; NUM_MAIN_COLS],
    next: &[G::Expr; NUM_MAIN_COLS],
    p: &[G::Expr; NUM_PERIODIC_COLS],
    act: G::Expr,
    continuation: bool,
) where
    G: LookupGroup,
    G::Expr: Algebra<Felt>,
{
    use program::*;
    let masks = [
        p[P_FIRST].dup(),
        p[P_RAW_EMIT].dup(),
        p[P_LENGTH].dup(),
        p[P_RAW].dup() - p[P_FIRST].dup() - p[P_RAW_EMIT].dup() - p[P_LENGTH].dup(),
        p[P_STATE].dup(),
        p[P_DIGEST_EMIT].dup(),
        p[P_DIGEST].dup() - p[P_DIGEST_EMIT].dup(),
        p[P_BIND].dup(),
        p[P_LAST].dup(),
    ];
    for (phase, mask) in masks.into_iter().enumerate() {
        let Some(degree) = phase_degree(phase, index, continuation) else {
            continue;
        };
        group.batch(
            "io-phase",
            act.dup() * mask,
            |batch| {
                for kind in selected_batches(phase, index, continuation) {
                    eval_batch(batch, kind, local, next, p);
                }
            },
            degree,
        );
    }
}
fn eval_batch<B>(
    batch: &mut B,
    kind: Batch,
    local: &[B::Expr; NUM_MAIN_COLS],
    next: &[B::Expr; NUM_MAIN_COLS],
    p: &[B::Expr; NUM_PERIODIC_COLS],
) where
    B: LookupBatch,
    B::Expr: Algebra<Felt>,
{
    let e = |i: usize| -> B::Expr { local[i].dup() };
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
                B::Expr::from_u32(INPUT_ADDR_BASE) + p[program::P_IDX].dup(),
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
            let addr = p[program::P_STATE_IDX].dup() * Felt::from_u8(2) + B::Expr::from_u32(off);
            batch.insert(
                "incoming",
                -one.dup(),
                word(e(COL_BLOCK_ID), B::Expr::from_u32(INPUT_ADDR_BASE + 16) + addr.dup(), e(col)),
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
                final_block.dup(),
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
                final_block.dup(),
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
            // Bind the exact byte length: CHUNKS zero-padding alone cannot distinguish a
            // message from the same bytes followed by zeros.
            let frame = [
                B::Expr::from(Sha256Precompile::domain().as_felt()),
                B::Expr::from_u32(Sha256Precompile::ASSERT_OP_ID),
                e(COL_LEN),
                B::Expr::ZERO,
            ];
            batch.insert(
                "node-init",
                final_block.dup(),
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
                final_block.dup(),
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
        Batch::RawBytes(offset) => {
            for i in offset..offset + 2 {
                batch.insert(
                    "byte",
                    one.dup(),
                    BytePairLutMsg::from_xor(
                        B::Expr::ZERO,
                        e(COL_RAW_BEGIN + i),
                        e(COL_RAW_BEGIN + i),
                    ),
                    d0,
                );
            }
        },
        Batch::DigestBytes(offset) => {
            // Each canonical XOR tuple ranges two digest bytes and pins its scratch witness.
            for (i, &column) in COL_DIGEST_XOR.iter().enumerate().skip(offset).take(2) {
                batch.insert(
                    "digest-byte-pair",
                    final_block.dup(),
                    BytePairLutMsg::from_xor(
                        e(COL_DIGEST_BEGIN + 2 * i),
                        e(COL_DIGEST_BEGIN + 2 * i + 1),
                        e(column),
                    ),
                    d1,
                );
            }
        },
        Batch::Left => {
            batch.insert("left-low", one.dup(), Range16Msg { w: e(COL_LEFT_LO16) }, d0);
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
            let bytes: &[B::Expr; 8] = local[COL_DIGEST_BEGIN..COL_DIGEST_BEGIN + 8]
                .try_into()
                .expect("SHA-256 digest word band");
            let [lo, hi] = halves_be(bytes);
            let addr = B::Expr::from_u32(OUTPUT_SLOTS[0])
                + p[program::P_DIGEST_IDX].dup() * Felt::from_u8(2);
            batch.insert("digest-hi", final_block.dup(), word(e(COL_BLOCK_ID), addr.dup(), hi), d1);
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
        Batch::Resume | Batch::Continue => {
            // Resume compares the preceding block's tail ID, before this block's first active
            // chunk advances it. Subtract that increment when matching continuation state.
            let resume = matches!(kind, Batch::Resume);
            let (mult, block_id, input_eidos) = if resume {
                (
                    one - e(COL_FIRST_BLOCK),
                    e(COL_BLOCK_ID),
                    e(COL_INPUT_EIDOS) - e(COL_CHUNK_ACTIVE),
                )
            } else {
                (final_block - one, e(COL_BLOCK_ID) + B::Expr::ONE, e(COL_INPUT_EIDOS))
            };
            batch.insert(
                "continuation",
                mult,
                super::Sha256IoContinuation {
                    block_id,
                    input_eidos,
                    len: e(COL_LEN),
                    left: e(COL_LEFT),
                    before: e(COL_BEFORE),
                    input_head: e(COL_INPUT_HEAD),
                },
                d1,
            );
        },
    }
}

pub fn eval_lookups<LB: lookup::LookupBuilder<F = Felt>>(
    frame: &lookup::LookupFrame<'_, LB::Expr>,
    builder: &mut LB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local: &[LB::Expr; NUM_MAIN_COLS] = frame.main.current
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-256 IO lookup current row band");
    let next: &[LB::Expr; NUM_MAIN_COLS] = frame.main.next
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-256 IO lookup next row band");
    let p: &[LB::Expr; NUM_PERIODIC_COLS] = frame.periodic
        [periodic_col_offset..periodic_col_offset + NUM_PERIODIC_COLS]
        .try_into()
        .expect("SHA-256 IO lookup periodic band");
    let act = local[COL_ACT].dup();
    for index in 0..NUM_AUX_COLS {
        let degree = lookup_column_degree(index, false);
        builder.next_column(
            |column| {
                column.group(
                    "io",
                    |group| eval_lookup_group(group, index, local, next, p, act.dup(), false),
                    degree,
                )
            },
            degree,
        );
    }
}
impl<LB: lookup::LookupBuilder<F = Felt>> lookup::LookupAir<LB> for Sha256IoAir {
    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }
    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }
    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }
    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        eval_lookups(frame, builder, 0, 0);
    }
}

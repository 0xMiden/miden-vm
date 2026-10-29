//! Serialized SHA-512 IO with shared payload cells.
//!
//! Each 64-row block checks raw input and padding on rows 0..16, incoming state on
//! rows 16..24, and the final digest on rows 24..32. Row 32 authenticates the Eidos
//! assertion; rows 33..64 carry invocation metadata to the continuation endpoint.
//! Raw input and digest bytes use little-endian CHUNKS packing while SHA words use
//! big-endian packing. Disjoint stages reuse the same physical payload cells.

pub mod program;

use alloc::{borrow::Cow, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    deferred::DEFERRED_CHUNKS_DOMAIN,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_precompiles::Sha512Precompile;
use miden_stark::{
    air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder},
    lookup::{
        ConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, build_logup_aux_trace,
    },
};
use miden_utils_sync::LazyLock;
pub use program::{IO_PERIOD, NUM_PERIODIC_COLS, io_program};

use crate::precompiles::{
    hash::sha512::compression::{INPUT_ADDR_BASE, OUTPUT_SLOTS, Sha512WordMsg},
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::{BytePairLutMsg, Range16Msg},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::BindingMsg,
        eidos::{EidosBlockMsg, EidosInitMsg, EidosOutMsg},
        initial_cv_from_frame,
    },
    utils::{current_main, halves_le, next_main},
};

pub const NUM_MAIN_COLS: usize = 37;
pub const NUM_AUX_COLS: usize = 6;
pub const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [2; NUM_AUX_COLS];

pub const COL_ACT: usize = 0;
pub const COL_BLOCK_ID: usize = 1;
pub const COL_FIRST_BLOCK: usize = 2;
pub const COL_FINAL_BLOCK: usize = 3;
/// Whether the preceding byte belonged to the message; initialized to one before the first byte.
pub const COL_BEFORE: usize = 4;
/// Raw message bytes remaining before this row's eight bytes, excluding SHA padding.
pub const COL_LEFT: usize = 5;
pub const COL_LEFT_LO16: usize = 6;
pub const COL_LEFT_HI16: usize = 7;
pub const COL_LEN: usize = 8;
pub const COL_CHUNK_ACTIVE: usize = 9;
/// Eidos compression ID of the current raw-input chunk; the chain tail on the final row.
pub const COL_INPUT_EIDOS: usize = 10;
/// Eidos compression ID of the digest chain head. Its two chunks occupy this ID and the next.
pub const COL_DIGEST_EIDOS: usize = 11;
/// Eidos compression ID of the assertion node.
pub const COL_NODE_EIDOS: usize = 12;
pub const COL_OUT_MULT: usize = 13;
/// Eidos compression ID of the raw-input chain head, carried through the invocation.
pub const COL_INPUT_HEAD: usize = 14;
pub const COL_RAW_BEGIN: usize = 15;
/// Eight presence bits, one per raw byte; they may fall from one to zero but never rise again.
pub const COL_MSG_BEGIN: usize = 23;
pub const COL_PREVIOUS_RAW: usize = 31;
pub const COL_WORD_LO: usize = 33;
pub const COL_WORD_HI: usize = 34;
/// Packed raw-input felts of a chunk's first row, carried to its emitting row.
pub const COL_CHUNK_HEAD_RAW: usize = 35;

// Disjoint raw, state, digest, and binding rows reuse the same payload cells.
pub const COL_STATE_LO: usize = COL_WORD_LO;
pub const COL_STATE_HI: usize = COL_WORD_HI;
pub const COL_DIGEST_BEGIN: usize = COL_RAW_BEGIN;
pub const COL_PREVIOUS_DIGEST: usize = COL_PREVIOUS_RAW;
pub const COL_CHUNK_HEAD_DIGEST: usize = COL_CHUNK_HEAD_RAW;
pub const COL_H_INPUT: usize = COL_RAW_BEGIN;
pub const COL_H_DIGEST: usize = COL_RAW_BEGIN + 4;
pub const H_SHA512_COLS: [usize; 4] =
    [COL_MSG_BEGIN, COL_MSG_BEGIN + 1, COL_MSG_BEGIN + 2, COL_MSG_BEGIN + 3];

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512IoAir;

static PERIODIC_COLUMNS: LazyLock<[Vec<Felt>; NUM_PERIODIC_COLS]> = LazyLock::new(io_program);

impl BaseAir<Felt> for Sha512IoAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Borrowed(PERIODIC_COLUMNS.as_slice())
    }
}

impl LiftedAir<Felt, QuadFelt> for Sha512IoAir {
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
/// Active rows form whole sixty-four-row blocks. Invocation boundaries reset the message counters;
/// all other block boundaries continue them. The composite AIR enforces these same boundaries
/// using its compression controller and continuation lookup instead of adjacent IO blocks.
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
    // Carry invocation state into the next active row unless this row closes the invocation.
    // In this dense layout, row 63 can carry directly into row 0 of the next compression block.
    let carry = next_act.clone() * (one.clone() - end);

    eval_main_rows(builder, &local, &next, &p, one.clone(), carry);

    // These controller constraints belong to the dense standalone wrapper. A composite caller
    // supplies the corresponding block/coverage constraints from the shared compression rows.
    // The first active block starts an invocation; block IDs advance exactly once per 64 rows.
    builder.when_first_row().assert_zero(v(COL_BLOCK_ID));
    builder.when_first_row().assert_zero(act.clone() * (first - one.clone()));
    builder
        .when_transition()
        .assert_zero(nv(COL_BLOCK_ID) - v(COL_BLOCK_ID) - last.clone());
    // Once activity falls to zero it stays zero, and it cannot change inside a block.
    builder
        .when_transition()
        .assert_zero((one.clone() - act.clone()) * next_act.clone());
    builder
        .when_transition()
        .assert_zero((one.clone() - last.clone()) * (next_act.clone() - act.clone()));
    // At an active block boundary, the next block starts a new invocation exactly when the
    // current block is final. This prevents both splitting and joining invocations arbitrarily.
    builder
        .when_transition()
        .assert_zero(next_act.clone() * last.clone() * (nv(COL_FIRST_BLOCK) - final_block.clone()));
    // Activity may stop only after a final block. Check the last trace row separately because
    // there is no next-row transition there to enforce completion of the final invocation.
    builder
        .when_transition()
        .assert_zero((act.clone() - next_act) * last * (one.clone() - final_block.clone()));
    builder.when_last_row().assert_zero(act * (one - final_block));
}

/// Evaluate the row-local IO equations shared by the dense standalone band and the composite
/// SHA-512 layout. `owned` gates interpretations of cells which are only meaningful on IO rows;
/// `carry` gates transport across the next-row boundary.
///
/// In the standalone AIR, `owned = 1` even on inactive IO padding rows. In the composite AIR,
/// `owned = act`, and `act` is zero outside the IO window. Only `carry`-gated equations transport
/// invocation state across a block boundary; the other transitions stop at their row/chunk limits.
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
    let end = p[program::P_RAW_LAST].clone() * final_block.clone();
    let raw = owned.clone() * p[program::P_RAW].clone();

    // These selectors describe IO data only. Gating by `owned` avoids imposing Boolean
    // constraints on the compression values occupying the same cells outside the IO window.
    for index in [COL_ACT, COL_FIRST_BLOCK, COL_FINAL_BLOCK, COL_BEFORE, COL_CHUNK_ACTIVE] {
        builder
            .assert_zero(owned.clone() * local[index].into() * (one.clone() - local[index].into()));
    }

    // Length and input-chain head identify an invocation and must not change while it continues.
    builder
        .when_transition()
        .assert_zero(carry.clone() * (nv(COL_LEN) - v(COL_LEN)));
    builder
        .when_transition()
        .assert_zero(carry.clone() * (nv(COL_INPUT_HEAD) - v(COL_INPUT_HEAD)));
    // First/final are block-wide flags: allow changes only after row 63. Boundary constraints
    // in the wrapper decide whether those changes describe a continuation or a new invocation.
    for index in [COL_FIRST_BLOCK, COL_FINAL_BLOCK] {
        builder
            .when_transition()
            .assert_zero(owned.clone() * (one.clone() - last.clone()) * (nv(index) - v(index)));
    }
    // Initialize the remaining-byte count and the prefix sentinel. The first raw chunk is also
    // the Eidos chain head, including the mandatory zero chunk for an empty message.
    let start = p[program::P_FIRST].clone() * first.clone();
    builder.assert_zero(act.clone() * start.clone() * (v(COL_LEFT) - v(COL_LEN)));
    builder.assert_zero(act.clone() * start.clone() * (v(COL_BEFORE) - one.clone()));
    builder.assert_zero(act.clone() * start * (v(COL_INPUT_HEAD) - v(COL_INPUT_EIDOS)));
    // Two Range16 lookups bound LEFT to u32. Since LEFT = LEN at invocation start, this also
    // bounds LEN; subsequent subtractions cannot wrap through the base field back into u32.
    builder.assert_zero(
        act.clone()
            * p[program::P_RAW].clone()
            * (v(COL_LEFT) - v(COL_LEFT_LO16) - v(COL_LEFT_HI16) * Felt::from_u32(1 << 16)),
    );

    let mut sum_msg = AB::Expr::ZERO;
    let mut previous = v(COL_BEFORE);
    // Presence bits form a single prefix per invocation. Its first 1 -> 0 transition adds
    // the 0x80 marker; later absent bytes remain zero, including in a padding-only final block.
    // For each byte, require a Boolean presence bit, forbid 0 -> 1, and force absent raw bytes
    // to zero. The last rule also ensures the Eidos commitment uses canonical zero padding.
    let padded: [AB::Expr; 8] = array::from_fn(|i| {
        let msg = v(COL_MSG_BEGIN + i);
        builder.assert_zero(
            raw.clone() * local[COL_MSG_BEGIN + i].into() * (one.clone() - msg.clone()),
        );
        builder.assert_zero(raw.clone() * v(COL_MSG_BEGIN + i) * (one.clone() - previous.clone()));
        builder.assert_zero(raw.clone() * v(COL_RAW_BEGIN + i) * (one.clone() - msg.clone()));
        let byte = v(COL_RAW_BEGIN + i) + (previous.clone() - msg.clone()) * Felt::from_u8(128);
        sum_msg += msg.clone();
        previous = msg;
        byte
    });
    // If the prefix has ended by this row's last byte, consume all remaining message bytes
    // here. Otherwise each of its eight presence bits is one, and the counter decreases by eight.
    builder.assert_zero(
        act.clone()
            * p[program::P_RAW].clone()
            * (one.clone() - previous.clone())
            * (v(COL_LEFT) - sum_msg.clone()),
    );
    // Carry the remaining count and last presence bit to the next row. This joins byte prefixes
    // across rows, while continuation lookups perform the same transport between sparse blocks.
    builder.when_transition().assert_zero(
        carry.clone() * (nv(COL_LEFT) - v(COL_LEFT) + p[program::P_RAW].clone() * sum_msg.clone()),
    );
    builder.when_transition().assert_zero(
        carry.clone()
            * (nv(COL_BEFORE)
                - v(COL_BEFORE)
                - p[program::P_RAW].clone() * (previous - v(COL_BEFORE))),
    );
    // Require exhaustion on the final raw row before its payload cells are reused.
    builder.assert_zero(act.clone() * end.clone() * (v(COL_LEFT) - sum_msg));
    // At row 14, BEFORE describes byte 111. The block is final exactly when that byte is
    // already past the message, leaving room for the marker before the 128-bit length suffix.
    builder.assert_zero(
        act.clone()
            * p[program::P_AT14].clone()
            * (final_block.clone() + v(COL_BEFORE) - one.clone()),
    );
    // Every word except the final length word is the big-endian packing of message/marker/zeros.
    // In a final block, the row-14 condition above forces its high length word to be zero too.
    let [word_lo, word_hi]: [AB::Expr; 2] = halves_be(&padded);
    let data_gate = act.clone() * (p[program::P_RAW].clone() - end.clone());
    builder.assert_zero(data_gate.clone() * (v(COL_WORD_LO) - word_lo));
    builder.assert_zero(data_gate * (v(COL_WORD_HI) - word_hi));
    // The u32 message length needs only the suffix's low 64 bits; row 14 supplies its zero
    // high word. Range16(word_hi), together with the compressor's u32 halves, keeps the low
    // word below 2^48 and prevents satisfying this equation with the field alias 8*len + p.
    builder.assert_zero(
        act.clone()
            * end
            * (v(COL_WORD_LO) + v(COL_WORD_HI) * Felt::new_unchecked(1u64 << 32)
                - v(COL_LEN) * Felt::from_u8(8)),
    );

    // Even an empty message has one zero-filled CHUNKS block. Later chunks are active only
    // when their first byte belongs to the message; SHA padding is never committed as input.
    let expected_chunk =
        v(COL_MSG_BEGIN) + p[program::P_FIRST].clone() * first * (one.clone() - v(COL_MSG_BEGIN));
    builder.assert_zero(
        act.clone() * p[program::P_CHUNK_FIRST].clone() * (v(COL_CHUNK_ACTIVE) - expected_chunk),
    );
    // All four rows of a chunk share its activity flag. Advance INPUT_EIDOS only when
    // crossing into an active next chunk; after the input ends it stays at the chain tail.
    builder.when_transition().assert_zero(
        owned.clone()
            * (p[program::P_RAW].clone() - p[program::P_CHUNK_LAST].clone())
            * (nv(COL_CHUNK_ACTIVE) - v(COL_CHUNK_ACTIVE)),
    );
    builder.when_transition().assert_zero(
        carry
            * (nv(COL_INPUT_EIDOS)
                - v(COL_INPUT_EIDOS)
                - (p[program::P_CHUNK_ADVANCE].clone() + last.clone()) * nv(COL_CHUNK_ACTIVE)),
    );
    // An Eidos block carries a whole chunk. Chunk rows 1 and 2 already see the preceding row's
    // packed felts; row 1 also forwards its predecessor so the emitting row sees all four rows.
    for (head, previous, gate) in [
        (
            COL_CHUNK_HEAD_RAW,
            COL_PREVIOUS_RAW,
            owned.clone() * p[program::P_CHUNK_SECOND].clone(),
        ),
        (
            COL_CHUNK_HEAD_DIGEST,
            COL_PREVIOUS_DIGEST,
            act.clone() * final_block.clone() * p[program::P_DIGEST_SECOND].clone(),
        ),
    ] {
        for i in 0..2 {
            builder
                .when_transition()
                .assert_zero(gate.clone() * (nv(head + i) - v(previous + i)));
        }
    }
    let raw: [AB::Var; 8] = array::from_fn(|i| local[COL_RAW_BEGIN + i]);
    let raw_le: [AB::Expr; 2] = halves_le(&raw, 256);
    // Preserve each row's two packed raw felts for the next row's chunk assembly. The chunk's
    // third row then has rows 0 and 1 in carried cells, row 2 locally, and row 3 through `next`.
    for (i, packed) in raw_le.into_iter().enumerate() {
        builder.when_transition().assert_zero(
            owned.clone() * p[program::P_RAW_NEXT].clone() * (nv(COL_PREVIOUS_RAW + i) - packed),
        );
    }

    // Initialize only the first block from the fixed SHA-512 IV. Later blocks obtain these
    // same state halves from the previous block's feedforward outputs through the word lookup.
    let state_gate = act.clone() * v(COL_FIRST_BLOCK) * p[program::P_STATE].clone();
    builder.assert_zero(state_gate.clone() * (v(COL_STATE_LO) - p[program::P_IV_LO].clone()));
    builder.assert_zero(state_gate * (v(COL_STATE_HI) - p[program::P_IV_HI].clone()));
    let digest: [AB::Var; 8] = array::from_fn(|i| local[COL_DIGEST_BEGIN + i]);
    let digest_le: [AB::Expr; 2] = halves_le(&digest, 256);
    // Only the final block exposes digest bytes, in rows 24..32. Carry their packed felts across
    // rows 24->25 through 30->31 for its two Eidos chunks, without constraining reused cells later.
    for (i, packed) in digest_le.into_iter().enumerate() {
        builder.when_transition().assert_zero(
            act.clone()
                * final_block.clone()
                * p[program::P_DIGEST_NEXT].clone()
                * (nv(COL_PREVIOUS_DIGEST + i) - packed),
        );
    }
    // This includes the binding row: the final EidosOut must refer to the same two-block digest
    // span.
    builder.when_transition().assert_zero(
        act.clone() * final_block * (one - last) * (nv(COL_DIGEST_EIDOS) - v(COL_DIGEST_EIDOS)),
    );
    // Only the binding row of a final block may publish truth claims. Zero the multiplicity on
    // every other owned row; the truth lookup uses it directly without another row selector.
    builder.assert_zero(
        (owned - act * v(COL_FINAL_BLOCK) * p[program::P_BIND].clone()) * v(COL_OUT_MULT),
    );
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

/// Interpret bytes in SHA-512's big-endian order, but return the halves as [low_u32, high_u32].
fn halves_be<E: Algebra<Felt>, V: Clone + Into<E>>(bytes: &[V; 8]) -> [E; 2] {
    let pack = |slice: &[V]| {
        slice
            .iter()
            .fold(E::ZERO, |acc, byte| acc * Felt::from_u32(256) + byte.clone().into())
    };
    [pack(&bytes[4..]), pack(&bytes[..4])]
}

#[derive(Clone, Copy)]
enum Term {
    Input,
    Incoming,
    Previous,
    DigestWord,
    RawBlock,
    DigestBlock,
    RawInit,
    DigestInit,
    RawDigest,
    FullDigest,
    NodeInit,
    NodeBlock,
    NodeOut,
    Truth,
    RawByte(usize),
    DigestByte(usize),
    LeftLow,
    LeftHigh,
    LengthHigh,
    Resume,
    Continue,
}

impl Term {
    const fn multiplicity_degree(self) -> usize {
        match self {
            Self::Input | Self::Incoming | Self::RawByte(_) | Self::LeftLow | Self::LeftHigh => 0,
            _ => 1,
        }
    }
}

// Each phase selects at most twelve affine messages. Pairing adjacent terms needs six columns.
// Subtracting event rows from the raw and digest masks makes the phase alternatives disjoint.
const PHASE_TERMS: [&[Term]; 9] = {
    use Term::*;
    [
        &[
            Input,
            Resume,
            RawByte(0),
            RawByte(1),
            RawByte(2),
            RawByte(3),
            RawByte(4),
            RawByte(5),
            RawByte(6),
            RawByte(7),
            LeftLow,
            LeftHigh,
        ],
        &[
            Input,
            RawBlock,
            RawByte(0),
            RawByte(1),
            RawByte(2),
            RawByte(3),
            RawByte(4),
            RawByte(5),
            RawByte(6),
            RawByte(7),
            LeftLow,
            LeftHigh,
        ],
        &[
            Input,
            LengthHigh,
            RawByte(0),
            RawByte(1),
            RawByte(2),
            RawByte(3),
            RawByte(4),
            RawByte(5),
            RawByte(6),
            RawByte(7),
            LeftLow,
            LeftHigh,
        ],
        &[
            Input,
            RawByte(0),
            RawByte(1),
            RawByte(2),
            RawByte(3),
            RawByte(4),
            RawByte(5),
            RawByte(6),
            RawByte(7),
            LeftLow,
            LeftHigh,
        ],
        &[Incoming, Previous],
        &[
            DigestWord,
            DigestBlock,
            DigestByte(0),
            DigestByte(1),
            DigestByte(2),
            DigestByte(3),
            DigestByte(4),
            DigestByte(5),
            DigestByte(6),
            DigestByte(7),
        ],
        &[
            DigestWord,
            DigestByte(0),
            DigestByte(1),
            DigestByte(2),
            DigestByte(3),
            DigestByte(4),
            DigestByte(5),
            DigestByte(6),
            DigestByte(7),
        ],
        &[RawInit, DigestInit, RawDigest, FullDigest, NodeInit, NodeBlock, NodeOut, Truth],
        &[Continue],
    ]
};

fn phase_masks<E: PrimeCharacteristicRing>(p: &[E; NUM_PERIODIC_COLS]) -> [E; 9] {
    use program::*;
    [
        p[P_FIRST].clone(),
        p[P_CHUNK_EMIT].clone(),
        p[P_RAW_LAST].clone(),
        p[P_RAW].clone() - p[P_FIRST].clone() - p[P_CHUNK_EMIT].clone() - p[P_RAW_LAST].clone(),
        p[P_STATE].clone(),
        p[P_DIGEST_EMIT].clone(),
        p[P_DIGEST].clone() - p[P_DIGEST_EMIT].clone(),
        p[P_BIND].clone(),
        p[P_LAST].clone(),
    ]
}

/// Degree after the activity and row-phase selectors. Each message has an affine denominator.
pub(super) fn lookup_column_degree(index: usize, continuation: bool) -> Deg {
    let mut result = Deg { v: 0, u: 0 };
    for terms in PHASE_TERMS {
        let Some(pair) = terms.chunks(2).nth(index) else {
            continue;
        };
        let mut count = 0;
        let mut mult = 0;
        for &term in pair {
            if !continuation && matches!(term, Term::Resume | Term::Continue) {
                continue;
            }
            count += 1;
            mult = mult.max(term.multiplicity_degree());
        }
        if count > 0 {
            result.v = result.v.max(2 + mult + count - 1);
            result.u = result.u.max(2 + count);
        }
    }
    result
}

/// Add IO alternatives under the fixed row masks. `continuation` transports state across the
/// compression rows in the composite AIR; standalone IO uses adjacent-row constraints instead.
pub(super) fn eval_lookup_group<G, V>(
    group: &mut G,
    index: usize,
    local: &[V; NUM_MAIN_COLS],
    next: &[V; NUM_MAIN_COLS],
    p: &[G::Expr; NUM_PERIODIC_COLS],
    act: G::Expr,
    continuation: bool,
) where
    G: LookupGroup,
    G::Expr: Algebra<Felt>,
    V: Copy + Into<G::Expr>,
{
    for (mask, terms) in phase_masks(p).into_iter().zip(PHASE_TERMS) {
        let Some(pair) = terms.chunks(2).nth(index) else {
            continue;
        };
        let selected =
            |term: &&Term| continuation || !matches!(term, Term::Resume | Term::Continue);
        let count = pair.iter().filter(selected).count();
        if count == 0 {
            continue;
        }
        let mult = pair
            .iter()
            .filter(selected)
            .map(|term| term.multiplicity_degree())
            .max()
            .unwrap();
        let degree = Deg { v: 2 + mult + count - 1, u: 2 + count };
        group.batch(
            "io-phase",
            act.clone() * mask,
            |batch| {
                for &term in pair.iter().filter(selected) {
                    eval_term(batch, term, local, next, p);
                }
            },
            degree,
        );
    }
}

/// Emit one IO interaction with activity and row-phase selection supplied by the enclosing batch.
/// Negative multiplicities provide records; positive ones consume matching records.
fn eval_term<B, V>(
    batch: &mut B,
    term: Term,
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
    let degree = Deg { v: term.multiplicity_degree(), u: 1 };
    let word = |block_id, addr, lo, hi| Sha512WordMsg { block_id, addr, lo, hi };
    match term {
        Term::Input => batch.insert(
            "input",
            -B::Expr::ONE,
            word(
                e(COL_BLOCK_ID),
                p[program::P_IDX].clone() + B::Expr::from_u32(INPUT_ADDR_BASE),
                e(COL_WORD_LO),
                e(COL_WORD_HI),
            ),
            degree,
        ),
        Term::Incoming => batch.insert(
            "incoming",
            -B::Expr::ONE,
            word(
                e(COL_BLOCK_ID),
                p[program::P_STATE_IDX].clone() + B::Expr::from_u32(INPUT_ADDR_BASE + 16),
                e(COL_STATE_LO),
                e(COL_STATE_HI),
            ),
            degree,
        ),
        // Incoming publishes this block's initial state. Non-first blocks authenticate the same
        // words against the preceding block's outputs, enforcing SHA chaining.
        Term::Previous => batch.insert(
            "previous",
            B::Expr::ONE - e(COL_FIRST_BLOCK),
            word(
                e(COL_BLOCK_ID) - B::Expr::ONE,
                p[program::P_STATE_IDX].clone() + B::Expr::from_u32(OUTPUT_SLOTS[0]),
                e(COL_STATE_LO),
                e(COL_STATE_HI),
            ),
            degree,
        ),
        Term::DigestWord => {
            let bytes: [V; 8] = array::from_fn(|i| local[COL_DIGEST_BEGIN + i]);
            let [lo, hi] = halves_be(&bytes);
            batch.insert(
                "digest-word",
                final_block,
                word(
                    e(COL_BLOCK_ID),
                    p[program::P_DIGEST_IDX].clone() + B::Expr::from_u32(OUTPUT_SLOTS[0]),
                    lo,
                    hi,
                ),
                degree,
            );
        },
        Term::RawBlock => batch.insert(
            "raw-block",
            e(COL_CHUNK_ACTIVE),
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
            degree,
        ),
        Term::DigestBlock => batch.insert(
            "digest-block",
            final_block,
            EidosBlockMsg {
                compression_id: e(COL_DIGEST_EIDOS) + p[program::P_DIGEST_CYCLE_OFFSET].clone(),
                block: chunk_block(
                    local,
                    next,
                    COL_CHUNK_HEAD_DIGEST,
                    COL_PREVIOUS_DIGEST,
                    COL_DIGEST_BEGIN,
                ),
            },
            degree,
        ),
        // On the binding row, INPUT_EIDOS is the chain tail. INPUT_EIDOS - INPUT_HEAD + 1
        // counts the zero-padded chunks; each contributes eight felts to the CHUNKS frame length.
        Term::RawInit => batch.insert(
            "raw-init",
            final_block,
            EidosInitMsg {
                compression_id: e(COL_INPUT_HEAD),
                initial_cv: chunks_initial_cv(
                    (e(COL_INPUT_EIDOS) - e(COL_INPUT_HEAD) + B::Expr::ONE) * B::Expr::from_u8(8),
                ),
            },
            degree,
        ),
        Term::DigestInit => batch.insert(
            "digest-init",
            final_block,
            EidosInitMsg {
                compression_id: e(COL_DIGEST_EIDOS),
                initial_cv: chunks_initial_cv(B::Expr::from_u8(16)),
            },
            degree,
        ),
        Term::RawDigest => batch.insert(
            "raw-digest",
            final_block,
            EidosOutMsg {
                chain_head_id: e(COL_INPUT_HEAD),
                compression_id: e(COL_INPUT_EIDOS),
                digest: array::from_fn(|i| e(COL_H_INPUT + i)),
            },
            degree,
        ),
        Term::FullDigest => batch.insert(
            "full-digest",
            final_block,
            EidosOutMsg {
                chain_head_id: e(COL_DIGEST_EIDOS),
                compression_id: e(COL_DIGEST_EIDOS) + B::Expr::ONE,
                digest: array::from_fn(|i| e(COL_H_DIGEST + i)),
            },
            degree,
        ),
        // Bind the exact byte length: CHUNKS zero-padding alone cannot distinguish a message
        // from the same bytes followed by zeros.
        Term::NodeInit => batch.insert(
            "node-init",
            final_block,
            EidosInitMsg {
                compression_id: e(COL_NODE_EIDOS),
                initial_cv: initial_cv_from_frame([
                    B::Expr::from(Sha512Precompile::domain().as_felt()),
                    B::Expr::from_u32(Sha512Precompile::ASSERT_OP_ID),
                    e(COL_LEN),
                    B::Expr::ZERO,
                ]),
            },
            degree,
        ),
        // Hash the authenticated input commitment followed by the digest commitment.
        Term::NodeBlock => batch.insert(
            "node-block",
            final_block,
            EidosBlockMsg {
                compression_id: e(COL_NODE_EIDOS),
                block: array::from_fn(|i| e(COL_H_INPUT + i)),
            },
            degree,
        ),
        Term::NodeOut => batch.insert(
            "node-out",
            final_block,
            EidosOutMsg {
                chain_head_id: e(COL_NODE_EIDOS),
                compression_id: e(COL_NODE_EIDOS),
                digest: H_SHA512_COLS.map(e),
            },
            degree,
        ),
        Term::Truth => {
            // The local out_mult pin makes this zero outside the final binding row.
            batch.insert(
                "truth",
                -e(COL_OUT_MULT),
                BindingMsg::truth(H_SHA512_COLS.map(e)),
                degree,
            );
        },
        Term::RawByte(i) | Term::DigestByte(i) => {
            let mult = if matches!(term, Term::DigestByte(_)) {
                final_block
            } else {
                B::Expr::ONE
            };
            batch.insert(
                "byte",
                mult,
                BytePairLutMsg::from_xor(B::Expr::ZERO, e(COL_RAW_BEGIN + i), e(COL_RAW_BEGIN + i)),
                degree,
            );
        },
        Term::LeftLow | Term::LeftHigh => {
            let col = if matches!(term, Term::LeftLow) {
                COL_LEFT_LO16
            } else {
                COL_LEFT_HI16
            };
            batch.insert("left", B::Expr::ONE, Range16Msg { w: e(col) }, degree);
        },
        Term::LengthHigh => {
            batch.insert("length-high", final_block, Range16Msg { w: e(COL_WORD_HI) }, degree)
        },
        Term::Resume | Term::Continue => {
            // Resume compares the preceding block's tail ID, before this block's first active
            // chunk advances it. Subtract that increment when matching continuation state.
            let resume = matches!(term, Term::Resume);
            let (mult, block_id, input_eidos) = if resume {
                (
                    B::Expr::ONE - e(COL_FIRST_BLOCK),
                    e(COL_BLOCK_ID),
                    e(COL_INPUT_EIDOS) - e(COL_CHUNK_ACTIVE),
                )
            } else {
                (final_block - B::Expr::ONE, e(COL_BLOCK_ID) + B::Expr::ONE, e(COL_INPUT_EIDOS))
            };
            batch.insert(
                "continuation",
                mult,
                super::Sha512IoContinuation {
                    block_id,
                    input_eidos,
                    len: e(COL_LEN),
                    left: e(COL_LEFT),
                    before: e(COL_BEFORE),
                    input_head: e(COL_INPUT_HEAD),
                },
                degree,
            );
        },
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
                    "sha512-io",
                    |group| {
                        eval_lookup_group(group, index, &local, &next, &p, act.clone(), false);
                    },
                    degree,
                );
            },
            degree,
        );
    }
}

impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for Sha512IoAir {
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

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
};
use miden_precompiles::Sha512Precompile;
use miden_stark::{
    air,
    air::LiftedAirBuilder as _,
    lookup::{self, Deg, LookupBatch, LookupColumn, LookupGroup},
};
use miden_utils_sync::LazyLock;
use p3_field::Dup;
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
    utils::halves_le,
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

impl air::LiftedAir for Sha512IoAir {
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

impl air::ProverAir<QuadFelt> for Sha512IoAir {
    type Error = lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}

/// Evaluate the local constraints in an independent main/periodic column band.
/// Active rows form whole sixty-four-row blocks. Invocation boundaries reset the message counters;
/// all other block boundaries continue them. The composite AIR enforces these same boundaries
/// using its compression controller and continuation lookup instead of adjacent IO blocks.
pub fn eval_main<AB: air::LiftedAirBuilder<F = Felt>>(
    frame: &air::Frame<'_, AB>,
    builder: &mut AB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local: &[AB::Expr; NUM_MAIN_COLS] = frame.main.current
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-512 current row band");
    let next: &[AB::Expr; NUM_MAIN_COLS] = frame.main.next
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-512 next row band");
    let p: &[AB::Expr; NUM_PERIODIC_COLS] = frame.periodic
        [periodic_col_offset..periodic_col_offset + NUM_PERIODIC_COLS]
        .try_into()
        .expect("SHA-512 IO periodic band");
    let one = AB::Expr::ONE;
    let v = |i: usize| -> AB::Expr { local[i].dup() };
    let nv = |i: usize| -> AB::Expr { next[i].dup() };
    let act = v(COL_ACT);
    let next_act = nv(COL_ACT);
    let first = v(COL_FIRST_BLOCK);
    let final_block = v(COL_FINAL_BLOCK);
    let last = p[program::P_LAST].dup();
    let end = last.dup() * final_block.dup();
    // Carry invocation state into the next active row unless this row closes the invocation.
    // In this dense layout, row 63 can carry directly into row 0 of the next compression block.
    let carry = next_act.dup() * (one.dup() - end);

    eval_main_rows(frame, builder, local, next, p, one.dup(), carry);

    // These controller constraints belong to the dense standalone wrapper. A composite caller
    // supplies the corresponding block/coverage constraints from the shared compression rows.
    // The first active block starts an invocation; block IDs advance exactly once per 64 rows.
    builder.when(frame.first_row()).assert_zero(v(COL_BLOCK_ID));
    builder.when(frame.first_row()).when(act.dup()).assert_one(first);
    builder
        .when(frame.transition())
        .assert_eq(nv(COL_BLOCK_ID), v(COL_BLOCK_ID) + last.dup());
    // Once activity falls to zero it stays zero, and it cannot change inside a block.
    builder
        .when(frame.transition())
        .when(one.dup() - act.dup())
        .assert_zero(next_act.dup());
    builder
        .when(frame.transition())
        .when(one.dup() - last.dup())
        .assert_eq(next_act.dup(), act.dup());
    // At an active block boundary, the next block starts a new invocation exactly when the
    // current block is final. This prevents both splitting and joining invocations arbitrarily.
    builder
        .when(frame.transition())
        .when(next_act.dup() * last.dup())
        .assert_eq(nv(COL_FIRST_BLOCK), final_block.dup());
    // Activity may stop only after a final block. Check the last trace row separately because
    // there is no next-row transition there to enforce completion of the final invocation.
    builder
        .when(frame.transition())
        .when((act.dup() - next_act) * last)
        .assert_eq(one.dup(), final_block.dup());
    builder.when(frame.last_row()).when(act).assert_eq(one, final_block);
}

/// Evaluate the row-local IO equations shared by the dense standalone band and the composite
/// SHA-512 layout. `owned` gates interpretations of cells which are only meaningful on IO rows;
/// `carry` gates transport across the next-row boundary.
///
/// In the standalone AIR, `owned = 1` even on inactive IO padding rows. In the composite AIR,
/// `owned = act`, and `act` is zero outside the IO window. Only `carry`-gated equations transport
/// invocation state across a block boundary; the other transitions stop at their row/chunk limits.
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
    let last = p[program::P_LAST].dup();
    let end = p[program::P_RAW_LAST].dup() * final_block.dup();
    let raw = owned.dup() * p[program::P_RAW].dup();

    // These selectors describe IO data only. Gating by `owned` avoids imposing Boolean
    // constraints on the compression values occupying the same cells outside the IO window.
    builder.when(owned.dup()).assert_bools(
        [COL_ACT, COL_FIRST_BLOCK, COL_FINAL_BLOCK, COL_BEFORE, COL_CHUNK_ACTIVE]
            .map(|index| local[index].dup()),
    );

    // Length and input-chain head identify an invocation and must not change while it continues.
    builder
        .when(frame.transition())
        .when(carry.dup())
        .assert_eq_arrays([nv(COL_LEN), nv(COL_INPUT_HEAD)], [v(COL_LEN), v(COL_INPUT_HEAD)]);
    // First/final are block-wide flags: allow changes only after row 63. Boundary constraints
    // in the wrapper decide whether those changes describe a continuation or a new invocation.
    for index in [COL_FIRST_BLOCK, COL_FINAL_BLOCK] {
        builder
            .when(frame.transition())
            .when(owned.dup() * (one.dup() - last.dup()))
            .assert_eq(nv(index), v(index));
    }
    // Initialize the remaining-byte count and the prefix sentinel. The first raw chunk is also
    // the Eidos chain head, including the mandatory zero chunk for an empty message.
    let start = p[program::P_FIRST].dup() * first.dup();
    builder.when(act.dup() * start).assert_eq_arrays(
        [v(COL_LEFT), v(COL_BEFORE), v(COL_INPUT_HEAD)],
        [v(COL_LEN), one.dup(), v(COL_INPUT_EIDOS)],
    );
    // Two Range16 lookups bound LEFT to u32. Since LEFT = LEN at invocation start, this also
    // bounds LEN; subsequent subtractions cannot wrap through the base field back into u32.
    builder
        .when(act.dup() * p[program::P_RAW].dup())
        .assert_eq(v(COL_LEFT), v(COL_LEFT_LO16) + v(COL_LEFT_HI16).mul_2exp_u64(16));

    let sum_msg: AB::Expr = (0..8).map(|i| v(COL_MSG_BEGIN + i)).sum();
    let mut previous = v(COL_BEFORE);
    // Presence bits form a single prefix per invocation. Its first 1 -> 0 transition adds
    // the 0x80 marker; later absent bytes remain zero, including in a padding-only final block.
    // For each byte, require a Boolean presence bit, forbid 0 -> 1, and force absent raw bytes
    // to zero. The last rule also ensures the Eidos commitment uses canonical zero padding.
    let padded: [AB::Expr; 8] = array::from_fn(|i| {
        let msg = v(COL_MSG_BEGIN + i);
        builder.when(raw.dup()).assert_bool(msg.dup());
        builder.when(raw.dup() * msg.dup()).assert_eq(one.dup(), previous.dup());
        builder
            .when(raw.dup() * (one.dup() - msg.dup()))
            .assert_zero(v(COL_RAW_BEGIN + i));
        let byte = v(COL_RAW_BEGIN + i) + (previous.dup() - msg.dup()).mul_2exp_u64(7);
        previous = msg;
        byte
    });
    // If the prefix has ended by this row's last byte, consume all remaining message bytes
    // here. Otherwise each of its eight presence bits is one, and the counter decreases by eight.
    builder
        .when(act.dup() * p[program::P_RAW].dup() * (one.dup() - previous.dup()))
        .assert_eq(v(COL_LEFT), sum_msg.dup());
    // Carry the remaining count and last presence bit to the next row. This joins byte prefixes
    // across rows, while continuation lookups perform the same transport between sparse blocks.
    builder
        .when(frame.transition())
        .when(carry.dup())
        .assert_eq(nv(COL_LEFT), v(COL_LEFT) - p[program::P_RAW].dup() * sum_msg.dup());
    builder.when(frame.transition()).when(carry.dup()).assert_eq(
        nv(COL_BEFORE),
        v(COL_BEFORE) + p[program::P_RAW].dup() * (previous - v(COL_BEFORE)),
    );
    // Require exhaustion on the final raw row before its payload cells are reused.
    builder.when(act.dup() * end.dup()).assert_eq(v(COL_LEFT), sum_msg);
    // At row 14, BEFORE describes byte 111. The block is final exactly when that byte is
    // already past the message, leaving room for the marker before the 128-bit length suffix.
    builder
        .when(act.dup() * p[program::P_AT14].dup())
        .assert_one(final_block.dup() + v(COL_BEFORE));
    // Every word except the final length word is the big-endian packing of message/marker/zeros.
    // In a final block, the row-14 condition above forces its high length word to be zero too.
    let [word_lo, word_hi]: [AB::Expr; 2] = halves_be(&padded);
    let data_gate = act.dup() * (p[program::P_RAW].dup() - end.dup());
    builder
        .when(data_gate)
        .assert_eq_arrays([v(COL_WORD_LO), v(COL_WORD_HI)], [word_lo, word_hi]);
    // The u32 message length needs only the suffix's low 64 bits; row 14 supplies its zero
    // high word. Range16(word_hi), together with the compressor's u32 halves, keeps the low
    // word below 2^48 and prevents satisfying this equation with the field alias 8*len + p.
    builder
        .when(act.dup() * end)
        .assert_eq(v(COL_WORD_LO) + v(COL_WORD_HI).mul_2exp_u64(32), v(COL_LEN).mul_2exp_u64(3));

    // Even an empty message has one zero-filled CHUNKS block. Later chunks are active only
    // when their first byte belongs to the message; SHA padding is never committed as input.
    let expected_chunk =
        v(COL_MSG_BEGIN) + p[program::P_FIRST].dup() * first * (one.dup() - v(COL_MSG_BEGIN));
    builder
        .when(act.dup() * p[program::P_CHUNK_FIRST].dup())
        .assert_eq(v(COL_CHUNK_ACTIVE), expected_chunk);
    // All four rows of a chunk share its activity flag. Advance INPUT_EIDOS only when
    // crossing into an active next chunk; after the input ends it stays at the chain tail.
    builder
        .when(frame.transition())
        .when(owned.dup() * (p[program::P_RAW].dup() - p[program::P_CHUNK_LAST].dup()))
        .assert_eq(nv(COL_CHUNK_ACTIVE), v(COL_CHUNK_ACTIVE));
    builder.when(frame.transition()).when(carry).assert_eq(
        nv(COL_INPUT_EIDOS),
        v(COL_INPUT_EIDOS)
            + (p[program::P_CHUNK_ADVANCE].dup() + last.dup()) * nv(COL_CHUNK_ACTIVE),
    );
    // An Eidos block carries a whole chunk. Chunk rows 1 and 2 already see the preceding row's
    // packed felts; row 1 also forwards its predecessor so the emitting row sees all four rows.
    for (head, previous, gate) in [
        (
            COL_CHUNK_HEAD_RAW,
            COL_PREVIOUS_RAW,
            owned.dup() * p[program::P_CHUNK_SECOND].dup(),
        ),
        (
            COL_CHUNK_HEAD_DIGEST,
            COL_PREVIOUS_DIGEST,
            act.dup() * final_block.dup() * p[program::P_DIGEST_SECOND].dup(),
        ),
    ] {
        builder
            .when(frame.transition())
            .when(gate)
            .assert_eq_arrays([nv(head), nv(head + 1)], [v(previous), v(previous + 1)]);
    }
    let raw: &[AB::Expr; 8] = local[COL_RAW_BEGIN..COL_RAW_BEGIN + 8]
        .try_into()
        .expect("SHA-512 raw byte band");
    let raw_le: [AB::Expr; 2] = halves_le::<AB::Expr, _>(raw, 256);
    // Preserve each row's two packed raw felts for the next row's chunk assembly. The chunk's
    // third row then has rows 0 and 1 in carried cells, row 2 locally, and row 3 through `next`.
    for (i, packed) in raw_le.into_iter().enumerate() {
        builder
            .when(frame.transition())
            .when(owned.dup() * p[program::P_RAW_NEXT].dup())
            .assert_eq(nv(COL_PREVIOUS_RAW + i), packed);
    }

    // Initialize only the first block from the fixed SHA-512 IV. Later blocks obtain these
    // same state halves from the previous block's feedforward outputs through the word lookup.
    let state_gate = act.dup() * v(COL_FIRST_BLOCK) * p[program::P_STATE].dup();
    builder.when(state_gate).assert_eq_arrays(
        [v(COL_STATE_LO), v(COL_STATE_HI)],
        [p[program::P_IV_LO].dup(), p[program::P_IV_HI].dup()],
    );
    let digest: &[AB::Expr; 8] = local[COL_DIGEST_BEGIN..COL_DIGEST_BEGIN + 8]
        .try_into()
        .expect("SHA-512 digest byte band");
    let digest_le: [AB::Expr; 2] = halves_le::<AB::Expr, _>(digest, 256);
    // Only the final block exposes digest bytes, in rows 24..32. Carry their packed felts across
    // rows 24->25 through 30->31 for its two Eidos chunks, without constraining reused cells later.
    for (i, packed) in digest_le.into_iter().enumerate() {
        builder
            .when(frame.transition())
            .when(act.dup() * final_block.dup() * p[program::P_DIGEST_NEXT].dup())
            .assert_eq(nv(COL_PREVIOUS_DIGEST + i), packed);
    }
    // This includes the binding row: the final EidosOut must refer to the same two-block digest
    // span.
    builder
        .when(frame.transition())
        .when(act.dup() * final_block * (one - last))
        .assert_eq(nv(COL_DIGEST_EIDOS), v(COL_DIGEST_EIDOS));
    // Only the binding row of a final block may publish truth claims. Zero the multiplicity on
    // every other owned row; the truth lookup uses it directly without another row selector.
    builder
        .when(owned - act * v(COL_FINAL_BLOCK) * p[program::P_BIND].dup())
        .assert_zero(v(COL_OUT_MULT));
}

/// The eight packed felts of the chunk whose third row is `local`: the carried first row, the
/// carried second row, and the little-endian halves of `local` and `next`.
fn chunk_block<E: Algebra<Felt>>(
    local: &[E; NUM_MAIN_COLS],
    next: &[E; NUM_MAIN_COLS],
    head: usize,
    previous: usize,
    bytes: usize,
) -> [E; 8] {
    let current: &[E; 8] =
        local[bytes..bytes + 8].try_into().expect("SHA-512 current chunk byte band");
    let following: &[E; 8] =
        next[bytes..bytes + 8].try_into().expect("SHA-512 next chunk byte band");
    let [current_lo, current_hi] = halves_le::<E, _>(current, 256);
    let [following_lo, following_hi] = halves_le::<E, _>(following, 256);
    [
        local[head].dup(),
        local[head + 1].dup(),
        local[previous].dup(),
        local[previous + 1].dup(),
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
fn halves_be<E: Algebra<Felt>>(bytes: &[E; 8]) -> [E; 2] {
    let pack = |slice: &[E]| {
        slice.iter().fold(E::ZERO, |acc, byte| acc * Felt::from_u32(256) + byte.dup())
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
        p[P_FIRST].dup(),
        p[P_CHUNK_EMIT].dup(),
        p[P_RAW_LAST].dup(),
        p[P_RAW].dup()
            - [P_FIRST, P_CHUNK_EMIT, P_RAW_LAST].map(|i| p[i].dup()).into_iter().sum::<E>(),
        p[P_STATE].dup(),
        p[P_DIGEST_EMIT].dup(),
        p[P_DIGEST].dup() - p[P_DIGEST_EMIT].dup(),
        p[P_BIND].dup(),
        p[P_LAST].dup(),
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
            act.dup() * mask,
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
fn eval_term<B>(
    batch: &mut B,
    term: Term,
    local: &[B::Expr; NUM_MAIN_COLS],
    next: &[B::Expr; NUM_MAIN_COLS],
    p: &[B::Expr; NUM_PERIODIC_COLS],
) where
    B: LookupBatch,
    B::Expr: Algebra<Felt>,
{
    let e = |i: usize| -> B::Expr { local[i].dup() };
    let final_block = e(COL_FINAL_BLOCK);
    let degree = Deg { v: term.multiplicity_degree(), u: 1 };
    let word = |block_id, addr, lo, hi| Sha512WordMsg { block_id, addr, lo, hi };
    match term {
        Term::Input => batch.insert(
            "input",
            -B::Expr::ONE,
            word(
                e(COL_BLOCK_ID),
                p[program::P_IDX].dup() + B::Expr::from_u32(INPUT_ADDR_BASE),
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
                p[program::P_STATE_IDX].dup() + B::Expr::from_u32(INPUT_ADDR_BASE + 16),
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
                p[program::P_STATE_IDX].dup() + B::Expr::from_u32(OUTPUT_SLOTS[0]),
                e(COL_STATE_LO),
                e(COL_STATE_HI),
            ),
            degree,
        ),
        Term::DigestWord => {
            let bytes: &[B::Expr; 8] = local[COL_DIGEST_BEGIN..COL_DIGEST_BEGIN + 8]
                .try_into()
                .expect("SHA-512 digest word byte band");
            let [lo, hi] = halves_be(bytes);
            batch.insert(
                "digest-word",
                final_block,
                word(
                    e(COL_BLOCK_ID),
                    p[program::P_DIGEST_IDX].dup() + B::Expr::from_u32(OUTPUT_SLOTS[0]),
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
                compression_id: e(COL_DIGEST_EIDOS) + p[program::P_DIGEST_CYCLE_OFFSET].dup(),
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
                    (e(COL_INPUT_EIDOS) - e(COL_INPUT_HEAD) + B::Expr::ONE).mul_2exp_u64(3),
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

pub fn eval_lookups<LB: lookup::LookupBuilder<F = Felt>>(
    frame: &lookup::LookupFrame<'_, LB::Expr>,
    builder: &mut LB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local: &[LB::Expr; NUM_MAIN_COLS] = frame.main.current
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-512 IO lookup current row band");
    let next: &[LB::Expr; NUM_MAIN_COLS] = frame.main.next
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-512 IO lookup next row band");
    let p: &[LB::Expr; NUM_PERIODIC_COLS] = frame.periodic
        [periodic_col_offset..periodic_col_offset + NUM_PERIODIC_COLS]
        .try_into()
        .expect("SHA-512 IO lookup periodic band");
    let act = local[COL_ACT].dup();
    for index in 0..NUM_AUX_COLS {
        let degree = lookup_column_degree(index, false);
        builder.next_column(
            |column| {
                column.group(
                    "sha512-io",
                    |group| {
                        eval_lookup_group(group, index, local, next, p, act.dup(), false);
                    },
                    degree,
                );
            },
            degree,
        );
    }
}

impl<LB: lookup::LookupBuilder<F = Felt>> lookup::LookupAir<LB> for Sha512IoAir {
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

//! Fixed-program SHA-512 compression AIR.
//!
//! Each row executes one instruction from [`program`]. Operands and ordinary results use eight
//! little-endian bytes on logic rows. Logic results store XOR bytes; ADD, INPUT, and CONST
//! store four u16 limbs. [`Sha512WordMsg`] carries the semantic result as two u32 halves. A
//! phase/cycle controller selects short periodic instruction templates instead of committing a full
//! 4096-row program table.

pub mod program;

use alloc::{borrow::Cow, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::{
    air,
    air::LiftedAirBuilder as _,
    lookup::{self, Deg, LookupBatch, LookupColumn, LookupGroup, LookupMessage},
};
use miden_utils_sync::LazyLock;
use p3_field::Dup;
pub use program::{
    COMPRESSION_PERIOD, INPUT_ADDR_BASE, MAX_PERIODIC_LENGTH, NUM_PERIODIC_COLS, OUTPUT_SLOTS, Op,
    Slot, compression_program, real_slot_count, slots,
};

use crate::precompiles::{
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::{BytePairLutMsg, Range16Msg},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{halves_le, pack_le},
};

pub const NUM_MAIN_COLS: usize = 53;
pub const NUM_AUX_COLS: usize = 7;
pub const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 3, 2, 2, 2, 2, 2];
pub const COL_BLOCK_ID: usize = 0;
pub const COL_ACT: usize = 1;
pub const COL_PHASE_BEGIN: usize = 2;
pub const COL_CYCLE: usize = 8;
pub const COL_PHASE_END: usize = 9;
pub const COL_PHASE_INV: usize = 10;
pub const COL_META_T: usize = 11;
pub const COL_META_INPUT_WORD: usize = 12;
pub const COL_META_W_MULT: usize = 13;
pub const COL_META_A_MULT: usize = 14;
pub const COL_META_E_MULT: usize = 15;
pub const COL_META_K_LO: usize = 16;
pub const COL_META_K_HI: usize = 17;
pub const COL_PROG_BEGIN: usize = 18;
pub const COL_SRC_A: usize = 25;
pub const COL_SRC_B: usize = 26;
pub const COL_ROL_K: usize = 27;
pub const COL_SWAP: usize = 28;
pub const COL_A_BEGIN: usize = 29;
pub const COL_B_BEGIN: usize = 37;
/// XOR bytes on logic rows; four little-endian u16 limbs on ADD, INPUT, and CONST rows.
pub const COL_R_BEGIN: usize = 45;
// ROL has no second operand; ADD has no rotation parameters.
pub const COL_ROT_BEGIN: usize = COL_B_BEGIN;
pub const COL_CARRY_LO: usize = COL_ROL_K;
pub const COL_CARRY_HI: usize = COL_SWAP;

/// A u64 word identified by its compression block and address, split into low/high u32 halves.
/// Instruction results use their slot index; external message/state words use
/// `INPUT_ADDR_BASE + index`, with message indices 0..16 and state indices 16..24.
#[derive(Debug, Clone)]
pub struct Sha512WordMsg<E> {
    pub block_id: E,
    pub addr: E,
    pub lo: E,
    pub hi: E,
}

impl<E, EF> LookupMessage<E, EF> for Sha512WordMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &miden_stark::lookup::Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Sha512Word as usize,
            [self.block_id.clone(), self.addr.clone(), self.lo.clone(), self.hi.clone()],
        )
    }
}

/// Round data is provided twice by the fixed table and consumed once by each
/// word-schedule and hash round. The block id prevents cross-block substitution.
#[derive(Debug, Clone)]
pub struct Sha512RoundMetadata<E> {
    pub block_id: E,
    pub t: E,
    pub input_word: E,
    pub w_mult: E,
    pub a_mult: E,
    pub e_mult: E,
    pub k_lo: E,
    pub k_hi: E,
}

impl<E, EF> LookupMessage<E, EF> for Sha512RoundMetadata<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &miden_stark::lookup::Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Sha512RoundMetadata as usize,
            [
                self.block_id.clone(),
                self.t.clone(),
                self.input_word.clone(),
                self.w_mult.clone(),
                self.a_mult.clone(),
                self.e_mult.clone(),
                self.k_lo.clone(),
                self.k_hi.clone(),
            ],
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512CompressionAir;

static PERIODIC_COLUMNS: LazyLock<[Vec<Felt>; NUM_PERIODIC_COLS]> =
    LazyLock::new(compression_program);

impl air::LiftedAir for Sha512CompressionAir {
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

impl air::ProverAir<QuadFelt> for Sha512CompressionAir {
    type Error = lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}

pub fn eval_main<AB: air::LiftedAirBuilder<F = Felt>>(
    frame: &air::Frame<'_, AB>,
    builder: &mut AB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    eval_main_with_io(frame, builder, main_col_offset, periodic_col_offset, AB::Expr::ZERO);
}

/// Keep the block controller live while the final sixty-four NOP rows hold IO witnesses.
///
/// The controller fixes the instruction schedule; the row equations below enforce ADD, CONST,
/// and the ROL decomposition. Operand provenance, bytewise logic, range checks, and round metadata
/// are enforced by `eval_lookup_batch`. Both parts are needed to prove a compression.
pub(super) fn eval_main_with_io<AB: air::LiftedAirBuilder<F = Felt>>(
    frame: &air::Frame<'_, AB>,
    builder: &mut AB,
    main_col_offset: usize,
    periodic_col_offset: usize,
    io_act: AB::Expr,
) {
    let local: &[AB::Expr; NUM_MAIN_COLS] = frame.main.current
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-512 current row band");
    let next: &[AB::Expr; NUM_MAIN_COLS] = frame.main.next
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-512 next row band");
    // The phase machine runs on inactive rows too, permitting a 128-row empty
    // trace while anchoring every active compression to exactly 4096 rows.
    let block_id: AB::Expr = local[COL_BLOCK_ID].dup();
    let act: AB::Expr = local[COL_ACT].dup();
    let act_next: AB::Expr = next[COL_ACT].dup();
    let cycle: AB::Expr = local[COL_CYCLE].dup();
    let phase_end: AB::Expr = local[COL_PHASE_END].dup();
    let phases: [AB::Expr; program::NUM_PHASES] =
        array::from_fn(|i| local[COL_PHASE_BEGIN + i].dup());
    let periodic: &[AB::Expr; NUM_PERIODIC_COLS] = frame.periodic
        [periodic_col_offset..periodic_col_offset + NUM_PERIODIC_COLS]
        .try_into()
        .expect("SHA-512 compression periodic band");
    let last = periodic[program::COL_P32_LAST].dup();
    let block_last = last.dup() * phase_end.dup() * phases[program::PHASE_PADDING].dup();
    // Exactly one phase is selected, even in inactive padding. Combined with the fixed initial
    // state and transitions below, this prevents the witness from skipping or mixing phases.
    builder.assert_bool(local[COL_ACT].dup());
    builder.assert_bool(local[COL_PHASE_END].dup());
    for i in 0..program::NUM_PHASES {
        builder.assert_bool(local[COL_PHASE_BEGIN + i].dup());
    }
    builder.assert_zero(phases.iter().map(Dup::dup).sum::<AB::Expr>() - AB::Expr::ONE);
    // Start at block zero, in the first cycle of MASK. The periodic lane already starts at zero.
    builder.when(frame.first_row()).assert_zero(block_id.dup());
    builder
        .when(frame.first_row())
        .assert_zero(phases[program::PHASE_MASK].dup() - AB::Expr::ONE);
    builder.when(frame.first_row()).assert_zero(cycle.dup());
    let phase_length: AB::Expr = phases
        .iter()
        .zip(program::PHASE_CYCLES)
        .map(|(phase, length)| phase.dup() * Felt::from(length))
        .sum();
    // `phase_end` marks the entire final 32-row cycle. The inverse witness makes it an
    // exact zero test; the lane-31 selector below controls when the phase actually advances.
    // For d = cycle + 1 - phase_length: d = 0 forces phase_end = 1; otherwise phase_end = 0
    // and phase_inv = 1/d. Neither an early exit nor a delayed phase change is possible.
    let remaining = cycle.dup() + AB::Expr::ONE - phase_length;
    builder.assert_zero(remaining.dup() * phase_end.dup());
    builder.assert_zero(remaining * local[COL_PHASE_INV].dup() - (AB::Expr::ONE - phase_end.dup()));
    // Active blocks form a prefix: activity cannot restart after becoming zero, and it can
    // change only at a block's last row. Thus an active block cannot omit any of its 4096 rows.
    builder
        .when(frame.transition())
        .assert_zero((AB::Expr::ONE - act.dup()) * act_next.dup());
    builder
        .when(frame.transition())
        .assert_zero((AB::Expr::ONE - block_last.dup()) * (act_next - act.dup()));
    // Give each block a unique consecutive ID for all word and metadata lookups.
    builder
        .when(frame.transition())
        .assert_zero(next[COL_BLOCK_ID].dup() - block_id - block_last.dup());
    // Hold the cycle within its 32 lanes. At lane 31, increment it unless the phase ends;
    // the final term then cancels cycle + 1, resetting the next phase's cycle to zero.
    builder.when(frame.transition()).assert_zero(
        next[COL_CYCLE].dup() - cycle.dup() - last.dup()
            + last.dup() * phase_end.dup() * (cycle.dup() + AB::Expr::ONE),
    );
    // Advance the one-hot phase only at the last lane of its last cycle. The cyclic previous
    // index also implements PADDING -> MASK at the start of the next compression block.
    for i in 0..program::NUM_PHASES {
        let previous = (i + program::NUM_PHASES - 1) % program::NUM_PHASES;
        builder.when(frame.transition()).assert_zero(
            next[COL_PHASE_BEGIN + i].dup()
                - phases[i].dup()
                - last.dup() * phase_end.dup() * (phases[previous].dup() - phases[i].dup()),
        );
    }
    // Transition constraints alone would accept a truncated active block.
    builder
        .when(frame.last_row())
        .assert_zero(act.dup() * (AB::Expr::ONE - block_last));
    // IO rows retain the controller but reinterpret the remaining cells. `act` gates execution
    // and lookups; `program_gate` still enforces template equations on inactive, non-IO rows.
    let act = act - io_act.dup();
    let program_gate = AB::Expr::ONE - io_act;

    let word_phase = phases[program::PHASE_WORDS].dup();
    let hash_phase = phases[program::PHASE_HASH].dup();
    let round: AB::Expr = local[COL_META_T].dup();
    let input_word: AB::Expr = local[COL_META_INPUT_WORD].dup();
    // Opcode lookup selectors must be Boolean before the metadata lookup is interpreted.
    // IO uses this cell only in the padding phase, where word_phase is zero.
    builder.assert_zero(word_phase.dup() * input_word.dup() * (input_word.dup() - AB::Expr::ONE));
    // A word-schedule cycle contains rounds 2*cycle and 2*cycle+1; a hash cycle contains one
    // round. Binding t to these counters prevents substituting another round's constants/fanout.
    builder.assert_zero(
        word_phase.dup()
            * (round.dup()
                - cycle.dup() * Felt::from(2u8)
                - periodic[program::COL_LANE_HALF].dup()),
    );
    builder.assert_zero(hash_phase.dup() * (round.dup() - cycle.dup()));
    // A metadata lookup authenticates only the first row of each word/hash round. Hold all
    // fields throughout its 16/32-row round so every instruction uses that authenticated data.
    let hold_metadata = word_phase * (AB::Expr::ONE - periodic[program::COL_WORD_LAST].dup())
        + hash_phase.dup() * (AB::Expr::ONE - last);
    for column in COL_META_T..=COL_META_K_HI {
        builder
            .when(frame.transition())
            .assert_zero(hold_metadata.dup() * (next[column].dup() - local[column].dup()));
    }

    // Materialize the opcode, sources, and rotation parameters from the selected fixed template.
    // On active compression rows this fixes opcode selectors (all zero for NOP), source addresses,
    // and ROL parameters rather than letting the witness choose an instruction. Destination fanout
    // can be used directly by its lookup without increasing the maximum degree.
    let word_last = periodic[program::COL_WORD_LAST].dup();
    let is_add: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_ADD].dup();
    for field in 0..11 {
        let mut expected = AB::Expr::ZERO;
        for (phase, phase_selector) in phases.iter().enumerate() {
            let template = &periodic[program::TEMPLATE_BEGIN + phase * program::TEMPLATE_COLS..];
            // The expansion template starts at W[16], after eight cycles of two input words.
            // Its affine source addresses therefore use cycle - 8; hash templates use cycle.
            let template_cycle = if phase == program::PHASE_WORDS {
                cycle.dup() - AB::Expr::from(Felt::from(8u8))
            } else {
                cycle.dup()
            };
            let value = match field {
                0..=6 => template[field].dup(),
                7 => {
                    template[program::T_SRC_A_BASE].dup()
                        + template_cycle * template[program::T_SRC_A_CYCLE_COEFF].dup()
                },
                8 => {
                    template[program::T_SRC_B_BASE].dup()
                        + template_cycle * template[program::T_SRC_B_CYCLE_COEFF].dup()
                },
                9 => template[program::T_ROL_K].dup(),
                10 => template[program::T_SWAP].dup(),
                _ => unreachable!(),
            };
            // The first 16 words use only the last lane, reading an external
            // input. Later words execute the full 16-instruction schedule.
            let value = if phase == program::PHASE_WORDS {
                let input_value = match field {
                    0 => word_last.dup(),
                    7 => word_last.dup() * round.dup(),
                    _ => AB::Expr::ZERO,
                };
                value.dup() + input_word.dup() * (input_value - value)
            } else {
                value
            };
            expected += phase_selector.dup() * value;
        }
        let residual = local[COL_PROG_BEGIN + field].dup() - expected;
        if field >= 9 {
            // ADD uses these otherwise idle rotation cells for its two carries.
            builder.assert_zero(program_gate.dup() * (AB::Expr::ONE - is_add.dup()) * residual);
        } else {
            builder.assert_zero(program_gate.dup() * residual);
        }
    }
    let is_const: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_CONST].dup();
    let is_rol: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_ROL].dup();
    let k: AB::Expr = local[COL_ROL_K].dup();
    let mask_template = program::TEMPLATE_BEGIN + program::PHASE_MASK * program::TEMPLATE_COLS;
    // MASK constants come directly from the periodic template. Hash-round K[t] is carried in
    // witness metadata and authenticated by the metadata lookup, then held across the round.
    let const_lo = phases[program::PHASE_MASK].dup()
        * periodic[mask_template + program::T_CONST_LO].dup()
        + hash_phase.dup() * local[COL_META_K_LO].dup();
    let const_hi = phases[program::PHASE_MASK].dup()
        * periodic[mask_template + program::T_CONST_HI].dup()
        + hash_phase * local[COL_META_K_HI].dup();

    let a: &[AB::Expr; 8] = local[COL_A_BEGIN..COL_A_BEGIN + 8].try_into().expect("SHA-512 a band");
    let b: &[AB::Expr; 8] = local[COL_B_BEGIN..COL_B_BEGIN + 8].try_into().expect("SHA-512 b band");
    let r: &[AB::Expr; 8] = local[COL_R_BEGIN..COL_R_BEGIN + 8].try_into().expect("SHA-512 r band");
    let limbs: &[AB::Expr; 8] =
        local[COL_ROT_BEGIN..COL_ROT_BEGIN + 8].try_into().expect("SHA-512 limbs band");
    let [a_lo, a_hi] = halves_le::<AB::Expr, _>(a, 256);
    let [b_lo, b_hi] = halves_le::<AB::Expr, _>(b, 256);
    let [r_lo, r_hi] = value_halves(r);
    let carry_lo: AB::Expr = local[COL_CARRY_LO].dup();
    let carry_hi: AB::Expr = local[COL_CARRY_HI].dup();
    // ADD reuses the two ROL-parameter cells as Boolean carries. Its operand halves are bound
    // to prior u32 results by source lookups; Range16 bounds the four result limbs.
    builder
        .when(program_gate.dup() * is_add.dup())
        .assert_bool(local[COL_CARRY_LO].dup());
    builder.when(program_gate * is_add.dup()).assert_bool(local[COL_CARRY_HI].dup());
    let gate_add = act.dup() * is_add;
    // Enforce r = a + b mod 2^64 through two integer equalities:
    // a_lo + b_lo = r_lo + 2^32*carry_lo,
    // a_hi + b_hi + carry_lo = r_hi + 2^32*carry_hi.
    // Each side is far below the base-field modulus, so field equality cannot hide overflow.
    // The high carry is deliberately discarded to implement wrapping addition.
    builder.assert_zero(
        gate_add.dup()
            * (a_lo.dup() + b_lo
                - r_lo.dup()
                - AB::Expr::from(Felt::new(1u64 << 32).unwrap()) * carry_lo.dup()),
    );
    builder.assert_zero(
        gate_add
            * (a_hi.dup() + b_hi + carry_lo
                - r_hi.dup()
                - AB::Expr::from(Felt::new(1u64 << 32).unwrap()) * carry_hi),
    );
    // CONST has no source lookup: bind its result halves directly to the selected mask
    // or round constant. The same result is then available to consumers through the word bus.
    let gate_const = act.dup() * is_const;
    builder.assert_zero(gate_const.dup() * (r_lo - const_lo));
    builder.assert_zero(gate_const * (r_hi - const_hi));
    // On ROL rows, B holds two four-u16 decompositions of
    // y = (input_half + 2^32) * k, where k = 2^(shift mod 32). For shift mod 32 in 1..=30,
    // we have 2^32 - 1 < y < p. Since p = 2^64 - 2^32 + 1, y + p exceeds 2^64 - 1:
    // four u16 limbs cannot encode a second representative of y modulo the base field.
    // RangePair lookups bound all eight limbs to u16. The source bus authenticates both
    // input halves as u32: sources precede destinations and every operation preserves that
    // range. The destination lookup reconstructs the rotated result from these limbs.
    let rol_gate = act * is_rol;
    let lo_decomp: AB::Expr = pack_le(&limbs[0..4], 1u64 << 16);
    let hi_decomp: AB::Expr = pack_le(&limbs[4..8], 1u64 << 16);
    let two32 = AB::Expr::from(Felt::new(1u64 << 32).unwrap());
    builder.assert_zero(rol_gate.dup() * ((a_lo + two32.dup()) * k.dup() - lo_decomp));
    builder.assert_zero(rol_gate * ((a_hi + two32) * k - hi_decomp));
}

/// Join each shifted half's low 32 bits with the bits spilling from the opposite half.
/// Subtract `k` to remove the decomposition bias, then swap halves for rotations of 32 or more.
fn rotated_halves<E: Algebra<Felt>>(limbs: &[E; 8], k: E, swap: E) -> [E; 2] {
    let x: [E; 8] = array::from_fn(|i| limbs[i].dup());
    let two16 = E::from(Felt::from(1u32 << 16));
    let lo = x[0].dup() + x[6].dup() + two16.dup() * (x[1].dup() + x[7].dup()) - k.dup();
    let hi = x[2].dup() + x[4].dup() + two16 * (x[3].dup() + x[5].dup()) - k;
    [lo.dup() + swap.dup() * (hi.dup() - lo.dup()), hi.dup() + swap * (lo - hi)]
}

/// Pack four u16 limbs as two u32 halves. Other result cells are unused on value rows.
fn value_halves<E: Algebra<Felt>>(r: &[E; 8]) -> [E; 2] {
    [pack_le(&r[..2], 1 << 16), pack_le(&r[2..4], 1 << 16)]
}

#[derive(Copy, Clone)]
pub(super) enum LookupKind {
    Input,
    Destination,
    Sources,
    LogicPair(usize),
    ValuePair(usize),
    RangePair(usize),
    MetadataProvider,
    MetadataConsumer,
}

/// Degree including the compression activity and opcode selectors.
pub(super) const fn lookup_column_degree(index: usize) -> Deg {
    match index {
        0 | 1 => Deg { v: 4, u: 4 },
        2 => Deg { v: 4, u: 3 },
        3..=6 => Deg { v: 3, u: 4 },
        _ => panic!("invalid SHA-512 lookup column"),
    }
}

/// Add compression fractions to a group whose other alternatives use disjoint IO rows.
pub(super) fn eval_lookup_group<G>(
    group: &mut G,
    index: usize,
    local: &[G::Expr; NUM_MAIN_COLS],
    periodic: &[G::Expr; NUM_PERIODIC_COLS],
    act: G::Expr,
) where
    G: LookupGroup,
    G::Expr: Algebra<Felt>,
{
    let opcode = |i: usize| -> G::Expr { local[COL_PROG_BEGIN + i].dup() };
    let emit = |group: &mut G, flag: G::Expr, kinds: &[LookupKind], degree| {
        group.batch(
            "compression",
            flag,
            |batch| {
                for &kind in kinds {
                    eval_lookup_batch(batch, kind, local, periodic);
                }
            },
            degree,
        );
    };
    match index {
        0 => emit(group, act, &[LookupKind::Destination], lookup_column_degree(index)),
        1 => emit(
            group,
            act,
            &[LookupKind::Sources, LookupKind::Input],
            lookup_column_degree(index),
        ),
        2 => emit(
            group,
            act,
            &[LookupKind::MetadataProvider, LookupKind::MetadataConsumer],
            lookup_column_degree(index),
        ),
        3..=6 => {
            let pair = index - 3;
            let degree = lookup_column_degree(index);
            let logic = opcode(program::T_IS_XOR)
                + opcode(program::T_IS_AND)
                + opcode(program::T_IS_ANDNOT);
            emit(group, act.dup() * logic, &[LookupKind::LogicPair(pair)], degree);
            if pair < 2 {
                emit(
                    group,
                    act.dup() * (opcode(program::T_IS_ADD) + opcode(program::T_IS_INPUT)),
                    &[LookupKind::ValuePair(pair)],
                    degree,
                );
            }
            emit(group, act * opcode(program::T_IS_ROL), &[LookupKind::RangePair(pair)], degree);
        },
        _ => unreachable!(),
    }
}

/// Emit one compression lookup batch into an already-opened lookup batch.
/// Negative multiplicities provide words/table entries; positive multiplicities consume them.
/// The enclosing group supplies the activity and, for logic/range checks, opcode selectors.
pub(super) fn eval_lookup_batch<B>(
    batch: &mut B,
    kind: LookupKind,
    local: &[B::Expr; NUM_MAIN_COLS],
    periodic: &[B::Expr; NUM_PERIODIC_COLS],
) where
    B: LookupBatch,
    B::Expr: Algebra<Felt>,
{
    let v = |index: usize| -> B::Expr { local[index].dup() };
    let p = |index: usize| -> B::Expr { periodic[index].dup() };
    let act = B::Expr::ONE;
    let entry_degree = match kind {
        LookupKind::Destination => Deg { v: 3, u: 3 },
        LookupKind::Sources | LookupKind::Input => Deg { v: 1, u: 1 },
        LookupKind::MetadataProvider | LookupKind::MetadataConsumer => Deg { v: 2, u: 1 },
        _ => Deg { v: 0, u: 1 },
    };

    match kind {
        LookupKind::Destination => {
            // Provide the result once per scheduled read. Intermediate fanouts are fixed by
            // the template; W/a/e fanouts vary by round and come from authenticated metadata.
            // The extra read of each feedforward result binds it to the IO state or digest.
            let bid = v(COL_BLOCK_ID);
            let phases: [B::Expr; program::NUM_PHASES] = array::from_fn(|i| v(COL_PHASE_BEGIN + i));
            let dst_mult: B::Expr = phases
                .iter()
                .enumerate()
                .map(|(phase, selector)| {
                    let template = program::TEMPLATE_BEGIN + phase * program::TEMPLATE_COLS;
                    let constant = if phase == program::PHASE_WORDS {
                        p(template + program::T_DST_CONST) * (B::Expr::ONE - v(COL_META_INPUT_WORD))
                    } else {
                        p(template + program::T_DST_CONST)
                    };
                    selector.dup()
                        * (constant
                            + p(template + program::T_DST_W) * v(COL_META_W_MULT)
                            + p(template + program::T_DST_A) * v(COL_META_A_MULT)
                            + p(template + program::T_DST_E) * v(COL_META_E_MULT))
                })
                .sum();
            // Reconstruct the unique destination address from the controller; the witness
            // cannot publish a result at another instruction's address to satisfy its readers.
            let slot = phases
                .iter()
                .zip(program::PHASE_BASES)
                .map(|(phase, base)| phase.dup() * Felt::from(base))
                .sum::<B::Expr>()
                + v(COL_CYCLE) * Felt::from(32u8)
                + p(program::COL_LANE);
            let r: &[B::Expr; 8] =
                local[COL_R_BEGIN..COL_R_BEGIN + 8].try_into().expect("SHA-512 lookup r band");
            let limbs: &[B::Expr; 8] = local[COL_ROT_BEGIN..COL_ROT_BEGIN + 8]
                .try_into()
                .expect("SHA-512 lookup limbs band");
            let [r_lo, r_hi] = value_halves(r);
            let [x_lo, x_hi] = halves_le::<B::Expr, _>(r, 256);
            let a: &[B::Expr; 8] =
                local[COL_A_BEGIN..COL_A_BEGIN + 8].try_into().expect("SHA-512 lookup a band");
            let b: &[B::Expr; 8] =
                local[COL_B_BEGIN..COL_B_BEGIN + 8].try_into().expect("SHA-512 lookup b band");
            let [a_lo, a_hi] = halves_le::<B::Expr, _>(a, 256);
            let [b_lo, b_hi] = halves_le::<B::Expr, _>(b, 256);
            let [c_lo, c_hi] = rotated_halves(limbs, v(COL_ROL_K), v(COL_SWAP));
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let is_and = v(COL_PROG_BEGIN + program::T_IS_AND);
            let is_andnot = v(COL_PROG_BEGIN + program::T_IS_ANDNOT);
            let logic = v(COL_PROG_BEGIN + program::T_IS_XOR) + is_and.dup() + is_andnot.dup();
            let half = B::Expr::from(Felt::new_unchecked(0x7fff_ffff_8000_0001));
            // X is the bytewise XOR. AND=(A+B-X)/2 and ANDNOT=(X-A+B)/2 as integers.
            // Keep the ROL term separate: nesting it around the logic correction raises degree.
            let output = |r: B::Expr, x: B::Expr, a: B::Expr, b: B::Expr, rotated: B::Expr| {
                r.dup()
                    + logic.dup() * (x.dup() - r.dup())
                    + is_and.dup() * (a.dup() + b.dup() - x.dup() * Felt::from_u8(3)) * half.dup()
                    + is_andnot.dup() * (b - a - x) * half.dup()
                    + is_rol.dup() * (rotated - r)
            };
            let out_lo = output(r_lo, x_lo, a_lo, b_lo, c_lo);
            let out_hi = output(r_hi, x_hi, a_hi, b_hi, c_hi);
            batch.insert(
                "dst",
                -act * dst_mult,
                Sha512WordMsg {
                    block_id: bid,
                    addr: slot,
                    lo: out_lo,
                    hi: out_hi,
                },
                entry_degree,
            );
        },
        LookupKind::Sources => {
            // Every operand read must match a provided (block, address, lo, hi) tuple. ROL
            // reads only A; binary instructions read both A and B; INPUT/CONST/NOP read neither.
            let bid = v(COL_BLOCK_ID);
            let a: &[B::Expr; 8] =
                local[COL_A_BEGIN..COL_A_BEGIN + 8].try_into().expect("SHA-512 lookup a band");
            let b: &[B::Expr; 8] =
                local[COL_B_BEGIN..COL_B_BEGIN + 8].try_into().expect("SHA-512 lookup b band");
            let [a_lo, a_hi] = halves_le::<B::Expr, _>(a, 256);
            let [b_lo, b_hi] = halves_le::<B::Expr, _>(b, 256);
            let is_xor = v(COL_PROG_BEGIN + program::T_IS_XOR);
            let is_and = v(COL_PROG_BEGIN + program::T_IS_AND);
            let is_andnot = v(COL_PROG_BEGIN + program::T_IS_ANDNOT);
            let is_add = v(COL_PROG_BEGIN + program::T_IS_ADD);
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let reads_a = is_xor.dup() + is_and.dup() + is_andnot.dup() + is_add.dup() + is_rol;
            let reads_b = is_xor + is_and + is_andnot + is_add;
            let addrs = [v(COL_SRC_A), v(COL_SRC_B)];
            batch.insert(
                "src_a",
                act.dup() * reads_a,
                Sha512WordMsg {
                    block_id: bid.dup(),
                    addr: addrs[0].dup(),
                    lo: a_lo,
                    hi: a_hi,
                },
                entry_degree,
            );
            batch.insert(
                "src_b",
                act * reads_b,
                Sha512WordMsg {
                    block_id: bid,
                    addr: addrs[1].dup(),
                    lo: b_lo,
                    hi: b_hi,
                },
                entry_degree,
            );
        },
        LookupKind::Input => {
            // INPUT copies a word supplied by IO. The external address range is disjoint from
            // instruction slots, so an internal result cannot stand in for a message/state word.
            let bid = v(COL_BLOCK_ID);
            let r: &[B::Expr; 8] =
                local[COL_R_BEGIN..COL_R_BEGIN + 8].try_into().expect("SHA-512 lookup r band");
            let [r_lo, r_hi] = value_halves(r);
            let is_input = v(COL_PROG_BEGIN + program::T_IS_INPUT);
            let ext_addr = B::Expr::from(Felt::from(INPUT_ADDR_BASE)) + v(COL_SRC_A);
            batch.insert(
                "input",
                act * is_input,
                Sha512WordMsg {
                    block_id: bid,
                    addr: ext_addr,
                    lo: r_lo,
                    hi: r_hi,
                },
                entry_degree,
            );
        },
        LookupKind::LogicPair(index) => {
            // The canonical XOR table also bounds both source bytes. AND and ANDNOT use the
            // same tuple; only the semantic destination word depends on the opcode.
            for i in [2 * index, 2 * index + 1] {
                batch.insert(
                    "byte",
                    B::Expr::ONE,
                    BytePairLutMsg::from_xor(
                        v(COL_A_BEGIN + i),
                        v(COL_B_BEGIN + i),
                        v(COL_R_BEGIN + i),
                    ),
                    entry_degree,
                );
            }
        },
        LookupKind::ValuePair(index) | LookupKind::RangePair(index) => {
            let begin = if matches!(kind, LookupKind::ValuePair(_)) {
                COL_R_BEGIN
            } else {
                COL_ROT_BEGIN
            };
            for i in [2 * index, 2 * index + 1] {
                batch.insert("limb", B::Expr::ONE, Range16Msg { w: v(begin + i) }, entry_degree);
            }
        },
        LookupKind::MetadataProvider => {
            // The 128 bootstrap rows cover one full metadata-table period. Provide two copies
            // of each valid entry: one for W[t]'s schedule and one for hash round t. Padding
            // entries 80..128 provide nothing, so they cannot authenticate an extra round.
            let bid = v(COL_BLOCK_ID);
            let phases: [B::Expr; program::NUM_PHASES] = array::from_fn(|i| v(COL_PHASE_BEGIN + i));
            let provider = -B::Expr::from(Felt::from(2u8))
                * act
                * phases[program::PHASE_BOOTSTRAP].dup()
                * p(program::COL_META_VALID);
            batch.insert(
                "provider",
                provider,
                Sha512RoundMetadata {
                    block_id: bid,
                    t: p(program::COL_META_T),
                    input_word: p(program::COL_META_INPUT_WORD),
                    w_mult: p(program::COL_META_W_MULT),
                    a_mult: p(program::COL_META_A_MULT),
                    e_mult: p(program::COL_META_E_MULT),
                    k_lo: p(program::COL_META_K_LO),
                    k_hi: p(program::COL_META_K_HI),
                },
                entry_degree,
            );
        },
        LookupKind::MetadataConsumer => {
            // Consume metadata at each round's first row. The controller fixes t and the local
            // hold constraints propagate these authenticated fields through the rest of the round.
            let bid = v(COL_BLOCK_ID);
            let phases: [B::Expr; program::NUM_PHASES] = array::from_fn(|i| v(COL_PHASE_BEGIN + i));
            let consumer = act
                * (phases[program::PHASE_WORDS].dup() * p(program::COL_WORD_FIRST)
                    + phases[program::PHASE_HASH].dup() * p(program::COL_HASH_FIRST));
            batch.insert(
                "consumer",
                consumer,
                Sha512RoundMetadata {
                    block_id: bid,
                    t: v(COL_META_T),
                    input_word: v(COL_META_INPUT_WORD),
                    w_mult: v(COL_META_W_MULT),
                    a_mult: v(COL_META_A_MULT),
                    e_mult: v(COL_META_E_MULT),
                    k_lo: v(COL_META_K_LO),
                    k_hi: v(COL_META_K_HI),
                },
                entry_degree,
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
        .expect("SHA-512 compression lookup row band");
    let periodic: &[LB::Expr; NUM_PERIODIC_COLS] = frame.periodic
        [periodic_col_offset..periodic_col_offset + NUM_PERIODIC_COLS]
        .try_into()
        .expect("SHA-512 compression lookup periodic band");
    let act = local[COL_ACT].dup();
    for index in 0..NUM_AUX_COLS {
        let degree = lookup_column_degree(index);
        builder.next_column(
            |column| {
                column.group(
                    "sha512",
                    |group| {
                        eval_lookup_group(group, index, local, periodic, act.dup());
                    },
                    degree,
                );
            },
            degree,
        );
    }
}

impl<LB: lookup::LookupBuilder<F = Felt>> lookup::LookupAir<LB> for Sha512CompressionAir {
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

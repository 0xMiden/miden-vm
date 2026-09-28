//! Fixed-program SHA-512 compression AIR.
//!
//! Each row executes one instruction from [`program`]. Operands and ordinary results use eight
//! little-endian bytes; [`Sha512WordMsg`] carries their packed u32 halves between producer and
//! consumer rows. A phase/cycle controller selects short periodic instruction templates instead
//! of committing a full 4096-row program table.

pub mod program;

use alloc::{borrow::Cow, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use miden_utils_sync::LazyLock;
pub use program::{
    COMPRESSION_PERIOD, INPUT_ADDR_BASE, MAX_PERIODIC_LENGTH, NUM_PERIODIC_COLS, OUTPUT_SLOTS, Op,
    Slot, compression_program, real_slot_count, slots,
};

use crate::{
    logup::{
        ConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, LookupMessage, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        build_logup_aux_trace,
    },
    primitives::byte_pair_lut::{BytePairLutMsg, Range16Msg},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, halves_le, next_main, pack_le},
};

pub const NUM_MAIN_COLS: usize = 53;
pub const NUM_AUX_COLS: usize = 13;
pub const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1];
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
    fn encode(&self, challenges: &crate::logup::Challenges<EF>) -> EF {
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
    fn encode(&self, challenges: &crate::logup::Challenges<EF>) -> EF {
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

impl BaseAir<Felt> for Sha512CompressionAir {
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

impl LiftedAir<Felt, QuadFelt> for Sha512CompressionAir {
    fn max_periodic_length(&self) -> usize {
        MAX_PERIODIC_LENGTH
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

pub fn eval_main<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    eval_main_with_io(builder, main_col_offset, periodic_col_offset, AB::Expr::ZERO);
}

/// Keep the block controller live while the final sixteen NOP rows hold IO witnesses.
///
/// The controller fixes the instruction schedule; the row equations below enforce ADD, CONST,
/// and the ROL decomposition. Operand provenance, bytewise logic, range checks, and round metadata
/// are enforced by `eval_lookup_batch`. Both parts are needed to prove a compression.
pub(super) fn eval_main_with_io<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    main_col_offset: usize,
    periodic_col_offset: usize,
    io_act: AB::Expr,
) {
    let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);
    let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), main_col_offset);
    let p = builder.periodic_values().to_vec();
    // The phase machine runs on inactive rows too, permitting a 128-row empty
    // trace while anchoring every active compression to exactly 4096 rows.
    let block_id: AB::Expr = local[COL_BLOCK_ID].into();
    let act: AB::Expr = local[COL_ACT].into();
    let act_next: AB::Expr = next[COL_ACT].into();
    let cycle: AB::Expr = local[COL_CYCLE].into();
    let phase_end: AB::Expr = local[COL_PHASE_END].into();
    let phases: [AB::Expr; program::NUM_PHASES] =
        array::from_fn(|i| local[COL_PHASE_BEGIN + i].into());
    let periodic: Vec<AB::Expr> = p[periodic_col_offset..].iter().map(|&v| v.into()).collect();
    let last = periodic[program::COL_P32_LAST].clone();
    let block_last = last.clone() * phase_end.clone() * phases[program::PHASE_PADDING].clone();
    // Exactly one phase is selected, even in inactive padding. Combined with the fixed initial
    // state and transitions below, this prevents the witness from skipping or mixing phases.
    builder.assert_bool(local[COL_ACT]);
    builder.assert_bool(local[COL_PHASE_END]);
    for i in 0..program::NUM_PHASES {
        builder.assert_bool(local[COL_PHASE_BEGIN + i]);
    }
    builder.assert_zero(phases.iter().cloned().sum::<AB::Expr>() - AB::Expr::ONE);
    // Start at block zero, in the first cycle of MASK. The periodic lane already starts at zero.
    builder.when_first_row().assert_zero(block_id.clone());
    builder
        .when_first_row()
        .assert_zero(phases[program::PHASE_MASK].clone() - AB::Expr::ONE);
    builder.when_first_row().assert_zero(cycle.clone());
    let phase_length: AB::Expr = phases
        .iter()
        .zip(program::PHASE_CYCLES)
        .map(|(phase, length)| phase.clone() * Felt::from(length))
        .sum();
    // `phase_end` marks the entire final 32-row cycle. The inverse witness makes it an
    // exact zero test; the lane-31 selector below controls when the phase actually advances.
    // For d = cycle + 1 - phase_length: d = 0 forces phase_end = 1; otherwise phase_end = 0
    // and phase_inv = 1/d. Neither an early exit nor a delayed phase change is possible.
    let remaining = cycle.clone() + AB::Expr::ONE - phase_length;
    builder.assert_zero(remaining.clone() * phase_end.clone());
    builder
        .assert_zero(remaining * local[COL_PHASE_INV].into() - (AB::Expr::ONE - phase_end.clone()));
    // Active blocks form a prefix: activity cannot restart after becoming zero, and it can
    // change only at a block's last row. Thus an active block cannot omit any of its 4096 rows.
    builder
        .when_transition()
        .assert_zero((AB::Expr::ONE - act.clone()) * act_next.clone());
    builder
        .when_transition()
        .assert_zero((AB::Expr::ONE - block_last.clone()) * (act_next - act.clone()));
    // Give each block a unique consecutive ID for all word and metadata lookups.
    builder
        .when_transition()
        .assert_zero(next[COL_BLOCK_ID].into() - block_id - block_last.clone());
    // Hold the cycle within its 32 lanes. At lane 31, increment it unless the phase ends;
    // the final term then cancels cycle + 1, resetting the next phase's cycle to zero.
    builder.when_transition().assert_zero(
        next[COL_CYCLE].into() - cycle.clone() - last.clone()
            + last.clone() * phase_end.clone() * (cycle.clone() + AB::Expr::ONE),
    );
    // Advance the one-hot phase only at the last lane of its last cycle. The cyclic previous
    // index also implements PADDING -> MASK at the start of the next compression block.
    for i in 0..program::NUM_PHASES {
        let previous = (i + program::NUM_PHASES - 1) % program::NUM_PHASES;
        builder.when_transition().assert_zero(
            next[COL_PHASE_BEGIN + i].into()
                - phases[i].clone()
                - last.clone() * phase_end.clone() * (phases[previous].clone() - phases[i].clone()),
        );
    }
    // Transition constraints alone would accept a truncated active block.
    builder.when_last_row().assert_zero(act.clone() * (AB::Expr::ONE - block_last));
    // IO rows retain the controller but reinterpret the remaining cells. `act` gates execution
    // and lookups; `program_gate` still enforces template equations on inactive, non-IO rows.
    let act = act - io_act.clone();
    let program_gate = AB::Expr::ONE - io_act;

    let word_phase = phases[program::PHASE_WORDS].clone();
    let hash_phase = phases[program::PHASE_HASH].clone();
    let round: AB::Expr = local[COL_META_T].into();
    let input_word: AB::Expr = local[COL_META_INPUT_WORD].into();
    // A word-schedule cycle contains rounds 2*cycle and 2*cycle+1; a hash cycle contains one
    // round. Binding t to these counters prevents substituting another round's constants/fanout.
    builder.assert_zero(
        word_phase.clone()
            * (round.clone()
                - cycle.clone() * Felt::from(2u8)
                - periodic[program::COL_LANE_HALF].clone()),
    );
    builder.assert_zero(hash_phase.clone() * (round.clone() - cycle.clone()));
    // A metadata lookup authenticates only the first row of each word/hash round. Hold all
    // fields throughout its 16/32-row round so every instruction uses that authenticated data.
    let hold_metadata = word_phase * (AB::Expr::ONE - periodic[program::COL_WORD_LAST].clone())
        + hash_phase.clone() * (AB::Expr::ONE - last);
    for column in COL_META_T..=COL_META_K_HI {
        builder
            .when_transition()
            .assert_zero(hold_metadata.clone() * (next[column].into() - local[column].into()));
    }

    // Materialize the opcode, sources, and rotation parameters from the selected fixed template.
    // On active compression rows this fixes opcode selectors (all zero for NOP), source addresses,
    // and ROL parameters rather than letting the witness choose an instruction. Destination fanout
    // can be used directly by its lookup without increasing the maximum degree.
    let word_last = periodic[program::COL_WORD_LAST].clone();
    let is_add: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_ADD].into();
    for field in 0..11 {
        let mut expected = AB::Expr::ZERO;
        for (phase, phase_selector) in phases.iter().enumerate() {
            let template = &periodic[program::TEMPLATE_BEGIN + phase * program::TEMPLATE_COLS..];
            // The expansion template starts at W[16], after eight cycles of two input words.
            // Its affine source addresses therefore use cycle - 8; hash templates use cycle.
            let template_cycle = if phase == program::PHASE_WORDS {
                cycle.clone() - AB::Expr::from(Felt::from(8u8))
            } else {
                cycle.clone()
            };
            let value = match field {
                0..=6 => template[field].clone(),
                7 => {
                    template[program::T_SRC_A_BASE].clone()
                        + template_cycle * template[program::T_SRC_A_CYCLE_COEFF].clone()
                },
                8 => {
                    template[program::T_SRC_B_BASE].clone()
                        + template_cycle * template[program::T_SRC_B_CYCLE_COEFF].clone()
                },
                9 => template[program::T_ROL_K].clone(),
                10 => template[program::T_SWAP].clone(),
                _ => unreachable!(),
            };
            // The first 16 words use only the last lane, reading an external
            // input. Later words execute the full 16-instruction schedule.
            let value = if phase == program::PHASE_WORDS {
                let input_value = match field {
                    0 => word_last.clone(),
                    7 => word_last.clone() * round.clone(),
                    _ => AB::Expr::ZERO,
                };
                value.clone() + input_word.clone() * (input_value - value)
            } else {
                value
            };
            expected += phase_selector.clone() * value;
        }
        let residual = local[COL_PROG_BEGIN + field].into() - expected;
        if field >= 9 {
            // ADD uses these otherwise idle rotation cells for its two carries.
            builder.assert_zero(program_gate.clone() * (AB::Expr::ONE - is_add.clone()) * residual);
        } else {
            builder.assert_zero(program_gate.clone() * residual);
        }
    }
    let is_const: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_CONST].into();
    let is_rol: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_ROL].into();
    let k: AB::Expr = local[COL_ROL_K].into();
    let mask_template = program::TEMPLATE_BEGIN + program::PHASE_MASK * program::TEMPLATE_COLS;
    // MASK constants come directly from the periodic template. Hash-round K[t] is carried in
    // witness metadata and authenticated by the metadata lookup, then held across the round.
    let const_lo = phases[program::PHASE_MASK].clone()
        * periodic[mask_template + program::T_CONST_LO].clone()
        + hash_phase.clone() * local[COL_META_K_LO].into();
    let const_hi = phases[program::PHASE_MASK].clone()
        * periodic[mask_template + program::T_CONST_HI].clone()
        + hash_phase * local[COL_META_K_HI].into();

    let a: [AB::Var; 8] = array::from_fn(|i| local[COL_A_BEGIN + i]);
    let b: [AB::Var; 8] = array::from_fn(|i| local[COL_B_BEGIN + i]);
    let r: [AB::Var; 8] = array::from_fn(|i| local[COL_R_BEGIN + i]);
    let limbs: [AB::Var; 8] = array::from_fn(|i| local[COL_ROT_BEGIN + i]);
    let [a_lo, a_hi] = halves_le(&a, 256);
    let [b_lo, b_hi] = halves_le(&b, 256);
    let [r_lo, r_hi] = halves_le(&r, 256);
    let carry_lo: AB::Expr = local[COL_CARRY_LO].into();
    let carry_hi: AB::Expr = local[COL_CARRY_HI].into();
    // ADD reuses the two ROL-parameter cells as Boolean carries. Its operand halves are bound
    // to prior u32 results by source lookups; the byte table range-checks its result bytes.
    builder
        .when(program_gate.clone() * is_add.clone())
        .assert_bool(local[COL_CARRY_LO]);
    builder.when(program_gate * is_add.clone()).assert_bool(local[COL_CARRY_HI]);
    let gate_add = act.clone() * is_add;
    // Enforce r = a + b mod 2^64 through two integer equalities:
    // a_lo + b_lo = r_lo + 2^32*carry_lo,
    // a_hi + b_hi + carry_lo = r_hi + 2^32*carry_hi.
    // Each side is far below the base-field modulus, so field equality cannot hide overflow.
    // The high carry is deliberately discarded to implement wrapping addition.
    builder.assert_zero(
        gate_add.clone()
            * (a_lo + b_lo
                - r_lo.clone()
                - AB::Expr::from(Felt::new(1u64 << 32).unwrap()) * carry_lo.clone()),
    );
    builder.assert_zero(
        gate_add
            * (a_hi + b_hi + carry_lo
                - r_hi.clone()
                - AB::Expr::from(Felt::new(1u64 << 32).unwrap()) * carry_hi),
    );
    // CONST has no source lookup: bind its range-checked result directly to the selected mask
    // or round constant. The same result is then available to consumers through the word bus.
    let gate_const = act.clone() * is_const;
    builder.assert_zero(gate_const.clone() * (r_lo.clone() - const_lo));
    builder.assert_zero(gate_const * (r_hi.clone() - const_hi));
    // On ROL rows, R holds the unrotated input and B holds two four-u16 decompositions of
    // y = (input_half + 2^32) * k, where k = 2^(shift mod 32). For shift mod 32 in 1..=30,
    // we have 2^32 - 1 < y < p. Since p = 2^64 - 2^32 + 1, y + p exceeds 2^64 - 1:
    // four u16 limbs cannot encode a second representative of y modulo the base field.
    // RangePair lookups bound all eight limbs to u16. The byte lookup also forces R = A on
    // these rows; the destination lookup reconstructs the rotated result from these limbs.
    let rol_gate = act * is_rol;
    let lo_decomp: AB::Expr = pack_le(&limbs[0..4], 1u64 << 16);
    let hi_decomp: AB::Expr = pack_le(&limbs[4..8], 1u64 << 16);
    let two32 = AB::Expr::from(Felt::new(1u64 << 32).unwrap());
    builder.assert_zero(rol_gate.clone() * ((r_lo + two32.clone()) * k.clone() - lo_decomp));
    builder.assert_zero(rol_gate * ((r_hi + two32) * k - hi_decomp));
}

/// Join each shifted half's low 32 bits with the bits spilling from the opposite half.
/// Subtract `k` to remove the decomposition bias, then swap halves for rotations of 32 or more.
fn rotated_halves<E: Algebra<Felt>, V: Copy + Into<E>>(limbs: &[V; 8], k: E, swap: E) -> [E; 2] {
    let x: [E; 8] = array::from_fn(|i| limbs[i].into());
    let two16 = E::from(Felt::from(1u32 << 16));
    let lo =
        x[0].clone() + x[6].clone() + two16.clone() * (x[1].clone() + x[7].clone()) - k.clone();
    let hi = x[2].clone() + x[4].clone() + two16 * (x[3].clone() + x[5].clone()) - k;
    [
        lo.clone() + swap.clone() * (hi.clone() - lo.clone()),
        hi.clone() + swap * (lo - hi),
    ]
}

#[derive(Copy, Clone)]
pub(super) enum LookupKind {
    Input,
    Destination,
    Sources,
    Byte(usize),
    BytePair(usize),
    RangePair(usize),
    MetadataProvider,
    MetadataConsumer,
}

pub(super) const SHARED_BATCHES: [LookupKind; 17] = [
    LookupKind::Input,
    LookupKind::Destination,
    LookupKind::Sources,
    LookupKind::Byte(0),
    LookupKind::Byte(1),
    LookupKind::Byte(2),
    LookupKind::Byte(3),
    LookupKind::Byte(4),
    LookupKind::Byte(5),
    LookupKind::Byte(6),
    LookupKind::Byte(7),
    LookupKind::RangePair(0),
    LookupKind::RangePair(1),
    LookupKind::RangePair(2),
    LookupKind::RangePair(3),
    LookupKind::MetadataProvider,
    LookupKind::MetadataConsumer,
];

pub(super) const fn lookup_batch_degree(kind: LookupKind, activity_degree: usize) -> Deg {
    match kind {
        LookupKind::Destination => Deg { v: 3 + activity_degree, u: 3 },
        LookupKind::Sources => Deg { v: 2 + activity_degree, u: 2 },
        LookupKind::Input => Deg { v: 1 + activity_degree, u: 1 },
        LookupKind::Byte(_) => Deg { v: 1 + activity_degree, u: 2 },
        LookupKind::BytePair(_) => Deg { v: 3 + activity_degree, u: 4 },
        LookupKind::RangePair(_) => Deg { v: 2 + activity_degree, u: 2 },
        LookupKind::MetadataProvider | LookupKind::MetadataConsumer => {
            Deg { v: 2 + activity_degree, u: 1 }
        },
    }
}

fn lookup_entry_degree(kind: LookupKind, activity_degree: usize) -> Deg {
    match kind {
        LookupKind::Destination => lookup_batch_degree(kind, activity_degree),
        LookupKind::Sources => Deg { v: 1 + activity_degree, u: 1 },
        LookupKind::Input | LookupKind::Byte(_) => lookup_batch_degree(kind, activity_degree),
        LookupKind::BytePair(_) => Deg { v: 1 + activity_degree, u: 2 },
        LookupKind::RangePair(_) => Deg { v: 1 + activity_degree, u: 1 },
        LookupKind::MetadataProvider | LookupKind::MetadataConsumer => {
            lookup_batch_degree(kind, activity_degree)
        },
    }
}

/// Emit one compression lookup batch into an already-opened lookup batch.
/// Negative multiplicities provide words/table entries; positive multiplicities consume them.
/// The caller either supplies `act` here or gates the enclosing batch in the composite AIR.
pub(super) fn eval_lookup_batch<B, V>(
    batch: &mut B,
    kind: LookupKind,
    local: &[V; NUM_MAIN_COLS],
    periodic: &[B::Expr; NUM_PERIODIC_COLS],
    act: B::Expr,
    activity_degree: usize,
) where
    B: LookupBatch,
    B::Expr: Algebra<Felt>,
    V: Copy + Into<B::Expr>,
{
    let v = |index: usize| -> B::Expr { local[index].into() };
    let p = |index: usize| -> B::Expr { periodic[index].clone() };
    let entry_degree = lookup_entry_degree(kind, activity_degree);

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
                    selector.clone()
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
                .map(|(phase, base)| phase.clone() * Felt::from(base))
                .sum::<B::Expr>()
                + v(COL_CYCLE) * Felt::from(32u8)
                + p(program::COL_LANE);
            let r: [V; 8] = array::from_fn(|i| local[COL_R_BEGIN + i]);
            let limbs: [V; 8] = array::from_fn(|i| local[COL_ROT_BEGIN + i]);
            let [r_lo, r_hi] = halves_le(&r, 256);
            // ROL publishes the reconstructed rotation, not the unrotated bytes in R.
            let [c_lo, c_hi] = rotated_halves(&limbs, v(COL_ROL_K), v(COL_SWAP));
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let out_lo = r_lo.clone() + is_rol.clone() * (c_lo - r_lo);
            let out_hi = r_hi.clone() + is_rol * (c_hi - r_hi);
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
            let a: [V; 8] = array::from_fn(|i| local[COL_A_BEGIN + i]);
            let b: [V; 8] = array::from_fn(|i| local[COL_B_BEGIN + i]);
            let [a_lo, a_hi] = halves_le(&a, 256);
            let [b_lo, b_hi] = halves_le(&b, 256);
            let is_xor = v(COL_PROG_BEGIN + program::T_IS_XOR);
            let is_and = v(COL_PROG_BEGIN + program::T_IS_AND);
            let is_andnot = v(COL_PROG_BEGIN + program::T_IS_ANDNOT);
            let is_add = v(COL_PROG_BEGIN + program::T_IS_ADD);
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let reads_a =
                is_xor.clone() + is_and.clone() + is_andnot.clone() + is_add.clone() + is_rol;
            let reads_b = is_xor + is_and + is_andnot + is_add;
            let addrs = [v(COL_SRC_A), v(COL_SRC_B)];
            batch.insert(
                "src_a",
                act.clone() * reads_a,
                Sha512WordMsg {
                    block_id: bid.clone(),
                    addr: addrs[0].clone(),
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
                    addr: addrs[1].clone(),
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
            let r: [V; 8] = array::from_fn(|i| local[COL_R_BEGIN + i]);
            let [r_lo, r_hi] = halves_le(&r, 256);
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
        LookupKind::Byte(index) | LookupKind::BytePair(index) => {
            // A single XOR-table tuple covers each byte's logic and range constraints:
            // - XOR checks (a, b, r) directly; AND/ANDNOT convert r to an XOR result below.
            // - ADD/INPUT/CONST check (0, r, r), which range-checks the result byte.
            // - ROL checks (a, 0, r), which range-checks a and forces r = a before rotation.
            let bid_kind = matches!(kind, LookupKind::BytePair(_));
            let pair_indices = if bid_kind {
                [index * 2, index * 2 + 1]
            } else {
                [index, index]
            };
            let is_xor = v(COL_PROG_BEGIN + program::T_IS_XOR);
            let is_and = v(COL_PROG_BEGIN + program::T_IS_AND);
            let is_andnot = v(COL_PROG_BEGIN + program::T_IS_ANDNOT);
            let is_add = v(COL_PROG_BEGIN + program::T_IS_ADD);
            let is_input = v(COL_PROG_BEGIN + program::T_IS_INPUT);
            let is_const = v(COL_PROG_BEGIN + program::T_IS_CONST);
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let logic = is_xor.clone() + is_and.clone() + is_andnot.clone();
            let value = is_add.clone() + is_input.clone() + is_const.clone();
            let a: [V; 8] = array::from_fn(|i| local[COL_A_BEGIN + i]);
            let b: [V; 8] = array::from_fn(|i| local[COL_B_BEGIN + i]);
            let r: [V; 8] = array::from_fn(|i| local[COL_R_BEGIN + i]);
            for i in pair_indices {
                let lut_a = (is_xor.clone() + is_andnot.clone() + is_rol.clone()) * v_at(&a, i)
                    + is_and.clone() * (B::Expr::from(Felt::from(255u8)) - v_at(&a, i));
                let b_value = logic.clone() * v_at(&b, i) + value.clone() * v_at(&r, i);
                // The table stores `lut_a xor b_value`. ANDNOT results map through
                // `a - b + 2r`; AND reads `lut_a = 255 - a`, so it uses the same identity.
                let r_i = v_at(&r, i);
                let x = r_i.clone()
                    + is_andnot.clone() * (v_at(&a, i) - v_at(&b, i) + r_i.clone())
                    + is_and.clone()
                        * (B::Expr::from(Felt::from(255u8)) - v_at(&a, i) - v_at(&b, i) + r_i);
                batch.insert(
                    "byte",
                    act.clone()
                        * (is_xor.clone()
                            + is_and.clone()
                            + is_andnot.clone()
                            + is_add.clone()
                            + is_rol.clone()
                            + is_input.clone()
                            + is_const.clone()),
                    BytePairLutMsg::from_xor(lut_a, b_value, x),
                    entry_degree,
                );
                if !bid_kind {
                    break;
                }
            }
        },
        LookupKind::RangePair(index) => {
            // These u16 bounds turn the ROL decomposition equations into bounded integer
            // decompositions. They are inactive when B holds ordinary second-operand bytes.
            let limbs: [V; 8] = array::from_fn(|i| local[COL_ROT_BEGIN + i]);
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            for i in [index * 2, index * 2 + 1] {
                batch.insert(
                    "limb",
                    act.clone() * is_rol.clone(),
                    Range16Msg { w: v_at(&limbs, i) },
                    entry_degree,
                );
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
                * phases[program::PHASE_BOOTSTRAP].clone()
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
                * (phases[program::PHASE_WORDS].clone() * p(program::COL_WORD_FIRST)
                    + phases[program::PHASE_HASH].clone() * p(program::COL_HASH_FIRST));
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

fn v_at<E, V: Copy + Into<E>>(values: &[V; 8], index: usize) -> E {
    values[index].into()
}

pub fn eval_lookups<LB: LookupBuilder<F = Felt>>(
    builder: &mut LB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);
    let periods = builder.periodic_values();
    let periodic: [LB::Expr; NUM_PERIODIC_COLS] =
        array::from_fn(|i| periods[periodic_col_offset + i].into());
    let act: LB::Expr = local[COL_ACT].into();
    let batches = [
        LookupKind::Destination,
        LookupKind::Sources,
        LookupKind::Input,
        LookupKind::BytePair(0),
        LookupKind::BytePair(1),
        LookupKind::BytePair(2),
        LookupKind::BytePair(3),
        LookupKind::RangePair(0),
        LookupKind::RangePair(1),
        LookupKind::RangePair(2),
        LookupKind::RangePair(3),
        LookupKind::MetadataProvider,
        LookupKind::MetadataConsumer,
    ];
    for kind in batches {
        let degree = lookup_batch_degree(kind, 1);
        builder.next_column(
            |column| {
                column.group(
                    "sha512",
                    |group| {
                        group.batch(
                            "f",
                            LB::Expr::ONE,
                            |batch| {
                                eval_lookup_batch(batch, kind, &local, &periodic, act.clone(), 1);
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

impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for Sha512CompressionAir {
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

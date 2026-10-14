//! Fixed-program SHA-256 compression AIR.

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
    utils::{current_main, next_main, pack_le},
};

pub const NUM_MAIN_COLS: usize = 39;
pub const NUM_AUX_COLS: usize = 9;
pub const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 2, 1, 2, 2, 2, 2, 1, 1];
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
pub const COL_META_K: usize = 16;
pub const COL_PROG_BEGIN: usize = 17;
pub const COL_SRC_A: usize = 24;
pub const COL_SRC_B: usize = 25;
pub const COL_ROL_K: usize = 26;
pub const COL_A_BEGIN: usize = 27;
pub const COL_B_BEGIN: usize = 31;
pub const COL_R_BEGIN: usize = 35;
// ROL has no second operand; ADD has no rotation parameter.
pub const COL_ROT_BEGIN: usize = COL_B_BEGIN;
pub const COL_CARRY: usize = COL_ROL_K;

#[derive(Debug, Clone)]
pub struct Sha256WordMsg<E> {
    pub block_id: E,
    pub addr: E,
    pub value: E,
}

impl<E, EF> LookupMessage<E, EF> for Sha256WordMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &crate::logup::Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Sha256Word as usize,
            [self.block_id.clone(), self.addr.clone(), self.value.clone()],
        )
    }
}

/// Round data is provided twice by the fixed table and consumed once by each
/// word-schedule and hash round. The block id prevents cross-block substitution.
#[derive(Debug, Clone)]
pub struct Sha256RoundMetadata<E> {
    pub block_id: E,
    pub t: E,
    pub input_word: E,
    pub w_mult: E,
    pub a_mult: E,
    pub e_mult: E,
    pub k: E,
}

impl<E, EF> LookupMessage<E, EF> for Sha256RoundMetadata<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &crate::logup::Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Sha256RoundMetadata as usize,
            [
                self.block_id.clone(),
                self.t.clone(),
                self.input_word.clone(),
                self.w_mult.clone(),
                self.a_mult.clone(),
                self.e_mult.clone(),
                self.k.clone(),
            ],
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256CompressionAir;

static PERIODIC_COLUMNS: LazyLock<[Vec<Felt>; NUM_PERIODIC_COLS]> =
    LazyLock::new(compression_program);

impl BaseAir<Felt> for Sha256CompressionAir {
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

impl LiftedAir<Felt, QuadFelt> for Sha256CompressionAir {
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

/// Keep the block controller live while the final 32 NOP rows hold IO witnesses.
pub(super) fn eval_main_with_io<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    main_col_offset: usize,
    periodic_col_offset: usize,
    io_act: AB::Expr,
) {
    let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);
    let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), main_col_offset);
    let periodic: [AB::Expr; NUM_PERIODIC_COLS] =
        array::from_fn(|i| builder.periodic_values()[periodic_col_offset + i].into());
    // The phase machine runs on inactive rows too, permitting a 128-row empty
    // trace while anchoring every active compression to exactly 4096 rows.
    let block_id: AB::Expr = local[COL_BLOCK_ID].into();
    let act: AB::Expr = local[COL_ACT].into();
    let act_next: AB::Expr = next[COL_ACT].into();
    let cycle: AB::Expr = local[COL_CYCLE].into();
    let phase_end: AB::Expr = local[COL_PHASE_END].into();
    let phases: [AB::Expr; program::NUM_PHASES] =
        array::from_fn(|i| local[COL_PHASE_BEGIN + i].into());
    let last = periodic[program::COL_P32_LAST].clone();
    let block_last = last.clone() * phase_end.clone() * phases[program::PHASE_PADDING].clone();
    builder.assert_bool(local[COL_ACT]);
    builder.assert_bool(local[COL_PHASE_END]);
    for i in 0..program::NUM_PHASES {
        builder.assert_bool(local[COL_PHASE_BEGIN + i]);
    }
    builder.assert_zero(phases.iter().cloned().sum::<AB::Expr>() - AB::Expr::ONE);
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
    let remaining = cycle.clone() + AB::Expr::ONE - phase_length;
    builder.assert_zero(remaining.clone() * phase_end.clone());
    builder
        .assert_zero(remaining * local[COL_PHASE_INV].into() - (AB::Expr::ONE - phase_end.clone()));
    builder
        .when_transition()
        .assert_zero((AB::Expr::ONE - act.clone()) * act_next.clone());
    builder
        .when_transition()
        .assert_zero((AB::Expr::ONE - block_last.clone()) * (act_next - act.clone()));
    builder
        .when_transition()
        .assert_zero(next[COL_BLOCK_ID].into() - block_id - block_last.clone());
    builder.when_transition().assert_zero(
        next[COL_CYCLE].into() - cycle.clone() - last.clone()
            + last.clone() * phase_end.clone() * (cycle.clone() + AB::Expr::ONE),
    );
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
    let act = act - io_act.clone();
    let program_gate = AB::Expr::ONE - io_act;

    let word_phase = phases[program::PHASE_WORDS].clone();
    let hash_phase = phases[program::PHASE_HASH].clone();
    let round: AB::Expr = local[COL_META_T].into();
    let input_word: AB::Expr = local[COL_META_INPUT_WORD].into();
    builder.assert_zero(
        word_phase.clone()
            * (round.clone()
                - cycle.clone() * Felt::from(2u8)
                - periodic[program::COL_LANE_HALF].clone()),
    );
    builder.assert_zero(hash_phase.clone() * (round.clone() - cycle.clone()));
    let hold_metadata = word_phase * (AB::Expr::ONE - periodic[program::COL_WORD_LAST].clone())
        + hash_phase.clone() * (AB::Expr::ONE - last);
    for column in COL_META_T..=COL_META_K {
        builder
            .when_transition()
            .assert_zero(hold_metadata.clone() * (next[column].into() - local[column].into()));
    }

    // Materialize the opcode, sources, and rotation parameter. Destination fanout
    // can be used directly by its lookup without increasing the maximum degree.
    let word_last = periodic[program::COL_WORD_LAST].clone();
    let is_add: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_ADD].into();
    for field in 0..10 {
        let mut expected = AB::Expr::ZERO;
        for (phase, phase_selector) in phases.iter().enumerate() {
            let template = &periodic[program::TEMPLATE_BEGIN + phase * program::TEMPLATE_COLS..];
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
                _ => unreachable!(),
            };
            // The first 16 words use only the last lane, reading an external
            // input. Later words execute the fifteen-instruction schedule.
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
        if field == 9 {
            // ADD uses this otherwise idle rotation cell for its carry.
            builder.assert_zero(program_gate.clone() * (AB::Expr::ONE - is_add.clone()) * residual);
        } else {
            builder.assert_zero(program_gate.clone() * residual);
        }
    }
    let is_const: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_CONST].into();
    let is_rol: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_ROL].into();
    let k: AB::Expr = local[COL_ROL_K].into();
    let mask_template = program::TEMPLATE_BEGIN + program::PHASE_MASK * program::TEMPLATE_COLS;
    let constant = phases[program::PHASE_MASK].clone()
        * periodic[mask_template + program::T_CONST].clone()
        + hash_phase * local[COL_META_K].into();

    let a: AB::Expr = pack_le(&local[COL_A_BEGIN..COL_A_BEGIN + 4], 256);
    let b: AB::Expr = pack_le(&local[COL_B_BEGIN..COL_B_BEGIN + 4], 256);
    let r: AB::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 4], 256);
    let two32 = AB::Expr::from(Felt::new(1u64 << 32).unwrap());
    builder.when(program_gate * is_add.clone()).assert_bool(local[COL_CARRY]);
    let carry: AB::Expr = local[COL_CARRY].into();
    builder.assert_zero(act.clone() * is_add * (a.clone() + b - r.clone() - two32.clone() * carry));
    builder.assert_zero(act.clone() * is_const * (r - constant));
    // The source bus authenticates a u32: sources precede destinations, and every operation
    // preserves that range. With `k = 2^s` for `s` in 1..=30, `(a + 2^32) * k` lies in
    // `[2^33, 2^63)`, so its four range-checked u16 limbs cannot encode a field-modulus alias.
    let decomposition: AB::Expr = pack_le(&local[COL_ROT_BEGIN..COL_ROT_BEGIN + 4], 1u64 << 16);
    builder.assert_zero(act * is_rol * ((a + two32) * k - decomposition));
}

/// The 32-bit left rotation encoded by a ROL row's limbs of `(x + 2^32) * k`: the low word
/// `x << s` plus the high word `(x >> (32 - s)) + k`, less the offset's contribution `k`.
fn rotated_word<E: Algebra<Felt>, V: Copy + Into<E>>(limbs: &[V; 4], k: E) -> E {
    let x: [E; 4] = array::from_fn(|i| limbs[i].into());
    let two16 = E::from(Felt::from(1u32 << 16));
    x[0].clone() + x[2].clone() + two16 * (x[1].clone() + x[3].clone()) - k
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

/// Compression batches that share a lookup column with an IO batch in the composite AIR.
pub(super) const SHARED_BATCHES: [LookupKind; 11] = [
    LookupKind::Input,
    LookupKind::Destination,
    LookupKind::Sources,
    LookupKind::Byte(0),
    LookupKind::Byte(1),
    LookupKind::Byte(2),
    LookupKind::Byte(3),
    LookupKind::RangePair(0),
    LookupKind::RangePair(1),
    LookupKind::MetadataProvider,
    LookupKind::MetadataConsumer,
];

pub(super) const fn lookup_batch_degree(kind: LookupKind, activity_degree: usize) -> Deg {
    match kind {
        LookupKind::Destination => Deg { v: 3 + activity_degree, u: 2 },
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
            let slot = phases
                .iter()
                .zip(program::PHASE_BASES)
                .map(|(phase, base)| phase.clone() * Felt::from(base))
                .sum::<B::Expr>()
                + v(COL_CYCLE) * Felt::from(32u8)
                + p(program::COL_LANE);
            let r: B::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 4], 256);
            let limbs: [V; 4] = array::from_fn(|i| local[COL_ROT_BEGIN + i]);
            let rotated = rotated_word(&limbs, v(COL_ROL_K));
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let out = r.clone() + is_rol * (rotated - r);
            batch.insert(
                "dst",
                -act * dst_mult,
                Sha256WordMsg { block_id: bid, addr: slot, value: out },
                entry_degree,
            );
        },
        LookupKind::Sources => {
            let bid = v(COL_BLOCK_ID);
            let a: B::Expr = pack_le(&local[COL_A_BEGIN..COL_A_BEGIN + 4], 256);
            let b: B::Expr = pack_le(&local[COL_B_BEGIN..COL_B_BEGIN + 4], 256);
            let is_xor = v(COL_PROG_BEGIN + program::T_IS_XOR);
            let is_and = v(COL_PROG_BEGIN + program::T_IS_AND);
            let is_andnot = v(COL_PROG_BEGIN + program::T_IS_ANDNOT);
            let is_add = v(COL_PROG_BEGIN + program::T_IS_ADD);
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let reads_a =
                is_xor.clone() + is_and.clone() + is_andnot.clone() + is_add.clone() + is_rol;
            let reads_b = is_xor + is_and + is_andnot + is_add;
            batch.insert(
                "src_a",
                act.clone() * reads_a,
                Sha256WordMsg {
                    block_id: bid.clone(),
                    addr: v(COL_SRC_A),
                    value: a,
                },
                entry_degree,
            );
            batch.insert(
                "src_b",
                act * reads_b,
                Sha256WordMsg {
                    block_id: bid,
                    addr: v(COL_SRC_B),
                    value: b,
                },
                entry_degree,
            );
        },
        LookupKind::Input => {
            let bid = v(COL_BLOCK_ID);
            let r: B::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 4], 256);
            let is_input = v(COL_PROG_BEGIN + program::T_IS_INPUT);
            let ext_addr = B::Expr::from(Felt::from(INPUT_ADDR_BASE)) + v(COL_SRC_A);
            batch.insert(
                "input",
                act * is_input,
                Sha256WordMsg { block_id: bid, addr: ext_addr, value: r },
                entry_degree,
            );
        },
        LookupKind::Byte(index) | LookupKind::BytePair(index) => {
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
            let logic = is_xor.clone() + is_and.clone() + is_andnot.clone();
            // Constant packed words are fixed by the AIR. Rotation inputs are already u32
            // on the source bus, and their outputs use the range-checked u16 decomposition.
            let value = is_add.clone() + is_input.clone();
            let a: [V; 4] = array::from_fn(|i| local[COL_A_BEGIN + i]);
            let b: [V; 4] = array::from_fn(|i| local[COL_B_BEGIN + i]);
            let r: [V; 4] = array::from_fn(|i| local[COL_R_BEGIN + i]);
            for i in pair_indices {
                let lut_a = (is_xor.clone() + is_andnot.clone()) * v_at(&a, i)
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
                            + is_input.clone()),
                    BytePairLutMsg::from_xor(lut_a, b_value, x),
                    entry_degree,
                );
                if !bid_kind {
                    break;
                }
            }
        },
        LookupKind::RangePair(index) => {
            let limbs: [V; 4] = array::from_fn(|i| local[COL_ROT_BEGIN + i]);
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
            let bid = v(COL_BLOCK_ID);
            let phases: [B::Expr; program::NUM_PHASES] = array::from_fn(|i| v(COL_PHASE_BEGIN + i));
            let provider = -B::Expr::from(Felt::from(2u8))
                * act
                * phases[program::PHASE_BOOTSTRAP].clone()
                * p(program::COL_META_VALID);
            batch.insert(
                "provider",
                provider,
                Sha256RoundMetadata {
                    block_id: bid,
                    t: p(program::COL_META_T),
                    input_word: p(program::COL_META_INPUT_WORD),
                    w_mult: p(program::COL_META_W_MULT),
                    a_mult: p(program::COL_META_A_MULT),
                    e_mult: p(program::COL_META_E_MULT),
                    k: p(program::COL_META_K),
                },
                entry_degree,
            );
        },
        LookupKind::MetadataConsumer => {
            let bid = v(COL_BLOCK_ID);
            let phases: [B::Expr; program::NUM_PHASES] = array::from_fn(|i| v(COL_PHASE_BEGIN + i));
            let consumer = act
                * (phases[program::PHASE_WORDS].clone() * p(program::COL_WORD_FIRST)
                    + phases[program::PHASE_HASH].clone() * p(program::COL_HASH_FIRST));
            batch.insert(
                "consumer",
                consumer,
                Sha256RoundMetadata {
                    block_id: bid,
                    t: v(COL_META_T),
                    input_word: v(COL_META_INPUT_WORD),
                    w_mult: v(COL_META_W_MULT),
                    a_mult: v(COL_META_A_MULT),
                    e_mult: v(COL_META_E_MULT),
                    k: v(COL_META_K),
                },
                entry_degree,
            );
        },
    }
}

fn v_at<E, V: Copy + Into<E>>(values: &[V; 4], index: usize) -> E {
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
        LookupKind::RangePair(0),
        LookupKind::RangePair(1),
        LookupKind::MetadataProvider,
        LookupKind::MetadataConsumer,
    ];
    for kind in batches {
        let degree = lookup_batch_degree(kind, 1);
        builder.next_column(
            |column| {
                column.group(
                    "sha256",
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

impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for Sha256CompressionAir {
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

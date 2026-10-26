//! Fixed-program SHA-256 compression AIR.

pub mod program;

use alloc::{borrow::Cow, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use miden_utils_sync::LazyLock;
pub use program::{
    COMPRESSION_PERIOD, INPUT_ADDR_BASE, MAX_PERIODIC_LENGTH, NUM_PERIODIC_COLS, OUTPUT_SLOTS, Op,
    Slot, compression_program, real_slot_count, slots,
};

use miden_stark::lookup::{
    ConstraintLookupBuilder,
    Deg,
    LookupAir,
    LookupBatch,
    LookupBuilder,
    LookupColumn,
    LookupGroup,
    LookupMessage,
    build_logup_aux_trace,
};
use crate::precompiles::{
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::{BytePairLutMsg, Range16Msg},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main, pack_le},
};

pub const NUM_MAIN_COLS: usize = 39;
pub const NUM_AUX_COLS: usize = 4;
pub const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [2; NUM_AUX_COLS];
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
/// XOR bytes on logic rows; two little-endian u16 limbs on ADD, INPUT, and CONST rows.
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
    fn encode(&self, challenges: &miden_stark::lookup::Challenges<EF>) -> EF {
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
    fn encode(&self, challenges: &miden_stark::lookup::Challenges<EF>) -> EF {
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
    // Opcode lookup selectors must be Boolean before the metadata lookup is interpreted.
    // IO uses this cell only in the padding phase, where word_phase is zero.
    builder.assert_zero(
        word_phase.clone() * input_word.clone() * (input_word.clone() - AB::Expr::ONE),
    );
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
    let r: AB::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 2], 1 << 16);
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
    LogicPair(usize),
    ValuePair,
    RangePair(usize),
    MetadataProvider,
    MetadataConsumer,
}

pub(super) const fn lookup_column_degree(index: usize) -> Deg {
    match index {
        0 => Deg { v: 5, u: 4 },
        1 => Deg { v: 4, u: 4 },
        2 | 3 => Deg { v: 3, u: 4 },
        _ => panic!("invalid SHA-256 lookup column"),
    }
}

/// Select metadata on a NOP word-round row. The hold equations bind the same metadata
/// across all sixteen word-round rows, so authentication on lane fourteen covers the whole round.
fn metadata_gate<E: Algebra<Felt>, V: Copy + Into<E>>(
    local: &[V; NUM_MAIN_COLS],
    p: &[E; NUM_PERIODIC_COLS],
) -> E {
    let word_template = program::TEMPLATE_BEGIN + program::PHASE_WORDS * program::TEMPLATE_COLS;
    let word_nop = E::ONE - (0..7).map(|i| p[word_template + i].clone()).sum::<E>();
    let word: E = local[COL_PHASE_BEGIN + program::PHASE_WORDS].into();
    let hash: E = local[COL_PHASE_BEGIN + program::PHASE_HASH].into();
    word * word_nop + hash * p[program::COL_HASH_FIRST].clone()
}

pub(super) fn eval_lookup_group<G, V>(
    group: &mut G,
    index: usize,
    local: &[V; NUM_MAIN_COLS],
    periodic: &[G::Expr; NUM_PERIODIC_COLS],
    act: G::Expr,
) where
    G: LookupGroup,
    G::Expr: Algebra<Felt>,
    V: Copy + Into<G::Expr>,
{
    let opcode = |i: usize| -> G::Expr { local[COL_PROG_BEGIN + i].into() };
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
        0 => emit(
            group,
            act,
            &[LookupKind::Destination, LookupKind::MetadataProvider],
            lookup_column_degree(index),
        ),
        1 => {
            let reads = opcode(program::T_IS_XOR)
                + opcode(program::T_IS_AND)
                + opcode(program::T_IS_ANDNOT)
                + opcode(program::T_IS_ADD)
                + opcode(program::T_IS_ROL);
            emit(group, act.clone() * reads, &[LookupKind::Sources], Deg { v: 4, u: 4 });
            emit(
                group,
                act.clone() * opcode(program::T_IS_INPUT),
                &[LookupKind::Input],
                Deg { v: 2, u: 3 },
            );
            emit(
                group,
                act * metadata_gate(local, periodic),
                &[LookupKind::MetadataConsumer],
                Deg { v: 3, u: 4 },
            );
        },
        2 | 3 => {
            let pair = index - 2;
            let logic = opcode(program::T_IS_XOR)
                + opcode(program::T_IS_AND)
                + opcode(program::T_IS_ANDNOT);
            emit(
                group,
                act.clone() * logic,
                &[LookupKind::LogicPair(pair)],
                lookup_column_degree(index),
            );
            if pair == 0 {
                emit(
                    group,
                    act.clone() * (opcode(program::T_IS_ADD) + opcode(program::T_IS_INPUT)),
                    &[LookupKind::ValuePair],
                    lookup_column_degree(index),
                );
            }
            emit(
                group,
                act * opcode(program::T_IS_ROL),
                &[LookupKind::RangePair(pair)],
                lookup_column_degree(index),
            );
        },
        _ => unreachable!(),
    }
}

/// Emit one compression lookup batch into an already-opened lookup batch.
pub(super) fn eval_lookup_batch<B, V>(
    batch: &mut B,
    kind: LookupKind,
    local: &[V; NUM_MAIN_COLS],
    periodic: &[B::Expr; NUM_PERIODIC_COLS],
) where
    B: LookupBatch,
    B::Expr: Algebra<Felt>,
    V: Copy + Into<B::Expr>,
{
    let v = |index: usize| -> B::Expr { local[index].into() };
    let p = |index: usize| -> B::Expr { periodic[index].clone() };
    let act = B::Expr::ONE;
    let entry_degree = match kind {
        LookupKind::Destination => Deg { v: 3, u: 2 },
        LookupKind::MetadataProvider => Deg { v: 2, u: 1 },
        LookupKind::Sources => Deg { v: 1, u: 1 },
        _ => Deg { v: 0, u: 1 },
    };

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
            let r: B::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 2], 1 << 16);
            let limbs: [V; 4] = array::from_fn(|i| local[COL_ROT_BEGIN + i]);
            let rotated = rotated_word(&limbs, v(COL_ROL_K));
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let x: B::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 4], 256);
            let a: B::Expr = pack_le(&local[COL_A_BEGIN..COL_A_BEGIN + 4], 256);
            let b: B::Expr = pack_le(&local[COL_B_BEGIN..COL_B_BEGIN + 4], 256);
            let is_and = v(COL_PROG_BEGIN + program::T_IS_AND);
            let is_andnot = v(COL_PROG_BEGIN + program::T_IS_ANDNOT);
            let logic = v(COL_PROG_BEGIN + program::T_IS_XOR) + is_and.clone() + is_andnot.clone();
            let half = B::Expr::from(Felt::new_unchecked(0x7fff_ffff_8000_0001));
            // With X = A xor B, the semantic words are AND=(A+B-X)/2 and ANDNOT=(X-A+B)/2.
            let out = r.clone()
                + logic * (x.clone() - r.clone())
                + is_and * (a.clone() + b.clone() - x.clone() * Felt::from_u8(3)) * half.clone()
                + is_andnot * (b - a - x) * half
                + is_rol * (rotated - r);
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
            let reads_b = is_xor + is_and + is_andnot + is_add;
            batch.insert(
                "src_a",
                act.clone(),
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
            let r: B::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 2], 1 << 16);
            let ext_addr = B::Expr::from(Felt::from(INPUT_ADDR_BASE)) + v(COL_SRC_A);
            batch.insert(
                "input",
                act,
                Sha256WordMsg { block_id: bid, addr: ext_addr, value: r },
                entry_degree,
            );
        },
        LookupKind::LogicPair(index) => {
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
        LookupKind::ValuePair | LookupKind::RangePair(_) => {
            let (begin, pair) = match kind {
                LookupKind::ValuePair => (COL_R_BEGIN, 0),
                LookupKind::RangePair(pair) => (COL_ROT_BEGIN, pair),
                _ => unreachable!(),
            };
            for i in [2 * pair, 2 * pair + 1] {
                batch.insert("limb", B::Expr::ONE, Range16Msg { w: v(begin + i) }, entry_degree);
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
            batch.insert(
                "consumer",
                B::Expr::ONE,
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

pub fn eval_lookups<LB: LookupBuilder<F = Felt>>(
    builder: &mut LB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local = current_main(builder.main(), main_col_offset);
    let periodic = array::from_fn(|i| builder.periodic_values()[periodic_col_offset + i].into());
    let act: LB::Expr = local[COL_ACT].into();
    for index in 0..NUM_AUX_COLS {
        let degree = lookup_column_degree(index);
        builder.next_column(
            |column| {
                column.group(
                    "sha256",
                    |group| {
                        eval_lookup_group(group, index, &local, &periodic, act.clone());
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

//! Fixed-program SHA-256 compression AIR.

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
    utils::pack_le,
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

impl air::LiftedAir for Sha256CompressionAir {
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

impl air::ProverAir<QuadFelt> for Sha256CompressionAir {
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

/// Keep the block controller live while the final 32 NOP rows hold IO witnesses.
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
        .expect("SHA-256 current row band");
    let next: &[AB::Expr; NUM_MAIN_COLS] = frame.main.next
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-256 next row band");
    let periodic: &[AB::Expr; NUM_PERIODIC_COLS] = frame.periodic
        [periodic_col_offset..periodic_col_offset + NUM_PERIODIC_COLS]
        .try_into()
        .expect("SHA-256 compression periodic band");
    // The phase machine runs on inactive rows too, permitting a 128-row empty
    // trace while anchoring every active compression to exactly 4096 rows.
    let block_id: AB::Expr = local[COL_BLOCK_ID].dup();
    let act: AB::Expr = local[COL_ACT].dup();
    let act_next: AB::Expr = next[COL_ACT].dup();
    let cycle: AB::Expr = local[COL_CYCLE].dup();
    let phase_end: AB::Expr = local[COL_PHASE_END].dup();
    let phases: [AB::Expr; program::NUM_PHASES] =
        array::from_fn(|i| local[COL_PHASE_BEGIN + i].dup());
    let last = periodic[program::COL_P32_LAST].dup();
    let block_last = last.dup() * phase_end.dup() * phases[program::PHASE_PADDING].dup();
    builder.assert_bools([local[COL_ACT].dup(), local[COL_PHASE_END].dup()]);
    builder.assert_bools(phases.each_ref().map(Dup::dup));
    builder.assert_one(phases.iter().map(Dup::dup).sum::<AB::Expr>());
    builder.when(frame.first_row()).assert_zero(block_id.dup());
    builder.when(frame.first_row()).assert_one(phases[program::PHASE_MASK].dup());
    builder.when(frame.first_row()).assert_zero(cycle.dup());
    let phase_length = AB::Expr::mixed_dot_product(&phases, &program::PHASE_CYCLES.map(Felt::from));
    let remaining = cycle.dup() + AB::Expr::ONE - phase_length;
    builder.when(phase_end.dup()).assert_zero(remaining.dup());
    builder.assert_eq(remaining * local[COL_PHASE_INV].dup(), AB::Expr::ONE - phase_end.dup());
    builder
        .when(frame.transition())
        .when(AB::Expr::ONE - act.dup())
        .assert_zero(act_next.dup());
    builder
        .when(frame.transition())
        .when(AB::Expr::ONE - block_last.dup())
        .assert_eq(act_next.dup(), act.dup());
    builder
        .when(frame.transition())
        .assert_eq(next[COL_BLOCK_ID].dup(), block_id.dup() + block_last.dup());
    builder.when(frame.transition()).assert_eq(
        next[COL_CYCLE].dup(),
        cycle.dup() + last.dup() - last.dup() * phase_end.dup() * (cycle.dup() + AB::Expr::ONE),
    );
    for i in 0..program::NUM_PHASES {
        let previous = (i + program::NUM_PHASES - 1) % program::NUM_PHASES;
        builder.when(frame.transition()).assert_eq(
            next[COL_PHASE_BEGIN + i].dup(),
            phases[i].dup()
                + last.dup() * phase_end.dup() * (phases[previous].dup() - phases[i].dup()),
        );
    }
    // Transition constraints alone would accept a truncated active block.
    builder
        .when(frame.last_row())
        .when(act.dup())
        .assert_zero(AB::Expr::ONE - block_last);
    let act = act.dup() - io_act.dup();
    let program_gate = AB::Expr::ONE - io_act;

    let word_phase = phases[program::PHASE_WORDS].dup();
    let hash_phase = phases[program::PHASE_HASH].dup();
    let round: AB::Expr = local[COL_META_T].dup();
    let input_word: AB::Expr = local[COL_META_INPUT_WORD].dup();
    // Opcode lookup selectors must be Boolean before the metadata lookup is interpreted.
    // IO uses this cell only in the padding phase, where word_phase is zero.
    builder.when(word_phase.dup()).assert_bool(input_word.dup());
    builder
        .when(word_phase.dup())
        .assert_eq(round.dup(), cycle.double() + periodic[program::COL_LANE_HALF].dup());
    builder.when(hash_phase.dup()).assert_eq(round.dup(), cycle.dup());
    let hold_metadata = word_phase * (AB::Expr::ONE - periodic[program::COL_WORD_LAST].dup())
        + hash_phase.dup() * (AB::Expr::ONE - last);
    for column in COL_META_T..=COL_META_K {
        builder
            .when(frame.transition())
            .when(hold_metadata.dup())
            .assert_eq(next[column].dup(), local[column].dup());
    }

    // Materialize the opcode, sources, and rotation parameter. Destination fanout
    // can be used directly by its lookup without increasing the maximum degree.
    let word_last = periodic[program::COL_WORD_LAST].dup();
    let is_add: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_ADD].dup();
    for field in 0..10 {
        let values = core::array::from_fn(|phase| {
            let template = &periodic[program::TEMPLATE_BEGIN + phase * program::TEMPLATE_COLS..];
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
                _ => unreachable!(),
            };
            // The first 16 words use only the last lane, reading an external
            // input. Later words execute the fifteen-instruction schedule.
            if phase == program::PHASE_WORDS {
                let input_value = match field {
                    0 => word_last.dup(),
                    7 => word_last.dup() * round.dup(),
                    _ => AB::Expr::ZERO,
                };
                value.dup() + input_word.dup() * (input_value - value)
            } else {
                value
            }
        });
        let expected = AB::Expr::dot_product(&phases, &values);
        if field == 9 {
            // ADD uses this otherwise idle rotation cell for its carry.
            builder
                .when(program_gate.dup() * (AB::Expr::ONE - is_add.dup()))
                .assert_eq(local[COL_PROG_BEGIN + field].dup(), expected);
        } else {
            builder
                .when(program_gate.dup())
                .assert_eq(local[COL_PROG_BEGIN + field].dup(), expected);
        }
    }
    let is_const: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_CONST].dup();
    let is_rol: AB::Expr = local[COL_PROG_BEGIN + program::T_IS_ROL].dup();
    let k: AB::Expr = local[COL_ROL_K].dup();
    let mask_template = program::TEMPLATE_BEGIN + program::PHASE_MASK * program::TEMPLATE_COLS;
    let constant = phases[program::PHASE_MASK].dup()
        * periodic[mask_template + program::T_CONST].dup()
        + hash_phase * local[COL_META_K].dup();

    let a: AB::Expr = pack_le(&local[COL_A_BEGIN..COL_A_BEGIN + 4], 256);
    let b: AB::Expr = pack_le(&local[COL_B_BEGIN..COL_B_BEGIN + 4], 256);
    let r: AB::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 2], 1 << 16);
    let two32 = AB::Expr::from(Felt::new(1u64 << 32).unwrap());
    builder.when(program_gate * is_add.dup()).assert_bool(local[COL_CARRY].dup());
    let carry = local[COL_CARRY].dup();
    builder
        .when(act.dup() * is_add.dup())
        .assert_eq(a.dup() + b, r.dup() + carry.mul_2exp_u64(32));
    builder.when(act.dup() * is_const.dup()).assert_eq(r, constant);
    // The source bus authenticates a u32: sources precede destinations, and every operation
    // preserves that range. With `k = 2^s` for `s` in 1..=30, `(a + 2^32) * k` lies in
    // `[2^33, 2^63)`, so its four range-checked u16 limbs cannot encode a field-modulus alias.
    let decomposition: AB::Expr = pack_le(&local[COL_ROT_BEGIN..COL_ROT_BEGIN + 4], 1u64 << 16);
    builder.when(act * is_rol).assert_eq((a + two32) * k, decomposition);
}

/// The 32-bit left rotation encoded by a ROL row's limbs of `(x + 2^32) * k`: the low word
/// `x << s` plus the high word `(x >> (32 - s)) + k`, less the offset's contribution `k`.
fn rotated_word<E: Algebra<Felt>>(limbs: &[E; 4], k: E) -> E {
    limbs[0].dup() + limbs[2].dup() + (limbs[1].dup() + limbs[3].dup()).mul_2exp_u64(16) - k
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
fn metadata_gate<E: Algebra<Felt>>(local: &[E; NUM_MAIN_COLS], p: &[E; NUM_PERIODIC_COLS]) -> E {
    let word_template = program::TEMPLATE_BEGIN + program::PHASE_WORDS * program::TEMPLATE_COLS;
    let word_nop = E::ONE - (0..7).map(|i| p[word_template + i].dup()).sum::<E>();
    let word: E = local[COL_PHASE_BEGIN + program::PHASE_WORDS].dup();
    let hash: E = local[COL_PHASE_BEGIN + program::PHASE_HASH].dup();
    word * word_nop + hash * p[program::COL_HASH_FIRST].dup()
}

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
        0 => emit(
            group,
            act,
            &[LookupKind::Destination, LookupKind::MetadataProvider],
            lookup_column_degree(index),
        ),
        1 => {
            let reads = [
                program::T_IS_XOR,
                program::T_IS_AND,
                program::T_IS_ANDNOT,
                program::T_IS_ADD,
                program::T_IS_ROL,
            ]
            .into_iter()
            .map(opcode)
            .sum::<G::Expr>();
            emit(group, act.dup() * reads, &[LookupKind::Sources], Deg { v: 4, u: 4 });
            emit(
                group,
                act.dup() * opcode(program::T_IS_INPUT),
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
                act.dup() * logic,
                &[LookupKind::LogicPair(pair)],
                lookup_column_degree(index),
            );
            if pair == 0 {
                emit(
                    group,
                    act.dup() * (opcode(program::T_IS_ADD) + opcode(program::T_IS_INPUT)),
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
        LookupKind::Destination => Deg { v: 3, u: 2 },
        LookupKind::MetadataProvider => Deg { v: 2, u: 1 },
        LookupKind::Sources => Deg { v: 1, u: 1 },
        _ => Deg { v: 0, u: 1 },
    };

    match kind {
        LookupKind::Destination => {
            let bid = v(COL_BLOCK_ID);
            let phases: &[B::Expr; program::NUM_PHASES] = local
                [COL_PHASE_BEGIN..COL_PHASE_BEGIN + program::NUM_PHASES]
                .try_into()
                .expect("declared AIR row band");
            let fanouts =
                [B::Expr::ONE, v(COL_META_W_MULT), v(COL_META_A_MULT), v(COL_META_E_MULT)];
            let weights = core::array::from_fn(|phase| {
                let template = program::TEMPLATE_BEGIN + phase * program::TEMPLATE_COLS;
                let constant = if phase == program::PHASE_WORDS {
                    p(template + program::T_DST_CONST) * (B::Expr::ONE - v(COL_META_INPUT_WORD))
                } else {
                    p(template + program::T_DST_CONST)
                };
                B::Expr::dot_product(
                    &fanouts,
                    &[
                        constant,
                        p(template + program::T_DST_W),
                        p(template + program::T_DST_A),
                        p(template + program::T_DST_E),
                    ],
                )
            });
            let dst_mult = B::Expr::dot_product(phases, &weights);
            let slot = B::Expr::mixed_dot_product(phases, &program::PHASE_BASES.map(Felt::from))
                + v(COL_CYCLE).mul_2exp_u64(5)
                + p(program::COL_LANE);
            let r: B::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 2], 1 << 16);
            let limbs: &[B::Expr; 4] = local[COL_ROT_BEGIN..COL_ROT_BEGIN + 4]
                .try_into()
                .expect("SHA-256 rotation limb band");
            let rotated = rotated_word(limbs, v(COL_ROL_K));
            let is_rol = v(COL_PROG_BEGIN + program::T_IS_ROL);
            let x: B::Expr = pack_le(&local[COL_R_BEGIN..COL_R_BEGIN + 4], 256);
            let a: B::Expr = pack_le(&local[COL_A_BEGIN..COL_A_BEGIN + 4], 256);
            let b: B::Expr = pack_le(&local[COL_B_BEGIN..COL_B_BEGIN + 4], 256);
            let is_and = v(COL_PROG_BEGIN + program::T_IS_AND);
            let is_andnot = v(COL_PROG_BEGIN + program::T_IS_ANDNOT);
            let logic = v(COL_PROG_BEGIN + program::T_IS_XOR) + is_and.dup() + is_andnot.dup();
            let half = B::Expr::from(Felt::new_unchecked(0x7fff_ffff_8000_0001));
            // With X = A xor B, the semantic words are AND=(A+B-X)/2 and ANDNOT=(X-A+B)/2.
            let out = r.dup()
                + logic * (x.dup() - r.dup())
                + is_and * (a.dup() + b.dup() - x.dup() * Felt::from_u8(3)) * half.dup()
                + is_andnot * (b - (a + x)) * half
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
                act.dup(),
                Sha256WordMsg {
                    block_id: bid.dup(),
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
            let phases: &[B::Expr; program::NUM_PHASES] = local
                [COL_PHASE_BEGIN..COL_PHASE_BEGIN + program::NUM_PHASES]
                .try_into()
                .expect("declared AIR row band");
            let provider =
                -act.double() * phases[program::PHASE_BOOTSTRAP].dup() * p(program::COL_META_VALID);
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

pub fn eval_lookups<LB: lookup::LookupBuilder<F = Felt>>(
    frame: &lookup::LookupFrame<'_, LB::Expr>,
    builder: &mut LB,
    main_col_offset: usize,
    periodic_col_offset: usize,
) {
    let local: &[LB::Expr; NUM_MAIN_COLS] = frame.main.current
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("SHA-256 compression lookup row band");
    let periodic: &[LB::Expr; NUM_PERIODIC_COLS] = frame.periodic
        [periodic_col_offset..periodic_col_offset + NUM_PERIODIC_COLS]
        .try_into()
        .expect("SHA-256 compression lookup periodic band");
    let act = local[COL_ACT].dup();
    for index in 0..NUM_AUX_COLS {
        let degree = lookup_column_degree(index);
        builder.next_column(
            |column| {
                column.group(
                    "sha256",
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

impl<LB: lookup::LookupBuilder<F = Felt>> lookup::LookupAir<LB> for Sha256CompressionAir {
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

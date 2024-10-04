use alloc::vec::Vec;
use core::marker::PhantomData;

use vm_core::{utils::range, ExtensionOf, Felt, FieldElement, StarkField};
use winter_air::{EvaluationFrame, LogUpGkrEvaluator, LogUpGkrOracle};

use crate::{
    decoder::{
        DECODER_ADDR_COL_IDX, DECODER_GROUP_COUNT_COL_IDX, DECODER_HASHER_STATE_OFFSET,
        DECODER_IN_SPAN_COL_IDX, DECODER_IS_LOOP_BODY_FLAG_COL_IDX, DECODER_OP_BATCH_FLAGS_OFFSET,
        DECODER_OP_BITS_EXTRA_COLS_OFFSET, DECODER_OP_BITS_OFFSET, DECODER_USER_OP_HELPERS_OFFSET,
    },
    trace::{
        chiplets::{MEMORY_D0_COL_IDX, MEMORY_D1_COL_IDX},
        range::{M_COL_IDX, V_COL_IDX},
        stack::STACK_TOP_OFFSET,
    },
    PublicInputs, CHIPLETS_OFFSET, STACK_TRACE_OFFSET, TRACE_WIDTH,
};

// CONSTANTS
// ===============================================================================================

// Random values

pub const RANGE_CHECKER_RAND_VALUES_OFFSET: usize = 0;
pub const RANGE_CHECKER_NUM_RAND_VALUES: usize = 1;

pub const OP_GROUP_TABLE_RAND_VALUES_OFFSET: usize = 1;
pub const OP_GROUP_TABLE_NUM_RAND_VALUES: usize = 4;

pub const BLOCK_HASH_TABLE_RAND_VALUES_OFFSET: usize =
    OP_GROUP_TABLE_RAND_VALUES_OFFSET + OP_GROUP_TABLE_NUM_RAND_VALUES;
pub const BLOCK_HASH_TABLE_NUM_RAND_VALUES: usize = 8;

pub const TOTAL_NUM_RAND_VALUES: usize =
    BLOCK_HASH_TABLE_RAND_VALUES_OFFSET + BLOCK_HASH_TABLE_NUM_RAND_VALUES;

// Fractions

pub const RANGE_CHECKER_FRACTIONS_OFFSET: usize = 0;
pub const RANGE_CHECKER_NUM_FRACTIONS: usize = 7;

pub const OP_GROUP_TABLE_FRACTIONS_OFFSET: usize =
    RANGE_CHECKER_FRACTIONS_OFFSET + RANGE_CHECKER_NUM_FRACTIONS;
pub const OP_GROUP_TABLE_NUM_FRACTIONS: usize = 8;

pub const BLOCK_HASH_TABLE_FRACTIONS_OFFSET: usize =
    OP_GROUP_TABLE_FRACTIONS_OFFSET + OP_GROUP_TABLE_NUM_FRACTIONS;
pub const BLOCK_HASH_TABLE_NUM_FRACTIONS: usize = 8;

pub const PADDING_FRACTIONS_OFFSET: usize =
    BLOCK_HASH_TABLE_FRACTIONS_OFFSET + BLOCK_HASH_TABLE_NUM_FRACTIONS;
pub const PADDING_NUM_FRACTIONS: usize = TOTAL_NUM_FRACTIONS - PADDING_FRACTIONS_OFFSET;

pub const TOTAL_NUM_FRACTIONS: usize = 32;

// LogUp GKR Evaluator
// ===============================================================================================

#[derive(Clone, Default)]
pub struct MidenLogUpGkrEval<B: FieldElement + StarkField> {
    oracles: Vec<LogUpGkrOracle>,
    _field: PhantomData<B>,
}

impl<B: FieldElement + StarkField> MidenLogUpGkrEval<B> {
    pub fn new() -> Self {
        let oracles = {
            let oracles_current_row = (0..TRACE_WIDTH).map(LogUpGkrOracle::CurrentRow);
            let oracles_next_row = (0..TRACE_WIDTH).map(LogUpGkrOracle::NextRow);

            oracles_current_row.chain(oracles_next_row).collect()
        };

        Self { oracles, _field: PhantomData }
    }
}

impl LogUpGkrEvaluator for MidenLogUpGkrEval<Felt> {
    type BaseField = Felt;

    type PublicInputs = PublicInputs;

    fn get_oracles(&self) -> &[LogUpGkrOracle] {
        &self.oracles
    }

    fn get_num_rand_values(&self) -> usize {
        TOTAL_NUM_RAND_VALUES
    }

    fn get_num_fractions(&self) -> usize {
        TOTAL_NUM_FRACTIONS
    }

    fn max_degree(&self) -> usize {
        10
    }

    fn build_query<E>(&self, frame: &EvaluationFrame<E>, query: &mut [E])
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let frame_current_then_next = frame.current().iter().chain(frame.next().iter());

        query.iter_mut().zip(frame_current_then_next).for_each(|(q, f)| *q = *f);
    }

    #[inline(always)]
    fn evaluate_query<F, E>(
        &self,
        query: &[F],
        _periodic_values: &[F],
        rand_values: &[E],
        numerator: &mut [E],
        denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        debug_assert_eq!(numerator.len(), TOTAL_NUM_FRACTIONS);
        debug_assert_eq!(denominator.len(), TOTAL_NUM_FRACTIONS);
        debug_assert_eq!(query.len(), TRACE_WIDTH * 2);

        let query_current = &query[0..TRACE_WIDTH];
        let query_next = &query[TRACE_WIDTH..];

        let op_flags_current = LogUpOpFlags::new(query_current);
        let op_flags_next = LogUpOpFlags::new(query_next);

        range_checker(
            query_current,
            &op_flags_current,
            rand_values[RANGE_CHECKER_FRACTIONS_OFFSET],
            &mut numerator[range(RANGE_CHECKER_FRACTIONS_OFFSET, RANGE_CHECKER_NUM_FRACTIONS)],
            &mut denominator[range(RANGE_CHECKER_FRACTIONS_OFFSET, RANGE_CHECKER_NUM_FRACTIONS)],
        );
        op_group_table(
            query_current,
            query_next,
            &op_flags_current,
            &rand_values[range(OP_GROUP_TABLE_RAND_VALUES_OFFSET, OP_GROUP_TABLE_NUM_RAND_VALUES)],
            &mut numerator[range(OP_GROUP_TABLE_FRACTIONS_OFFSET, OP_GROUP_TABLE_NUM_FRACTIONS)],
            &mut denominator[range(OP_GROUP_TABLE_FRACTIONS_OFFSET, OP_GROUP_TABLE_NUM_FRACTIONS)],
        );
        block_hash_table(
            query_current,
            query_next,
            &op_flags_current,
            &op_flags_next,
            &rand_values
                [range(BLOCK_HASH_TABLE_RAND_VALUES_OFFSET, BLOCK_HASH_TABLE_NUM_RAND_VALUES)],
            &mut numerator
                [range(BLOCK_HASH_TABLE_FRACTIONS_OFFSET, BLOCK_HASH_TABLE_NUM_FRACTIONS)],
            &mut denominator
                [range(BLOCK_HASH_TABLE_FRACTIONS_OFFSET, BLOCK_HASH_TABLE_NUM_FRACTIONS)],
        );
        padding(
            &mut numerator[range(PADDING_FRACTIONS_OFFSET, PADDING_NUM_FRACTIONS)],
            &mut denominator[range(PADDING_FRACTIONS_OFFSET, PADDING_NUM_FRACTIONS)],
        );
    }

    fn compute_claim<E>(&self, inputs: &Self::PublicInputs, rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        // block hash table
        let block_hash_table_claim = {
            let alphas = &rand_values
                [range(BLOCK_HASH_TABLE_RAND_VALUES_OFFSET, BLOCK_HASH_TABLE_NUM_RAND_VALUES)];
            let program_hash = inputs.program_info.program_hash();

            -(alphas[0] + inner_product(&alphas[2..6], program_hash.as_elements()))
        };

        block_hash_table_claim.inv()
    }
}

/// TODO(plafer): docs
#[inline(always)]
fn range_checker<F, E>(
    query_current: &[F],
    op_flags_current: &LogUpOpFlags<F>,
    alpha: E,
    numerator: &mut [E],
    denominator: &mut [E],
) where
    F: FieldElement,
    E: FieldElement + ExtensionOf<F>,
{
    // numerators
    let multiplicity = query_current[M_COL_IDX];
    let f_m = {
        let mem_selec0 = query_current[CHIPLETS_OFFSET];
        let mem_selec1 = query_current[CHIPLETS_OFFSET + 1];
        let mem_selec2 = query_current[CHIPLETS_OFFSET + 2];

        E::from(mem_selec0 * mem_selec1 * (F::ONE - mem_selec2))
    };

    let f_rc: E = op_flags_current.f_range_check().into();
    numerator[0] = E::from(multiplicity);
    numerator[1] = f_m;
    numerator[2] = f_m;
    numerator[3] = f_rc;
    numerator[4] = f_rc;
    numerator[5] = f_rc;
    numerator[6] = f_rc;

    // denominators
    let table_denom = alpha - E::from(query_current[V_COL_IDX]);
    let memory_denom_0 = -(alpha - E::from(query_current[MEMORY_D0_COL_IDX]));
    let memory_denom_1 = -(alpha - E::from(query_current[MEMORY_D1_COL_IDX]));
    let stack_value_denom_0 = -(alpha - E::from(query_current[DECODER_USER_OP_HELPERS_OFFSET]));
    let stack_value_denom_1 = -(alpha - E::from(query_current[DECODER_USER_OP_HELPERS_OFFSET + 1]));
    let stack_value_denom_2 = -(alpha - E::from(query_current[DECODER_USER_OP_HELPERS_OFFSET + 2]));
    let stack_value_denom_3 = -(alpha - E::from(query_current[DECODER_USER_OP_HELPERS_OFFSET + 3]));

    denominator[0] = table_denom;
    denominator[1] = memory_denom_0;
    denominator[2] = memory_denom_1;
    denominator[3] = stack_value_denom_0;
    denominator[4] = stack_value_denom_1;
    denominator[5] = stack_value_denom_2;
    denominator[6] = stack_value_denom_3;
}

/// TODO(plafer): docs
#[inline(always)]
fn op_group_table<F, E>(
    query_current: &[F],
    query_next: &[F],
    op_flags_current: &LogUpOpFlags<F>,
    alphas: &[E],
    numerator: &mut [E],
    denominator: &mut [E],
) where
    F: FieldElement,
    E: FieldElement + ExtensionOf<F>,
{
    // numerators
    let f_delete_group = E::from(
        query_current[DECODER_IN_SPAN_COL_IDX]
            * (query_current[DECODER_GROUP_COUNT_COL_IDX]
                - query_next[DECODER_GROUP_COUNT_COL_IDX]),
    );

    let (f_g2, f_g4, f_g8) = {
        let bc0 = query_current[DECODER_OP_BATCH_FLAGS_OFFSET];
        let bc1 = query_current[DECODER_OP_BATCH_FLAGS_OFFSET + 1];
        let bc2 = query_current[DECODER_OP_BATCH_FLAGS_OFFSET + 2];

        (
            E::from((F::ONE - bc0) * (F::ONE - bc1) * bc2),
            E::from((F::ONE - bc0) * bc1 * (F::ONE - bc2)),
            E::from(bc0),
        )
    };

    numerator[0] = f_delete_group;
    numerator[1] = f_g2 + f_g4 + f_g8; // v1
    numerator[2] = f_g4 + f_g8; // v2
    numerator[3] = f_g4 + f_g8; // v3
    numerator[4] = f_g8; // v4
    numerator[5] = f_g8; // v5
    numerator[6] = f_g8; // v6
    numerator[7] = f_g8; // v7

    // denominators
    let addr = query_current[DECODER_ADDR_COL_IDX];
    let addr_next = query_next[DECODER_ADDR_COL_IDX];
    let group_count = query_current[DECODER_GROUP_COUNT_COL_IDX];
    let h0_next = query_next[DECODER_HASHER_STATE_OFFSET];
    let op_next = LogUpOpFlags::new(query_next).op_value();
    let h2 = query_current[DECODER_HASHER_STATE_OFFSET + 2];
    let s0_next = query_next[STACK_TRACE_OFFSET + STACK_TOP_OFFSET];
    let (v1, v2, v3, v4, v5, v6, v7) = {
        let v = |idx: u8| {
            alphas[0]
                + alphas[1].mul_base(addr_next)
                + alphas[2].mul_base(group_count - idx.into())
                + alphas[3].mul_base(query_current[DECODER_HASHER_STATE_OFFSET + idx as usize])
        };

        (v(1), v(2), v(3), v(4), v(5), v(6), v(7))
    };

    let f_push = op_flags_current.f_push();
    let f_emit = op_flags_current.f_emit();
    let f_imm = op_flags_current.f_imm();

    denominator[0] = -(alphas[0]
        + alphas[1].mul_base(addr)
        + alphas[2].mul_base(group_count)
        + alphas[3].mul_base(
            (F::from(128_u32) * h0_next + op_next) * (F::ONE - f_imm)
                + s0_next * f_push
                + h2 * f_emit,
        ));
    denominator[1] = v1;
    denominator[2] = v2;
    denominator[3] = v3;
    denominator[4] = v4;
    denominator[5] = v5;
    denominator[6] = v6;
    denominator[7] = v7;
}

#[inline(always)]
fn block_hash_table<F, E>(
    query_current: &[F],
    query_next: &[F],
    op_flags_current: &LogUpOpFlags<F>,
    op_flags_next: &LogUpOpFlags<F>,
    alphas: &[E],
    numerator: &mut [E],
    denominator: &mut [E],
) where
    F: FieldElement,
    E: FieldElement + ExtensionOf<F>,
{
    let stack_0 = query_current[STACK_TRACE_OFFSET + STACK_TOP_OFFSET];

    // numerators
    let f_join: E = op_flags_current.f_join().into();

    numerator[0] = op_flags_current.f_end().into();
    numerator[1] = f_join;
    numerator[2] = f_join;
    numerator[3] = op_flags_current.f_split().into();
    numerator[4] = (op_flags_current.f_loop() * stack_0).into();
    numerator[5] = op_flags_current.f_repeat().into();
    numerator[6] = op_flags_current.f_dyn().into();
    // TODO(plafer): update docs (no mention of call or syscall)
    numerator[7] = (op_flags_current.f_call() + op_flags_current.f_syscall()).into();

    // denominators
    let addr_next = query_next[DECODER_ADDR_COL_IDX];
    let h0_to_3 = &query_current[range(DECODER_HASHER_STATE_OFFSET, 4)];
    let h4_to_7 = &query_current[range(DECODER_HASHER_STATE_OFFSET + 4, 4)];
    let stack_1 = query_current[STACK_TRACE_OFFSET + STACK_TOP_OFFSET + 1];
    let stack_2 = query_current[STACK_TRACE_OFFSET + STACK_TOP_OFFSET + 2];
    let stack_3 = query_current[STACK_TRACE_OFFSET + STACK_TOP_OFFSET + 3];
    // TODO(plafer): update docs (this is h4 in docs)
    let f_is_loop_body = query_current[DECODER_IS_LOOP_BODY_FLAG_COL_IDX];
    let child1 = alphas[0] + alphas[1].mul_base(addr_next) + inner_product(&alphas[2..6], h0_to_3);
    let child2 = alphas[0] + alphas[1].mul_base(addr_next) + inner_product(&alphas[2..6], h4_to_7);

    let u_end = {
        // TODO(plafer): update docs (f_halt missing)
        let is_first_child =
            F::ONE - (op_flags_next.f_end() + op_flags_next.f_repeat() + op_flags_next.f_halt());

        // TODO(plafer): Double check addr_next; docs inconsistent with BlockHashTableRow
        alphas[0]
            + alphas[1].mul_base(addr_next)
            + inner_product(&alphas[2..6], h0_to_3)
            + alphas[6].mul_base(is_first_child)
            + alphas[7].mul_base(f_is_loop_body)
    };

    let v_join_1 = child1 + alphas[6];
    let v_join_2 = child2;
    let v_split = child1.mul_base(stack_0) + child2.mul_base(F::ONE - stack_0);
    let v_loop = child1 + alphas[7];
    let v_repeat = child1 + alphas[7];
    let v_dyn = alphas[0]
        + alphas[1].mul_base(addr_next)
        + inner_product(&alphas[2..6], &[stack_3, stack_2, stack_1, stack_0]);

    denominator[0] = -u_end;
    denominator[1] = v_join_1;
    denominator[2] = v_join_2;
    denominator[3] = v_split;
    denominator[4] = v_loop;
    denominator[5] = v_repeat;
    denominator[6] = v_dyn;
    denominator[7] = child1;
}

/// TODO(plafer): docs
fn padding<E>(numerator: &mut [E], denominator: &mut [E])
where
    E: FieldElement,
{
    numerator.fill(E::ZERO);
    denominator.fill(E::ONE);
}

// TODO(plafer): save intermediary values between flags instead of recomputing
struct LogUpOpFlags<F: FieldElement> {
    b0: F,
    b1: F,
    b2: F,
    b3: F,
    b4: F,
    b5: F,
    b6: F,
    e0: F,
    e1: F,
}

impl<F: FieldElement> LogUpOpFlags<F> {
    pub fn new(query: &[F]) -> Self {
        Self {
            b0: query[DECODER_OP_BITS_OFFSET],
            b1: query[DECODER_OP_BITS_OFFSET + 1],
            b2: query[DECODER_OP_BITS_OFFSET + 2],
            b3: query[DECODER_OP_BITS_OFFSET + 3],
            b4: query[DECODER_OP_BITS_OFFSET + 4],
            b5: query[DECODER_OP_BITS_OFFSET + 5],
            b6: query[DECODER_OP_BITS_OFFSET + 6],
            e0: query[DECODER_OP_BITS_EXTRA_COLS_OFFSET],
            e1: query[DECODER_OP_BITS_EXTRA_COLS_OFFSET + 1],
        }
    }

    pub fn op_value(&self) -> F {
        self.b0
            + F::from(2_u32) * self.b1
            + F::from(4_u32) * self.b2
            + F::from(8_u32) * self.b3
            + F::from(16_u32) * self.b4
            + F::from(32_u32) * self.b5
            + F::from(64_u32) * self.b6
    }

    pub fn f_push(&self) -> F {
        self.e0 * self.b3 * (F::ONE - self.b2) * self.b1 * self.b0
    }

    pub fn f_emit(&self) -> F {
        self.e0 * self.b3 * (F::ONE - self.b2) * self.b1 * (F::ONE - self.b0)
    }

    pub fn f_imm(&self) -> F {
        self.f_push() + self.f_emit()
    }

    pub fn f_range_check(&self) -> F {
        (F::ONE - self.b4) * (F::ONE - self.b5) * self.b6
    }

    pub fn f_join(&self) -> F {
        self.e0 * (F::ONE - self.b3) * self.b2 * self.b1 * self.b0
    }

    pub fn f_split(&self) -> F {
        self.e0 * (F::ONE - self.b3) * self.b2 * (F::ONE - self.b1) * (F::ONE - self.b0)
    }

    pub fn f_loop(&self) -> F {
        self.e0 * (F::ONE - self.b3) * self.b2 * (F::ONE - self.b1) * self.b0
    }

    pub fn f_dyn(&self) -> F {
        self.e0 * self.b3 * (F::ONE - self.b2) * (F::ONE - self.b1) * (F::ONE - self.b0)
    }

    pub fn f_repeat(&self) -> F {
        self.e1 * self.b4 * (F::ONE - self.b3) * self.b2
    }

    pub fn f_end(&self) -> F {
        self.e1 * self.b4 * (F::ONE - self.b3) * (F::ONE - self.b2)
    }

    pub fn f_syscall(&self) -> F {
        self.e1 * (F::ONE - self.b4) * self.b3 * (F::ONE - self.b2)
    }

    pub fn f_call(&self) -> F {
        self.e1 * (F::ONE - self.b4) * self.b3 * self.b2
    }

    pub fn f_halt(&self) -> F {
        self.e1 * self.b4 * self.b3 * self.b2
    }
}

// HELPERS
// -----------------------------------------------------------------------------------------------

fn inner_product<F, E>(alphas: &[E], eles: &[F]) -> E
where
    F: FieldElement,
    E: FieldElement + ExtensionOf<F>,
{
    alphas
        .iter()
        .zip(eles.iter())
        .fold(E::ZERO, |acc, (alpha, ele)| acc + alpha.mul_base(*ele))
}

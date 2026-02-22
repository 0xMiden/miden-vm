//! Memory chiplet constraints.
//!
//! The memory chiplet provides linear read-write random access memory.
//! Memory is element-addressable with addresses in range [0, 2^32).
//!
//! ## Column Layout (within chiplet, offset by selectors)
//!
//! | Column    | Purpose                                        |
//! |-----------|------------------------------------------------|
//! | is_read   | Read/write selector: 1=read, 0=write           |
//! | is_word   | Element/word access: 0=element, 1=word         |
//! | ctx       | Context ID                                     |
//! | word_addr | Word address                                   |
//! | idx0, idx1 | Element index bits (0-3)                      |
//! | clk       | Clock cycle of operation                       |
//! | v0-v3     | Memory word values                             |
//! | d0, d1    | Delta tracking columns                         |
//! | d_inv     | Delta inverse                                  |
//! | f_scw     | Same context/word flag                         |
//!
//! ## Address range checks (TODO)
//!
//! The trace stores a word address plus idx bits, i.e. `addr = 4 * w_addr + idx`.
//! To fully range-check addresses, we plan to commit to 16-bit limbs of `w_addr`
//! (w0, w1) and enforce:
//!   addr = 4 * (w0 + 2^16 * w1) + idx0 + 2 * idx1.
//! Range checks should include `w0`, `w1`, and `4 * w1`; the extra term
//! prevents wraparound, and Goldilocks satisfies P > 2^18 so this is sound.

use core::ops::{Add, Mul, Sub};

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::selectors::memory_chiplet_flag;
use crate::{
    Felt, MainTraceRow,
    constraints::tagging::{TagGroup, TaggingAirBuilderExt, tagged_assert_zero_integrity},
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            MEMORY_CLK_COL_IDX, MEMORY_CTX_COL_IDX, MEMORY_D_INV_COL_IDX, MEMORY_D0_COL_IDX,
            MEMORY_D1_COL_IDX, MEMORY_FLAG_SAME_CONTEXT_AND_WORD, MEMORY_IDX0_COL_IDX,
            MEMORY_IDX1_COL_IDX, MEMORY_IS_READ_COL_IDX, MEMORY_IS_WORD_ACCESS_COL_IDX,
            MEMORY_V_COL_RANGE, MEMORY_WORD_COL_IDX,
        },
    },
};

// TAGGING IDS
// ================================================================================================

pub(super) const MEMORY_BASE_ID: usize =
    super::bitwise::BITWISE_BASE_ID + super::bitwise::BITWISE_COUNT;
pub(super) const MEMORY_COUNT: usize = 21;
const MEMORY_BINARY_BASE_ID: usize = MEMORY_BASE_ID;
const MEMORY_WORD_IDX_BASE_ID: usize = MEMORY_BASE_ID + 4;
const MEMORY_FIRST_ROW_BASE_ID: usize = MEMORY_BASE_ID + 6;
const MEMORY_DELTA_INV_BASE_ID: usize = MEMORY_BASE_ID + 10;
const MEMORY_DELTA_TRANSITION_ID: usize = MEMORY_BASE_ID + 14;
const MEMORY_SCW_FLAG_ID: usize = MEMORY_BASE_ID + 15;
const MEMORY_SCW_READS_ID: usize = MEMORY_BASE_ID + 16;
const MEMORY_VALUE_CONSIST_BASE_ID: usize = MEMORY_BASE_ID + 17;

const MEMORY_BINARY_NAMESPACE: &str = "chiplets.memory.binary";
const MEMORY_WORD_IDX_NAMESPACE: &str = "chiplets.memory.word_idx.zero";
const MEMORY_FIRST_ROW_NAMESPACE: &str = "chiplets.memory.first_row.zero";
const MEMORY_DELTA_INV_NAMESPACE: &str = "chiplets.memory.delta.inv";
const MEMORY_DELTA_TRANSITION_NAMESPACE: &str = "chiplets.memory.delta.transition";
const MEMORY_SCW_FLAG_NAMESPACE: &str = "chiplets.memory.scw.flag";
const MEMORY_SCW_READS_NAMESPACE: &str = "chiplets.memory.scw.reads";
const MEMORY_VALUE_CONSIST_NAMESPACE: &str = "chiplets.memory.value.consistency";

const MEMORY_BINARY_NAMES: [&str; 4] = [MEMORY_BINARY_NAMESPACE; 4];
const MEMORY_WORD_IDX_NAMES: [&str; 2] = [MEMORY_WORD_IDX_NAMESPACE; 2];
const MEMORY_FIRST_ROW_NAMES: [&str; 4] = [MEMORY_FIRST_ROW_NAMESPACE; 4];
const MEMORY_DELTA_INV_NAMES: [&str; 4] = [MEMORY_DELTA_INV_NAMESPACE; 4];
const MEMORY_DELTA_TRANSITION_NAMES: [&str; 1] = [MEMORY_DELTA_TRANSITION_NAMESPACE; 1];
const MEMORY_SCW_FLAG_NAMES: [&str; 1] = [MEMORY_SCW_FLAG_NAMESPACE; 1];
const MEMORY_SCW_READS_NAMES: [&str; 1] = [MEMORY_SCW_READS_NAMESPACE; 1];
const MEMORY_VALUE_CONSIST_NAMES: [&str; 4] = [MEMORY_VALUE_CONSIST_NAMESPACE; 4];

const MEMORY_BINARY_TAGS: TagGroup = TagGroup {
    base: MEMORY_BINARY_BASE_ID,
    names: &MEMORY_BINARY_NAMES,
};
const MEMORY_WORD_IDX_TAGS: TagGroup = TagGroup {
    base: MEMORY_WORD_IDX_BASE_ID,
    names: &MEMORY_WORD_IDX_NAMES,
};
const MEMORY_FIRST_ROW_TAGS: TagGroup = TagGroup {
    base: MEMORY_FIRST_ROW_BASE_ID,
    names: &MEMORY_FIRST_ROW_NAMES,
};
const MEMORY_DELTA_INV_TAGS: TagGroup = TagGroup {
    base: MEMORY_DELTA_INV_BASE_ID,
    names: &MEMORY_DELTA_INV_NAMES,
};
const MEMORY_DELTA_TRANSITION_TAGS: TagGroup = TagGroup {
    base: MEMORY_DELTA_TRANSITION_ID,
    names: &MEMORY_DELTA_TRANSITION_NAMES,
};
const MEMORY_SCW_FLAG_TAGS: TagGroup = TagGroup {
    base: MEMORY_SCW_FLAG_ID,
    names: &MEMORY_SCW_FLAG_NAMES,
};
const MEMORY_SCW_READS_TAGS: TagGroup = TagGroup {
    base: MEMORY_SCW_READS_ID,
    names: &MEMORY_SCW_READS_NAMES,
};
const MEMORY_VALUE_CONSIST_TAGS: TagGroup = TagGroup {
    base: MEMORY_VALUE_CONSIST_BASE_ID,
    names: &MEMORY_VALUE_CONSIST_NAMES,
};

// ENTRY POINTS
// ================================================================================================

/// Enforce all memory chiplet constraints.
pub fn enforce_memory_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s1_next: AB::Expr = next.chiplets[1].clone().into();
    let s2_next: AB::Expr = next.chiplets[2].clone().into();

    let is_transition: AB::Expr = builder.is_transition();

    enforce_memory_constraints_all_rows(builder, local, next);

    let flag_next_row_first_memory = is_transition.clone()
        * flag_next_row_first_memory(s0.clone(), s1.clone(), s1_next, s2_next.clone());
    enforce_memory_constraints_first_row(builder, local, next, flag_next_row_first_memory);

    let flag_memory_active_not_last =
        is_transition * flag_memory_active_not_last_row(s0, s1, s2_next);
    enforce_memory_constraints_all_rows_except_last(
        builder,
        local,
        next,
        flag_memory_active_not_last,
    );
}

/// Enforce memory chiplet constraints that apply to all rows.
///
/// This enforces:
/// - Binary constraints for selectors and indices
pub fn enforce_memory_constraints_all_rows<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    _next: &MainTraceRow<AB::Var>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Compute memory active flag from top-level selectors
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let memory_flag = memory_chiplet_flag(s0, s1, s2);

    // Load memory columns using typed struct
    let cols: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(local);

    let one: AB::Expr = AB::Expr::ONE;

    // Binary constraints
    let gate = memory_flag.clone();
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_BINARY_TAGS,
        &mut idx,
        gate.clone() * cols.is_read.clone() * (cols.is_read.clone() - one.clone()),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_BINARY_TAGS,
        &mut idx,
        gate.clone() * cols.is_word.clone() * (cols.is_word.clone() - one.clone()),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_BINARY_TAGS,
        &mut idx,
        gate.clone() * cols.idx0.clone() * (cols.idx0.clone() - one.clone()),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_BINARY_TAGS,
        &mut idx,
        gate * cols.idx1.clone() * (cols.idx1.clone() - one),
    );

    // For word access, idx bits must be zero (only element accesses use idx0/idx1).
    let word_gate = memory_flag.clone() * cols.is_word.clone();
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_WORD_IDX_TAGS,
        &mut idx,
        word_gate.clone() * cols.idx0.clone(),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_WORD_IDX_TAGS,
        &mut idx,
        word_gate * cols.idx1.clone(),
    );
}

/// Enforce memory first row initialization constraints.
///
/// When entering the memory chiplet, unwritten values must be 0.
pub fn enforce_memory_constraints_first_row<AB>(
    builder: &mut AB,
    _local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flag_next_row_first_memory: AB::Expr,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Load next row columns using typed struct
    let cols_next: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(next);

    let one: AB::Expr = AB::Expr::ONE;

    // Element selection flags
    let f0 = (one.clone() - cols_next.idx1.clone()) * (one.clone() - cols_next.idx0.clone());
    let f1 = (one.clone() - cols_next.idx1.clone()) * cols_next.idx0.clone();
    let f2 = cols_next.idx1.clone() * (one.clone() - cols_next.idx0.clone());
    let f3 = cols_next.idx1.clone() * cols_next.idx0.clone();

    // c_i = 1 when v'[i] needs to be constrained (not written to)
    let c0 = compute_c_i(f0, cols_next.is_read.clone(), cols_next.is_word.clone());
    let c1 = compute_c_i(f1, cols_next.is_read.clone(), cols_next.is_word.clone());
    let c2 = compute_c_i(f2, cols_next.is_read.clone(), cols_next.is_word.clone());
    let c3 = compute_c_i(f3, cols_next.is_read.clone(), cols_next.is_word.clone());

    // First row: if v'[i] is not written to, then v'[i] = 0
    let gate = flag_next_row_first_memory;
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_FIRST_ROW_TAGS,
        &mut idx,
        gate.clone() * c0 * cols_next.values[0].clone(),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_FIRST_ROW_TAGS,
        &mut idx,
        gate.clone() * c1 * cols_next.values[1].clone(),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_FIRST_ROW_TAGS,
        &mut idx,
        gate.clone() * c2 * cols_next.values[2].clone(),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_FIRST_ROW_TAGS,
        &mut idx,
        gate * c3 * cols_next.values[3].clone(),
    );
}

/// Enforce memory transition constraints (all rows except last).
///
/// This enforces:
/// - Delta inverse constraints
/// - Context/address/clock delta constraints
/// - Same context/word flag constraints
/// - Value consistency constraints
pub fn enforce_memory_constraints_all_rows_except_last<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flag_memory_active_not_last: AB::Expr,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Load columns using typed struct
    let cols: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(local);
    let cols_next: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(next);

    let one: AB::Expr = AB::Expr::ONE;
    let two_pow_16: AB::Expr = AB::Expr::from_u32(1 << 16);

    let deltas = MemoryDeltas::new(&cols, &cols_next, one.clone(), two_pow_16);

    // ==========================================================================
    // DELTA INVERSE CONSTRAINTS
    // ==========================================================================
    enforce_delta_inverse_constraints::<AB>(
        builder,
        flag_memory_active_not_last.clone(),
        &deltas,
        one.clone(),
    );

    // ==========================================================================
    // DELTA CONSTRAINTS (monotonicity)
    // ==========================================================================
    enforce_delta_transition_constraint::<AB>(
        builder,
        flag_memory_active_not_last.clone(),
        &deltas,
    );

    // ==========================================================================
    // SAME CONTEXT/WORD FLAG
    // ==========================================================================
    enforce_scw_flag_constraint::<AB>(
        builder,
        flag_memory_active_not_last.clone(),
        &cols_next,
        &deltas,
        one.clone(),
    );

    // ==========================================================================
    // SAME CONTEXT/WORD READ-ONLY CONSTRAINTS
    // ==========================================================================
    enforce_scw_readonly_constraint::<AB>(
        builder,
        flag_memory_active_not_last.clone(),
        &cols,
        &cols_next,
        &deltas,
        one.clone(),
    );

    // ==========================================================================
    // VALUE CONSISTENCY
    // ==========================================================================

    // Element selection flags
    let f0 = (one.clone() - cols_next.idx1.clone()) * (one.clone() - cols_next.idx0.clone());
    let f1 = (one.clone() - cols_next.idx1.clone()) * cols_next.idx0.clone();
    let f2 = cols_next.idx1.clone() * (one.clone() - cols_next.idx0.clone());
    let f3 = cols_next.idx1.clone() * cols_next.idx0.clone();

    // c_i = 1 when v'[i] needs to be constrained
    let c0 = compute_c_i(f0, cols_next.is_read.clone(), cols_next.is_word.clone());
    let c1 = compute_c_i(f1, cols_next.is_read.clone(), cols_next.is_word.clone());
    let c2 = compute_c_i(f2, cols_next.is_read.clone(), cols_next.is_word.clone());
    let c3 = compute_c_i(f3, cols_next.is_read.clone(), cols_next.is_word.clone());

    // When v'[i] is not written to:
    // - if f_scw' = 1: v'[i] = v[i] (copy from previous)
    // - if f_scw' = 0: v'[i] = 0 (initialize to zero)
    // Combined: f_scw' * (v'[i] - v[i]) + !f_scw' * v'[i] = 0
    let constrain_value = |c: AB::Expr, v: AB::Expr, v_next: AB::Expr| {
        flag_memory_active_not_last.clone()
            * c
            * (cols_next.flag_same_ctx_word.clone() * (v_next.clone() - v)
                + (one.clone() - cols_next.flag_same_ctx_word.clone()) * v_next)
    };

    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_VALUE_CONSIST_TAGS,
        &mut idx,
        constrain_value(c0, cols.values[0].clone(), cols_next.values[0].clone()),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_VALUE_CONSIST_TAGS,
        &mut idx,
        constrain_value(c1, cols.values[1].clone(), cols_next.values[1].clone()),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_VALUE_CONSIST_TAGS,
        &mut idx,
        constrain_value(c2, cols.values[2].clone(), cols_next.values[2].clone()),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_VALUE_CONSIST_TAGS,
        &mut idx,
        constrain_value(c3, cols.values[3].clone(), cols_next.values[3].clone()),
    );
}

// INTERNAL HELPERS
// ================================================================================================

/// Derived delta values for memory transitions.
///
/// These capture the deltas, selection flags, and the computed monotonicity term
/// used across multiple constraint groups.
struct MemoryDeltas<E> {
    ctx_delta: E,
    addr_delta: E,
    clk_delta: E,
    n0: E,
    n1: E,
    delta_next: E,
    computed_delta: E,
}

impl<E> MemoryDeltas<E>
where
    E: Clone + Add<Output = E> + Sub<Output = E> + Mul<Output = E>,
{
    fn new(cols: &MemoryColumns<E>, cols_next: &MemoryColumns<E>, one: E, two_pow_16: E) -> Self {
        let ctx_delta = cols_next.ctx.clone() - cols.ctx.clone();
        let addr_delta = cols_next.word_addr.clone() - cols.word_addr.clone();
        let clk_delta = cols_next.clk.clone() - cols.clk.clone();

        // n0 = ctx_delta * d_inv'
        // n1 = addr_delta * d_inv'
        let n0 = ctx_delta.clone() * cols_next.d_inv.clone();
        let n1 = addr_delta.clone() * cols_next.d_inv.clone();

        // delta_next = d1' * 2^16 + d0'
        let delta_next = cols_next.d1.clone() * two_pow_16 + cols_next.d0.clone();

        // n0 * ctx_delta + !n0 * (n1 * addr_delta + !n1 * clk_delta) = delta_next
        let computed_delta = n0.clone() * ctx_delta.clone()
            + (one.clone() - n0.clone())
                * (n1.clone() * addr_delta.clone() + (one - n1.clone()) * clk_delta.clone());

        Self {
            ctx_delta,
            addr_delta,
            clk_delta,
            n0,
            n1,
            delta_next,
            computed_delta,
        }
    }
}

/// Typed access to memory chiplet columns.
///
/// This struct provides named access to memory columns, eliminating error-prone
/// index arithmetic. Created from a `MainTraceRow` reference.
pub struct MemoryColumns<E> {
    /// Read/write selector: 1=read, 0=write
    pub is_read: E,
    /// Element/word access: 0=element, 1=word
    pub is_word: E,
    /// Context ID
    pub ctx: E,
    /// Word address
    pub word_addr: E,
    /// First bit of element index
    pub idx0: E,
    /// Second bit of element index
    pub idx1: E,
    /// Clock cycle
    pub clk: E,
    /// Memory word values (4 elements)
    pub values: [E; 4],
    /// Delta low 16 bits
    pub d0: E,
    /// Delta high 16 bits
    pub d1: E,
    /// Delta inverse
    pub d_inv: E,
    /// Same context/word flag
    pub flag_same_ctx_word: E,
}

impl<E: Clone> MemoryColumns<E> {
    /// Extract memory columns from a main trace row.
    pub fn from_row<AB>(row: &MainTraceRow<AB::Var>) -> Self
    where
        AB: MidenAirBuilder<F = Felt>,
        AB::Var: Into<E> + Clone,
    {
        let load = |global_idx: usize| {
            let local_idx = global_idx - CHIPLETS_OFFSET;
            row.chiplets[local_idx].clone().into()
        };

        MemoryColumns {
            is_read: load(MEMORY_IS_READ_COL_IDX),
            is_word: load(MEMORY_IS_WORD_ACCESS_COL_IDX),
            ctx: load(MEMORY_CTX_COL_IDX),
            word_addr: load(MEMORY_WORD_COL_IDX),
            idx0: load(MEMORY_IDX0_COL_IDX),
            idx1: load(MEMORY_IDX1_COL_IDX),
            clk: load(MEMORY_CLK_COL_IDX),
            values: core::array::from_fn(|i| load(MEMORY_V_COL_RANGE.start + i)),
            d0: load(MEMORY_D0_COL_IDX),
            d1: load(MEMORY_D1_COL_IDX),
            d_inv: load(MEMORY_D_INV_COL_IDX),
            flag_same_ctx_word: load(MEMORY_FLAG_SAME_CONTEXT_AND_WORD),
        }
    }
}

/// Compute c_i: 1 if v'[i] needs to be constrained (not written to), 0 otherwise.
///
/// c_i = is_read' + !is_read' * z_i
/// where z_i = !is_word' * !f_i (element access and not this element)
fn compute_c_i<E: PrimeCharacteristicRing>(f_i: E, is_read_next: E, is_word_next: E) -> E {
    let z_i = (E::ONE - is_word_next) * (E::ONE - f_i);
    is_read_next.clone() + (E::ONE - is_read_next) * z_i
}

/// Enforce delta inverse constraints for ctx/addr/clk monotonicity.
fn enforce_delta_inverse_constraints<AB>(
    builder: &mut AB,
    flag_memory_active_not_last: AB::Expr,
    deltas: &MemoryDeltas<AB::Expr>,
    one: AB::Expr,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let n0 = deltas.n0.clone();
    let n1 = deltas.n1.clone();
    let ctx_delta = deltas.ctx_delta.clone();
    let addr_delta = deltas.addr_delta.clone();

    let gate = flag_memory_active_not_last;
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_INV_TAGS,
        &mut idx,
        gate.clone() * n0.clone() * (n0.clone() - one.clone()),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_INV_TAGS,
        &mut idx,
        gate.clone() * (one.clone() - n0.clone()) * ctx_delta.clone(),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_INV_TAGS,
        &mut idx,
        gate.clone() * (one.clone() - n0.clone()) * n1.clone() * (n1.clone() - one.clone()),
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_INV_TAGS,
        &mut idx,
        gate * (one.clone() - n0.clone()) * (one.clone() - n1.clone()) * addr_delta.clone(),
    );
}

/// Enforce the combined delta transition constraint.
fn enforce_delta_transition_constraint<AB>(
    builder: &mut AB,
    flag_memory_active_not_last: AB::Expr,
    deltas: &MemoryDeltas<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_TRANSITION_TAGS,
        &mut idx,
        flag_memory_active_not_last * (deltas.computed_delta.clone() - deltas.delta_next.clone()),
    );
}

/// Enforce f_scw' = !n0 * !n1 for same context/word transitions.
fn enforce_scw_flag_constraint<AB>(
    builder: &mut AB,
    flag_memory_active_not_last: AB::Expr,
    cols_next: &MemoryColumns<AB::Expr>,
    deltas: &MemoryDeltas<AB::Expr>,
    one: AB::Expr,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_SCW_FLAG_TAGS,
        &mut idx,
        flag_memory_active_not_last
            * (cols_next.flag_same_ctx_word.clone()
                - (one.clone() - deltas.n0.clone()) * (one - deltas.n1.clone())),
    );
}

/// Enforce read-only access when context and word address are unchanged.
fn enforce_scw_readonly_constraint<AB>(
    builder: &mut AB,
    flag_memory_active_not_last: AB::Expr,
    cols: &MemoryColumns<AB::Expr>,
    cols_next: &MemoryColumns<AB::Expr>,
    deltas: &MemoryDeltas<AB::Expr>,
    one: AB::Expr,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // If ctx/word are unchanged and clk_delta = 0, both rows must be reads.
    // Constraint: f_scw' * (1 - clk_delta * d_inv') * ((1 - is_read) + (1 - is_read')) = 0
    let clk_no_change = one.clone() - deltas.clk_delta.clone() * cols_next.d_inv.clone();
    let read_required =
        (one.clone() - cols.is_read.clone()) + (one.clone() - cols_next.is_read.clone());
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_SCW_READS_TAGS,
        &mut idx,
        flag_memory_active_not_last
            * cols_next.flag_same_ctx_word.clone()
            * clk_no_change
            * read_required,
    );
}

/// Memory chiplet flag for current row active and continuing to next row.
pub fn flag_memory_active_not_last_row<E: PrimeCharacteristicRing>(s0: E, s1: E, s2_next: E) -> E {
    // Memory active when s0 = s1 = 1 and not transitioning out (s2' = 0)
    s0 * s1 * (E::ONE - s2_next)
}

/// Flag for transitioning into memory chiplet (first row of memory).
pub fn flag_next_row_first_memory<E: PrimeCharacteristicRing>(
    s0: E,
    s1: E,
    s1_next: E,
    s2_next: E,
) -> E {
    // Current row is bitwise (!s1), next row is memory (s1' & !s2')
    (E::ONE - s1) * s0.clone() * s1_next * (E::ONE - s2_next)
}

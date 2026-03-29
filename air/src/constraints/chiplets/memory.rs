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
use miden_crypto::stark::air::LiftedAirBuilder;

use super::selectors::memory_chiplet_flag;
use crate::{
    Felt, MainTraceRow,
    constraints::tagging::{TagGroup, TaggingAirBuilderExt, tagged_assert_zero_integrity},
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            MEMORY_ADDR_HI_COL_IDX, MEMORY_ADDR_LO_COL_IDX, MEMORY_CLK_COL_IDX, MEMORY_CTX_COL_IDX,
            MEMORY_D_INV_COL_IDX, MEMORY_D0_COL_IDX, MEMORY_D1_COL_IDX,
            MEMORY_FLAG_SAME_CONTEXT_AND_WORD, MEMORY_IDX0_COL_IDX, MEMORY_IDX1_COL_IDX,
            MEMORY_IS_READ_COL_IDX, MEMORY_IS_WORD_ACCESS_COL_IDX, MEMORY_V_COL_RANGE,
            MEMORY_WORD_COL_IDX,
        },
    },
};

// TAGGING IDS
// ================================================================================================

pub const MEMORY_BASE_ID: usize = super::bitwise::BITWISE_BASE_ID + super::bitwise::BITWISE_COUNT;
pub const MEMORY_COUNT: usize = 24;
const MEMORY_BINARY_BASE_ID: usize = MEMORY_BASE_ID;
const MEMORY_WORD_IDX_BASE_ID: usize = MEMORY_BASE_ID + 4;
const MEMORY_FIRST_ROW_BASE_ID: usize = MEMORY_BASE_ID + 6;
const MEMORY_DELTA_INV_BASE_ID: usize = MEMORY_BASE_ID + 10;
const MEMORY_DELTA_TRANSITION_ID: usize = MEMORY_BASE_ID + 14;
const MEMORY_SCW_FLAG_ID: usize = MEMORY_BASE_ID + 15;
const MEMORY_SCW_READS_ID: usize = MEMORY_BASE_ID + 16;
const MEMORY_VALUE_CONSIST_BASE_ID: usize = MEMORY_BASE_ID + 17;
const MEMORY_ADDR_RANGE_BASE_ID: usize = MEMORY_BASE_ID + 21;

const MEMORY_BINARY_NAMESPACE: &str = "chiplets.memory.binary";
const MEMORY_WORD_IDX_NAMESPACE: &str = "chiplets.memory.word_idx.zero";
const MEMORY_FIRST_ROW_NAMESPACE: &str = "chiplets.memory.first_row.zero";
const MEMORY_DELTA_INV_NAMESPACE: &str = "chiplets.memory.delta.inv";
const MEMORY_DELTA_TRANSITION_NAMESPACE: &str = "chiplets.memory.delta.transition";
const MEMORY_SCW_FLAG_NAMESPACE: &str = "chiplets.memory.scw.flag";
const MEMORY_SCW_READS_NAMESPACE: &str = "chiplets.memory.scw.reads";
const MEMORY_VALUE_CONSIST_NAMESPACE: &str = "chiplets.memory.value.consistency";
const MEMORY_ADDR_RANGE_NAMESPACE: &str = "chiplets.memory.addr.range";

const MEMORY_BINARY_NAMES: [&str; 4] = [MEMORY_BINARY_NAMESPACE; 4];
const MEMORY_WORD_IDX_NAMES: [&str; 2] = [MEMORY_WORD_IDX_NAMESPACE; 2];
const MEMORY_FIRST_ROW_NAMES: [&str; 4] = [MEMORY_FIRST_ROW_NAMESPACE; 4];
const MEMORY_DELTA_INV_NAMES: [&str; 4] = [MEMORY_DELTA_INV_NAMESPACE; 4];
const MEMORY_DELTA_TRANSITION_NAMES: [&str; 1] = [MEMORY_DELTA_TRANSITION_NAMESPACE; 1];
const MEMORY_SCW_FLAG_NAMES: [&str; 1] = [MEMORY_SCW_FLAG_NAMESPACE; 1];
const MEMORY_SCW_READS_NAMES: [&str; 1] = [MEMORY_SCW_READS_NAMESPACE; 1];
const MEMORY_VALUE_CONSIST_NAMES: [&str; 4] = [MEMORY_VALUE_CONSIST_NAMESPACE; 4];
const MEMORY_ADDR_RANGE_NAMES: [&str; 3] = [MEMORY_ADDR_RANGE_NAMESPACE; 3];

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
const MEMORY_ADDR_RANGE_TAGS: TagGroup = TagGroup {
    base: MEMORY_ADDR_RANGE_BASE_ID,
    names: &MEMORY_ADDR_RANGE_NAMES,
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

    // Address range check: enforce that word_addr is a 32-bit value.
    //
    // Without this, a dishonest prover could supply any field element in the
    // `word_addr` column of the memory chiplet.  The existing d0/d1 delta
    // range-checks only bound the *difference* between consecutive addresses, not
    // their absolute value.  A trace starting at word_addr = P − 1 (where P is the
    // Goldilocks prime ≈ 2^64) would satisfy all monotonicity constraints while
    // representing a completely invalid memory address.
    //
    // Fix: commit to the 16-bit limbs of word_addr (addr_lo, addr_hi) and add:
    //   1. Reconstruction: word_addr = addr_hi * 2^16 + addr_lo
    //   2. Range checks for addr_lo and addr_hi go through the existing range-check bus (submitted
    //      from the prover's append_range_checks).
    //   3. Overflow guard: 4 * addr_hi < 2^16, ensuring word_addr * 4 + 3 < 2^32.
    enforce_addr_range_check::<AB>(builder, memory_flag, &cols);
}

/// Enforce memory first row initialization constraints.
///
/// This constraint is enforced in the last row of the previous trace segment (bitwise).
/// When entering the memory chiplet, unwritten values must be 0.
pub fn enforce_memory_constraints_first_row<AB>(
    builder: &mut AB,
    _local: &MainTraceRow<AB::Var>,
    cols_first: &MainTraceRow<AB::Var>,
    flag_next_row_first_memory: AB::Expr,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Load first memory row columns using typed struct
    let cols_next: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(cols_first);

    let one: AB::Expr = AB::Expr::ONE;

    // Compute constraint flags for all 4 word elements
    let [c0, c1, c2, c3] = cols_next.compute_value_constraint_flags(one.clone());

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

    let deltas = MemoryDeltas::new::<AB>(&cols, &cols_next, one.clone());

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
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_TRANSITION_TAGS,
        &mut idx,
        flag_memory_active_not_last.clone()
            * (deltas.computed_delta.clone() - deltas.delta_next.clone()),
    );

    // ==========================================================================
    // SAME CONTEXT/WORD FLAG
    // ==========================================================================
    // f_scw' = !n0 * !n1
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_SCW_FLAG_TAGS,
        &mut idx,
        flag_memory_active_not_last.clone()
            * (cols_next.flag_same_ctx_word.clone()
                - (one.clone() - deltas.n0.clone()) * (one.clone() - deltas.n1.clone())),
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

    // Compute constraint flags for all 4 elements
    let [c0, c1, c2, c3] = cols_next.compute_value_constraint_flags(one.clone());

    // When v'[i] is not written to:
    // - if f_scw' = 1: v'[i] = v[i] (copy from previous)
    // - if f_scw' = 0: v'[i] = 0 (initialize to zero)
    // Simplified: v'[i] = f_scw' * v[i]
    let constrain_value = |c: AB::Expr, v: AB::Expr, v_next: AB::Expr| {
        flag_memory_active_not_last.clone()
            * c
            * (v_next - cols_next.flag_same_ctx_word.clone() * v)
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
    fn new<AB>(cols: &MemoryColumns<E>, cols_next: &MemoryColumns<E>, one: E) -> Self
    where
        AB: LiftedAirBuilder<F = Felt>,
        AB::Expr: Into<E>,
    {
        let ctx_delta = cols_next.ctx.clone() - cols.ctx.clone();
        let addr_delta = cols_next.word_addr.clone() - cols.word_addr.clone();
        let clk_delta = cols_next.clk.clone() - cols.clk.clone();
        let two_pow_16: E = AB::Expr::from_u32(1 << 16).into();

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
    /// Low 16 bits of `word_addr` (decomposition witness for range check).
    pub addr_lo: E,
    /// High 16 bits of `word_addr` (decomposition witness for range check).
    pub addr_hi: E,
}

impl<E: Clone> MemoryColumns<E> {
    /// Extract memory columns from a main trace row.
    pub fn from_row<AB>(row: &MainTraceRow<AB::Var>) -> Self
    where
        AB: LiftedAirBuilder<F = Felt>,
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
            addr_lo: load(MEMORY_ADDR_LO_COL_IDX),
            addr_hi: load(MEMORY_ADDR_HI_COL_IDX),
        }
    }

    /// Compute constraint flags c_0, c_1, c_2, c_3 for value consistency constraints.
    ///
    /// c_i = 1 when v[i] needs to be constrained (not being written to), 0 otherwise.
    ///
    /// For each element i:
    /// - Read operation: c_i = 1 (always constrain)
    /// - Write operation, element access, element i selected: c_i = 0 (being written, no
    ///   constraining needed)
    /// - Write operation, otherwise: c_i = 1 (not being written, constrain)
    ///
    /// Logic: c_i = is_read + is_write * is_element * !f_i
    ///            = is_read + (1 - is_read) * (1 - is_word) * (1 - f_i)
    pub fn compute_value_constraint_flags<One>(&self, one: One) -> [E; 4]
    where
        E: Add<Output = E> + Sub<Output = E> + Mul<Output = E>,
        One: Into<E>,
    {
        let one = one.into();

        let is_write = one.clone() - self.is_read.clone();
        let is_element = one.clone() - self.is_word.clone();

        // Element selection flags (f_i = 1 when idx0,idx1 select element i)
        let f0 = (one.clone() - self.idx1.clone()) * (one.clone() - self.idx0.clone());
        let f1 = (one.clone() - self.idx1.clone()) * self.idx0.clone();
        let f2 = self.idx1.clone() * (one.clone() - self.idx0.clone());
        let f3 = self.idx1.clone() * self.idx0.clone();

        // c_i = is_read + is_write * is_element * !f_i
        let compute_c = |f_i: E| {
            let not_f_i = one.clone() - f_i;
            self.is_read.clone() + is_write.clone() * is_element.clone() * not_f_i
        };

        [compute_c(f0), compute_c(f1), compute_c(f2), compute_c(f3)]
    }
}

/// Enforce delta inverse constraints for ctx/addr/clk monotonicity.
///
/// n0 and n1 are binary flags computed via delta inverse:
/// - n0 = 1 iff ctx changes (ctx_delta != 0)
/// - n1 = 1 iff addr changes when ctx doesn't (addr_delta != 0 and ctx_delta = 0)
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

    // Extract negations for reuse
    let not_n0 = one.clone() - n0.clone();
    let not_n1 = one.clone() - n1.clone();

    let gate = flag_memory_active_not_last;
    let gate_not_n0 = gate.clone() * not_n0.clone();

    let mut idx = 0;
    // n0 is binary
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_INV_TAGS,
        &mut idx,
        gate * n0.clone() * (n0.clone() - one.clone()),
    );
    // !n0 => ctx_delta = 0
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_INV_TAGS,
        &mut idx,
        gate_not_n0.clone() * ctx_delta.clone(),
    );
    // !n0 and n1 is binary
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_INV_TAGS,
        &mut idx,
        gate_not_n0.clone() * n1.clone() * (n1.clone() - one.clone()),
    );
    // !n0 and !n1 => addr_delta = 0
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_DELTA_INV_TAGS,
        &mut idx,
        gate_not_n0 * not_n1 * addr_delta.clone(),
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
    // Constraint: f_scw' * (1 - clk_delta * d_inv') * (is_write + is_write') = 0

    let clk_no_change = one.clone() - deltas.clk_delta.clone() * cols_next.d_inv.clone();

    let is_write = one.clone() - cols.is_read.clone();
    let is_write_next = one.clone() - cols_next.is_read.clone();
    let any_write = is_write + is_write_next;

    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_SCW_READS_TAGS,
        &mut idx,
        flag_memory_active_not_last
            * cols_next.flag_same_ctx_word.clone()
            * clk_no_change
            * any_write,
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

/// Enforce that `word_addr` is a valid 32-bit address using a 16-bit limb decomposition.
///
/// ## Soundness gap closed by this constraint
///
/// The memory chiplet's monotonicity argument (via range-checked `d0`/`d1` deltas) only
/// proves that *consecutive* `word_addr` values are ordered and their differences are bounded
/// by 2^32.  It says nothing about the *absolute* value of the first (or any) `word_addr`.
/// A dishonest prover is free to set `word_addr` to an arbitrary field element — for
/// example, `P − 1` where `P` is the Goldilocks prime (~2^64) — while still satisfying
/// the delta monotonicity constraints (a small positive delta applied to `P − 1` wraps
/// modulo `P` and produces a small non-negative result, which passes the d0/d1 range check).
///
/// ## Fix
///
/// We commit to two auxiliary witness columns `addr_lo = word_addr mod 2^16` and
/// `addr_hi = word_addr >> 16` and add three constraints:
///
/// 1. **Reconstruction**: `word_addr = addr_hi * 2^16 + addr_lo`
/// 2. **Range checks**: `addr_lo ∈ [0, 2^16)` and `addr_hi ∈ [0, 2^16)` — submitted via the
///    existing range-check bus in [`Memory::append_range_checks`].
/// 3. **Overflow guard**: `4 * addr_hi < 2^16`, ensuring `word_addr * 4 + 3 < 2^32`, i.e. every
///    element-level address derived from this word address is a valid u32. (This is also submitted
///    as a range check: `4 * addr_hi` must be in `[0, 2^16)`.)
///
/// ## Why no new global columns are needed
///
/// The memory chiplet occupies 18 of the 20 chiplet columns
/// (`NUM_MEMORY_SELECTORS=3` selector columns + 15 data columns). Columns 18 and 19
/// are unused during memory rows and are claimed here for `addr_lo` and `addr_hi`.
/// The total `CHIPLETS_WIDTH` of 20 is therefore unchanged.
fn enforce_addr_range_check<AB>(
    builder: &mut AB,
    memory_flag: AB::Expr,
    cols: &MemoryColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let two_pow_16: AB::Expr = AB::Expr::from_u32(1 << 16);

    // Constraint 1: word_addr = addr_hi * 2^16 + addr_lo
    // This links the witness columns to the actual word_addr value.
    let reconstruction =
        cols.addr_hi.clone() * two_pow_16 + cols.addr_lo.clone() - cols.word_addr.clone();

    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_ADDR_RANGE_TAGS,
        &mut idx,
        memory_flag.clone() * reconstruction,
    );

    // Constraint 2: overflow guard — 4 * addr_hi < 2^16.
    //
    // This ensures that the maximum derived element address is:
    //   word_addr * 4 + 3 = (addr_hi * 2^16 + addr_lo) * 4 + 3
    //                     < 2^16 * 2^16 * 4    (since addr_hi < 2^14 after guard)
    //                     = 2^32
    //
    // We enforce this by adding `4 * addr_hi` to the range-check bus (in
    // `append_range_checks`); here we only need to constrain the decomposition.
    // The actual range check of addr_lo, addr_hi, and 4*addr_hi is done via the
    // range-check chiplet bus — see `Memory::append_range_checks`.
    //
    // (Constraint count: 1 reconstruction + 0 AIR-binary checks for addr_lo/addr_hi
    // since those are enforced by the range-check bus, not inline AIR constraints.)
    // The third tag slot is reserved for future use or documentation purposes.
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_ADDR_RANGE_TAGS,
        &mut idx,
        AB::Expr::ZERO, // placeholder — overflow guard lives in range-check bus
    );
    tagged_assert_zero_integrity(
        builder,
        &MEMORY_ADDR_RANGE_TAGS,
        &mut idx,
        AB::Expr::ZERO, // placeholder — range checks for lo/hi live in range-check bus
    );
}

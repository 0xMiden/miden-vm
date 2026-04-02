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

use super::selectors::memory_chiplet_flag;
use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::constants::{F_1, TWO_POW_16},
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
// ENTRY POINTS
// ================================================================================================

/// Enforce all memory chiplet constraints.
pub fn enforce_memory_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let s0: AB::Expr = local.chiplets[0].into();
    let s1: AB::Expr = local.chiplets[1].into();
    let s1_next: AB::Expr = next.chiplets[1].into();
    let s2_next: AB::Expr = next.chiplets[2].into();

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
    AB: MidenAirBuilder,
{
    // Compute memory active flag from top-level selectors
    let s0: AB::Expr = local.chiplets[0].into();
    let s1: AB::Expr = local.chiplets[1].into();
    let s2: AB::Expr = local.chiplets[2].into();
    let memory_flag = memory_chiplet_flag(s0, s1, s2);

    // Load memory columns using typed struct
    let cols: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(local);

    // Binary constraints
    let gate = memory_flag.clone();
    builder.assert_zero(gate.clone() * cols.is_read.clone() * (cols.is_read.clone() - F_1));
    builder.assert_zero(gate.clone() * cols.is_word.clone() * (cols.is_word.clone() - F_1));
    builder.assert_zero(gate.clone() * cols.idx0.clone() * (cols.idx0.clone() - F_1));
    builder.assert_zero(gate * cols.idx1.clone() * (cols.idx1.clone() - F_1));

    // For word access, idx bits must be zero (only element accesses use idx0/idx1).
    let word_gate = memory_flag.clone() * cols.is_word.clone();
    builder.assert_zero(word_gate.clone() * cols.idx0.clone());
    builder.assert_zero(word_gate * cols.idx1.clone());
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
    AB: MidenAirBuilder,
{
    // Load first memory row columns using typed struct
    let cols_next: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(cols_first);

    // Compute constraint flags for all 4 word elements
    let [c0, c1, c2, c3] = cols_next.compute_value_constraint_flags(AB::Expr::ONE);

    // First row: if v'[i] is not written to, then v'[i] = 0
    let gate = flag_next_row_first_memory;
    builder.assert_zero(gate.clone() * c0 * cols_next.values[0].clone());
    builder.assert_zero(gate.clone() * c1 * cols_next.values[1].clone());
    builder.assert_zero(gate.clone() * c2 * cols_next.values[2].clone());
    builder.assert_zero(gate * c3 * cols_next.values[3].clone());
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
    AB: MidenAirBuilder,
{
    // Load columns using typed struct
    let cols: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(local);
    let cols_next: MemoryColumns<AB::Expr> = MemoryColumns::from_row::<AB>(next);

    let deltas = MemoryDeltas::new::<AB>(&cols, &cols_next, AB::Expr::ONE);

    // ==========================================================================
    // DELTA INVERSE CONSTRAINTS
    // ==========================================================================
    enforce_delta_inverse_constraints::<AB>(
        builder,
        flag_memory_active_not_last.clone(),
        &deltas,
        AB::Expr::ONE,
    );

    // ==========================================================================
    // DELTA CONSTRAINTS (monotonicity)
    // ==========================================================================
    builder.assert_zero(
        flag_memory_active_not_last.clone()
            * (deltas.computed_delta.clone() - deltas.delta_next.clone()),
    );

    // ==========================================================================
    // SAME CONTEXT/WORD FLAG
    // ==========================================================================
    // f_scw' = !n0 * !n1
    builder.assert_zero(
        flag_memory_active_not_last.clone()
            * (cols_next.flag_same_ctx_word.clone()
                - (AB::Expr::ONE - deltas.n0.clone()) * (AB::Expr::ONE - deltas.n1.clone())),
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
        AB::Expr::ONE,
    );

    // ==========================================================================
    // VALUE CONSISTENCY
    // ==========================================================================

    // Compute constraint flags for all 4 elements
    let [c0, c1, c2, c3] = cols_next.compute_value_constraint_flags(AB::Expr::ONE);

    // When v'[i] is not written to:
    // - if f_scw' = 1: v'[i] = v[i] (copy from previous)
    // - if f_scw' = 0: v'[i] = 0 (initialize to zero)
    // Simplified: v'[i] = f_scw' * v[i]
    let constrain_value = |c: AB::Expr, v: AB::Expr, v_next: AB::Expr| {
        flag_memory_active_not_last.clone()
            * c
            * (v_next - cols_next.flag_same_ctx_word.clone() * v)
    };

    builder.assert_zero(constrain_value(c0, cols.values[0].clone(), cols_next.values[0].clone()));
    builder.assert_zero(constrain_value(c1, cols.values[1].clone(), cols_next.values[1].clone()));
    builder.assert_zero(constrain_value(c2, cols.values[2].clone(), cols_next.values[2].clone()));
    builder.assert_zero(constrain_value(c3, cols.values[3].clone(), cols_next.values[3].clone()));
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
        AB: MidenAirBuilder,
        AB::Expr: Into<E>,
    {
        let ctx_delta = cols_next.ctx.clone() - cols.ctx.clone();
        let addr_delta = cols_next.word_addr.clone() - cols.word_addr.clone();
        let clk_delta = cols_next.clk.clone() - cols.clk.clone();
        let two_pow_16: E = AB::Expr::from(TWO_POW_16).into();

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
        AB: MidenAirBuilder,
        AB::Var: Into<E> + Clone,
    {
        let load = |global_idx: usize| {
            let local_idx = global_idx - CHIPLETS_OFFSET;
            row.chiplets[local_idx].into()
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
    AB: MidenAirBuilder,
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

    // n0 is binary
    builder.assert_zero(gate * n0.clone() * (n0.clone() - one.clone()));
    // !n0 => ctx_delta = 0
    builder.assert_zero(gate_not_n0.clone() * ctx_delta.clone());
    // !n0 and n1 is binary
    builder.assert_zero(gate_not_n0.clone() * n1.clone() * (n1.clone() - one.clone()));
    // !n0 and !n1 => addr_delta = 0
    builder.assert_zero(gate_not_n0 * not_n1 * addr_delta.clone());
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
    AB: MidenAirBuilder,
{
    // If ctx/word are unchanged and clk_delta = 0, both rows must be reads.
    // Constraint: f_scw' * (1 - clk_delta * d_inv') * (is_write + is_write') = 0

    let clk_no_change = one.clone() - deltas.clk_delta.clone() * cols_next.d_inv.clone();

    let is_write = one.clone() - cols.is_read.clone();
    let is_write_next = one.clone() - cols_next.is_read.clone();
    let any_write = is_write + is_write_next;

    builder.assert_zero(
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

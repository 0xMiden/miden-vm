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

use miden_core::field::PrimeCharacteristicRing;

use super::selectors::ChipletFlags;
use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{
        constants::{F_1, TWO_POW_16},
        utils::BoolNot,
    },
    trace::{MemoryCols, chiplets::borrow_chiplet},
};

// ENTRY POINTS
// ================================================================================================

/// Enforce all memory chiplet constraints.
pub fn enforce_memory_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    enforce_memory_constraints_all_rows(builder, local, next, flags);

    let flag_next_row_first_memory = flags.next_is_first.clone();
    enforce_memory_constraints_first_row(builder, local, next, flag_next_row_first_memory);

    let flag_memory_active_not_last = flags.is_transition.clone();
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
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let memory_flag = flags.is_active.clone();

    let cols: &MemoryCols<AB::Var> = borrow_chiplet(&local.chiplets[3..18]);

    let is_read: AB::Expr = cols.is_read.into();
    let is_word: AB::Expr = cols.is_word.into();
    let idx0: AB::Expr = cols.idx0.into();
    let idx1: AB::Expr = cols.idx1.into();

    // Binary constraints
    let gate = memory_flag.clone();
    builder.assert_zero(gate.clone() * is_read.clone() * (is_read - F_1));
    builder.assert_zero(gate.clone() * is_word.clone() * (is_word.clone() - F_1));
    builder.assert_zero(gate.clone() * idx0.clone() * (idx0.clone() - F_1));
    builder.assert_zero(gate * idx1.clone() * (idx1.clone() - F_1));

    // For word access, idx bits must be zero (only element accesses use idx0/idx1).
    let word_gate = memory_flag.clone() * is_word;
    builder.assert_zero(word_gate.clone() * idx0);
    builder.assert_zero(word_gate * idx1);
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
    let cols_next: &MemoryCols<AB::Var> = borrow_chiplet(&cols_first.chiplets[3..18]);

    // Compute constraint flags for all 4 word elements
    let [c0, c1, c2, c3] = compute_value_constraint_flags::<AB>(cols_next);

    // First row: if v'[i] is not written to, then v'[i] = 0
    let gate = flag_next_row_first_memory;
    builder.assert_zero(gate.clone() * c0 * cols_next.values[0].into());
    builder.assert_zero(gate.clone() * c1 * cols_next.values[1].into());
    builder.assert_zero(gate.clone() * c2 * cols_next.values[2].into());
    builder.assert_zero(gate * c3 * cols_next.values[3].into());
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
    let cols: &MemoryCols<AB::Var> = borrow_chiplet(&local.chiplets[3..18]);
    let cols_next: &MemoryCols<AB::Var> = borrow_chiplet(&next.chiplets[3..18]);

    let deltas = compute_memory_deltas::<AB>(cols, cols_next);

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
    let is_same_ctx_and_word_next: AB::Expr = cols_next.is_same_ctx_and_word.into();
    builder.assert_zero(
        flag_memory_active_not_last.clone()
            * (is_same_ctx_and_word_next.clone() - deltas.n0.not() * deltas.n1.not()),
    );

    // ==========================================================================
    // SAME CONTEXT/WORD READ-ONLY CONSTRAINTS
    // ==========================================================================
    enforce_scw_readonly_constraint::<AB>(
        builder,
        flag_memory_active_not_last.clone(),
        cols,
        cols_next,
        &deltas,
    );

    // ==========================================================================
    // VALUE CONSISTENCY
    // ==========================================================================

    // Compute constraint flags for all 4 elements
    let [c0, c1, c2, c3] = compute_value_constraint_flags::<AB>(cols_next);

    // When v'[i] is not written to:
    // - if f_scw' = 1: v'[i] = v[i] (copy from previous)
    // - if f_scw' = 0: v'[i] = 0 (initialize to zero)
    // Simplified: v'[i] = f_scw' * v[i]
    let constrain_value = |c: AB::Expr, v: AB::Var, v_next: AB::Var| {
        flag_memory_active_not_last.clone()
            * c
            * (v_next.into() - is_same_ctx_and_word_next.clone() * v.into())
    };

    builder.assert_zero(constrain_value(c0, cols.values[0], cols_next.values[0]));
    builder.assert_zero(constrain_value(c1, cols.values[1], cols_next.values[1]));
    builder.assert_zero(constrain_value(c2, cols.values[2], cols_next.values[2]));
    builder.assert_zero(constrain_value(c3, cols.values[3], cols_next.values[3]));
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
    d_inv_next: E,
}

/// Compute derived delta values from two consecutive memory rows.
fn compute_memory_deltas<AB>(
    cols: &MemoryCols<AB::Var>,
    cols_next: &MemoryCols<AB::Var>,
) -> MemoryDeltas<AB::Expr>
where
    AB: MidenAirBuilder,
{
    let ctx_delta: AB::Expr = cols_next.ctx.into() - cols.ctx.into();
    let addr_delta: AB::Expr = cols_next.word_addr.into() - cols.word_addr.into();
    let clk_delta: AB::Expr = cols_next.clk.into() - cols.clk.into();
    let two_pow_16: AB::Expr = TWO_POW_16.into();
    let d_inv_next: AB::Expr = cols_next.d_inv.into();

    // n0 = ctx_delta * d_inv'
    // n1 = addr_delta * d_inv'
    let n0 = ctx_delta.clone() * d_inv_next.clone();
    let n1 = addr_delta.clone() * d_inv_next.clone();

    // delta_next = d1' * 2^16 + d0'
    let delta_next: AB::Expr = cols_next.d1.into() * two_pow_16 + cols_next.d0.into();

    let one = AB::Expr::ONE;

    // n0 * ctx_delta + !n0 * (n1 * addr_delta + !n1 * clk_delta) = delta_next
    let computed_delta = n0.clone() * ctx_delta.clone()
        + (one.clone() - n0.clone())
            * (n1.clone() * addr_delta.clone() + (one - n1.clone()) * clk_delta.clone());

    MemoryDeltas {
        ctx_delta,
        addr_delta,
        clk_delta,
        n0,
        n1,
        delta_next,
        computed_delta,
        d_inv_next,
    }
}

/// Compute constraint flags c_0, c_1, c_2, c_3 for value consistency constraints.
///
/// c_i = 1 when v[i] needs to be constrained (not being written to), 0 otherwise.
///
/// For each element i:
/// - Read operation: c_i = 1 (always constrain)
/// - Write operation, element access, element i selected: c_i = 0 (being written, no constraining
///   needed)
/// - Write operation, otherwise: c_i = 1 (not being written, constrain)
///
/// Logic: c_i = is_read + is_write * is_element * !f_i
///            = is_read + (1 - is_read) * (1 - is_word) * (1 - f_i)
fn compute_value_constraint_flags<AB>(cols: &MemoryCols<AB::Var>) -> [AB::Expr; 4]
where
    AB: MidenAirBuilder,
{
    let one = AB::Expr::ONE;
    let is_read: AB::Expr = cols.is_read.into();
    let is_word: AB::Expr = cols.is_word.into();
    let idx0: AB::Expr = cols.idx0.into();
    let idx1: AB::Expr = cols.idx1.into();

    let is_write = one.clone() - is_read.clone();
    let is_element = one.clone() - is_word;

    // Element selection flags (f_i = 1 when idx0,idx1 select element i)
    let f0 = (one.clone() - idx1.clone()) * (one.clone() - idx0.clone());
    let f1 = (one.clone() - idx1.clone()) * idx0.clone();
    let f2 = idx1.clone() * (one.clone() - idx0.clone());
    let f3 = idx1 * idx0;

    // c_i = is_read + is_write * is_element * !f_i
    let compute_c = |f_i: AB::Expr| {
        let not_f_i = one.clone() - f_i;
        is_read.clone() + is_write.clone() * is_element.clone() * not_f_i
    };

    [compute_c(f0), compute_c(f1), compute_c(f2), compute_c(f3)]
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
    let gate_not_n0 = gate.clone() * not_n0;

    // n0 is binary
    builder.assert_zero(gate * n0.clone() * (n0 - one.clone()));
    // !n0 => ctx_delta = 0
    builder.assert_zero(gate_not_n0.clone() * ctx_delta);
    // !n0 and n1 is binary
    builder.assert_zero(gate_not_n0.clone() * n1.clone() * (n1 - one));
    // !n0 and !n1 => addr_delta = 0
    builder.assert_zero(gate_not_n0 * not_n1 * addr_delta);
}

/// Enforce read-only access when context and word address are unchanged.
fn enforce_scw_readonly_constraint<AB>(
    builder: &mut AB,
    flag_memory_active_not_last: AB::Expr,
    cols: &MemoryCols<AB::Var>,
    cols_next: &MemoryCols<AB::Var>,
    deltas: &MemoryDeltas<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // If ctx/word are unchanged and clk_delta = 0, both rows must be reads.
    // Constraint: f_scw' * (1 - clk_delta * d_inv') * (is_write + is_write') = 0

    let one = AB::Expr::ONE;
    let clk_no_change = one.clone() - deltas.clk_delta.clone() * deltas.d_inv_next.clone();

    let is_write = one.clone() - cols.is_read.into();
    let is_write_next = one - cols_next.is_read.into();
    let any_write = is_write + is_write_next;

    builder.assert_zero(
        flag_memory_active_not_last
            * cols_next.is_same_ctx_and_word.into()
            * clk_no_change
            * any_write,
    );
}

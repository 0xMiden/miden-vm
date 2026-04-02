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
//! | d0, d1    | Lower/upper 16 bits of the active delta        |
//! | d_inv     | Inverse of the active delta (docs: column `t`) |
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
use miden_crypto::stark::air::AirBuilder;

use super::selectors::ChipletFlags;
use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{constants::TWO_POW_16, utils::BoolNot},
    trace::MemoryCols,
};

// ENTRY POINTS
// ================================================================================================

/// Enforce all memory chiplet constraints.
///
/// The memory trace is sorted by (ctx, word_addr, clk). Consecutive rows are compared
/// via deltas to enforce monotonicity of this ordering. A priority-select mechanism
/// using `ctx_changed` and `addr_changed` (docs: `n0`, `n1`) determines which delta
/// is active: context change takes priority over address change, which takes priority
/// over clock change.
pub fn enforce_memory_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let cols = local.memory();
    let cols_next = next.memory();

    // ==========================================================================
    // BINARY CONSTRAINTS (all rows)
    // ==========================================================================
    // Selectors and indices must be binary.
    {
        let builder = &mut builder.when(flags.is_active.clone());
        builder.assert_bool(cols.is_read);
        builder.assert_bool(cols.is_word);
        builder.assert_bool(cols.idx0);
        builder.assert_bool(cols.idx1);

        // For word access, idx bits must be zero (only element accesses use idx0/idx1).
        {
            let builder = &mut builder.when(cols.is_word);
            builder.assert_zero(cols.idx0);
            builder.assert_zero(cols.idx1);
        }
    }

    // not_written[i] = 1 when v'[i] is NOT being written and must be constrained.
    // Computed once, shared between first-row initialization and value consistency.
    let not_written = compute_not_written_flags::<AB>(cols_next);

    // ==========================================================================
    // FIRST-ROW INITIALIZATION
    // ==========================================================================
    // Enforced at the bitwise→memory boundary. When entering the memory chiplet,
    // values not being written must be zero.
    {
        let builder = &mut builder.when(flags.next_is_first.clone());
        for (i, nw) in not_written.iter().enumerate() {
            builder.when(nw.clone()).assert_zero(cols_next.values[i]);
        }
    }

    // ==========================================================================
    // TRANSITION CONSTRAINTS (all rows except last)
    // ==========================================================================
    // Enforces: delta inverse, monotonicity, same-context/word flag, read-only,
    // and value consistency.
    let builder = &mut builder.when(flags.is_transition.clone());

    // --- delta inverse ---
    // d_inv (docs: column `t`) is shared across all three priority levels (ctx, addr, clk).
    // The assert_bool + assert_zero pairs below form conditional inverses that force d_inv
    // to the correct value at each level.
    let d_inv_next = cols_next.d_inv;

    // Context: prover sets d_inv = 1/ctx_delta → ctx_changed = 1.
    let ctx_delta = cols_next.ctx - cols.ctx;
    let ctx_changed = ctx_delta.clone() * d_inv_next;
    let same_ctx = ctx_changed.not();
    // ctx_changed must be boolean. When ctx_delta ≠ 0, this forces ctx_changed ∈ {0, 1}.
    // If ctx_changed were 0 (same_ctx = 1), the assert_zero(ctx_delta) below would
    // require ctx_delta = 0 — contradiction. So ctx_changed = 1, forcing d_inv = 1/ctx_delta.
    builder.assert_bool(ctx_changed.clone());

    // Address: prover sets d_inv = 1/addr_delta → addr_changed = 1.
    // Only meaningful when same_ctx = 1; when context changes, addr_changed =
    // addr_delta/ctx_delta which is unconstrained, but always gated by same_ctx.
    let addr_delta = cols_next.word_addr - cols.word_addr;
    let addr_changed = addr_delta.clone() * d_inv_next;
    let same_addr = addr_changed.not();

    // When context is unchanged (same_ctx = 1):
    {
        let builder = &mut builder.when(same_ctx.clone());
        // Completes the ctx_changed enforcement: ctx_delta must be zero.
        builder.assert_zero(ctx_delta.clone());
        // addr_changed must be boolean. Same enforcement as ctx_changed: when
        // addr_delta ≠ 0, this + the assert_zero(addr_delta) below forces
        // addr_changed = 1, i.e. d_inv = 1/addr_delta.
        builder.assert_bool(addr_changed.clone());
        // Completes the addr_changed enforcement: addr_delta must be zero.
        builder.when(same_addr.clone()).assert_zero(addr_delta.clone());
    }

    // --- same context/word flag ---
    // f_scw' = 1 when both context and word address are unchanged between rows.
    // Not constrained in the first row (intentional — first-row constraints use
    // not_written flags directly, not f_scw).
    let f_scw_next = cols_next.is_same_ctx_and_word;
    builder.assert_eq(f_scw_next, same_ctx.clone() * same_addr.clone());

    // --- monotonicity ---
    // The priority-selected delta must equal the range-checked decomposition.
    // d0, d1 are range-checked 16-bit limbs, so delta_next >= 0. For ctx and addr,
    // delta = 0 would contradict the flag being 1, so those deltas are strictly
    // positive. For clk, delta = 0 is allowed (duplicate reads; see read-only).
    //   ctx changed  → ctx_delta
    //   addr changed → addr_delta  (reachable only when same context)
    //   neither      → clk_delta
    let clk_delta = cols_next.clk - cols.clk;
    let computed_delta = {
        let ctx_term = ctx_changed * ctx_delta;
        let addr_term = addr_changed * addr_delta;
        let clk_term = same_addr * clk_delta.clone();
        ctx_term + same_ctx * (addr_term + clk_term)
    };
    let delta_next = cols_next.d1 * TWO_POW_16 + cols_next.d0;
    builder.assert_eq(computed_delta, delta_next);

    // --- read-only constraint ---
    // When context/word are unchanged (f_scw'=1) and the clock doesn't advance,
    // both operations must be reads.
    //
    // clk_no_change = 1 - clk_delta * d_inv is used as a when() gate. Unlike the ctx
    // and addr levels, no constraint forces d_inv = 1/clk_delta. This is intentional:
    //   clk advances → prover must set d_inv = 1/clk_delta to get clk_no_change = 0,
    //     otherwise the gate stays active and blocks writes the prover needs.
    //   clk unchanged → clk_delta = 0, so clk_no_change = 1 regardless of d_inv.
    // One-sided safe: a wrong d_inv can only block writes, never enable them.
    {
        let clk_no_change = AB::Expr::ONE - clk_delta * d_inv_next;
        let is_write = cols.is_read.into().not();
        let is_write_next = cols_next.is_read.into().not();
        let any_write = is_write + is_write_next;

        builder.when(f_scw_next).when(clk_no_change).assert_zero(any_write);
    }

    // --- value consistency ---
    // Values not being written must follow the consistency rule:
    //   same context/word (f_scw'=1): v'[i] = v[i]  (copy from previous row)
    //   new context/word  (f_scw'=0): v'[i] = 0      (initialize to zero)
    // Combined: v'[i] = f_scw' * v[i]
    let values = cols.values;
    let values_next = cols_next.values;
    for (i, nw) in not_written.into_iter().enumerate() {
        builder.when(nw).assert_eq(values_next[i], f_scw_next * values[i]);
    }
}

// INTERNAL HELPERS
// ================================================================================================

/// Compute "not written" flags for each of the 4 word elements.
///
/// Returns `not_written[i]`: 1 when `v[i]` is NOT the write target (must be constrained),
/// 0 when `v[i]` IS being written (unconstrained).
///
/// The three operation modes:
/// - **Read** (`is_read=1`): all flags = 1 (reads don't change any value)
/// - **Word write** (`is_word=1`): all flags = 0 (all 4 elements are written)
/// - **Element write** (`is_word=0, is_read=0`): flag = 0 for the selected element, 1 for the other
///   three
///
/// Corresponds to `c_i` in the docs, with `selected[i]` ≡ docs' `f_i`.
///
/// Formula: `not_written[i] = is_read + is_write * is_element * !selected[i]`
fn compute_not_written_flags<AB>(cols: &MemoryCols<AB::Var>) -> [AB::Expr; 4]
where
    AB: MidenAirBuilder,
{
    let is_read = cols.is_read;
    let is_write = is_read.into().not();

    let is_word = cols.is_word;
    let is_element = is_word.into().not();

    // One-hot element selection: selected[i] = 1 when idx = 2*idx1 + idx0 equals i.
    let idx0 = cols.idx0;
    let idx1 = cols.idx1;
    let not_idx0 = idx0.into().not();
    let not_idx1 = idx1.into().not();

    let selected = [
        not_idx1.clone() * not_idx0.clone(), // element 0: idx = 0b00
        not_idx1 * idx0,                     // element 1: idx = 0b01
        idx1 * not_idx0,                     // element 2: idx = 0b10
        idx1 * idx0,                         // element 3: idx = 0b11
    ];

    // not_written[i] = is_read + is_write * is_element * !selected[i]
    let is_element_write = is_write * is_element;
    selected.map(|s_i| is_read + is_element_write.clone() * s_i.not())
}

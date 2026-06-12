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
//! | f_sca     | Same context/addr flag (`is_same_ctx_and_addr`) |
//! | w0        | Lower 16 bits of word index (word_addr / 4)   |
//! | w1        | Upper 16 bits of word index (word_addr / 4)   |
//!
//! ## Address range checks
//!
//! The constraint `word_addr = 4 * (w0 + 2^16 * w1)` decomposes the word address
//! into 16-bit limbs. Combined with range checks on `w0`, `w1`, and `4 * w1` via
//! the wiring bus, this proves all memory addresses are valid 32-bit values.
//! The `4 * w1` check prevents Goldilocks field wraparound (P > 2^18).

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use super::selectors::ChipletFlags;
use crate::{
    ChipletCols, MidenAirBuilder,
    constraints::{
        chiplets::columns::MemoryCols,
        constants::{F_4, TWO_POW_16},
        utils::BoolNot,
    },
};

// ENTRY POINTS
// ================================================================================================

/// Enforce all memory chiplet constraints.
///
/// The memory trace is ordered by (ctx, addr, clk). Consecutive rows are compared
/// via deltas to enforce monotonicity of this ordering. A select mechanism
/// using `ctx_changed` and `addr_changed` (docs: `n0`, `n1`) determines which delta
/// is active: context change takes precedence over address change, which takes
/// precedence over clock change.
pub fn enforce_memory_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
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

        let word_addr_lo = local.memory_word_addr_lo();
        let word_addr_hi = local.memory_word_addr_hi();
        let word_addr = (word_addr_hi * TWO_POW_16 + word_addr_lo) * F_4;
        builder.assert_eq(cols.word_addr, word_addr);

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
    // Enforces: delta inverse, monotonicity, same-context/addr flag, read-only,
    // and value consistency.
    let builder = &mut builder.when(flags.is_transition.clone());

    // --- delta inverse ---
    // d_inv (docs: column `t`) is shared across all three delta levels (ctx, addr, clk).
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

    // --- same context/addr flag ---
    // f_sca' = 1 when both context and word address are unchanged between rows.
    // Stored in a dedicated column for degree reduction (same_ctx * same_addr is
    // degree 4; the column lets downstream constraints use it at degree 1).
    // Not constrained in the first row (intentional — first-row constraints use
    // not_written flags directly, not f_sca).
    let same_ctx_and_addr = cols_next.is_same_ctx_and_addr;
    builder.assert_eq(same_ctx_and_addr, same_ctx.clone() * same_addr.clone());

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
    // When context/addr are unchanged (f_sca'=1) and the clock doesn't advance,
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

        builder.when(same_ctx_and_addr).when(clk_no_change).assert_zero(any_write);
    }

    // --- value consistency ---
    // Values not being written must follow the consistency rule:
    //   same context/addr (f_sca'=1): v'[i] = v[i]  (copy from previous row)
    //   new context/addr  (f_sca'=0): v'[i] = 0      (initialize to zero)
    // Combined: v'[i] = f_sca' * v[i]
    let values = cols.values;
    let values_next = cols_next.values;
    for (i, nw) in not_written.into_iter().enumerate() {
        builder.when(nw).assert_eq(values_next[i], same_ctx_and_addr * values[i]);
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
/// Corresponds to `c_i` in the docs, with `selected[i]` ≡ `f_i`.
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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::borrow::BorrowMut;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };
    use miden_crypto::stark::{
        air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow},
        matrix::RowMajorMatrix,
    };

    use super::enforce_memory_constraints;
    use crate::{
        ChipletCols, MemoryCols,
        constraints::chiplets::selectors::ChipletFlags,
        trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, CHIPLETS_WIDTH, TRACE_WIDTH},
    };

    struct ConstraintEvalBuilder {
        main: RowMajorMatrix<Felt>,
        aux: RowMajorMatrix<QuadFelt>,
        randomness: Vec<QuadFelt>,
        permutation_values: Vec<QuadFelt>,
        periodic_values: Vec<Felt>,
        preprocessed: RowWindow<'static, Felt>,
        evaluations: Vec<QuadFelt>,
    }

    impl ConstraintEvalBuilder {
        fn new() -> Self {
            Self {
                main: RowMajorMatrix::new(vec![Felt::ZERO; TRACE_WIDTH * 2], TRACE_WIDTH),
                aux: RowMajorMatrix::new(
                    vec![QuadFelt::ZERO; AUX_TRACE_WIDTH * 2],
                    AUX_TRACE_WIDTH,
                ),
                randomness: vec![QuadFelt::ZERO; AUX_TRACE_RAND_CHALLENGES],
                permutation_values: vec![QuadFelt::ZERO; AUX_TRACE_WIDTH],
                periodic_values: Vec::new(),
                preprocessed: RowWindow::from_two_rows(&[], &[]),
                evaluations: Vec::new(),
            }
        }
    }

    impl AirBuilder for ConstraintEvalBuilder {
        type F = Felt;
        type Expr = Felt;
        type Var = Felt;
        type PreprocessedWindow = RowWindow<'static, Felt>;
        type MainWindow = RowMajorMatrix<Felt>;
        type PublicVar = Felt;
        type PeriodicVar = Felt;

        fn main(&self) -> Self::MainWindow {
            self.main.clone()
        }

        fn preprocessed(&self) -> &Self::PreprocessedWindow {
            &self.preprocessed
        }

        fn is_first_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_last_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_transition(&self) -> Self::Expr {
            Felt::ONE
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            self.evaluations.push(QuadFelt::from(x.into()));
        }

        fn public_values(&self) -> &[Self::PublicVar] {
            &[]
        }

        fn periodic_values(&self) -> &[Self::PeriodicVar] {
            &self.periodic_values
        }
    }

    impl ExtensionBuilder for ConstraintEvalBuilder {
        type EF = QuadFelt;
        type ExprEF = QuadFelt;
        type VarEF = QuadFelt;

        fn assert_zero_ext<I>(&mut self, x: I)
        where
            I: Into<Self::ExprEF>,
        {
            self.evaluations.push(x.into());
        }
    }

    impl PermutationAirBuilder for ConstraintEvalBuilder {
        type MP = RowMajorMatrix<QuadFelt>;
        type RandomVar = QuadFelt;
        type PermutationVar = QuadFelt;

        fn permutation(&self) -> Self::MP {
            self.aux.clone()
        }

        fn permutation_randomness(&self) -> &[Self::RandomVar] {
            &self.randomness
        }

        fn permutation_values(&self) -> &[Self::PermutationVar] {
            &self.permutation_values
        }
    }

    fn memory_flags() -> ChipletFlags<Felt> {
        ChipletFlags {
            is_active: Felt::ONE,
            is_transition: Felt::ZERO,
            is_last: Felt::ZERO,
            next_is_first: Felt::ZERO,
        }
    }

    fn memory_row() -> ChipletCols<Felt> {
        ChipletCols {
            chiplets: [Felt::ZERO; CHIPLETS_WIDTH - 2],
            s_perm: Felt::ZERO,
            chip_clk: Felt::ONE,
        }
    }

    fn memory_cols(row: &mut ChipletCols<Felt>) -> &mut MemoryCols<Felt> {
        row.chiplets[3..18].borrow_mut()
    }

    fn set_word_addr_limbs(row: &mut ChipletCols<Felt>, lo: u64, hi: u64) {
        row.chiplets[18] = Felt::new_unchecked(lo);
        row.chiplets[19] = Felt::new_unchecked(hi);
    }

    fn eval_memory_constraints(row: &ChipletCols<Felt>) -> Vec<QuadFelt> {
        let next = memory_row();
        let mut builder = ConstraintEvalBuilder::new();
        enforce_memory_constraints(&mut builder, row, &next, &memory_flags());
        builder.evaluations
    }

    fn assert_constraints_accept(row: &ChipletCols<Felt>) {
        let evaluations = eval_memory_constraints(row);
        assert!(
            evaluations.iter().all(|value| *value == QuadFelt::ZERO),
            "expected all memory constraints to evaluate to zero; got {evaluations:?}",
        );
    }

    fn assert_constraints_reject(row: &ChipletCols<Felt>) {
        let evaluations = eval_memory_constraints(row);
        assert!(
            evaluations.iter().any(|value| *value != QuadFelt::ZERO),
            "expected at least one nonzero memory constraint evaluation",
        );
    }

    #[test]
    fn memory_constraints_bind_word_addr_to_range_checked_limbs() {
        let mut valid = memory_row();
        {
            let cols = memory_cols(&mut valid);
            cols.is_read = Felt::ONE;
            cols.is_word = Felt::ONE;
            cols.word_addr = Felt::new_unchecked(4 * (7 + (3 << 16)));
        }
        set_word_addr_limbs(&mut valid, 7, 3);
        assert_constraints_accept(&valid);

        let mut invalid = valid.clone();
        set_word_addr_limbs(&mut invalid, 0, 0);
        assert_constraints_reject(&invalid);
    }
}

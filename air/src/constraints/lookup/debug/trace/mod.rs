//! Combined real-trace balance + per-column `(U, V)` oracle debug surface.
//!
//! One walk over a concrete main trace, row by row, produces two outputs projected out of
//! the shared [`run_trace_walk`] driver:
//!
//! - **Balance** — signed multiplicities keyed by encoded denominator. Any residual at the end of
//!   the walk is an unmatched interaction.
//! - **Column oracle folds** — per-row per-column `(U_col, V_col)` pairs computed via the
//!   constraint-path cross-multiplication rule, used by the processor's LogUp cross-check.
//!
//! Layout:
//!
//! - [`builder`] — the [`DebugTraceBuilder`] (plus column / group / batch handles) that drives each
//!   per-row walk.
//! - This file — the report types ([`BalanceReport`], [`Unmatched`], …), the row-by-row
//!   [`run_trace_walk`] driver, and the two public entry points.

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{borrow::Borrow, fmt};

use miden_core::{
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::RowWindow;

use super::super::{LookupAir, LookupChallenges};
use crate::Felt;

pub mod builder;

pub use builder::{DebugTraceBatch, DebugTraceBuilder, DebugTraceColumn, DebugTraceGroup};

// REPORT TYPES
// ================================================================================================

/// An unmatched interaction: an encoded denom with non-zero net multiplicity after walking
/// the full trace.
#[derive(Debug, Clone)]
pub struct Unmatched {
    /// Encoded denominator represented as its basis-coefficient tuple `[u64; 2]`.
    pub denom_basis: [u64; 2],
    /// Net signed multiplicity modulo the field prime.
    pub net_multiplicity: Felt,
    /// Free-text summary suitable for inclusion in an assertion message.
    pub summary: String,
}

/// Per-row mutual-exclusion violation inside a cached-encoding group.
#[derive(Debug, Clone)]
pub struct MutualExclusionViolation {
    pub row: usize,
    pub column_idx: usize,
    pub group_idx: usize,
    pub active_flags: usize,
}

/// Full report returned by [`check_trace_balance`].
#[derive(Debug, Default)]
pub struct BalanceReport {
    pub unmatched: Vec<Unmatched>,
    pub mutex_violations: Vec<MutualExclusionViolation>,
}

impl BalanceReport {
    pub fn is_ok(&self) -> bool {
        self.unmatched.is_empty() && self.mutex_violations.is_empty()
    }
}

impl fmt::Display for BalanceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_ok() {
            return writeln!(f, "BalanceReport: OK");
        }
        writeln!(
            f,
            "BalanceReport: {} unmatched, {} mutex violations",
            self.unmatched.len(),
            self.mutex_violations.len(),
        )?;
        for u in &self.unmatched {
            writeln!(f, "  {}", u.summary)?;
        }
        for m in &self.mutex_violations {
            writeln!(
                f,
                "  mutex violation at row {} col {} group {}: {} active flags",
                m.row, m.column_idx, m.group_idx, m.active_flags,
            )?;
        }
        Ok(())
    }
}

// STATE
// ================================================================================================

/// Scratch state threaded through [`DebugTraceBuilder`] for every row in the walk. The
/// driver creates one instance per walk; it resets `column_folds` at the start of each
/// row and keeps `balances` / `mutex_violations` accumulating across rows.
pub struct DebugTraceState {
    /// Signed-multiplicity accumulator keyed by encoded-denominator basis coefficients.
    /// `BTreeMap` for `no_std` friendliness + deterministic iteration.
    pub(super) balances: BTreeMap<[u64; 2], Felt>,
    pub(super) mutex_violations: Vec<MutualExclusionViolation>,
    /// Per-column `(U_col, V_col)`. Reset to `(ONE, ZERO)` at the start of each row by
    /// [`run_trace_walk`].
    pub(super) column_folds: Vec<(QuadFelt, QuadFelt)>,
}

pub(super) fn denom_key(v: QuadFelt) -> [u64; 2] {
    let slice: &[Felt] = v.as_basis_coefficients_slice();
    [slice[0].as_canonical_u64(), slice[1].as_canonical_u64()]
}

pub(super) fn accumulate_balance(state: &mut DebugTraceState, v: QuadFelt, mult: Felt) {
    let key = denom_key(v);
    let entry = state.balances.entry(key).or_insert(Felt::ZERO);
    *entry += mult;
}

impl DebugTraceState {
    /// Fold a group's `(U_g, V_g)` into the column's `(U_col, V_col)` slot using the
    /// constraint-path cross-multiplication rule `(U, V) ← (U·U_g, V·U_g + V_g·U)`.
    ///
    /// Free function on the state (not on the column handle) so it can be called from
    /// inside a live `DebugTraceGroup` scope via `group.state.fold_group(...)` — the
    /// column's `&mut self` is still borrowed through the group at that point.
    pub(super) fn fold_group(&mut self, column_idx: usize, u_g: QuadFelt, v_g: QuadFelt) {
        let (u_col, v_col) = self.column_folds[column_idx];
        self.column_folds[column_idx] = (u_col * u_g, v_col * u_g + v_g * u_col);
    }
}

// ENTRY POINTS
// ================================================================================================

/// Walk a complete main trace and return the balance report (unmatched interactions +
/// mutex violations).
pub fn check_trace_balance<A>(
    air: &A,
    main_trace: &RowMajorMatrix<Felt>,
    periodic_columns: &[Vec<Felt>],
    public_values: &[Felt],
    challenges: &LookupChallenges<QuadFelt>,
) -> BalanceReport
where
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    run_trace_walk(air, main_trace, periodic_columns, public_values, challenges).balance
}

/// Walk a complete main trace and return the per-row constraint-path `(U_col, V_col)`
/// folds. `folds[r][col]` is the fold for column `col` at row `r`.
pub fn collect_column_oracle_folds<A>(
    air: &A,
    main_trace: &RowMajorMatrix<Felt>,
    periodic_columns: &[Vec<Felt>],
    public_values: &[Felt],
    challenges: &LookupChallenges<QuadFelt>,
) -> Vec<Vec<(QuadFelt, QuadFelt)>>
where
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    run_trace_walk(air, main_trace, periodic_columns, public_values, challenges).folds_per_row
}

// SHARED DRIVER
// ================================================================================================

struct TraceWalkOutput {
    balance: BalanceReport,
    folds_per_row: Vec<Vec<(QuadFelt, QuadFelt)>>,
}

/// Shared row-by-row driver used by both public entry points. Each row gets a fresh
/// [`DebugTraceBuilder`] with column folds reset to `(ONE, ZERO)`; the balance accumulator
/// persists across rows, the folds snapshot at row end.
fn run_trace_walk<A>(
    air: &A,
    main_trace: &RowMajorMatrix<Felt>,
    periodic_columns: &[Vec<Felt>],
    public_values: &[Felt],
    challenges: &LookupChallenges<QuadFelt>,
) -> TraceWalkOutput
where
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    let num_rows = main_trace.height();
    let width = main_trace.width();
    let flat: &[Felt] = main_trace.values.borrow();
    let num_cols = air.num_columns();

    let mut state = DebugTraceState {
        balances: BTreeMap::new(),
        mutex_violations: Vec::new(),
        column_folds: vec![(QuadFelt::ONE, QuadFelt::ZERO); num_cols],
    };
    let mut folds_per_row: Vec<Vec<(QuadFelt, QuadFelt)>> = Vec::with_capacity(num_rows);
    let mut periodic_row: Vec<Felt> = vec![Felt::ZERO; periodic_columns.len()];

    for r in 0..num_rows {
        let curr = &flat[r * width..(r + 1) * width];
        let nxt_idx = (r + 1) % num_rows;
        let next = &flat[nxt_idx * width..(nxt_idx + 1) * width];
        let window = RowWindow::from_two_rows(curr, next);

        for (i, col) in periodic_columns.iter().enumerate() {
            periodic_row[i] = col[r % col.len()];
        }

        // Reset per-row folds; balances and mutex_violations persist.
        for fold in state.column_folds.iter_mut() {
            *fold = (QuadFelt::ONE, QuadFelt::ZERO);
        }

        {
            let mut lb = DebugTraceBuilder::new(
                window,
                &periodic_row,
                public_values,
                challenges,
                &mut state,
                r,
            );
            air.eval(&mut lb);
        }

        folds_per_row.push(state.column_folds.clone());
    }

    TraceWalkOutput { balance: finalize(state), folds_per_row }
}

fn finalize(state: DebugTraceState) -> BalanceReport {
    let DebugTraceState { balances, mutex_violations, .. } = state;
    let mut unmatched = Vec::new();
    for (denom_basis, net) in balances {
        if net != Felt::ZERO {
            let summary = format!(
                "denom [{:?}, {:?}] net multiplicity {:?}",
                denom_basis[0], denom_basis[1], net,
            );
            unmatched.push(Unmatched {
                denom_basis,
                net_multiplicity: net,
                summary,
            });
        }
    }
    BalanceReport { unmatched, mutex_violations }
}

// Keep `ToString` live on `no_std` paths where `format!` uses it indirectly.
#[allow(dead_code)]
fn _keep_to_string<T: ToString>(t: T) -> String {
    t.to_string()
}

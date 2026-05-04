//! Combined real-trace balance + per-column `(U, V)` oracle debug surface.
//!
//! One walk over a concrete main trace, row by row, produces three outputs projected
//! out of the shared `run_trace_walk` driver:
//!
//! - **Balance** — signed multiplicities keyed by encoded denominator. Any residual at the end of
//!   the walk is an unmatched interaction.
//! - **Push log** — a [`PushRecord`] per interaction emission, capturing pre-encoding payload,
//!   encoded denominator, signed multiplicity, and `(row, column, group)` source coordinates.
//!   Joined back against the balance map at finalize time so each unmatched denominator lists the
//!   exact pushes that summed to it.
//! - **Column oracle folds** — per-row per-column `(U_col, V_col)` pairs computed via the
//!   constraint-path cross-multiplication rule, used by the processor's LogUp cross-check.
//!
//! Layout:
//!
//! - [`builder`] — the `DebugTraceBuilder` (plus column / group / batch handles) that drives each
//!   per-row walk.
//! - This file — the report types ([`BalanceReport`], [`Unmatched`], [`PushRecord`], …), the
//!   row-by-row `run_trace_walk` driver, and the two public entry points.

use alloc::{string::String, vec, vec::Vec};
use core::{borrow::Borrow, fmt};
use std::collections::HashMap;

use miden_core::{
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::RowWindow;

use super::super::{Challenges, LookupAir};
use crate::Felt;

pub mod builder;

pub use builder::{
    DebugBoundaryEmitter, DebugTraceBatch, DebugTraceBuilder, DebugTraceColumn, DebugTraceGroup,
};

// REPORT TYPES
// ================================================================================================

/// An unmatched interaction: an encoded denom with non-zero net multiplicity after walking
/// the full trace.
#[derive(Debug, Clone)]
pub struct Unmatched {
    pub denom: QuadFelt,
    /// Net signed multiplicity modulo the field prime.
    pub net_multiplicity: Felt,
    /// Every push that landed on this encoded denominator during the walk, in emission
    /// order. The caller can bucket these by `msg_repr` / column / row to isolate the
    /// specific emit that left the denom unbalanced.
    pub contributions: Vec<PushRecord>,
}

/// One interaction emission captured during a trace walk.
///
/// Populated for every push that passes its flag check, regardless of whether the
/// interaction eventually balances. When a denom lands in [`BalanceReport::unmatched`],
/// the join against the push log shows exactly which emits (row, column, group,
/// payload) summed to the residual multiplicity.
#[derive(Debug, Clone)]
pub struct PushRecord {
    pub row: usize,
    pub column_idx: usize,
    pub group_idx: usize,
    /// `format!("{:?}", msg)` of the `LookupMessage` instance. `"<encoded>"` for
    /// `insert_encoded` sites, where only the pre-computed denominator is known.
    pub msg_repr: String,
    pub denom: QuadFelt,
    pub multiplicity: Felt,
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
        /// How many contributing pushes to print per unmatched denom before truncating.
        const MAX_CONTRIB_LINES: usize = 4;

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
            writeln!(f, "  denom {:?} net multiplicity {:?}", u.denom, u.net_multiplicity)?;
            for r in u.contributions.iter().take(MAX_CONTRIB_LINES) {
                writeln!(
                    f,
                    "    row={} col={} group={} mult={:?} msg={}",
                    r.row, r.column_idx, r.group_idx, r.multiplicity, r.msg_repr,
                )?;
            }
            if u.contributions.len() > MAX_CONTRIB_LINES {
                writeln!(
                    f,
                    "    … {} more contributions",
                    u.contributions.len() - MAX_CONTRIB_LINES,
                )?;
            }
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
/// row and keeps `balances` / `push_log` / `mutex_violations` accumulating across rows.
pub struct DebugTraceState {
    /// Signed-multiplicity accumulator keyed by encoded denominator. Sorted at
    /// finalize time for deterministic output.
    pub(super) balances: HashMap<QuadFelt, Felt>,
    /// Per-push record of every interaction emission. Joined against `balances` in
    /// [`finalize`] so each unmatched denom carries its source pushes.
    pub(super) push_log: Vec<PushRecord>,
    pub(super) mutex_violations: Vec<MutualExclusionViolation>,
    /// Per-column `(U_col, V_col)`. Reset to `(ONE, ZERO)` at the start of each row by
    /// [`run_trace_walk`].
    pub(super) column_folds: Vec<(QuadFelt, QuadFelt)>,
}

// ENTRY POINTS
// ================================================================================================

/// Walk a complete main trace and return the balance report (unmatched interactions +
/// mutex violations).
///
/// Includes boundary contributions from [`LookupAir::eval_boundary`], so a fully
/// closed AIR produces `BalanceReport::is_ok() == true`. `var_len_public_inputs` is
/// the same shape the prover hands to `miden_crypto::stark::prover::prove_single`
/// (e.g. `&[&kernel_felts]`); pass `&[]` if the AIR has no variable-length public
/// inputs or no boundary contributions that consume them.
pub fn check_trace_balance<A>(
    air: &A,
    main_trace: &RowMajorMatrix<Felt>,
    periodic_columns: &[Vec<Felt>],
    public_values: &[Felt],
    var_len_public_inputs: &[&[Felt]],
    challenges: &Challenges<QuadFelt>,
) -> BalanceReport
where
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    run_trace_walk(
        air,
        main_trace,
        periodic_columns,
        public_values,
        var_len_public_inputs,
        challenges,
    )
    .balance
}

/// Walk a complete main trace and return the per-row constraint-path `(U_col, V_col)`
/// folds. `folds[r][col]` is the fold for column `col` at row `r`.
///
/// Does not incorporate boundary contributions — the folds are a per-row property of
/// the main trace, independent of once-per-proof outer emissions.
pub fn collect_column_oracle_folds<A>(
    air: &A,
    main_trace: &RowMajorMatrix<Felt>,
    periodic_columns: &[Vec<Felt>],
    public_values: &[Felt],
    challenges: &Challenges<QuadFelt>,
) -> Vec<Vec<(QuadFelt, QuadFelt)>>
where
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    run_trace_walk(air, main_trace, periodic_columns, public_values, &[], challenges).folds_per_row
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
    var_len_public_inputs: &[&[Felt]],
    challenges: &Challenges<QuadFelt>,
) -> TraceWalkOutput
where
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    let num_rows = main_trace.height();
    let width = main_trace.width();
    let flat: &[Felt] = main_trace.values.borrow();
    let num_cols = air.num_columns();

    let mut state = DebugTraceState {
        balances: HashMap::new(),
        push_log: Vec::new(),
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
            let mut lb = DebugTraceBuilder::new(window, &periodic_row, challenges, &mut state, r);
            air.eval(&mut lb);
        }

        folds_per_row.push(state.column_folds.clone());
    }

    // Boundary / outer interactions (once per proof, no row): kernel init, block
    // hash, log-precompile terminals, …. Accumulates into the same balance map as
    // the per-row trace emissions — a fully closed AIR produces `is_ok() == true`.
    {
        let mut boundary = DebugBoundaryEmitter {
            challenges,
            state: &mut state,
            public_values,
            var_len_public_inputs,
        };
        air.eval_boundary(&mut boundary);
    }

    TraceWalkOutput { balance: finalize(state), folds_per_row }
}

fn finalize(state: DebugTraceState) -> BalanceReport {
    let DebugTraceState { balances, push_log, mutex_violations, .. } = state;

    // Group every push by its encoded denom so each unmatched denom can pull its
    // contributing records in O(1). Preserves emission order within each bucket.
    let mut contrib_by_denom: HashMap<QuadFelt, Vec<PushRecord>> = HashMap::new();
    for record in push_log {
        contrib_by_denom.entry(record.denom).or_default().push(record);
    }

    let mut unmatched = Vec::new();
    for (denom, net) in balances {
        if net == Felt::ZERO {
            continue;
        }
        let contributions = contrib_by_denom.remove(&denom).unwrap_or_default();
        unmatched.push(Unmatched {
            denom,
            net_multiplicity: net,
            contributions,
        });
    }
    // Sort for deterministic output — `HashMap` iteration order is arbitrary.
    unmatched.sort_by_key(|u| u.denom);
    BalanceReport { unmatched, mutex_violations }
}

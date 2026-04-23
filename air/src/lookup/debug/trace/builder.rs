//! `DebugTraceBuilder` — the `LookupBuilder` adapter that updates
//! [`super::DebugTraceState`] per row of a concrete main trace.
//!
//! Pure implementation detail: instantiation happens inside
//! `super::run_trace_walk`. The builder, column, group, and batch handles all collapse
//! their associated types to `Felt` / `QuadFelt`.

use alloc::{format, string::ToString};

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::RowWindow;

use super::{
    super::super::{
        BoundaryBuilder, Challenges, Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
        LookupMessage,
    },
    DebugTraceState, MutualExclusionViolation, PushRecord,
};
use crate::Felt;

// BUILDER
// ================================================================================================

/// Real-trace `LookupBuilder` that updates [`super::DebugTraceState`] per row.
pub struct DebugTraceBuilder<'a> {
    main: RowWindow<'a, Felt>,
    periodic_values: &'a [Felt],
    challenges: &'a Challenges<QuadFelt>,
    state: &'a mut DebugTraceState,
    row_idx: usize,
    column_idx: usize,
}

impl<'a> DebugTraceBuilder<'a> {
    pub fn new(
        main: RowWindow<'a, Felt>,
        periodic_values: &'a [Felt],
        challenges: &'a Challenges<QuadFelt>,
        state: &'a mut DebugTraceState,
        row_idx: usize,
    ) -> Self {
        Self {
            main,
            periodic_values,
            challenges,
            state,
            row_idx,
            column_idx: 0,
        }
    }
}

impl<'a> LookupBuilder for DebugTraceBuilder<'a> {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;

    type EF = QuadFelt;
    type ExprEF = QuadFelt;
    type VarEF = QuadFelt;

    type PeriodicVar = Felt;

    type MainWindow = RowWindow<'a, Felt>;

    type Column<'c>
        = DebugTraceColumn<'c>
    where
        Self: 'c;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }

    fn next_column<'c, R>(
        &'c mut self,
        f: impl FnOnce(&mut Self::Column<'c>) -> R,
        _deg: Deg,
    ) -> R {
        let mut col = DebugTraceColumn {
            challenges: self.challenges,
            state: &mut *self.state,
            row_idx: self.row_idx,
            column_idx: self.column_idx,
            next_group_idx: 0,
        };
        let result = f(&mut col);
        self.column_idx += 1;
        result
    }
}

// COLUMN
// ================================================================================================

pub struct DebugTraceColumn<'c> {
    challenges: &'c Challenges<QuadFelt>,
    state: &'c mut DebugTraceState,
    row_idx: usize,
    column_idx: usize,
    next_group_idx: usize,
}

impl<'c> DebugTraceColumn<'c> {
    /// Common path shared by `group` and `group_with_cached_encoding`. Opens a group,
    /// drives the caller's closure, folds the group's `(U_g, V_g)` into the column's
    /// running `(U_col, V_col)`, and (for cached-encoding groups) records any mutex
    /// violation.
    fn open_group<'g>(
        &'g mut self,
        is_cached_encoding: bool,
        f: impl FnOnce(&mut DebugTraceGroup<'g>),
    ) {
        let group_idx = self.next_group_idx;
        let column_idx = self.column_idx;
        let row_idx = self.row_idx;

        let mut group = DebugTraceGroup {
            challenges: self.challenges,
            state: &mut *self.state,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
            row_idx,
            column_idx,
            group_idx,
            check_mutex: is_cached_encoding,
            active_flag_count: 0,
        };
        f(&mut group);

        if group.check_mutex && group.active_flag_count > 1 {
            group.state.mutex_violations.push(MutualExclusionViolation {
                row: row_idx,
                column_idx,
                group_idx,
                active_flags: group.active_flag_count,
            });
        }
        // Fold `(U_g, V_g)` into `(U_col, V_col)`:  (U, V) ← (U·U_g, V·U_g + V_g·U)
        let (u_col, v_col) = group.state.column_folds[column_idx];
        group.state.column_folds[column_idx] = (u_col * group.u, v_col * group.u + group.v * u_col);

        self.next_group_idx += 1;
    }
}

impl<'c> LookupColumn for DebugTraceColumn<'c> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Group<'g>
        = DebugTraceGroup<'g>
    where
        Self: 'g;

    fn group<'g>(
        &'g mut self,
        _name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        self.open_group(false, f);
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        _name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'g>),
        _encoded: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        // Run only the canonical closure: both closures must describe the same
        // interaction set by contract (`DebugStructureBuilder` verifies their folds
        // agree on sampled rows), and running both here would double-count balance
        // multiplicities.
        self.open_group(true, canonical);
    }
}

// GROUP
// ================================================================================================

pub struct DebugTraceGroup<'g> {
    challenges: &'g Challenges<QuadFelt>,
    state: &'g mut DebugTraceState,
    u: QuadFelt,
    v: QuadFelt,
    row_idx: usize,
    column_idx: usize,
    group_idx: usize,
    /// `true` for `group_with_cached_encoding` — triggers the mutex check at group close.
    check_mutex: bool,
    active_flag_count: usize,
}

impl<'g> DebugTraceGroup<'g> {
    /// Count active flags for mutex checks. Only meaningful when `check_mutex == true`,
    /// but cheap enough to run unconditionally.
    fn track_mutex(&mut self, flag: Felt) {
        if self.check_mutex && flag != Felt::ZERO {
            self.active_flag_count += 1;
        }
    }

    /// Push one `(multiplicity, denom)` into both the balance map and the push log,
    /// with the group's current `(row, col, group)` source coordinates.
    fn record(&mut self, msg_repr: alloc::string::String, denom: QuadFelt, multiplicity: Felt) {
        *self.state.balances.entry(denom).or_insert(Felt::ZERO) += multiplicity;
        self.state.push_log.push(PushRecord {
            row: self.row_idx,
            column_idx: self.column_idx,
            group_idx: self.group_idx,
            msg_repr,
            denom,
            multiplicity,
        });
    }
}

impl<'g> LookupGroup for DebugTraceGroup<'g> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Batch<'b>
        = DebugTraceBatch<'b>
    where
        Self: 'b;

    fn insert<M>(
        &mut self,
        _name: &'static str,
        flag: Felt,
        multiplicity: Felt,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<Felt, QuadFelt>,
    {
        self.track_mutex(flag);
        if flag == Felt::ZERO {
            return;
        }
        let built = msg();
        let v_msg = built.encode(self.challenges);
        self.record(format!("{built:?}"), v_msg, multiplicity);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: Felt,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        self.track_mutex(flag);
        let active = flag != Felt::ZERO;
        let (n, d) = {
            let mut batch = DebugTraceBatch {
                challenges: self.challenges,
                state: &mut *self.state,
                active,
                n: QuadFelt::ZERO,
                d: QuadFelt::ONE,
                row_idx: self.row_idx,
                column_idx: self.column_idx,
                group_idx: self.group_idx,
            };
            build(&mut batch);
            (batch.n, batch.d)
        };
        self.u += (d - QuadFelt::ONE) * flag;
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[QuadFelt] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> QuadFelt {
        self.challenges.bus_prefix[bus_id]
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: Felt,
        multiplicity: Felt,
        encoded: impl FnOnce() -> QuadFelt,
        _deg: Deg,
    ) {
        self.track_mutex(flag);
        if flag == Felt::ZERO {
            return;
        }
        let v_msg = encoded();
        self.record("<encoded>".to_string(), v_msg, multiplicity);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }
}

// BATCH
// ================================================================================================

pub struct DebugTraceBatch<'b> {
    challenges: &'b Challenges<QuadFelt>,
    state: &'b mut DebugTraceState,
    /// `false` if the outer group's flag was zero — batch-level short-circuit for balance
    /// accumulation. `(N, D)` still tracks normally so the outer group's `(U_g, V_g)` fold
    /// stays correct.
    active: bool,
    n: QuadFelt,
    d: QuadFelt,
    /// Source coordinates inherited from the enclosing group for push-log records.
    row_idx: usize,
    column_idx: usize,
    group_idx: usize,
}

impl<'b> DebugTraceBatch<'b> {
    fn record(&mut self, msg_repr: alloc::string::String, denom: QuadFelt, multiplicity: Felt) {
        *self.state.balances.entry(denom).or_insert(Felt::ZERO) += multiplicity;
        self.state.push_log.push(PushRecord {
            row: self.row_idx,
            column_idx: self.column_idx,
            group_idx: self.group_idx,
            msg_repr,
            denom,
            multiplicity,
        });
    }
}

impl<'b> LookupBatch for DebugTraceBatch<'b> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Felt, msg: M, _deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg.encode(self.challenges);
        if self.active {
            self.record(format!("{msg:?}"), v_msg, multiplicity);
        }
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: Felt,
        encoded: impl FnOnce() -> QuadFelt,
        _deg: Deg,
    ) {
        let v_msg = encoded();
        if self.active {
            self.record("<encoded>".to_string(), v_msg, multiplicity);
        }
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }
}

// BOUNDARY EMITTER
// ================================================================================================

/// `BoundaryBuilder` impl that writes once-per-proof emissions into the same
/// [`DebugTraceState`] as the per-row `DebugTraceBuilder`. Emissions are tagged with
/// `row: usize::MAX` and `msg_repr` prefixed `[boundary:<name>]` so they're visible
/// in the report as originating outside the trace.
pub struct DebugBoundaryEmitter<'a> {
    pub(super) challenges: &'a Challenges<QuadFelt>,
    pub(super) state: &'a mut DebugTraceState,
    pub(super) public_values: &'a [Felt],
    pub(super) var_len_public_inputs: &'a [&'a [Felt]],
}

impl<'a> BoundaryBuilder for DebugBoundaryEmitter<'a> {
    type F = Felt;
    type EF = QuadFelt;

    fn public_values(&self) -> &[Felt] {
        self.public_values
    }

    fn var_len_public_inputs(&self) -> &[&[Felt]] {
        self.var_len_public_inputs
    }

    fn insert<M>(&mut self, name: &'static str, multiplicity: Felt, msg: M)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let denom = msg.encode(self.challenges);
        *self.state.balances.entry(denom).or_insert(Felt::ZERO) += multiplicity;
        self.state.push_log.push(PushRecord {
            row: usize::MAX,
            column_idx: usize::MAX,
            group_idx: usize::MAX,
            msg_repr: format!("[boundary:{name}] {msg:?}"),
            denom,
            multiplicity,
        });
    }
}

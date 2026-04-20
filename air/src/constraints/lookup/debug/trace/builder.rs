//! `DebugTraceBuilder` — the [`LookupBuilder`] adapter that updates
//! [`super::DebugTraceState`] per row of a concrete main trace.
//!
//! Pure implementation detail: instantiation happens inside
//! [`super::run_trace_walk`]. The builder, column, group, and batch handles all collapse
//! their associated types to `Felt` / `QuadFelt`.

use core::marker::PhantomData;

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::RowWindow;

use super::{
    super::super::{
        Deg, LookupBatch, LookupBuilder, LookupChallenges, LookupColumn, LookupGroup,
        LookupMessage, chiplet_air::ChipletLookupBuilder, main_air::MainLookupBuilder,
    },
    DebugTraceState, MutualExclusionViolation, accumulate_balance,
};
use crate::Felt;

// BUILDER
// ================================================================================================

/// Real-trace `LookupBuilder` that updates [`super::DebugTraceState`] per row.
pub struct DebugTraceBuilder<'a> {
    main: RowWindow<'a, Felt>,
    periodic_values: &'a [Felt],
    public_values: &'a [Felt],
    challenges: &'a LookupChallenges<QuadFelt>,
    state: &'a mut DebugTraceState,
    row_idx: usize,
    column_idx: usize,
}

impl<'a> DebugTraceBuilder<'a> {
    pub fn new(
        main: RowWindow<'a, Felt>,
        periodic_values: &'a [Felt],
        public_values: &'a [Felt],
        challenges: &'a LookupChallenges<QuadFelt>,
        state: &'a mut DebugTraceState,
        row_idx: usize,
    ) -> Self {
        Self {
            main,
            periodic_values,
            public_values,
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
    type PublicVar = Felt;

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

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    fn next_column<'c, R>(
        &'c mut self,
        f: impl FnOnce(&mut Self::Column<'c>) -> R,
        _deg: Deg,
    ) -> R {
        let col_idx = self.column_idx;
        let mut col = DebugTraceColumn {
            challenges: self.challenges,
            state: &mut *self.state,
            row_idx: self.row_idx,
            column_idx: col_idx,
            next_group_idx: 0,
        };
        let result = f(&mut col);
        self.column_idx += 1;
        result
    }
}

impl<'a> MainLookupBuilder for DebugTraceBuilder<'a> {}
impl<'a> ChipletLookupBuilder for DebugTraceBuilder<'a> {}

// COLUMN
// ================================================================================================

pub struct DebugTraceColumn<'c> {
    challenges: &'c LookupChallenges<QuadFelt>,
    state: &'c mut DebugTraceState,
    row_idx: usize,
    column_idx: usize,
    next_group_idx: usize,
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
        let group_idx = self.next_group_idx;
        let column_idx = self.column_idx;
        // The fold write and any mutex logging happen via `group.state` while the group is
        // still live — the column's `&mut self.state` reborrow is pinned to the GAT
        // lifetime `'g`, so `self.state` is unreachable outside this block.
        {
            let mut group = DebugTraceGroup {
                challenges: self.challenges,
                state: &mut *self.state,
                u: QuadFelt::ONE,
                v: QuadFelt::ZERO,
                row_idx: self.row_idx,
                column_idx,
                group_idx,
                check_mutex: false,
                active_flag_count: 0,
            };
            f(&mut group);
            let (u, v) = (group.u, group.v);
            group.state.fold_group(column_idx, u, v);
        }
        self.next_group_idx += 1;
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        _name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'g>),
        _encoded: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        // Run only the canonical closure on the real trace side — both closures describe
        // the same interaction set by contract, and `DebugStructureBuilder` already
        // verifies their `(U_g, V_g)` folds agree on sampled rows. Running both here
        // would double-count balance multiplicities.
        let group_idx = self.next_group_idx;
        let column_idx = self.column_idx;
        let row_idx = self.row_idx;
        {
            let mut group = DebugTraceGroup {
                challenges: self.challenges,
                state: &mut *self.state,
                u: QuadFelt::ONE,
                v: QuadFelt::ZERO,
                row_idx,
                column_idx,
                group_idx,
                check_mutex: true,
                active_flag_count: 0,
            };
            canonical(&mut group);
            let (u, v) = (group.u, group.v);
            if group.check_mutex && group.active_flag_count > 1 {
                let active_flags = group.active_flag_count;
                group.state.mutex_violations.push(MutualExclusionViolation {
                    row: row_idx,
                    column_idx,
                    group_idx,
                    active_flags,
                });
            }
            group.state.fold_group(column_idx, u, v);
        }
        self.next_group_idx += 1;
    }
}

// GROUP
// ================================================================================================

pub struct DebugTraceGroup<'g> {
    challenges: &'g LookupChallenges<QuadFelt>,
    state: &'g mut DebugTraceState,
    u: QuadFelt,
    v: QuadFelt,
    row_idx: usize,
    column_idx: usize,
    group_idx: usize,
    /// Whether this group is a `group_with_cached_encoding` and should count active flags.
    check_mutex: bool,
    active_flag_count: usize,
}

impl<'g> DebugTraceGroup<'g> {
    fn track_mutex(&mut self, flag: Felt) {
        if self.check_mutex && flag != Felt::ZERO {
            self.active_flag_count += 1;
        }
        // Keep context fields live so a future mutex-violation log site has them available.
        let _ = (self.row_idx, self.column_idx, self.group_idx);
    }
}

impl<'g> LookupGroup for DebugTraceGroup<'g> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Batch<'b>
        = DebugTraceBatch<'b>
    where
        Self: 'b;

    fn add<M>(&mut self, _name: &'static str, flag: Felt, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        self.track_mutex(flag);
        if flag == Felt::ZERO {
            return;
        }
        let v_msg = msg().encode(self.challenges);
        accumulate_balance(self.state, v_msg, Felt::ONE);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag;
    }

    fn remove<M>(&mut self, _name: &'static str, flag: Felt, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        self.track_mutex(flag);
        if flag == Felt::ZERO {
            return;
        }
        let v_msg = msg().encode(self.challenges);
        accumulate_balance(self.state, v_msg, Felt::NEG_ONE);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v -= flag;
    }

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
        let v_msg = msg().encode(self.challenges);
        accumulate_balance(self.state, v_msg, multiplicity);
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
                _phantom: PhantomData,
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
        accumulate_balance(self.state, v_msg, multiplicity);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }
}

// BATCH
// ================================================================================================

pub struct DebugTraceBatch<'b> {
    challenges: &'b LookupChallenges<QuadFelt>,
    state: &'b mut DebugTraceState,
    /// `false` if the outer group's flag was zero — batch-level short-circuit for balance
    /// accumulation. `(N, D)` still tracks normally so the outer group's `(U_g, V_g)` fold
    /// stays correct.
    active: bool,
    n: QuadFelt,
    d: QuadFelt,
    _phantom: PhantomData<&'b ()>,
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
            accumulate_balance(self.state, v_msg, multiplicity);
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
            accumulate_balance(self.state, v_msg, multiplicity);
        }
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }
}

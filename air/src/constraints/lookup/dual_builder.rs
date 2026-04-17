//! Test-only [`LookupBuilder`] that runs both closures of
//! [`LookupColumn::group_with_cached_encoding`] and compares their
//! `(U_g, V_g)` contributions bit-for-bit.
//!
//! This builder is used by the `miden_lookup_air_cached_encoding_equivalence`
//! test to prove that, for every `col.group_with_cached_encoding(canonical,
//! encoded)` call inside any of the 8 Miden buses, the two closures produce
//! bitwise-identical accumulator pairs on every random main-trace row.
//!
//! Unlike [`ConstraintLookupBuilder`](super::ConstraintLookupBuilder) (which
//! runs only the `encoded` closure) and
//! [`ProverLookupBuilder`](super::ProverLookupBuilder) (which runs only the
//! `canonical` closure), this builder runs both and asserts they agree.
//! The arithmetic mirrors the constraint-path formulas from
//! [`super::constraint`] verbatim — no flag-zero short-circuit, so every
//! update step is evaluated for every interaction.
//!
//! ## Scope
//!
//! Only per-group equivalence is checked. The test does NOT fold group
//! contributions into a column-level `(U, V)` pair (cross-multiplication) —
//! that concern is covered by the existing degree-budget test.

#![cfg(test)]

use alloc::vec::Vec;
use core::marker::PhantomData;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::stark::air::RowWindow;

use super::{
    Deg, LookupBatch, LookupBuilder, LookupChallenges, LookupColumn, LookupGroup, LookupMessage,
    chiplet_air::ChipletLookupBuilder, main_air::MainLookupBuilder,
};

// GROUP MISMATCH
// ================================================================================================

/// Captured mismatch between the canonical and encoded closures of a single
/// `group_with_cached_encoding` call.
#[derive(Debug)]
pub struct GroupMismatch {
    pub column_idx: usize,
    pub group_idx: usize,
    pub u_canonical: QuadFelt,
    pub v_canonical: QuadFelt,
    pub u_encoded: QuadFelt,
    pub v_encoded: QuadFelt,
}

// DUAL BUILDER
// ================================================================================================

/// Test-only [`LookupBuilder`] that compares the canonical vs encoded
/// closures of every `group_with_cached_encoding` call.
///
/// Every associated type collapses to [`Felt`] / [`QuadFelt`] (same shape
/// as [`super::ProverLookupBuilder`]). The builder owns a mutable borrow
/// of a [`Vec<GroupMismatch>`] the caller provides; mismatches detected
/// inside `group_with_cached_encoding` are pushed onto it.
pub struct DualBuilder<'a> {
    main: RowWindow<'a, Felt>,
    periodic_values: &'a [Felt],
    public_values: &'a [Felt],
    challenges: &'a LookupChallenges<QuadFelt>,
    mismatches: &'a mut Vec<GroupMismatch>,
    column_idx: usize,
    group_idx_within_column: usize,
}

impl<'a> DualBuilder<'a> {
    pub fn new(
        main: RowWindow<'a, Felt>,
        periodic_values: &'a [Felt],
        public_values: &'a [Felt],
        challenges: &'a LookupChallenges<QuadFelt>,
        mismatches: &'a mut Vec<GroupMismatch>,
    ) -> Self {
        Self {
            main,
            periodic_values,
            public_values,
            challenges,
            mismatches,
            column_idx: 0,
            group_idx_within_column: 0,
        }
    }
}

impl<'a> LookupBuilder for DualBuilder<'a> {
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
        = DualColumn<'c>
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
        // Reset the group counter at the start of every column so each
        // `GroupMismatch` carries a column-local index.
        self.group_idx_within_column = 0;
        let column_idx = self.column_idx;
        let mut col = DualColumn {
            challenges: self.challenges,
            mismatches: &mut *self.mismatches,
            column_idx,
            group_idx_within_column: &mut self.group_idx_within_column,
        };
        let result = f(&mut col);
        self.column_idx += 1;
        result
    }
}

// EXTENSION TRAIT IMPLS
// ================================================================================================

// Empty impls pick up the default polynomial bodies of `build_op_flags` /
// `build_chiplet_active`. The dual builder is test-only, so it always runs through the
// polynomial path.

impl<'a> MainLookupBuilder for DualBuilder<'a> {}

impl<'a> ChipletLookupBuilder for DualBuilder<'a> {}

// DUAL COLUMN
// ================================================================================================

/// Per-column handle for [`DualBuilder`].
///
/// Holds no running `(U, V)` pair — the test only compares per-group
/// contributions, not column-level folds. Each `group` or
/// `group_with_cached_encoding` call runs its closure against a fresh
/// [`DualGroup`] seeded with `(u, v) = (ONE, ZERO)`.
pub struct DualColumn<'c> {
    challenges: &'c LookupChallenges<QuadFelt>,
    mismatches: &'c mut Vec<GroupMismatch>,
    column_idx: usize,
    group_idx_within_column: &'c mut usize,
}

impl<'c> LookupColumn for DualColumn<'c> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Group<'g>
        = DualGroup<'g>
    where
        Self: 'g;

    fn group<'g>(
        &'g mut self,
        _name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        // Non-cached group: no dual-closure comparison possible, so just
        // run the closure against a fresh `DualGroup` and bump the
        // counter. The final `(u, v)` is discarded — we only fold
        // per-group `(U_g, V_g)` into a column pair in the canonical
        // adapters, and this test doesn't care about column-level folds.
        let mut group = DualGroup {
            challenges: self.challenges,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
            _phantom: PhantomData,
        };
        f(&mut group);
        *self.group_idx_within_column += 1;
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        _name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'g>),
        encoded: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        // Run both closures against their own independent state machines
        // seeded to `(u, v) = (ONE, ZERO)`, then compare the final pairs.
        let mut g_canonical = DualGroup {
            challenges: self.challenges,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
            _phantom: PhantomData,
        };
        let mut g_encoded = DualGroup {
            challenges: self.challenges,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
            _phantom: PhantomData,
        };

        canonical(&mut g_canonical);
        encoded(&mut g_encoded);

        if g_canonical.u != g_encoded.u || g_canonical.v != g_encoded.v {
            self.mismatches.push(GroupMismatch {
                column_idx: self.column_idx,
                group_idx: *self.group_idx_within_column,
                u_canonical: g_canonical.u,
                v_canonical: g_canonical.v,
                u_encoded: g_encoded.u,
                v_encoded: g_encoded.v,
            });
        }
        *self.group_idx_within_column += 1;
    }
}

// DUAL GROUP (simple path)
// ================================================================================================

/// Canonical-path group handle for [`DualColumn`].
///
/// Mirrors [`super::constraint::ConstraintGroup`] verbatim — same
/// `(U_g, V_g)` update formulas, no flag-zero short-circuit. Used for
/// both the plain `group(f)` path and the canonical closure of
/// `group_with_cached_encoding`.
pub struct DualGroup<'g> {
    challenges: &'g LookupChallenges<QuadFelt>,
    u: QuadFelt,
    v: QuadFelt,
    _phantom: PhantomData<&'g ()>,
}

impl<'g> LookupGroup for DualGroup<'g> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Batch<'b>
        = DualBatch<'b>
    where
        Self: 'b;

    fn insert<M>(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // General case: `V_g += flag · multiplicity`.
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: Self::Expr,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        // Same batch algebra as `ConstraintGroup::batch`: start with
        // `(N, D) = (0, 1)`, run `build`, then fold the final `(N, D)`
        // into `(U_g, V_g)` via
        // `U_g += (D − 1) · flag`, `V_g += N · flag`.
        let mut batch = DualBatch {
            challenges: self.challenges,
            n: QuadFelt::ZERO,
            d: QuadFelt::ONE,
            _phantom: PhantomData,
        };
        build(&mut batch);
        let DualBatch { n, d, .. } = batch;
        self.u += (d - QuadFelt::ONE) * flag;
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[Self::ExprEF] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        self.challenges.bus_prefix[bus_id]
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        // Same update formula as `insert`, but the denominator is
        // user-supplied instead of coming from `LookupMessage::encode`.
        let v_msg = encoded();
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }
}

// DUAL BATCH
// ================================================================================================

/// Batch handle for [`DualGroup`].
///
/// Mirrors [`super::constraint::ConstraintBatch`]: tracks an internal
/// `(N, D)` pair and absorbs each interaction via the cross-multiplication
/// rule `N' = N·v + m·D`, `D' = D·v`. The outer group folds the final
/// `(N, D)` into its `(U_g, V_g)` using the batch's outer flag.
pub struct DualBatch<'b> {
    challenges: &'b LookupChallenges<QuadFelt>,
    n: QuadFelt,
    d: QuadFelt,
    _phantom: PhantomData<&'b ()>,
}

impl<'b> LookupBatch for DualBatch<'b> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Self::Expr, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // General case: `(N, D) ← (N·v + m·D, D·v)`.
        let v_msg = msg.encode(self.challenges);
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        // Same as `insert`, but the denominator is user-supplied.
        let v_msg = encoded();
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }
}

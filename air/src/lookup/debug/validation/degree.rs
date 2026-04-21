//! Symbolic `(U, V)` fold walker that cross-checks declared per-group / per-column
//! [`Deg`] annotations against the degrees the symbolic expressions actually carry.
//!
//! Mirrors the structural template of
//! [`ConstraintLookupBuilder`](super::super::super::ConstraintLookupBuilder)
//! — same `(U, V)` algebra, same column / group / batch split — but never asks the
//! inner [`SymbolicAirBuilder`] to emit constraints. All we do with the symbolic
//! `(U, V)` is call [`SymbolicExpression::degree_multiple`] on it at each group /
//! column close and fail fast if the observed numerator / denominator degree exceeds
//! the inline [`Deg`] the author declared.

use core::marker::PhantomData;

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::{
    AirBuilder, PeriodicAirBuilder, PermutationAirBuilder,
    symbolic::{
        SymbolicAirBuilder, SymbolicExpression, SymbolicExpressionExt, SymbolicVariable,
        SymbolicVariableExt,
    },
};

use super::{
    super::super::{
        Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
        LookupMessage,
    },
    ValidationError,
};
use crate::Felt;

type Inner = SymbolicAirBuilder<Felt, QuadFelt>;
type Expr = SymbolicExpression<Felt>;
type ExprEF = SymbolicExpressionExt<Felt, QuadFelt>;

// BUILDER
// ================================================================================================

/// Symbolic walker that measures every group and column `(U, V)` degree against the
/// declared [`Deg`] and stashes the first mismatch.
///
/// The first error is preserved in [`Self::take_error`]; any later mismatch is ignored
/// so [`validate`](super::validate) can short-circuit cleanly once the outer
/// [`LookupAir::eval`] returns.
pub struct DegreeCheckBuilder<'ab> {
    ab: &'ab mut Inner,
    challenges: Challenges<ExprEF>,
    column_idx: usize,
    declared_columns: usize,
    error: Option<ValidationError>,
}

impl<'ab> DegreeCheckBuilder<'ab> {
    pub fn new<A>(ab: &'ab mut Inner, air: &A) -> Self
    where
        A: LookupAir<Self>,
    {
        let (alpha, beta): (ExprEF, ExprEF) = {
            let r = ab.permutation_randomness();
            (r[0].into(), r[1].into())
        };
        let challenges =
            Challenges::<ExprEF>::new(alpha, beta, air.max_message_width(), air.num_bus_ids());
        Self {
            ab,
            challenges,
            column_idx: 0,
            declared_columns: air.num_columns(),
            error: None,
        }
    }

    /// Consume the walker and return the first recorded error, if any. Called after
    /// [`LookupAir::eval`] returns.
    pub fn take_error(mut self) -> Option<ValidationError> {
        if self.error.is_none() && self.column_idx != self.declared_columns {
            self.error = Some(ValidationError::NumColumnsMismatch {
                declared: self.declared_columns,
                observed: self.column_idx,
            });
        }
        self.error
    }
}

impl<'ab> LookupBuilder for DegreeCheckBuilder<'ab> {
    type F = Felt;
    type Expr = Expr;
    type Var = SymbolicVariable<Felt>;

    type EF = QuadFelt;
    type ExprEF = ExprEF;
    type VarEF = SymbolicVariableExt<Felt, QuadFelt>;

    type PeriodicVar = SymbolicVariable<Felt>;

    type MainWindow = <Inner as AirBuilder>::MainWindow;

    type Column<'c>
        = DegreeCheckColumn<'c>
    where
        Self: 'c;

    fn main(&self) -> Self::MainWindow {
        self.ab.main()
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.ab.periodic_values()
    }

    fn next_column<'c, R>(&'c mut self, f: impl FnOnce(&mut Self::Column<'c>) -> R, deg: Deg) -> R {
        let column_idx = self.column_idx;
        self.column_idx += 1;

        let already_errored = self.error.is_some();
        let mut col = DegreeCheckColumn {
            challenges: &self.challenges,
            u: ExprEF::ONE,
            v: ExprEF::ZERO,
            column_idx,
            next_group_idx: 0,
            error: None,
            _phantom: PhantomData,
        };
        let result = f(&mut col);

        // Bubble up the first error observed at any level.
        if !already_errored {
            if let Some(err) = col.error.take() {
                self.error = Some(err);
            } else {
                let observed = Deg {
                    n: col.v.degree_multiple(),
                    d: col.u.degree_multiple(),
                };
                if observed.n > deg.n || observed.d > deg.d {
                    self.error = Some(ValidationError::ColumnDegreeMismatch {
                        column_idx,
                        declared: deg,
                        observed,
                    });
                }
            }
        }

        result
    }
}

// COLUMN
// ================================================================================================

pub struct DegreeCheckColumn<'c> {
    challenges: &'c Challenges<ExprEF>,
    u: ExprEF,
    v: ExprEF,
    column_idx: usize,
    next_group_idx: usize,
    /// First group-level error observed while walking this column, drained by
    /// [`DegreeCheckBuilder::next_column`] after the closure returns.
    error: Option<ValidationError>,
    _phantom: PhantomData<&'c ()>,
}

impl<'c> DegreeCheckColumn<'c> {
    fn fold_group(&mut self, u_g: ExprEF, v_g: ExprEF) {
        self.v = self.v.clone() * u_g.clone() + v_g * self.u.clone();
        self.u = self.u.clone() * u_g;
    }

    fn check_group(
        &mut self,
        name: &'static str,
        group_idx: usize,
        declared: Deg,
        u: &ExprEF,
        v: &ExprEF,
    ) {
        if self.error.is_some() {
            return;
        }
        let observed = Deg {
            n: v.degree_multiple(),
            d: u.degree_multiple(),
        };
        if observed.n > declared.n || observed.d > declared.d {
            self.error = Some(ValidationError::GroupDegreeMismatch {
                column_idx: self.column_idx,
                group_idx,
                name,
                declared,
                observed,
            });
        }
    }
}

impl<'c> LookupColumn for DegreeCheckColumn<'c> {
    type Expr = Expr;
    type ExprEF = ExprEF;

    type Group<'g>
        = DegreeCheckGroup<'g>
    where
        Self: 'g;

    fn group<'g>(&'g mut self, name: &'static str, f: impl FnOnce(&mut Self::Group<'g>), deg: Deg) {
        let group_idx = self.next_group_idx;
        self.next_group_idx += 1;

        let mut group = DegreeCheckGroup {
            challenges: self.challenges,
            u: ExprEF::ONE,
            v: ExprEF::ZERO,
        };
        f(&mut group);
        let DegreeCheckGroup { u, v, .. } = group;
        self.check_group(name, group_idx, deg, &u, &v);
        self.fold_group(u, v);
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        name: &'static str,
        _canonical: impl FnOnce(&mut Self::Group<'g>),
        encoded: impl FnOnce(&mut Self::Group<'g>),
        deg: Deg,
    ) {
        let group_idx = self.next_group_idx;
        self.next_group_idx += 1;

        // Degree check uses the `encoded` closure, consistent with the production
        // constraint path which also only evaluates `encoded` and discards `canonical`.
        let mut group = DegreeCheckGroup {
            challenges: self.challenges,
            u: ExprEF::ONE,
            v: ExprEF::ZERO,
        };
        encoded(&mut group);
        let DegreeCheckGroup { u, v, .. } = group;
        self.check_group(name, group_idx, deg, &u, &v);
        self.fold_group(u, v);
    }
}

// GROUP
// ================================================================================================

pub struct DegreeCheckGroup<'g> {
    challenges: &'g Challenges<ExprEF>,
    u: ExprEF,
    v: ExprEF,
}

impl<'g> LookupGroup for DegreeCheckGroup<'g> {
    type Expr = Expr;
    type ExprEF = ExprEF;

    type Batch<'b>
        = DegreeCheckBatch<'b>
    where
        Self: 'b;

    fn add<M>(&mut self, _name: &'static str, flag: Expr, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<Expr, ExprEF>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - ExprEF::ONE) * flag.clone();
        self.v += flag;
    }

    fn remove<M>(&mut self, _name: &'static str, flag: Expr, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<Expr, ExprEF>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - ExprEF::ONE) * flag.clone();
        self.v -= flag;
    }

    fn insert<M>(
        &mut self,
        _name: &'static str,
        flag: Expr,
        multiplicity: Expr,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<Expr, ExprEF>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - ExprEF::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: Expr,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        let mut batch = DegreeCheckBatch {
            challenges: self.challenges,
            n: ExprEF::ZERO,
            d: ExprEF::ONE,
        };
        build(&mut batch);
        let DegreeCheckBatch { n, d, .. } = batch;
        self.u += (d - ExprEF::ONE) * flag.clone();
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[ExprEF] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> ExprEF {
        self.challenges.bus_prefix[bus_id].clone()
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: Expr,
        multiplicity: Expr,
        encoded: impl FnOnce() -> ExprEF,
        _deg: Deg,
    ) {
        let v_msg = encoded();
        self.u += (v_msg - ExprEF::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }
}

// BATCH
// ================================================================================================

pub struct DegreeCheckBatch<'b> {
    challenges: &'b Challenges<ExprEF>,
    n: ExprEF,
    d: ExprEF,
}

impl<'b> LookupBatch for DegreeCheckBatch<'b> {
    type Expr = Expr;
    type ExprEF = ExprEF;

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Expr, msg: M, _deg: Deg)
    where
        M: LookupMessage<Expr, ExprEF>,
    {
        let v_msg = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v_msg.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v_msg;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: Expr,
        encoded: impl FnOnce() -> ExprEF,
        _deg: Deg,
    ) {
        let v_msg = encoded();
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v_msg.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v_msg;
    }
}

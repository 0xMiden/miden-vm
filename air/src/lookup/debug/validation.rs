//! Single AIR self-validation entry point, backed by one unified walker.
//!
//! Exposes one free function, [`validate`], and one extension trait,
//! [`ValidateLookupAir`], so any qualifying [`LookupAir`] can be checked with
//! `air.validate(layout)`. One short-circuit [`Result<(), ValidationError>`] covers:
//!
//! - `num_columns` declared vs observed (the walker counts `next_column` calls).
//! - Per-group and per-column `Deg { n, d }` declared vs observed (via
//!   [`SymbolicExpression::degree_multiple`] on the running `(U, V)`).
//! - Cached-encoding canonical vs encoded `(U, V)` equivalence, checked by evaluating the symbolic
//!   difference `U_c·V_e − U_e·V_c` at a random row.
//! - Simple-group scope: no illegal `insert_encoded` outside the `encoded` closure.
//!
//! The global max-degree budget is **not** checked here — the STARK prover's
//! quotient validation already enforces it and duplicating that check muddies
//! this module's purpose.
//!
//! # Why one walker
//!
//! Previously two walkers ran back-to-back over the same `LookupAir::eval` —
//! one symbolic (degree), one concrete (encoding equivalence). They shared the
//! same `(U, V)` fold algebra. Because [`SymbolicExpression`] is a closed
//! `{Leaf, Add, Sub, Neg, Mul}` tree whose leaves can be mapped to concrete
//! field elements given a row valuation, we keep just the symbolic
//! accumulators and evaluate the cached-encoding difference on demand at a
//! random row. Speed is a non-goal here; the `Arc` allocations in the
//! symbolic tree are debug-only.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::{
    rand::random_felt,
    stark::air::{
        AirBuilder, PeriodicAirBuilder, PermutationAirBuilder,
        symbolic::{
            BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicAirBuilder, SymbolicExpr,
            SymbolicExpression, SymbolicExpressionExt, SymbolicVariable, SymbolicVariableExt,
        },
    },
};

use super::super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
    LookupMessage,
};
use crate::Felt;

type Inner = SymbolicAirBuilder<Felt, QuadFelt>;
type Expr = SymbolicExpression<Felt>;
type ExprEF = SymbolicExpressionExt<Felt, QuadFelt>;

// VALIDATION ERROR
// ================================================================================================

/// First problem [`validate`] observed. See the module docstring for the per-check
/// semantics; each variant corresponds to one of the checks.
#[derive(Clone, Debug)]
pub enum ValidationError {
    /// [`LookupAir::num_columns`] disagreed with the number of `next_column` calls
    /// issued by `eval`.
    NumColumnsMismatch { declared: usize, observed: usize },
    /// A column's declared `Deg` differs from the observed symbolic degree of
    /// its accumulated `(U, V)`. Declared degrees are authoritative and must
    /// match exactly — loose upper bounds are rejected.
    ColumnDegreeMismatch {
        column_idx: usize,
        declared: Deg,
        observed: Deg,
    },
    /// A group's declared `Deg` differs from the observed symbolic degree of
    /// the group's `(U, V)` fold. Declared degrees are authoritative and must
    /// match exactly — loose upper bounds are rejected.
    GroupDegreeMismatch {
        column_idx: usize,
        group_idx: usize,
        name: &'static str,
        declared: Deg,
        observed: Deg,
    },
    /// A cached-encoding group's canonical and encoded closures produced different
    /// `(U, V)` pairs: the symbolic difference `U_c·V_e − U_e·V_c` evaluated to a
    /// non-zero `QuadFelt` at the sampled random row.
    EncodingMismatch {
        column_idx: usize,
        group_idx: usize,
        name: &'static str,
        diff: QuadFelt,
    },
    /// A simple-mode group called `insert_encoded`, which is only legal inside the
    /// `encoded` closure of `group_with_cached_encoding`.
    ScopeViolation {
        column_idx: usize,
        group_idx: usize,
        name: &'static str,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NumColumnsMismatch { declared, observed } => {
                write!(f, "num_columns mismatch: declared {declared}, observed {observed}")
            },
            Self::ColumnDegreeMismatch { column_idx, declared, observed } => write!(
                f,
                "column[{column_idx}] degree mismatch: declared (n={}, d={}), observed (n={}, d={})",
                declared.n, declared.d, observed.n, observed.d,
            ),
            Self::GroupDegreeMismatch {
                column_idx,
                group_idx,
                name,
                declared,
                observed,
            } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} degree mismatch: declared (n={}, d={}), observed (n={}, d={})",
                declared.n, declared.d, observed.n, observed.d,
            ),
            Self::EncodingMismatch { column_idx, group_idx, name, diff } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} cached-encoding mismatch: U_c·V_e − U_e·V_c = {diff:?}",
            ),
            Self::ScopeViolation { column_idx, group_idx, name } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} simple group called insert_encoded",
            ),
        }
    }
}

// LAYOUT
// ================================================================================================

/// Subset of the full `AirLayout` struct that [`validate`] actually consumes. Kept
/// local so callers don't need to thread prover-only fields (permutation width,
/// committed final count) through just to run the self-check.
#[derive(Clone, Copy, Debug)]
pub struct ValidateLayout {
    pub trace_width: usize,
    pub num_public_values: usize,
    pub num_periodic_columns: usize,
    pub permutation_width: usize,
    pub num_permutation_challenges: usize,
    pub num_permutation_values: usize,
}

impl ValidateLayout {
    fn to_symbolic(self) -> miden_crypto::stark::air::symbolic::AirLayout {
        miden_crypto::stark::air::symbolic::AirLayout {
            preprocessed_width: 0,
            main_width: self.trace_width,
            num_public_values: self.num_public_values,
            permutation_width: self.permutation_width,
            num_permutation_challenges: self.num_permutation_challenges,
            num_permutation_values: self.num_permutation_values,
            num_periodic_columns: self.num_periodic_columns,
        }
    }
}

// VALIDATE
// ================================================================================================

/// Run every AIR self-check in one walk.
///
/// Short-circuits on the first problem. See [`ValidationError`] for the variants.
pub fn validate<A>(air: &A, layout: ValidateLayout) -> Result<(), ValidationError>
where
    for<'ab, 'r> A: LookupAir<ValidationBuilder<'ab, 'r>>,
{
    // Sample a single random row valuation shared by the symbolic and concrete
    // sides. `alpha`/`beta` are instantiated twice: once as symbolic `Challenge`
    // leaves inside `SymbolicAirBuilder::permutation_randomness`, and once as
    // concrete `QuadFelt`s in `row_valuation`. The evaluator below maps
    // `ExtEntry::Challenge { index: 0/1 }` back to these concrete values.
    let current: Vec<Felt> = (0..layout.trace_width).map(|_| random_felt()).collect();
    let next: Vec<Felt> = (0..layout.trace_width).map(|_| random_felt()).collect();
    let periodic: Vec<Felt> = (0..layout.num_periodic_columns).map(|_| random_felt()).collect();
    let alpha = QuadFelt::new([random_felt(), random_felt()]);
    let beta = QuadFelt::new([random_felt(), random_felt()]);

    let mut sym = SymbolicAirBuilder::<Felt, QuadFelt>::new(layout.to_symbolic());
    let row_valuation = RowValuation {
        current: &current,
        next: &next,
        periodic: &periodic,
        alpha,
        beta,
    };
    let mut builder = ValidationBuilder::new(&mut sym, air, row_valuation);
    air.eval(&mut builder);
    match builder.take_error() {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

// EXTENSION TRAIT
// ================================================================================================

/// Extension trait that adapts [`validate`] into a method on any qualifying
/// [`LookupAir`]. Call sites write `MyLookupAir.validate(layout)` instead of
/// `validate(&MyLookupAir, layout)`.
pub trait ValidateLookupAir {
    fn validate(&self, layout: ValidateLayout) -> Result<(), ValidationError>;
}

impl<A> ValidateLookupAir for A
where
    for<'ab, 'r> A: LookupAir<ValidationBuilder<'ab, 'r>>,
{
    fn validate(&self, layout: ValidateLayout) -> Result<(), ValidationError> {
        validate(self, layout)
    }
}

// ROW VALUATION
// ================================================================================================

/// Concrete valuation used to evaluate symbolic `(U, V)` trees when the walker
/// needs a numeric answer (cached-encoding equivalence). Borrowed, so construction
/// is cheap and the walker's lifetime tracks the owning `Vec`s in [`validate`].
#[derive(Clone, Copy)]
struct RowValuation<'r> {
    current: &'r [Felt],
    next: &'r [Felt],
    periodic: &'r [Felt],
    /// `Challenge[0]` in any `SymbolicExpressionExt` tree.
    alpha: QuadFelt,
    /// `Challenge[1]` in any `SymbolicExpressionExt` tree.
    beta: QuadFelt,
}

impl<'r> RowValuation<'r> {
    fn eval_base(&self, expr: &Expr) -> Felt {
        match expr {
            SymbolicExpr::Leaf(leaf) => self.eval_base_leaf(leaf),
            SymbolicExpr::Add { x, y, .. } => self.eval_base(x) + self.eval_base(y),
            SymbolicExpr::Sub { x, y, .. } => self.eval_base(x) - self.eval_base(y),
            SymbolicExpr::Neg { x, .. } => -self.eval_base(x),
            SymbolicExpr::Mul { x, y, .. } => self.eval_base(x) * self.eval_base(y),
        }
    }

    fn eval_base_leaf(&self, leaf: &BaseLeaf<Felt>) -> Felt {
        match leaf {
            BaseLeaf::Constant(c) => *c,
            BaseLeaf::Variable(SymbolicVariable { entry, index, .. }) => match entry {
                BaseEntry::Main { offset: 0 } => self.current[*index],
                BaseEntry::Main { offset: 1 } => self.next[*index],
                BaseEntry::Periodic => self.periodic[*index],
                BaseEntry::Main { offset } => {
                    panic!("unexpected main offset {offset} in LookupAir::eval")
                },
                // LookupBuilder doesn't expose preprocessed or public values, and
                // LookupAir::eval can't construct these leaves.
                BaseEntry::Preprocessed { .. } | BaseEntry::Public => {
                    panic!("unexpected {entry:?} leaf in LookupAir::eval")
                },
            },
            // Selector leaves are only produced by `AirBuilder::is_first_row` / etc.,
            // which LookupBuilder does not expose.
            BaseLeaf::IsFirstRow | BaseLeaf::IsLastRow | BaseLeaf::IsTransition => {
                panic!("selector leaf {leaf:?} unexpected in LookupAir::eval")
            },
        }
    }

    fn eval_ext(&self, expr: &ExprEF) -> QuadFelt {
        match expr {
            SymbolicExpr::Leaf(leaf) => self.eval_ext_leaf(leaf),
            SymbolicExpr::Add { x, y, .. } => self.eval_ext(x) + self.eval_ext(y),
            SymbolicExpr::Sub { x, y, .. } => self.eval_ext(x) - self.eval_ext(y),
            SymbolicExpr::Neg { x, .. } => -self.eval_ext(x),
            SymbolicExpr::Mul { x, y, .. } => self.eval_ext(x) * self.eval_ext(y),
        }
    }

    fn eval_ext_leaf(&self, leaf: &ExtLeaf<Felt, QuadFelt>) -> QuadFelt {
        match leaf {
            ExtLeaf::Base(inner) => self.eval_base(inner).into(),
            ExtLeaf::ExtConstant(c) => *c,
            ExtLeaf::ExtVariable(SymbolicVariableExt { entry, index, .. }) => match entry {
                ExtEntry::Challenge => match *index {
                    0 => self.alpha,
                    1 => self.beta,
                    i => panic!("unexpected challenge index {i} in LookupAir::eval"),
                },
                // LookupBuilder doesn't expose permutation columns or permutation
                // values — the prover-side builder is the only one that touches them.
                ExtEntry::Permutation { .. } | ExtEntry::PermutationValue => {
                    panic!("unexpected {entry:?} leaf in LookupAir::eval")
                },
            },
        }
    }
}

// BUILDER
// ================================================================================================

/// Unified walker that cross-checks `(U, V)` degrees, cached-encoding equivalence,
/// and simple-group scope in a single pass over [`LookupAir::eval`]. The first
/// error observed is preserved in an internal slot; any later problem is ignored
/// so [`validate`] can short-circuit cleanly once `eval` returns.
pub struct ValidationBuilder<'ab, 'r> {
    ab: &'ab mut Inner,
    sym_challenges: Challenges<ExprEF>,
    row_valuation: RowValuation<'r>,
    column_idx: usize,
    declared_columns: usize,
    error: Option<ValidationError>,
}

impl<'ab, 'r> ValidationBuilder<'ab, 'r> {
    fn new<A>(ab: &'ab mut Inner, air: &A, row_valuation: RowValuation<'r>) -> Self
    where
        A: LookupAir<Self>,
    {
        let (alpha, beta): (ExprEF, ExprEF) = {
            let r = ab.permutation_randomness();
            (r[0].into(), r[1].into())
        };
        let sym_challenges =
            Challenges::<ExprEF>::new(alpha, beta, air.max_message_width(), air.num_bus_ids());
        Self {
            ab,
            sym_challenges,
            row_valuation,
            column_idx: 0,
            declared_columns: air.num_columns(),
            error: None,
        }
    }

    fn take_error(mut self) -> Option<ValidationError> {
        if self.error.is_none() && self.column_idx != self.declared_columns {
            self.error = Some(ValidationError::NumColumnsMismatch {
                declared: self.declared_columns,
                observed: self.column_idx,
            });
        }
        self.error
    }
}

impl<'ab, 'r> LookupBuilder for ValidationBuilder<'ab, 'r> {
    type F = Felt;
    type Expr = Expr;
    type Var = SymbolicVariable<Felt>;

    type EF = QuadFelt;
    type ExprEF = ExprEF;
    type VarEF = SymbolicVariableExt<Felt, QuadFelt>;

    type PeriodicVar = SymbolicVariable<Felt>;

    type MainWindow = <Inner as AirBuilder>::MainWindow;

    type Column<'c>
        = ValidationColumn<'c, 'r>
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
        let mut col = ValidationColumn {
            challenges: &self.sym_challenges,
            row_valuation: self.row_valuation,
            u: ExprEF::ONE,
            v: ExprEF::ZERO,
            column_idx,
            next_group_idx: 0,
            error: None,
            _phantom: PhantomData,
        };
        let result = f(&mut col);

        if !already_errored {
            if let Some(err) = col.error.take() {
                self.error = Some(err);
            } else {
                let observed = Deg {
                    n: col.v.degree_multiple(),
                    d: col.u.degree_multiple(),
                };
                if observed != deg {
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

pub struct ValidationColumn<'c, 'r> {
    challenges: &'c Challenges<ExprEF>,
    row_valuation: RowValuation<'r>,
    u: ExprEF,
    v: ExprEF,
    column_idx: usize,
    next_group_idx: usize,
    /// First group-level error observed while walking this column, drained by
    /// [`ValidationBuilder::next_column`] after the closure returns.
    error: Option<ValidationError>,
    _phantom: PhantomData<&'c ()>,
}

impl<'c, 'r> ValidationColumn<'c, 'r> {
    fn fold_group(&mut self, u_g: ExprEF, v_g: ExprEF) {
        self.v = self.v.clone() * u_g.clone() + v_g * self.u.clone();
        self.u = self.u.clone() * u_g;
    }

    fn check_group_degree(
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
        if observed != declared {
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

/// Build a fresh group scoped to `challenges`. Taken as a free function (not a
/// method) so calling it doesn't borrow the containing `ValidationColumn` —
/// the caller can still mutate `self.error` while the group is alive.
fn fresh_group<'g>(
    challenges: &'g Challenges<ExprEF>,
    inside_encoded_closure: bool,
) -> ValidationGroup<'g> {
    ValidationGroup {
        challenges,
        u: ExprEF::ONE,
        v: ExprEF::ZERO,
        inside_encoded_closure,
        used_insert_encoded: false,
    }
}

impl<'c, 'r> LookupColumn for ValidationColumn<'c, 'r> {
    type Expr = Expr;
    type ExprEF = ExprEF;

    type Group<'g>
        = ValidationGroup<'g>
    where
        Self: 'g;

    fn group<'g>(&'g mut self, name: &'static str, f: impl FnOnce(&mut Self::Group<'g>), deg: Deg) {
        let group_idx = self.next_group_idx;
        self.next_group_idx += 1;

        let mut group = fresh_group(self.challenges, false);
        f(&mut group);
        let ValidationGroup { u, v, used_insert_encoded, .. } = group;

        if self.error.is_none() && used_insert_encoded {
            self.error = Some(ValidationError::ScopeViolation {
                column_idx: self.column_idx,
                group_idx,
                name,
            });
        }
        self.check_group_degree(name, group_idx, deg, &u, &v);
        self.fold_group(u, v);
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'g>),
        encoded: impl FnOnce(&mut Self::Group<'g>),
        deg: Deg,
    ) {
        let group_idx = self.next_group_idx;
        self.next_group_idx += 1;

        let mut canon = fresh_group(self.challenges, false);
        canonical(&mut canon);

        let mut enc = fresh_group(self.challenges, true);
        encoded(&mut enc);

        // Cached-encoding equivalence: the two closures must agree on `(U, V)`
        // up to cross-multiplication, i.e. `U_c·V_e − U_e·V_c == 0`. We don't
        // rely on symbolic simplification to zero — we evaluate the difference
        // at the shared random row.
        if self.error.is_none() {
            let diff_expr = canon.u.clone() * enc.v.clone() - enc.u.clone() * canon.v;
            let diff = self.row_valuation.eval_ext(&diff_expr);
            if diff != QuadFelt::ZERO {
                self.error = Some(ValidationError::EncodingMismatch {
                    column_idx: self.column_idx,
                    group_idx,
                    name,
                    diff,
                });
            }
        }

        // Degree check and column fold use the `encoded` half, consistent with
        // the production constraint path which only emits the encoded form.
        let ValidationGroup { u, v, .. } = enc;
        self.check_group_degree(name, group_idx, deg, &u, &v);
        self.fold_group(u, v);
    }
}

// GROUP
// ================================================================================================

pub struct ValidationGroup<'g> {
    challenges: &'g Challenges<ExprEF>,
    u: ExprEF,
    v: ExprEF,
    /// Set when this group was opened via the `encoded` closure of
    /// `group_with_cached_encoding`; toggles the legal use of `insert_encoded`.
    inside_encoded_closure: bool,
    /// `true` if `insert_encoded` was called outside its legal scope. The column
    /// inspects this flag at close time and raises `ScopeViolation` if the group
    /// was simple.
    used_insert_encoded: bool,
}

impl<'g> LookupGroup for ValidationGroup<'g> {
    type Expr = Expr;
    type ExprEF = ExprEF;

    type Batch<'b>
        = ValidationBatch<'b>
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
        let mut batch = ValidationBatch {
            challenges: self.challenges,
            n: ExprEF::ZERO,
            d: ExprEF::ONE,
        };
        build(&mut batch);
        let ValidationBatch { n, d, .. } = batch;
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
        if !self.inside_encoded_closure {
            self.used_insert_encoded = true;
        }
        let v_msg = encoded();
        self.u += (v_msg - ExprEF::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }
}

// BATCH
// ================================================================================================

pub struct ValidationBatch<'b> {
    challenges: &'b Challenges<ExprEF>,
    n: ExprEF,
    d: ExprEF,
}

impl<'b> LookupBatch for ValidationBatch<'b> {
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

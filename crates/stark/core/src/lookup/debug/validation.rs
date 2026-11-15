//! Single AIR self-validation entry point, backed by one unified walker.
//!
//! Exposes one free function, [`validate`], and one extension trait,
//! [`ValidateLookupAir`], so any qualifying [`LookupAir`] can be checked with
//! `air.validate(layout)`. One short-circuit [`Result<(), ValidationError>`] covers:
//!
//! - `column_shape().len()` declared vs observed (the walker counts `next_column` calls).
//! - Per-group and per-column `Deg { v, u }` declared vs observed (via
//!   [`SymbolicExpression::degree_multiple`] on the running `(V, U)`).
//! - Cached-encoding canonical vs encoded `(V, U)` equivalence, checked by evaluating the symbolic
//!   difference `U_c·V_e − U_e·V_c` at a random row.
//! - Group scope: no illegal [`LookupGroup::insert_encoded`] outside the `encoded` closure.
//!   Encoded entries in [`LookupBatch`] retain their existing policy.
//!
//! The global max-degree budget is **not** checked here — the STARK prover's
//! quotient validation already enforces it, and duplicating that check would
//! blur this module's purpose.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use miden_crypto::{
    Felt,
    field::{Algebra, BinomialExtensionField, PrimeCharacteristicRing},
};
use rand::RngExt;

use super::super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
    LookupMessage,
};
use crate::air::native;
use crate::air::{
    AirBuilder, PermutationAirBuilder,
    symbolic::{
        BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicAirBuilder, SymbolicExpr,
        SymbolicExpression, SymbolicExpressionExt, SymbolicVariable, SymbolicVariableExt,
    },
};
use crate::lookup::native as native_lookup;

type QuadFelt = BinomialExtensionField<Felt, 2>;
type Inner = SymbolicAirBuilder<Felt, QuadFelt>;
type Expr = SymbolicExpression<Felt>;
type ExprEF = SymbolicExpressionExt<Felt, QuadFelt>;
type NativeExpr = native::symbolic::SymbolicExpression<Felt>;
type NativeExprEF = native::symbolic::SymbolicExpressionExt<Felt, QuadFelt>;

// VALIDATION ERROR
// ================================================================================================

/// First problem [`validate`] observed. See the module docstring for the per-check
/// semantics; each variant corresponds to one of the checks.
#[derive(Clone, Debug)]
pub enum ValidationError {
    /// Invalid native schema, rejected before allocating symbolic rows or sampling a valuation.
    Spec(native::SpecError),
    /// Lookup challenge encoding requires the alpha/beta prefix.
    Challenges { declared: usize },
    /// [`LookupAir::column_shape`] disagreed with the number of `next_column` calls issued by
    /// `eval`.
    NumColumnsMismatch { declared: usize, observed: usize },
    /// A column's declared `Deg` differs from the observed symbolic degree of
    /// its accumulated `(V, U)`. Declared degrees are authoritative and must
    /// match exactly — loose upper bounds are rejected.
    ColumnDegreeMismatch {
        column_idx: usize,
        declared: Deg,
        observed: Deg,
    },
    /// A group's declared `Deg` differs from the observed symbolic degree of
    /// the group's `(V, U)` fold. Declared degrees are authoritative and must
    /// match exactly — loose upper bounds are rejected.
    GroupDegreeMismatch {
        column_idx: usize,
        group_idx: usize,
        name: &'static str,
        declared: Deg,
        observed: Deg,
    },
    /// A cached-encoding group's canonical and encoded closures produced different
    /// `(V, U)` pairs: the symbolic difference `V_c·U_e − V_e·U_c` evaluated to a
    /// non-zero `QuadFelt` at the sampled random row.
    EncodingMismatch {
        column_idx: usize,
        group_idx: usize,
        name: &'static str,
        diff: QuadFelt,
    },
    /// A simple or canonical group called `insert_encoded`, which is only legal inside the
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
            Self::Spec(error) => fmt::Display::fmt(error, f),
            Self::Challenges { declared } => {
                write!(f, "lookup validation needs at least two challenges, got {declared}")
            },
            Self::NumColumnsMismatch { declared, observed } => {
                write!(f, "num_columns mismatch: declared {declared}, observed {observed}")
            },
            Self::ColumnDegreeMismatch { column_idx, declared, observed } => write!(
                f,
                "column[{column_idx}] degree mismatch: declared (v={}, u={}), observed (v={}, u={})",
                declared.v, declared.u, observed.v, observed.u,
            ),
            Self::GroupDegreeMismatch {
                column_idx,
                group_idx,
                name,
                declared,
                observed,
            } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} degree mismatch: declared (v={}, u={}), observed (v={}, u={})",
                declared.v, declared.u, observed.v, observed.u,
            ),
            Self::EncodingMismatch { column_idx, group_idx, name, diff } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} cached-encoding mismatch: V_c·U_e − V_e·U_c = {diff:?}",
            ),
            Self::ScopeViolation { column_idx, group_idx, name } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} called insert_encoded outside the encoded closure",
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
    pub preprocessed_width: usize,
    pub trace_width: usize,
    pub num_public_values: usize,
    pub num_periodic_columns: usize,
    pub permutation_width: usize,
    pub num_permutation_challenges: usize,
    pub num_permutation_values: usize,
}

impl ValidateLayout {
    fn to_symbolic(self) -> crate::air::symbolic::AirLayout {
        crate::air::symbolic::AirLayout {
            preprocessed_width: self.preprocessed_width,
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
    let sampled =
        SampledRow::new(layout.trace_width, layout.preprocessed_width, layout.num_periodic_columns);
    let mut sym = SymbolicAirBuilder::<Felt, QuadFelt>::new(layout.to_symbolic());
    let row_valuation = sampled.valuation();
    let mut builder = ValidationBuilder::new(&mut sym, air, row_valuation);
    air.eval(&mut builder);
    match builder.take_error() {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

// NATIVE VALIDATE
// ================================================================================================

/// Validate a native lookup declaration over expression-valued borrowed rows.
///
/// This diagnostic uses the same production Felt/QuadFelt field pair as [`validate`]; it does not
/// claim generic-field coverage. The borrowed schema is checked before symbolic allocation or
/// random sampling. Every cached description within this walk uses one shared concrete valuation.
/// Public, auxiliary and export leaves are outside the lookup frame and remain invalid inputs.
pub fn validate_native<A>(air: &A, spec: &native::AirSpec<'_, Felt>) -> Result<(), ValidationError>
where
    for<'r> A: native_lookup::LookupAir<NativeValidationBuilder<'r>>,
{
    spec.validate().map_err(ValidationError::Spec)?;
    if spec.num_challenges < 2 {
        return Err(ValidationError::Challenges { declared: spec.num_challenges });
    }
    use native::symbolic::{BaseInput, RowOffset};
    let offsets = [RowOffset::Current, RowOffset::Next];
    let main: [Vec<_>; 2] = offsets.map(|offset| {
        (0..spec.main_width)
            .map(|index| NativeExpr::input(BaseInput::Main { offset, index }))
            .collect()
    });
    let preprocessed: [Vec<_>; 2] = offsets.map(|offset| {
        (0..spec.preprocessed_width())
            .map(|index| NativeExpr::input(BaseInput::Preprocessed { offset, index }))
            .collect()
    });
    let periodic: Vec<_> = (0..spec.periodic_columns.len())
        .map(|index| NativeExpr::input(BaseInput::Periodic(index)))
        .collect();
    let sampled = SampledRow::new(spec.main_width, spec.preprocessed_width(), periodic.len());
    let frame = native_lookup::LookupFrame {
        main: native::Rows { current: &main[0], next: &main[1] },
        preprocessed: native::Rows {
            current: &preprocessed[0],
            next: &preprocessed[1],
        },
        periodic: &periodic,
    };
    let mut builder = NativeValidationBuilder::new(air, sampled.valuation());
    native_lookup::LookupAir::eval(air, &frame, &mut builder);
    match builder.take_error() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Native top-level driver for the shared validation column/group/batch callbacks.
///
/// Rows are borrowed separately by the declaration. This driver contains no upstream symbolic
/// builder or variable/window facade; its callbacks retain native expression trees directly.
pub struct NativeValidationBuilder<'r> {
    sym_challenges: Challenges<NativeExprEF>,
    row_valuation: RowValuation<'r>,
    column_idx: usize,
    declared_columns: usize,
    error: Option<ValidationError>,
}

impl<'r> NativeValidationBuilder<'r> {
    fn new<A>(air: &A, row_valuation: RowValuation<'r>) -> Self
    where
        A: native_lookup::LookupAir<Self>,
    {
        use native::symbolic::AuxInput;
        Self {
            sym_challenges: Challenges::new(
                NativeExprEF::input(AuxInput::Challenge(0)),
                NativeExprEF::input(AuxInput::Challenge(1)),
                air.max_message_width(),
                air.num_bus_ids(),
            ),
            row_valuation,
            column_idx: 0,
            declared_columns: air.column_shape().len(),
            error: None,
        }
    }

    fn take_error(self) -> Option<ValidationError> {
        finish_columns(self.error, self.declared_columns, self.column_idx)
    }
}

impl<'r> native_lookup::LookupBuilder for NativeValidationBuilder<'r> {
    type F = Felt;
    type Expr = NativeExpr;
    type ExprEF = NativeExprEF;

    type Column<'c>
        = ValidationColumn<'c, 'r, NativeExpr, NativeExprEF>
    where
        Self: 'c;

    fn next_column<'c, R>(&'c mut self, f: impl FnOnce(&mut Self::Column<'c>) -> R, deg: Deg) -> R {
        let column_idx = self.column_idx;
        self.column_idx += 1;
        let already_errored = self.error.is_some();
        let mut column = ValidationColumn::new(
            &self.sym_challenges,
            self.row_valuation,
            column_idx,
            native_operations(),
        );
        let result = f(&mut column);
        if !already_errored {
            self.error = column.finish(deg);
        }
        result
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

/// One concrete assignment is shared by all cached descriptions in a validation walk.
struct SampledRow {
    current: Vec<Felt>,
    next: Vec<Felt>,
    preprocessed_current: Vec<Felt>,
    preprocessed_next: Vec<Felt>,
    periodic: Vec<Felt>,
    alpha: QuadFelt,
    beta: QuadFelt,
}

impl SampledRow {
    fn new(main_width: usize, preprocessed_width: usize, periodic_columns: usize) -> Self {
        let mut rng = rand::rng();
        Self {
            current: (0..main_width).map(|_| rng.random()).collect(),
            next: (0..main_width).map(|_| rng.random()).collect(),
            preprocessed_current: (0..preprocessed_width).map(|_| rng.random()).collect(),
            preprocessed_next: (0..preprocessed_width).map(|_| rng.random()).collect(),
            periodic: (0..periodic_columns).map(|_| rng.random()).collect(),
            alpha: QuadFelt::new(rng.random()),
            beta: QuadFelt::new(rng.random()),
        }
    }

    fn valuation(&self) -> RowValuation<'_> {
        RowValuation {
            current: &self.current,
            next: &self.next,
            preprocessed_current: &self.preprocessed_current,
            preprocessed_next: &self.preprocessed_next,
            periodic: &self.periodic,
            alpha: self.alpha,
            beta: self.beta,
        }
    }
}

/// Concrete valuation used to evaluate symbolic `(V, U)` trees when the walker
/// needs a numeric answer (cached-encoding equivalence).
#[derive(Clone, Copy)]
struct RowValuation<'r> {
    current: &'r [Felt],
    next: &'r [Felt],
    preprocessed_current: &'r [Felt],
    preprocessed_next: &'r [Felt],
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
                BaseEntry::Preprocessed { offset: 0 } => self.preprocessed_current[*index],
                BaseEntry::Preprocessed { offset: 1 } => self.preprocessed_next[*index],
                BaseEntry::Main { offset } | BaseEntry::Preprocessed { offset } => {
                    panic!("unexpected {entry:?} offset {offset} in LookupAir::eval")
                },
                // LookupBuilder doesn't expose public values, and LookupAir::eval can't
                // construct these leaves.
                BaseEntry::Public => panic!("unexpected {entry:?} leaf in LookupAir::eval"),
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

impl RowValuation<'_> {
    fn eval_native_base(&self, expression: &NativeExpr) -> Felt {
        use native::symbolic::{BaseInput, BaseLeaf, SymbolicExpr};
        match expression {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Constant(value) => *value,
                BaseLeaf::Input(input) => match input {
                    BaseInput::Main { offset, index } => {
                        [self.current, self.next][offset.index()][*index]
                    },
                    BaseInput::Preprocessed { offset, index } => {
                        [self.preprocessed_current, self.preprocessed_next][offset.index()][*index]
                    },
                    BaseInput::Periodic(index) => self.periodic[*index],
                    BaseInput::Public(_) => panic!("unexpected public leaf in LookupAir::eval"),
                },
                BaseLeaf::IsFirstRow | BaseLeaf::IsLastRow | BaseLeaf::IsTransition => {
                    panic!("selector leaf {leaf:?} unexpected in LookupAir::eval")
                },
            },
            SymbolicExpr::Add { x, y, .. } => self.eval_native_base(x) + self.eval_native_base(y),
            SymbolicExpr::Sub { x, y, .. } => self.eval_native_base(x) - self.eval_native_base(y),
            SymbolicExpr::Mul { x, y, .. } => self.eval_native_base(x) * self.eval_native_base(y),
            SymbolicExpr::Neg { x, .. } => -self.eval_native_base(x),
        }
    }

    fn eval_native_ext(&self, expression: &NativeExprEF) -> QuadFelt {
        use native::symbolic::{AuxInput, ExtLeaf, SymbolicExpr};
        match expression {
            SymbolicExpr::Leaf(leaf) => match leaf {
                ExtLeaf::Base(inner) => self.eval_native_base(inner).into(),
                ExtLeaf::ExtConstant(value) => *value,
                ExtLeaf::Input(input) => match input {
                    AuxInput::Challenge(0) => self.alpha,
                    AuxInput::Challenge(1) => self.beta,
                    AuxInput::Challenge(index) => {
                        panic!("unexpected challenge index {index} in LookupAir::eval")
                    },
                    AuxInput::Trace { .. } | AuxInput::Export(_) => {
                        panic!("unexpected {input:?} leaf in LookupAir::eval")
                    },
                },
            },
            SymbolicExpr::Add { x, y, .. } => self.eval_native_ext(x) + self.eval_native_ext(y),
            SymbolicExpr::Sub { x, y, .. } => self.eval_native_ext(x) - self.eval_native_ext(y),
            SymbolicExpr::Mul { x, y, .. } => self.eval_native_ext(x) * self.eval_native_ext(y),
            SymbolicExpr::Neg { x, .. } => -self.eval_native_ext(x),
        }
    }
}

// BUILDER
// ================================================================================================

/// Unified walker that cross-checks `(V, U)` degrees, cached-encoding equivalence,
/// and group scope in a single pass over [`LookupAir::eval`]. The first
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
            declared_columns: air.column_shape().len(),
            error: None,
        }
    }

    fn take_error(self) -> Option<ValidationError> {
        finish_columns(self.error, self.declared_columns, self.column_idx)
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
    type PreprocessedWindow = <Inner as AirBuilder>::PreprocessedWindow;

    type Column<'c>
        = ValidationColumn<'c, 'r>
    where
        Self: 'c;

    fn main(&self) -> Self::MainWindow {
        self.ab.main()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.ab.preprocessed()
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.ab.periodic_values()
    }

    fn next_column<'c, R>(&'c mut self, f: impl FnOnce(&mut Self::Column<'c>) -> R, deg: Deg) -> R {
        let column_idx = self.column_idx;
        self.column_idx += 1;

        let already_errored = self.error.is_some();
        let mut col = ValidationColumn::new(
            &self.sym_challenges,
            self.row_valuation,
            column_idx,
            legacy_operations(),
        );
        let result = f(&mut col);

        if !already_errored {
            self.error = col.finish(deg);
        }

        result
    }
}

fn finish_columns(
    error: Option<ValidationError>,
    declared: usize,
    observed: usize,
) -> Option<ValidationError> {
    error.or_else(|| {
        (declared != observed).then_some(ValidationError::NumColumnsMismatch { declared, observed })
    })
}

/// Only raw diagnostic degree and concrete valuation differ between the two symbolic ASTs.
/// All column/group/batch arithmetic and validation policy remains in the shared callbacks below.
struct ExpressionOperations<E> {
    raw_degree: fn(&E) -> usize,
    evaluate: for<'r> fn(RowValuation<'r>, &E) -> QuadFelt,
}

fn legacy_operations() -> ExpressionOperations<ExprEF> {
    ExpressionOperations {
        raw_degree: ExprEF::degree_multiple,
        evaluate: |valuation, expression| valuation.eval_ext(expression),
    }
}

fn native_operations() -> ExpressionOperations<NativeExprEF> {
    ExpressionOperations {
        raw_degree: NativeExprEF::degree_multiple,
        evaluate: |valuation, expression| valuation.eval_native_ext(expression),
    }
}

// COLUMN
// ================================================================================================

pub struct ValidationColumn<'c, 'r, B: PrimeCharacteristicRing = Expr, E: Algebra<B> = ExprEF> {
    challenges: &'c Challenges<E>,
    row_valuation: RowValuation<'r>,
    operations: ExpressionOperations<E>,
    u: E,
    v: E,
    column_idx: usize,
    next_group_idx: usize,
    /// First group-level error observed while walking this column, drained by
    /// [`ValidationBuilder::next_column`] after the closure returns.
    error: Option<ValidationError>,
    _phantom: PhantomData<B>,
}

impl<'c, 'r, B: PrimeCharacteristicRing, E: Algebra<B>> ValidationColumn<'c, 'r, B, E> {
    fn new(
        challenges: &'c Challenges<E>,
        row_valuation: RowValuation<'r>,
        column_idx: usize,
        operations: ExpressionOperations<E>,
    ) -> Self {
        Self {
            challenges,
            row_valuation,
            operations,
            u: E::ONE,
            v: E::ZERO,
            column_idx,
            next_group_idx: 0,
            error: None,
            _phantom: PhantomData,
        }
    }

    fn finish(self, declared: Deg) -> Option<ValidationError> {
        self.error.or_else(|| {
            let observed = Deg {
                v: (self.operations.raw_degree)(&self.v),
                u: (self.operations.raw_degree)(&self.u),
            };
            (observed != declared).then_some(ValidationError::ColumnDegreeMismatch {
                column_idx: self.column_idx,
                declared,
                observed,
            })
        })
    }

    fn fold_group(&mut self, u_g: E, v_g: E) {
        self.v = self.v.clone() * u_g.clone() + v_g * self.u.clone();
        self.u = self.u.clone() * u_g;
    }

    fn check_group_degree(
        &mut self,
        name: &'static str,
        group_idx: usize,
        declared: Deg,
        u: &E,
        v: &E,
    ) {
        if self.error.is_some() {
            return;
        }
        let observed = Deg {
            v: (self.operations.raw_degree)(v),
            u: (self.operations.raw_degree)(u),
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
fn fresh_group<'g, B: PrimeCharacteristicRing, E: Algebra<B>>(
    challenges: &'g Challenges<E>,
    inside_encoded_closure: bool,
) -> ValidationGroup<'g, B, E> {
    ValidationGroup {
        challenges,
        u: E::ONE,
        v: E::ZERO,
        inside_encoded_closure,
        used_insert_encoded: false,
        _phantom: PhantomData,
    }
}

impl<'c, 'r, B: PrimeCharacteristicRing, E: Algebra<B>> LookupColumn
    for ValidationColumn<'c, 'r, B, E>
{
    type Expr = B;
    type ExprEF = E;

    type Group<'g>
        = ValidationGroup<'g, B, E>
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
        if self.error.is_none() && canon.used_insert_encoded {
            self.error = Some(ValidationError::ScopeViolation {
                column_idx: self.column_idx,
                group_idx,
                name,
            });
        }

        let mut enc = fresh_group(self.challenges, true);
        encoded(&mut enc);

        // Cached-encoding equivalence: the two closures must agree on `(V, U)`
        // up to cross-multiplication, i.e. `V_c·U_e − V_e·U_c == 0`. We don't
        // rely on symbolic simplification to zero — we evaluate the difference
        // at the shared random row.
        if self.error.is_none() {
            let diff_expr = canon.v.clone() * enc.u.clone() - enc.v.clone() * canon.u;
            let diff = (self.operations.evaluate)(self.row_valuation, &diff_expr);
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

pub struct ValidationGroup<'g, B: PrimeCharacteristicRing = Expr, E: Algebra<B> = ExprEF> {
    challenges: &'g Challenges<E>,
    u: E,
    v: E,
    /// Set when this group was opened via the `encoded` closure of
    /// `group_with_cached_encoding`; toggles the legal use of `insert_encoded`.
    inside_encoded_closure: bool,
    /// `true` if `insert_encoded` was called outside its legal scope. The column
    /// inspects this flag at close time and raises `ScopeViolation` if the group
    /// was simple.
    used_insert_encoded: bool,
    _phantom: PhantomData<B>,
}

impl<'g, B: PrimeCharacteristicRing, E: Algebra<B>> LookupGroup for ValidationGroup<'g, B, E> {
    type Expr = B;
    type ExprEF = E;

    type Batch<'b>
        = ValidationBatch<'b, B, E>
    where
        Self: 'b;

    fn add<M>(&mut self, _name: &'static str, flag: B, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<B, E>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - E::ONE) * flag.clone();
        self.v += flag;
    }

    fn remove<M>(&mut self, _name: &'static str, flag: B, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<B, E>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - E::ONE) * flag.clone();
        self.v -= flag;
    }

    fn insert<M>(
        &mut self,
        _name: &'static str,
        flag: B,
        multiplicity: B,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<B, E>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - E::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: B,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        let mut batch = ValidationBatch {
            challenges: self.challenges,
            n: E::ZERO,
            d: E::ONE,
            _phantom: PhantomData,
        };
        build(&mut batch);
        let ValidationBatch { n, d, .. } = batch;
        self.u += (d - E::ONE) * flag.clone();
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[E] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> E {
        self.challenges.bus_prefix[bus_id].clone()
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: B,
        multiplicity: B,
        encoded: impl FnOnce() -> E,
        _deg: Deg,
    ) {
        if !self.inside_encoded_closure {
            self.used_insert_encoded = true;
        }
        let v_msg = encoded();
        self.u += (v_msg - E::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }
}

// BATCH
// ================================================================================================

pub struct ValidationBatch<'b, B: PrimeCharacteristicRing = Expr, E: Algebra<B> = ExprEF> {
    challenges: &'b Challenges<E>,
    n: E,
    d: E,
    _phantom: PhantomData<B>,
}

impl<'b, B: PrimeCharacteristicRing, E: Algebra<B>> LookupBatch for ValidationBatch<'b, B, E> {
    type Expr = B;
    type ExprEF = E;

    fn insert<M>(&mut self, _name: &'static str, multiplicity: B, msg: M, _deg: Deg)
    where
        M: LookupMessage<B, E>,
    {
        let v_msg = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v_msg.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v_msg;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: B,
        encoded: impl FnOnce() -> E,
        _deg: Deg,
    ) {
        let v_msg = encoded();
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v_msg.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v_msg;
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec};
    use core::cell::Cell;

    use p3_field::Dup;

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum Issue {
        None,
        PlainEncodedBatch,
        GroupDegree,
        ColumnDegree,
        ColumnCount,
        CachedMismatch,
        SimpleScope,
        CanonicalScope,
    }

    struct Probe {
        issue: Issue,
        calls: Cell<usize>,
    }

    impl Probe {
        fn new(issue: Issue) -> Self {
            Self { issue, calls: Cell::new(0) }
        }

        fn shape(&self) -> &[usize] {
            if matches!(self.issue, Issue::ColumnCount) {
                &[2, 2]
            } else {
                &[2]
            }
        }
    }

    #[derive(Debug)]
    struct Message<B>(B);

    impl<B: PrimeCharacteristicRing, E: Algebra<B>> LookupMessage<B, E> for Message<B> {
        fn encode(&self, challenges: &Challenges<E>) -> E {
            challenges.encode(0, [self.0.dup()])
        }
    }

    #[derive(Debug)]
    struct UnitMessage;

    impl<B: PrimeCharacteristicRing, E: Algebra<B>> LookupMessage<B, E> for UnitMessage {
        fn encode(&self, _challenges: &Challenges<E>) -> E {
            E::ONE
        }
    }

    /// Both ASTs execute these same column/group/batch callbacks.
    fn batch<G: LookupGroup>(group: &mut G, value: G::Expr, encoded: bool) {
        let other = value.dup() + G::Expr::ONE;
        if encoded {
            let prefix = group.bus_prefix(0);
            let beta = group.beta_powers()[0].dup();
            let first = prefix.dup() + beta.dup() * value;
            let second = prefix + beta * other;
            group.batch(
                "pair",
                G::Expr::ONE,
                |batch| {
                    batch.insert_encoded("a", G::Expr::ONE, || first, Deg { v: 0, u: 1 });
                    batch.insert_encoded("b", G::Expr::ONE, || second, Deg { v: 0, u: 1 });
                },
                Deg { v: 1, u: 2 },
            );
        } else {
            group.batch(
                "pair",
                G::Expr::ONE,
                |batch| {
                    batch.insert("a", G::Expr::ONE, Message(value), Deg { v: 0, u: 1 });
                    batch.insert("b", G::Expr::ONE, Message(other), Deg { v: 0, u: 1 });
                },
                Deg { v: 1, u: 2 },
            );
        }
    }

    fn out_of_scope<G: LookupGroup>(group: &mut G) {
        // The invalid call is mathematically zero, so only the scope policy can reject it.
        group.insert_encoded(
            "illegal",
            G::Expr::ZERO,
            G::Expr::ZERO,
            || G::ExprEF::ONE,
            Deg { v: 0, u: 0 },
        );
    }

    impl<LB: native_lookup::LookupBuilder<F = Felt>> native_lookup::LookupAir<LB> for Probe {
        fn column_shape(&self) -> &[usize] {
            self.shape()
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
            self.calls.set(self.calls.get() + 1);
            let value = frame.main.current[0].dup()
                + frame.main.next[0].dup() * LB::Expr::from_u32(2)
                + frame.preprocessed.current[0].dup() * LB::Expr::from_u32(3)
                + frame.preprocessed.next[0].dup() * LB::Expr::from_u32(4)
                + frame.periodic[0].dup() * LB::Expr::from_u32(5);
            let degree = if matches!(self.issue, Issue::CachedMismatch) {
                Deg { v: 0, u: 0 }
            } else {
                Deg { v: 1, u: 2 }
            };
            let column_degree = if matches!(self.issue, Issue::ColumnDegree) {
                Deg { v: 2, u: 3 }
            } else {
                degree
            };
            let group_degree = if matches!(self.issue, Issue::GroupDegree) {
                Deg { v: 2, u: 3 }
            } else {
                degree
            };
            let returned = builder.next_column(
                |column| {
                    if matches!(self.issue, Issue::SimpleScope | Issue::PlainEncodedBatch) {
                        column.group(
                            "probe",
                            |group| {
                                batch(group, value, matches!(self.issue, Issue::PlainEncodedBatch));
                                if matches!(self.issue, Issue::SimpleScope) {
                                    out_of_scope(group);
                                }
                            },
                            group_degree,
                        );
                    } else {
                        let canonical_value = value.dup();
                        column.group_with_cached_encoding(
                            "probe",
                            |canonical| {
                                if matches!(self.issue, Issue::CachedMismatch) {
                                    canonical.add(
                                        "unit",
                                        LB::Expr::ONE,
                                        || UnitMessage,
                                        Deg { v: 0, u: 0 },
                                    );
                                } else {
                                    batch(canonical, canonical_value, false);
                                }
                                if matches!(self.issue, Issue::CanonicalScope) {
                                    out_of_scope(canonical);
                                }
                            },
                            |encoded| {
                                if !matches!(self.issue, Issue::CachedMismatch) {
                                    batch(encoded, value, true);
                                }
                            },
                            group_degree,
                        );
                    }
                    17
                },
                column_degree,
            );
            assert_eq!(returned, 17);
        }
    }

    // A test-only legacy facade reaches the same declaration, not a second equation body.
    impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for Probe {
        fn column_shape(&self) -> &[usize] {
            self.shape()
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }
        fn eval(&self, builder: &mut LB) {
            native::migration::eval_lookup(self, builder, 1);
        }
    }

    fn spec() -> native::AirSpec<'static, Felt> {
        native::AirSpec {
            main_width: 1,
            aux_width: 3,
            num_public_values: 0,
            num_challenges: 2,
            num_exports: 1,
            preprocessed: Some(native::PreprocessedSpec { width: 1, log_height: 1 }),
            periodic_columns: Cow::Owned(vec![vec![Felt::ONE; 2]]),
        }
    }

    fn layout(spec: &native::AirSpec<'_, Felt>) -> ValidateLayout {
        ValidateLayout {
            preprocessed_width: spec.preprocessed_width(),
            trace_width: spec.main_width,
            num_public_values: spec.num_public_values,
            num_periodic_columns: spec.periodic_columns.len(),
            permutation_width: spec.aux_width,
            num_permutation_challenges: spec.num_challenges,
            num_permutation_values: spec.num_exports,
        }
    }

    #[test]
    fn old_and_native_callbacks_share_degree_cache_scope_and_column_checks() {
        for issue in [
            Issue::None,
            Issue::PlainEncodedBatch,
            Issue::GroupDegree,
            Issue::ColumnDegree,
            Issue::ColumnCount,
            Issue::CachedMismatch,
            Issue::SimpleScope,
            Issue::CanonicalScope,
        ] {
            let probe = Probe::new(issue);
            let spec = spec();
            for result in [validate(&probe, layout(&spec)), validate_native(&probe, &spec)] {
                match issue {
                    Issue::None | Issue::PlainEncodedBatch => result.unwrap(),
                    Issue::GroupDegree => assert!(matches!(
                        result,
                        Err(ValidationError::GroupDegreeMismatch {
                            column_idx: 0,
                            group_idx: 0,
                            name: "probe",
                            declared: Deg { v: 2, u: 3 },
                            observed: Deg { v: 1, u: 2 }
                        })
                    )),
                    Issue::ColumnDegree => assert!(matches!(
                        result,
                        Err(ValidationError::ColumnDegreeMismatch {
                            column_idx: 0,
                            declared: Deg { v: 2, u: 3 },
                            observed: Deg { v: 1, u: 2 }
                        })
                    )),
                    Issue::ColumnCount => assert!(matches!(
                        result,
                        Err(ValidationError::NumColumnsMismatch { declared: 2, observed: 1 })
                    )),
                    Issue::CachedMismatch => assert!(
                        matches!(result, Err(ValidationError::EncodingMismatch { column_idx: 0, group_idx: 0, name: "probe", diff }) if diff == QuadFelt::ONE)
                    ),
                    Issue::SimpleScope | Issue::CanonicalScope => assert!(matches!(
                        result,
                        Err(ValidationError::ScopeViolation {
                            column_idx: 0,
                            group_idx: 0,
                            name: "probe"
                        })
                    )),
                }
            }
            assert_eq!(probe.calls.get(), 2);
        }
    }

    #[test]
    fn native_schema_and_challenge_prefix_are_rejected_before_declaration() {
        let probe = Probe::new(Issue::None);
        let mut invalid = spec();
        invalid.main_width = 0;
        invalid.aux_width = usize::MAX;
        assert!(matches!(
            validate_native(&probe, &invalid),
            Err(ValidationError::Spec(native::SpecError::EmptyMain))
        ));
        let mut invalid = spec();
        invalid.num_challenges = 1;
        assert!(matches!(
            validate_native(&probe, &invalid),
            Err(ValidationError::Challenges { declared: 1 })
        ));
        assert_eq!(probe.calls.get(), 0);
    }

    #[test]
    fn old_and_native_visitors_use_the_same_explicit_namespaced_assignment() {
        use crate::air::WindowAccess;
        use native::symbolic::{AuxInput, BaseInput, RowOffset};

        let current = [Felt::from_u32(1)];
        let next = [Felt::from_u32(2)];
        let preprocessed_current = [Felt::from_u32(3)];
        let preprocessed_next = [Felt::from_u32(4)];
        let periodic = [Felt::from_u32(5)];
        let alpha = QuadFelt::new([Felt::from_u32(7), Felt::from_u32(11)]);
        let beta = QuadFelt::new([Felt::from_u32(13), Felt::from_u32(17)]);
        let valuation = RowValuation {
            current: &current,
            next: &next,
            preprocessed_current: &preprocessed_current,
            preprocessed_next: &preprocessed_next,
            periodic: &periodic,
            alpha,
            beta,
        };
        let symbolic = Inner::new(layout(&spec()).to_symbolic());
        let main = symbolic.main();
        let preprocessed = symbolic.preprocessed();
        let legacy_base = Expr::from(main.current_slice()[0])
            + Expr::from(main.next_slice()[0]) * Felt::from_u32(2)
            + Expr::from(preprocessed.current_slice()[0]) * Felt::from_u32(3)
            + Expr::from(preprocessed.next_slice()[0]) * Felt::from_u32(4)
            + Expr::from(symbolic.periodic_values()[0]) * Felt::from_u32(5);
        let legacy = ExprEF::from(legacy_base)
            + ExprEF::from(symbolic.permutation_randomness()[0])
            + ExprEF::from(symbolic.permutation_randomness()[1]) * Felt::TWO;
        let native_base =
            NativeExpr::input(BaseInput::Main { offset: RowOffset::Current, index: 0 })
                + NativeExpr::input(BaseInput::Main { offset: RowOffset::Next, index: 0 })
                    * Felt::from_u32(2)
                + NativeExpr::input(BaseInput::Preprocessed {
                    offset: RowOffset::Current,
                    index: 0,
                }) * Felt::from_u32(3)
                + NativeExpr::input(BaseInput::Preprocessed { offset: RowOffset::Next, index: 0 })
                    * Felt::from_u32(4)
                + NativeExpr::input(BaseInput::Periodic(0)) * Felt::from_u32(5);
        let native = NativeExprEF::from(native_base)
            + NativeExprEF::input(AuxInput::Challenge(0))
            + NativeExprEF::input(AuxInput::Challenge(1)) * Felt::TWO;
        let expected = QuadFelt::from(Felt::from_u32(55)) + alpha + beta.double();
        assert_eq!(valuation.eval_ext(&legacy), expected);
        assert_eq!(valuation.eval_native_ext(&native), expected);
    }

    #[test]
    #[should_panic(expected = "unexpected public leaf")]
    fn native_public_leaf_remains_outside_lookup_scope() {
        let sampled = SampledRow::new(1, 1, 1);
        sampled
            .valuation()
            .eval_native_base(&NativeExpr::input(native::symbolic::BaseInput::Public(0)));
    }

    #[test]
    #[should_panic(expected = "unexpected Export")]
    fn native_export_leaf_remains_outside_lookup_scope() {
        let sampled = SampledRow::new(1, 1, 1);
        let _ = sampled
            .valuation()
            .eval_native_ext(&NativeExprEF::input(native::symbolic::AuxInput::Export(0)));
    }
}

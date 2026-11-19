//! Single AIR self-validation entry point, backed by one unified walker.
//!
//! [`validate_native`] checks a lookup declaration against its checked source schema.
//! One short-circuit [`Result<(), ValidationError>`] covers:
//!
//! - `column_shape().len()` declared vs observed (the walker counts `next_column` calls).
//! - Per-group and per-column `Deg { v, u }` declared vs observed (via
//!   [`air::symbolic::SymbolicExpression::degree_multiple`] on the running `(V, U)`).
//! - Cached-encoding canonical vs encoded `(V, U)` equivalence, checked by evaluating the symbolic
//!   difference `U_c·V_e − U_e·V_c` at a random row.
//! - Group scope: no illegal [`LookupGroup::insert_encoded`] outside the `encoded` closure. Encoded
//!   entries in [`LookupBatch`] retain their existing policy.
//!
//! The global max-degree budget is **not** checked here — the STARK prover's
//! quotient validation already enforces it, and duplicating that check would
//! blur this module's purpose.

use alloc::vec::Vec;
use core::fmt;

use miden_crypto::{
    Felt,
    field::{BinomialExtensionField, PrimeCharacteristicRing},
};
use rand::RngExt;

use super::super::{Challenges, Deg, LookupBatch, LookupColumn, LookupGroup, LookupMessage};
use crate::{air, lookup};

type QuadFelt = BinomialExtensionField<Felt, 2>;
type NativeExpr = air::symbolic::SymbolicExpression<Felt>;
type NativeExprEF = air::symbolic::SymbolicExpressionExt<Felt, QuadFelt>;

// VALIDATION ERROR
// ================================================================================================

/// First problem [`validate_native`] observed. See the module docstring for the per-check
/// semantics; each variant corresponds to one of the checks.
#[derive(Clone, Debug)]
pub enum ValidationError {
    /// Invalid native schema, rejected before allocating symbolic rows or sampling a valuation.
    Spec(air::SpecError),
    /// Lookup challenge encoding requires the alpha/beta prefix.
    Challenges { declared: usize },
    /// [`lookup::LookupAir::column_shape`] disagreed with the number of `next_column` calls issued
    /// by `eval`.
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

// VALIDATE
// ================================================================================================

/// Validate a native lookup declaration over expression-valued borrowed rows.
///
/// This diagnostic uses the production Felt/QuadFelt field pair; it does not claim generic-field
/// coverage. The borrowed schema is checked before symbolic allocation or
/// random sampling. Every cached description within this walk uses one shared concrete valuation.
/// Public, auxiliary and export leaves are outside the lookup frame and remain invalid inputs.
pub fn validate_native<A>(air: &A, spec: &air::AirSpec<'_, Felt>) -> Result<(), ValidationError>
where
    for<'r> A: lookup::LookupAir<NativeValidationBuilder<'r>>,
{
    spec.validate().map_err(ValidationError::Spec)?;
    if spec.num_challenges < 2 {
        return Err(ValidationError::Challenges { declared: spec.num_challenges });
    }
    use crate::air::symbolic::{BaseInput, RowOffset};
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
    let frame = lookup::LookupFrame {
        main: air::Rows { current: &main[0], next: &main[1] },
        preprocessed: air::Rows {
            current: &preprocessed[0],
            next: &preprocessed[1],
        },
        periodic: &periodic,
    };
    let mut builder = NativeValidationBuilder::new(air, sampled.valuation());
    lookup::LookupAir::eval(air, &frame, &mut builder);
    match builder.take_error() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Native top-level driver for the shared validation column/group/batch callbacks.
///
/// Rows are borrowed separately by the declaration; callbacks retain symbolic expression trees
/// directly.
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
        A: lookup::LookupAir<Self>,
    {
        use crate::air::symbolic::AuxInput;
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

impl<'r> lookup::LookupBuilder for NativeValidationBuilder<'r> {
    type F = Felt;
    type Expr = NativeExpr;
    type ExprEF = NativeExprEF;

    type Column<'c>
        = ValidationColumn<'c, 'r>
    where
        Self: 'c;

    fn next_column<'c, R>(&'c mut self, f: impl FnOnce(&mut Self::Column<'c>) -> R, deg: Deg) -> R {
        let column_idx = self.column_idx;
        self.column_idx += 1;
        let already_errored = self.error.is_some();
        let mut column =
            ValidationColumn::new(&self.sym_challenges, self.row_valuation, column_idx);
        let result = f(&mut column);
        if !already_errored {
            self.error = column.finish(deg);
        }
        result
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

impl RowValuation<'_> {
    fn eval_native_base(&self, expression: &NativeExpr) -> Felt {
        use crate::air::symbolic::{BaseInput, BaseLeaf, SymbolicExpr};
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
        use crate::air::symbolic::{AuxInput, ExtLeaf, SymbolicExpr};
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

fn finish_columns(
    error: Option<ValidationError>,
    declared: usize,
    observed: usize,
) -> Option<ValidationError> {
    error.or_else(|| {
        (declared != observed).then_some(ValidationError::NumColumnsMismatch { declared, observed })
    })
}

// COLUMN
// ================================================================================================

pub struct ValidationColumn<'c, 'r> {
    challenges: &'c Challenges<NativeExprEF>,
    row_valuation: RowValuation<'r>,

    u: NativeExprEF,
    v: NativeExprEF,
    column_idx: usize,
    next_group_idx: usize,
    /// First group-level error observed while walking this column, drained by
    /// [`NativeValidationBuilder::next_column`] after the closure returns.
    error: Option<ValidationError>,
}

impl<'c, 'r> ValidationColumn<'c, 'r> {
    fn new(
        challenges: &'c Challenges<NativeExprEF>,
        row_valuation: RowValuation<'r>,
        column_idx: usize,
    ) -> Self {
        Self {
            challenges,
            row_valuation,
            u: NativeExprEF::ONE,
            v: NativeExprEF::ZERO,
            column_idx,
            next_group_idx: 0,
            error: None,
        }
    }

    fn finish(self, declared: Deg) -> Option<ValidationError> {
        self.error.or_else(|| {
            let observed = Deg {
                v: self.v.degree_multiple(),
                u: self.u.degree_multiple(),
            };
            (observed != declared).then_some(ValidationError::ColumnDegreeMismatch {
                column_idx: self.column_idx,
                declared,
                observed,
            })
        })
    }

    fn fold_group(&mut self, u_g: NativeExprEF, v_g: NativeExprEF) {
        self.v = self.v.clone() * u_g.clone() + v_g * self.u.clone();
        self.u = self.u.clone() * u_g;
    }

    fn check_group_degree(
        &mut self,
        name: &'static str,
        group_idx: usize,
        declared: Deg,
        u: &NativeExprEF,
        v: &NativeExprEF,
    ) {
        if self.error.is_some() {
            return;
        }
        let observed = Deg {
            v: v.degree_multiple(),
            u: u.degree_multiple(),
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
    challenges: &'g Challenges<NativeExprEF>,
    inside_encoded_closure: bool,
) -> ValidationGroup<'g> {
    ValidationGroup {
        challenges,
        u: NativeExprEF::ONE,
        v: NativeExprEF::ZERO,
        inside_encoded_closure,
        used_insert_encoded: false,
    }
}

impl<'c, 'r> LookupColumn for ValidationColumn<'c, 'r> {
    type Expr = NativeExpr;
    type ExprEF = NativeExprEF;

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
            let diff = self.row_valuation.eval_native_ext(&diff_expr);
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
    challenges: &'g Challenges<NativeExprEF>,
    u: NativeExprEF,
    v: NativeExprEF,
    /// Set when this group was opened via the `encoded` closure of
    /// `group_with_cached_encoding`; toggles the legal use of `insert_encoded`.
    inside_encoded_closure: bool,
    /// `true` if `insert_encoded` was called outside its legal scope. The column
    /// inspects this flag at close time and raises `ScopeViolation` if the group
    /// was simple.
    used_insert_encoded: bool,
}

impl<'g> LookupGroup for ValidationGroup<'g> {
    type Expr = NativeExpr;
    type ExprEF = NativeExprEF;

    type Batch<'b>
        = ValidationBatch<'b>
    where
        Self: 'b;

    fn add<M>(&mut self, _name: &'static str, flag: NativeExpr, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<NativeExpr, NativeExprEF>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - NativeExprEF::ONE) * flag.clone();
        self.v += flag;
    }

    fn remove<M>(
        &mut self,
        _name: &'static str,
        flag: NativeExpr,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<NativeExpr, NativeExprEF>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - NativeExprEF::ONE) * flag.clone();
        self.v -= flag;
    }

    fn insert<M>(
        &mut self,
        _name: &'static str,
        flag: NativeExpr,
        multiplicity: NativeExpr,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<NativeExpr, NativeExprEF>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - NativeExprEF::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: NativeExpr,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        let mut batch = ValidationBatch {
            challenges: self.challenges,
            n: NativeExprEF::ZERO,
            d: NativeExprEF::ONE,
        };
        build(&mut batch);
        let ValidationBatch { n, d, .. } = batch;
        self.u += (d - NativeExprEF::ONE) * flag.clone();
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[NativeExprEF] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> NativeExprEF {
        self.challenges.bus_prefix[bus_id].clone()
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: NativeExpr,
        multiplicity: NativeExpr,
        encoded: impl FnOnce() -> NativeExprEF,
        _deg: Deg,
    ) {
        if !self.inside_encoded_closure {
            self.used_insert_encoded = true;
        }
        let v_msg = encoded();
        self.u += (v_msg - NativeExprEF::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }
}

// BATCH
// ================================================================================================

pub struct ValidationBatch<'b> {
    challenges: &'b Challenges<NativeExprEF>,
    n: NativeExprEF,
    d: NativeExprEF,
}

impl<'b> LookupBatch for ValidationBatch<'b> {
    type Expr = NativeExpr;
    type ExprEF = NativeExprEF;

    fn insert<M>(&mut self, _name: &'static str, multiplicity: NativeExpr, msg: M, _deg: Deg)
    where
        M: LookupMessage<NativeExpr, NativeExprEF>,
    {
        let v_msg = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v_msg.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v_msg;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: NativeExpr,
        encoded: impl FnOnce() -> NativeExprEF,
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

    use p3_field::{Algebra, Dup};

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

    impl<LB: lookup::LookupBuilder<F = Felt>> lookup::LookupAir<LB> for Probe {
        fn column_shape(&self) -> &[usize] {
            self.shape()
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
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

    fn spec() -> air::AirSpec<'static, Felt> {
        air::AirSpec {
            main_width: 1,
            aux_width: 3,
            num_public_values: 0,
            num_challenges: 2,
            num_exports: 1,
            preprocessed: Some(air::PreprocessedSpec { width: 1, log_height: 1 }),
            periodic_columns: Cow::Owned(vec![vec![Felt::ONE; 2]]),
        }
    }

    #[test]
    fn native_callbacks_check_degrees_cache_scope_and_columns() {
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
            let result = validate_native(&probe, &spec);
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
            assert_eq!(probe.calls.get(), 1);
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
            Err(ValidationError::Spec(air::SpecError::EmptyMain))
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
    fn native_visitor_uses_explicit_namespaced_assignment() {
        use crate::air::symbolic::{AuxInput, BaseInput, RowOffset};

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
        assert_eq!(valuation.eval_native_ext(&native), expected);
    }

    #[test]
    #[should_panic(expected = "unexpected public leaf")]
    fn native_public_leaf_remains_outside_lookup_scope() {
        let sampled = SampledRow::new(1, 1, 1);
        sampled
            .valuation()
            .eval_native_base(&NativeExpr::input(air::symbolic::BaseInput::Public(0)));
    }

    #[test]
    #[should_panic(expected = "unexpected Export")]
    fn native_export_leaf_remains_outside_lookup_scope() {
        let sampled = SampledRow::new(1, 1, 1);
        let _ = sampled
            .valuation()
            .eval_native_ext(&NativeExprEF::input(air::symbolic::AuxInput::Export(0)));
    }
}

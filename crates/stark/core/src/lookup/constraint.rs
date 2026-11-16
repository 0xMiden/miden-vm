//! Constraint-path adapter for the closure-based LogUp API.
//!
//! The adapter turns each row's interactions into cross-multiplied `(V, U)` pairs. Fraction
//! columns check `U · aux − V = 0`; column 0 is the running accumulator.
//!
//! ## LogUp constraint structure
//!
//! The aux trace has one **accumulator** (col 0) and several **fraction columns** (cols 1+).
//! Each bus interaction on row `r` contributes a rational term `mᵢ / dᵢ` to one of the
//! columns. Because the verifier cannot check rational equations directly, each column
//! stores the *numerator–denominator pair* `(Nᵢ, Dᵢ)` — the cross-multiplied sum of all
//! interactions assigned to that column on row `r`. The constraints then check:
//!
//! - Fraction columns (i > 0): `Dᵢ · acc[i] - Nᵢ = 0` on every row. This binds `acc[i]` to `Nᵢ/Dᵢ`,
//!   the row's fraction sum for column `i`.
//!
//! - **Accumulator** (col 0): a normalized cyclic running sum.
//!   - `when_first: acc[0] = 0` anchors the witness.
//!   - On every row, including the last-to-first edge, `D₀ · (acc_next[0] - Σᵢ acc[i] +
//!     sigma_prime) - N₀ = 0`.
//!   - The committed value is `sigma_prime = sigma / n`. Summing the cyclic recurrence over all `n`
//!     rows binds `n · sigma_prime` to the trace's global LogUp sum `sigma`.
//!
//! ## Algebra location
//!
//! Per-interaction encoding lives inside each
//! [`LookupMessage::encode`] body, so the adapter carries **no scratch
//! buffer**: every `add` / `remove` / `insert` body is a two-liner that
//! calls `msg.encode(self.challenges)` and absorbs the resulting
//! `EE` denominator into the running `(V, U)` (group) or
//! `(N, D)` (batch) pair.
//!
//! The running-pair updates are also inlined at every call site (no
//! `absorb_single` / `absorb` helpers), which lets the `add` / `remove`
//! paths skip the `flag * E::ONE` / `flag * E::NEG_ONE` multiplication
//! — on the constraint path that shrinks the symbolic tree by one node
//! per single-interaction call.
//!
//! ## Challenge handling
//!
//! The top-level [`ConstraintLookupBuilder`](super::ConstraintLookupBuilder) reads α/β from
//! the borrowed uniform inputs once at construction and stores shared [`Challenges<EE>`].
//! Its β powers and bus prefixes are sized from the authored
//! [`LookupAir`](super::LookupAir). Immutable current/next auxiliary slices stay with that
//! adapter and each completed column emits its equations through the separate assertion sink.

use core::marker::PhantomData;

use p3_field::{Algebra, Dup, PrimeCharacteristicRing};

use super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupFrame, LookupGroup,
    LookupMessage,
};
use crate::air::{Frame, Inputs, LiftedAirBuilder, Rows};

/// Inputs used only when closing the accumulator column.
struct AccumulatorInputs<E, EE> {
    pub next: EE,
    pub sigma: EE,
    pub first: E,
}

/// Finalization in native lookup assertion order.
///
/// `current` contains the declared LogUp prefix for the accumulator, or just the selected
/// fraction-column value otherwise. Trailing auxiliary registers never enter the recurrence.
/// The optional anchor precedes the all-row equation and uses the `acc * first` multiplication
/// order.
fn column_constraints<E, EE>(
    u: EE,
    v: EE,
    mut current: impl Iterator<Item = EE>,
    accumulator: Option<AccumulatorInputs<E, EE>>,
) -> (Option<EE>, EE)
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    let acc = current.next().expect("a lookup column must supply its current auxiliary value");
    if let Some(AccumulatorInputs { next, sigma, first }) = accumulator {
        let mut sum = acc.dup();
        for value in current {
            sum += value;
        }
        // This remains unfiltered on the last-to-first edge. Summing over all rows gives
        // n*sigma = the global LogUp sum; the anchor fixes the additive constant.
        (Some(acc * first), u * (next - sum + sigma) - v)
    } else {
        (None, u * acc - v)
    }
}

// CONSTRAINT COLUMN
// ================================================================================================

/// Per-column arithmetic for native constraint emission.
///
/// Holds only the running `(V, U)` accumulator and shared precomputed challenges. Inputs and
/// mutable assertion emission stay with the top-level adapter, outside this callback's borrow.
pub struct ConstraintColumn<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    challenges: &'a Challenges<EE>,
    u: EE,
    v: EE,
    _phantom: PhantomData<E>,
}

impl<'a, E, EE> ConstraintColumn<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    pub(super) fn new(challenges: &'a Challenges<EE>) -> Self {
        Self {
            challenges,
            u: EE::ONE,
            v: EE::ZERO,
            _phantom: PhantomData,
        }
    }

    pub(super) fn into_pair(self) -> (EE, EE) {
        (self.u, self.v)
    }

    /// Compose an inner group with `V ← V·U_g + V_g·U`, `U ← U·U_g`.
    fn fold_group(&mut self, u_g: EE, v_g: EE) {
        self.v = self.v.dup() * u_g.dup() + v_g * self.u.dup();
        self.u = self.u.dup() * u_g;
    }
}

impl<'a, E, EE> LookupColumn for ConstraintColumn<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    type Expr = E;
    type ExprEF = EE;

    type Group<'g>
        = ConstraintGroup<'g, E, EE>
    where
        Self: 'g,
        E: 'g,
        EE: 'g;

    fn group<'g>(
        &'g mut self,
        _name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let mut group = ConstraintGroup {
            challenges: self.challenges,
            u: EE::ONE,
            v: EE::ZERO,
            _phantom: PhantomData,
        };
        f(&mut group);
        let ConstraintGroup { u, v, .. } = group;
        self.fold_group(u, v);
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        _name: &'static str,
        _canonical: impl FnOnce(&mut Self::Group<'g>),
        encoded: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        // Constraint path: only the `encoded` closure runs; the
        // `canonical` closure is dropped unused. This matches the plan's
        // split where `canonical` is the prover-path description.
        let mut group = ConstraintGroup {
            challenges: self.challenges,
            u: EE::ONE,
            v: EE::ZERO,
            _phantom: PhantomData,
        };
        encoded(&mut group);
        let ConstraintGroup { u, v, .. } = group;
        self.fold_group(u, v);
    }
}

// CONSTRAINT GROUP
// ================================================================================================

/// Per-group handle for the constraint path.
///
/// Implements [`LookupGroup`] with working `beta_powers`, `bus_prefix`,
/// and `insert_encoded` overrides (the constraint path always has the
/// precomputed challenge tables available).
///
/// Accumulates an internal `(V_g, U_g)` pair as the author calls
/// `add` / `remove` / `insert` / `batch`. The column consumes the pair
/// via `ConstraintColumn::fold_group` once the group closure returns.
///
/// Each per-interaction `add` / `remove` / `insert` body calls
/// `msg.encode(self.challenges)` directly and folds the resulting
/// denominator into `(V_g, U_g)` inline — no intermediate scratch
/// buffer and no helper method call.
pub struct ConstraintGroup<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    challenges: &'a Challenges<EE>,
    u: EE,
    v: EE,
    _phantom: PhantomData<E>,
}

impl<'a, E, EE> LookupGroup for ConstraintGroup<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    type Expr = E;
    type ExprEF = EE;

    type Batch<'b>
        = ConstraintBatch<'b, E, EE>
    where
        Self: 'b,
        E: 'b,
        EE: 'b;

    fn add<M>(&mut self, _name: &'static str, flag: Self::Expr, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `add` = multiplicity +1. `V_g += flag · 1 = flag`, skipping
        // the redundant multiplication that a generic `insert` would
        // emit.
        let v = msg().encode(self.challenges);
        self.u += (v - EE::ONE) * flag.dup();
        self.v += flag;
    }

    fn remove<M>(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `remove` = multiplicity −1. `V_g += flag · (−1) = −flag`.
        let v = msg().encode(self.challenges);
        self.u += (v - EE::ONE) * flag.dup();
        self.v -= flag;
    }

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
        let v = msg().encode(self.challenges);
        self.u += (v - EE::ONE) * flag.dup();
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: Self::Expr,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        // Batch algebra: start with `(N, D) = (0, 1)`, run `build`,
        // then fold the final `(N, D)` into `(V_g, U_g)` via
        // `V_g += N · flag`, `U_g += (D − 1) · flag`.
        let mut batch = ConstraintBatch {
            challenges: self.challenges,
            n: EE::ZERO,
            d: EE::ONE,
            _phantom: PhantomData,
        };
        build(&mut batch);
        let ConstraintBatch { n, d, .. } = batch;
        self.u += (d - EE::ONE) * flag.dup();
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[Self::ExprEF] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        self.challenges.bus_prefix[bus_id].dup()
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        // Same `(V_g, U_g)` update as `insert`, but the denominator
        // comes straight from the user's pre-computed closure instead
        // of a `LookupMessage::encode` call.
        let v = encoded();
        self.u += (v - EE::ONE) * flag.dup();
        self.v += flag * multiplicity;
    }
}

// CONSTRAINT BATCH
// ================================================================================================

/// Batch handle returned by [`LookupGroup::batch`].
///
/// Wraps an internal `(N, D)` pair and absorbs each interaction via the
/// cross-multiplication rule `N' = N·v + m·D`, `D' = D·v`. The
/// enclosing [`ConstraintGroup::batch`] folds the final `(N, D)` into
/// the group's `(V_g, U_g)` using the outer flag.
///
/// Per-interaction encoding lives on the message itself
/// ([`LookupMessage::encode`]), and the `(N, D)` update is inlined at
/// every call site (no `absorb` helper) so the `add` / `remove` paths
/// can skip the `m · D` multiplication when `m = ±1`.
pub struct ConstraintBatch<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    challenges: &'a Challenges<EE>,
    n: EE,
    d: EE,
    _phantom: PhantomData<E>,
}

impl<'a, E, EE> LookupBatch for ConstraintBatch<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    type Expr = E;
    type ExprEF = EE;

    fn add<M>(&mut self, _name: &'static str, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `m = 1`: `(N, D) ← (N·v + D, D·v)`. Skips the `m · D` mul.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.dup();
        self.n = self.n.dup() * v.dup() + d_prev;
        self.d = self.d.dup() * v;
    }

    fn remove<M>(&mut self, _name: &'static str, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `m = −1`: `(N, D) ← (N·v − D, D·v)`.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.dup();
        self.n = self.n.dup() * v.dup() - d_prev;
        self.d = self.d.dup() * v;
    }

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Self::Expr, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // General case: `(N, D) ← (N·v + m·D, D·v)`.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.dup();
        self.n = self.n.dup() * v.dup() + d_prev * multiplicity;
        self.d = self.d.dup() * v;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        // Same as `insert`, but the denominator is a user-supplied
        // pre-encoded `ExprEF` instead of a `LookupMessage::encode`
        // call.
        let v = encoded();
        let d_prev = self.d.dup();
        self.n = self.n.dup() * v.dup() + d_prev * multiplicity;
        self.d = self.d.dup() * v;
    }
}

/// Constraint adapter with immutable row inputs separate from mutable assertion emission.
///
/// The builder owns one challenge table and duplicates only the first selector and normalized
/// export it needs. Column callbacks borrow that table, not the sink or row frame. Auxiliary
/// columns after the declared LogUp prefix are independently constrained by the source.
pub struct ConstraintLookupBuilder<'rows, 'sink, B: LiftedAirBuilder> {
    sink: &'sink mut B,
    aux: Rows<'rows, B::ExtExpr>,
    first: B::Expr,
    sigma: B::ExtExpr,
    challenges: Challenges<B::ExtExpr>,
    column_idx: usize,
    num_columns: usize,
}

impl<'rows, 'sink, B: LiftedAirBuilder> ConstraintLookupBuilder<'rows, 'sink, B> {
    /// Build challenge tables once for one lookup evaluation.
    ///
    /// The caller supplies the same frame/uniform inputs as its source evaluation. LogUp requires
    /// two challenge values, normalized export zero, and enough current/next auxiliary columns.
    /// Malformed source geometry is a construction invariant and panics here.
    pub fn new<A>(
        frame: &Frame<'rows, B>,
        inputs: Inputs<'_, B>,
        sink: &'sink mut B,
        air: &A,
    ) -> Self
    where
        A: LookupAir<Self>,
    {
        let num_columns = air.column_shape().len();
        assert!(num_columns > 0, "a LogUp argument must declare at least one column");
        assert!(inputs.challenges.len() >= 2, "LogUp requires alpha and beta challenges");
        assert!(!inputs.exports.is_empty(), "LogUp requires normalized export zero");
        assert!(frame.aux.current.len() >= num_columns, "LogUp auxiliary prefix is missing");
        assert!(frame.aux.next.len() >= num_columns, "LogUp next auxiliary prefix is missing");
        let challenges = Challenges::new(
            inputs.challenge(0),
            inputs.challenge(1),
            air.max_message_width(),
            air.num_bus_ids(),
        );
        Self {
            sink,
            aux: frame.aux,
            first: frame.first_row(),
            sigma: inputs.export(0),
            challenges,
            column_idx: 0,
            num_columns,
        }
    }

    pub fn finish(self) {
        assert_eq!(
            self.column_idx, self.num_columns,
            "LookupAir::eval emitted {} columns, but column_shape declares {}",
            self.column_idx, self.num_columns,
        );
    }
}

impl<B: LiftedAirBuilder> LookupBuilder for ConstraintLookupBuilder<'_, '_, B> {
    type F = B::F;
    type Expr = B::Expr;
    type ExprEF = B::ExtExpr;

    type Column<'a>
        = ConstraintColumn<'a, B::Expr, B::ExtExpr>
    where
        Self: 'a;

    fn next_column<'a, R>(
        &'a mut self,
        f: impl FnOnce(&mut Self::Column<'a>) -> R,
        _deg: Deg,
    ) -> R {
        let mut column = ConstraintColumn::new(&self.challenges);
        let result = f(&mut column);
        let (u, v) = column.into_pair();
        let index = self.column_idx;
        assert!(index < self.num_columns, "LookupAir::eval emitted more columns than declared");
        self.column_idx += 1;

        let (band, accumulator) = if index == 0 {
            (
                &self.aux.current[..self.num_columns],
                Some(AccumulatorInputs {
                    next: self.aux.next[0].dup(),
                    sigma: self.sigma.dup(),
                    first: self.first.dup(),
                }),
            )
        } else {
            (&self.aux.current[index..index + 1], None)
        };
        let (anchor, relation) = column_constraints(u, v, band.iter().map(Dup::dup), accumulator);
        if let Some(anchor) = anchor {
            self.sink.assert_zero_ext(anchor);
        }
        self.sink.assert_zero_ext(relation);
        result
    }
}

/// Evaluate one authored lookup declaration using the source's exact frame and inputs.
pub fn eval_lookup<'rows, 'sink, A, B>(
    air: &A,
    frame: &Frame<'rows, B>,
    inputs: Inputs<'_, B>,
    sink: &'sink mut B,
) where
    B: LiftedAirBuilder,
    A: LookupAir<ConstraintLookupBuilder<'rows, 'sink, B>>,
{
    let lookup_frame = LookupFrame::from_frame(frame);
    let mut builder = ConstraintLookupBuilder::new(frame, inputs, sink, air);
    air.eval(&lookup_frame, &mut builder);
    builder.finish();
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec, vec::Vec};

    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks as F;

    use super::*;
    use crate::{
        air::{
            AirFrame, AirSpec, Assertion, ConstraintMeta, LiftedAir, Selectors, UniformInputs,
            capture,
            symbolic::{AuxInput, BaseLeaf, ExtLeaf, RowOffset, SymbolicExpr},
        },
        lookup::{LookupColumn, LookupGroup},
    };

    struct EmptyLookup;

    impl<LB: LookupBuilder<F = F>> LookupAir<LB> for EmptyLookup {
        fn column_shape(&self) -> &[usize] {
            &[1, 1]
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, _frame: &LookupFrame<'_, LB::Expr>, builder: &mut LB) {
            for result in [17, 23] {
                let observed = builder.next_column(
                    |column| {
                        column.group("empty", |_| {}, Deg { v: 0, u: 0 });
                        result
                    },
                    Deg { v: 0, u: 0 },
                );
                assert_eq!(observed, result);
            }
        }
    }

    impl LiftedAir for EmptyLookup {
        type F = F;

        fn spec(&self) -> AirSpec<'_, F> {
            AirSpec {
                main_width: 1,
                aux_width: 3,
                num_public_values: 0,
                num_challenges: 2,
                num_exports: 1,
                preprocessed: None,
                periodic_columns: Cow::Borrowed(&[]),
            }
        }

        fn eval<B: LiftedAirBuilder<F = F>>(
            &self,
            frame: &Frame<'_, B>,
            inputs: Inputs<'_, B>,
            sink: &mut B,
        ) {
            eval_lookup(self, frame, inputs, sink);
        }
    }

    struct CachedLookup;

    impl<LB: LookupBuilder<F = F>> LookupAir<LB> for CachedLookup {
        fn column_shape(&self) -> &[usize] {
            &[2]
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, _frame: &LookupFrame<'_, LB::Expr>, builder: &mut LB) {
            builder.next_column(
                |column| {
                    column.group_with_cached_encoding(
                        "cached",
                        |_| panic!("constraint path must use the encoded description"),
                        |group| {
                            group.selected_batch2_encoded(
                                "two slots",
                                "first",
                                LB::Expr::ONE,
                                || LB::ExprEF::from(LB::Expr::from_u32(3)),
                                "second",
                                LB::Expr::TWO,
                                || LB::ExprEF::from(LB::Expr::from_u32(5)),
                            )
                        },
                        Deg { v: 0, u: 0 },
                    );
                },
                Deg { v: 0, u: 0 },
            );
        }
    }

    #[derive(Default)]
    struct Sink(Vec<F>);

    impl LiftedAirBuilder for Sink {
        type F = F;
        type Expr = F;
        type ExtExpr = F;

        fn emit_base(&mut self, _value: F, _meta: ConstraintMeta<'_>) {
            panic!("lookup equations must remain extension assertions")
        }

        fn emit_ext(&mut self, value: F, _meta: ConstraintMeta<'_>) {
            self.0.push(value);
        }
    }

    #[test]
    fn zero_anchor_prefix_and_fraction_slots_preserve_their_order() {
        let current = [F::TWO, F::from_u32(3), F::from_u32(999)];
        let next = [F::from_u32(7), F::from_u32(11), F::from_u32(888)];
        let frame = AirFrame {
            main: Rows { current: &[F::ZERO], next: &[F::ZERO] },
            preprocessed: Rows { current: &[], next: &[] },
            aux: Rows { current: &current, next: &next },
            periodic: &[],
            selectors: Selectors {
                first: F::ZERO,
                last: F::ONE,
                transition: F::ONE,
            },
        };
        let inputs = UniformInputs {
            public_values: &[],
            challenges: &[F::from_u32(13), F::from_u32(17)],
            exports: &[F::from_u32(5)],
        };
        let mut sink = Sink::default();
        eval_lookup(&EmptyLookup, &frame, inputs, &mut sink);
        // 2*0; 1*(7-(2+3)+5)-0; 1*3-0. Suffix 999 is not part of LogUp.
        assert_eq!(sink.0, vec![F::ZERO, F::from_u32(7), F::from_u32(3)]);
        let mut sink = Sink::default();
        eval_lookup(&CachedLookup, &frame, inputs, &mut sink);
        // The two fractions combine to (V,U)=(11,15), so 15*(7-2+5)-11=139.
        assert_eq!(sink.0, vec![F::ZERO, F::from_u32(139)]);
    }

    #[test]
    fn noncopy_symbolic_inputs_keep_anchor_operand_and_emission_order() {
        let captured = capture(&EmptyLookup).unwrap();
        assert_eq!(captured.assertions.len(), 3);
        assert_eq!(captured.descriptor.analysis().counts().ext, 3);
        let Assertion::Extension(SymbolicExpr::Mul { x, y, .. }) = &captured.assertions[0] else {
            panic!("anchor must be acc * first")
        };
        assert!(matches!(
            x.as_ref(),
            SymbolicExpr::Leaf(ExtLeaf::Input(AuxInput::Trace {
                offset: RowOffset::Current,
                index: 0,
            }))
        ));
        assert!(matches!(
            y.as_ref(),
            SymbolicExpr::Leaf(ExtLeaf::Base(SymbolicExpr::Leaf(BaseLeaf::IsFirstRow)))
        ));
        assert!(
            captured
                .assertions
                .iter()
                .all(|assertion| matches!(assertion, Assertion::Extension(_)))
        );
    }
}

//! Ordered assertion emission, independent of input access.

use p3_field::{Algebra, Dup, Field, PrimeCharacteristicRing};

/// One synchronous diagnostic label and its nested labels.
///
/// At the receiving sink this chain is ordered from outermost to innermost. Nodes are borrowed
/// only for the emission call; a capturing sink must copy names it wants to retain.
#[derive(Clone, Copy, Debug)]
pub struct ConstraintPath<'a> {
    pub name: &'a str,
    pub nested: Option<&'a ConstraintPath<'a>>,
}

/// Optional non-mathematical context for one assertion emission.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConstraintMeta<'a> {
    pub path: Option<&'a ConstraintPath<'a>>,
}

/// A sink for base- and extension-class assertions in global emission order.
///
/// The sink has no trace windows or concrete extension field. Expressions may be non-`Copy`.
/// Every emission is significant, including duplicates and assertions gated by zero; consumers
/// must preserve its class and global position. Diagnostic metadata never changes the relation.
pub trait LiftedAirBuilder: Sized {
    type F: Field;
    type Expr: Algebra<Self::F>;
    type ExtExpr: Algebra<Self::Expr>;

    fn emit_base(&mut self, value: Self::Expr, meta: ConstraintMeta<'_>);
    fn emit_ext(&mut self, value: Self::ExtExpr, meta: ConstraintMeta<'_>);

    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.emit_base(value.into(), ConstraintMeta::default());
    }

    fn assert_one<I: Into<Self::Expr>>(&mut self, value: I) {
        self.assert_zero(value.into() - Self::Expr::ONE);
    }

    fn assert_eq<I: Into<Self::Expr>, J: Into<Self::Expr>>(&mut self, left: I, right: J) {
        self.assert_zero(left.into() - right.into());
    }

    /// Asserts the canonical Boolean vanishing polynomial `x * (x - 1)`.
    ///
    /// Using the ring operation preserves symbolic intent and allows concrete algebras to
    /// choose their implementation.
    fn assert_bool<I: Into<Self::Expr>>(&mut self, value: I) {
        let value: Self::Expr = value.into();
        self.assert_zero(value.bool_check());
    }

    fn assert_bools<const N: usize, I: Into<Self::Expr>>(&mut self, values: [I; N]) {
        for value in values {
            self.assert_bool(value);
        }
    }

    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, values: [I; N]) {
        for value in values {
            self.assert_zero(value);
        }
    }

    fn assert_eq_arrays<const N: usize, I: Into<Self::Expr>, J: Into<Self::Expr>>(
        &mut self,
        left: [I; N],
        right: [J; N],
    ) {
        for (left, right) in left.into_iter().zip(right) {
            self.assert_eq(left, right);
        }
    }

    fn assert_zero_ext<I: Into<Self::ExtExpr>>(&mut self, value: I) {
        self.emit_ext(value.into(), ConstraintMeta::default());
    }

    fn assert_eq_ext<I: Into<Self::ExtExpr>, J: Into<Self::ExtExpr>>(&mut self, left: I, right: J) {
        self.assert_zero_ext(left.into() - right.into());
    }

    fn assert_one_ext<I: Into<Self::ExtExpr>>(&mut self, value: I) {
        self.assert_eq_ext(value, Self::ExtExpr::ONE);
    }

    fn assert_zeros_ext<const N: usize, I: Into<Self::ExtExpr>>(&mut self, values: [I; N]) {
        for value in values {
            self.assert_zero_ext(value);
        }
    }

    fn assert_eq_ext_arrays<const N: usize, I: Into<Self::ExtExpr>, J: Into<Self::ExtExpr>>(
        &mut self,
        left: [I; N],
        right: [J; N],
    ) {
        for (left, right) in left.into_iter().zip(right) {
            self.assert_eq_ext(left, right);
        }
    }

    fn when<I: Into<Self::Expr>>(&mut self, condition: I) -> Filtered<'_, Self> {
        Filtered { inner: self, condition: condition.into() }
    }

    fn when_ne<I: Into<Self::Expr>, J: Into<Self::Expr>>(
        &mut self,
        left: I,
        right: J,
    ) -> Filtered<'_, Self> {
        self.when(left.into() - right.into())
    }

    fn scope<R>(&mut self, name: &str, f: impl FnOnce(&mut Named<'_, Self>) -> R) -> R {
        f(&mut self.named(name))
    }

    fn named<'a>(&'a mut self, name: &'a str) -> Named<'a, Self> {
        Named { inner: self, name }
    }
}

/// Multiplies each assertion by a base expression without suppressing any emission.
pub struct Filtered<'a, B: LiftedAirBuilder> {
    inner: &'a mut B,
    condition: B::Expr,
}

impl<B: LiftedAirBuilder> LiftedAirBuilder for Filtered<'_, B> {
    type F = B::F;
    type Expr = B::Expr;
    type ExtExpr = B::ExtExpr;

    fn emit_base(&mut self, value: Self::Expr, meta: ConstraintMeta<'_>) {
        self.inner.emit_base(self.condition.dup() * value, meta);
    }

    fn emit_ext(&mut self, value: Self::ExtExpr, meta: ConstraintMeta<'_>) {
        self.inner.emit_ext(value * self.condition.dup(), meta);
    }
}

/// Adds a borrowed label to every assertion emitted through this wrapper.
pub struct Named<'a, B: LiftedAirBuilder> {
    inner: &'a mut B,
    name: &'a str,
}

impl<B: LiftedAirBuilder> LiftedAirBuilder for Named<'_, B> {
    type F = B::F;
    type Expr = B::Expr;
    type ExtExpr = B::ExtExpr;

    fn emit_base(&mut self, value: Self::Expr, meta: ConstraintMeta<'_>) {
        let path = ConstraintPath { name: self.name, nested: meta.path };
        self.inner.emit_base(value, ConstraintMeta { path: Some(&path) });
    }

    fn emit_ext(&mut self, value: Self::ExtExpr, meta: ConstraintMeta<'_>) {
        let path = ConstraintPath { name: self.name, nested: meta.path };
        self.inner.emit_ext(value, ConstraintMeta { path: Some(&path) });
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec::Vec};

    use super::*;
    use crate::{
        air::{
            AirSpec, Assertion, capture_from_spec,
            symbolic::{ExprView, ExpressionDomain},
        },
        testing::configs::{Felt, QuadFelt},
    };

    #[derive(Default)]
    struct NumericSink {
        values: Vec<(ExpressionDomain, QuadFelt)>,
    }

    impl LiftedAirBuilder for NumericSink {
        type F = Felt;
        type Expr = Felt;
        type ExtExpr = QuadFelt;

        fn emit_base(&mut self, value: Felt, _: ConstraintMeta<'_>) {
            self.values.push((ExpressionDomain::Base, value.into()));
        }

        fn emit_ext(&mut self, value: QuadFelt, _: ConstraintMeta<'_>) {
            self.values.push((ExpressionDomain::Extension, value));
        }
    }

    #[test]
    fn boolean_builder_methods_retain_ring_operations_and_ordered_gates() {
        fn checks<S: LiftedAirBuilder>(sink: &mut S, values: &[S::Expr]) {
            sink.assert_bools([values[0].dup(), values[1].dup()]);
            sink.when(values[2].dup()).assert_bool(values[0].dup());
            sink.when(S::Expr::ZERO).assert_bool(values[1].dup());
        }

        let symbolic = capture_from_spec::<Felt, QuadFelt>(
            AirSpec {
                main_width: 3,
                aux_width: 0,
                num_public_values: 0,
                num_challenges: 0,
                num_exports: 0,
                preprocessed: None,
                periodic_columns: Cow::Borrowed(&[]),
            },
            |frame, _, sink| checks(sink, frame.main.current),
        )
        .unwrap();
        assert_eq!(symbolic.assertions.len(), 4, "zero gates still emit");
        for assertion in &symbolic.assertions[..2] {
            let Assertion::Base(value) = assertion else {
                panic!("Boolean assertions retain the base class");
            };
            assert!(matches!(value.as_ref().view(), ExprView::BoolCheck { .. }));
        }
        let Assertion::Base(gated) = &symbolic.assertions[2] else {
            panic!("gated Boolean assertions retain the base class");
        };
        assert!(matches!(gated.as_ref().view(), ExprView::Mul { y, .. }
            if matches!(y.view(), ExprView::BoolCheck { .. })));

        // Non-Boolean values and a non-Boolean gate verify the actual polynomial.
        let mut numeric = NumericSink::default();
        checks(&mut numeric, &[Felt::from_u64(5), Felt::from_u64(7), Felt::from_u64(11)]);
        assert_eq!(
            numeric.values,
            [20, 42, 220, 0]
                .into_iter()
                .map(|value| (ExpressionDomain::Base, Felt::from_u64(value).into()))
                .collect::<Vec<_>>()
        );
    }
}

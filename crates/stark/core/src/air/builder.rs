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

    fn assert_bool<I: Into<Self::Expr>>(&mut self, value: I) {
        let value = value.into();
        self.assert_zero(value.dup() * (value - Self::Expr::ONE));
    }

    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, values: [I; N]) {
        for value in values {
            self.assert_zero(value);
        }
    }

    fn assert_zero_ext<I: Into<Self::ExtExpr>>(&mut self, value: I) {
        self.emit_ext(value.into(), ConstraintMeta::default());
    }

    fn assert_eq_ext<I: Into<Self::ExtExpr>, J: Into<Self::ExtExpr>>(&mut self, left: I, right: J) {
        self.assert_zero_ext(left.into() - right.into());
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

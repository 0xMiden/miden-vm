// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from p3-air 0.8.0; see this module's documentation for provenance.

//! Owned symbolic algebra with shared operations and typed source domains.
//!
//! [`Expr`] uses sealed [`Base`] and [`Extension`] markers over one representation. Leaves
//! are inline; immutable operations and their checked degree caches are shared through `Arc`.
//! [`ExprRef`] and [`ExprView`] expose borrowed inspection while construction validates domains,
//! operation arities, and degree bounds. Base-to-extension conversions retain explicit lifts for
//! dynamic values and normalize base-embedded constants into the result domain.
//!
//! Addition and subtraction use ordered sums and negation. Binary operators retain small sum
//! nodes so accumulation stays linear and preserves reusable or prepared intermediates. Explicit
//! reductions collect their direct terms; use-aware flattening belongs to the compiler.
//!
//! Sums, products, linear combinations, powers, signed power-of-two scaling, and boolean checks
//! preserve useful ring operations. Each operation produces one scalar expression. Quadratic
//! extension squares, XOR, XOR3, and ANDN use the field traits' arithmetic expansions.
//! Checked [`super::capture_with`] constructs expression-valued inputs; [`super::SymbolicSink`]
//! retains every assertion in global emission order. Serialization preserves sharing and validates
//! topology and domains while recomputing degree caches. Actual-height capacity queries use
//! [`super::DegreeProfile`] independently of those diagnostic caches.
//!
//! # Provenance
//!
//! Derived from `p3-air` 0.8.0, upstream revision
//! `a21e3ed42905040ad49c519e402f018381c12d0c` (`air/src/symbolic`). Original code is
//! Copyright (c) 2022 The Plonky3 Authors, licensed under MIT OR Apache-2.0.
//! The original license texts remain alongside this module as `LICENSE-MIT` and `LICENSE-APACHE`.
mod expression;
pub(crate) mod expression_ext;
mod flatten;
mod input;
#[cfg(test)]
mod tests;
mod traversal;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    fmt,
    iter::{Product, Sum},
    marker::PhantomData,
    ops,
};
use p3_field::{Algebra, Dup, ExtensionField, Field, InjectiveMonomial, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};

pub use expression::SymbolicExpression;
pub use expression_ext::SymbolicExpressionExt;
pub use input::{AuxInput, BaseInput, RowOffset};
pub use traversal::{ExprChildren, ExprList, ExprRef, ExprView};

/// Source algebra of an expression. Base polynomials may evaluate in an extension at OOD points.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExpressionDomain {
    Base,
    Extension,
}

mod sealed {
    pub trait Sealed {}
}
/// A sealed marker selecting the source algebra of an expression.
pub trait Domain: sealed::Sealed + Clone + fmt::Debug {
    const DOMAIN: ExpressionDomain;
}
#[derive(Clone, Copy, Debug)]
pub struct Base;
#[derive(Clone, Copy, Debug)]
pub struct Extension;
impl sealed::Sealed for Base {}
impl sealed::Sealed for Extension {}
impl Domain for Base {
    const DOMAIN: ExpressionDomain = ExpressionDomain::Base;
}
impl Domain for Extension {
    const DOMAIN: ExpressionDomain = ExpressionDomain::Extension;
}

/// A symbolic value. Leaves are inline so ring identities can be associated constants;
/// operations, their operands, and checked degree caches are shared by `Arc`.
///
/// The domain marker records the authored algebra even when both domains evaluate in the same
/// numerical field. Dynamic base operands are lifted explicitly into extension expressions;
/// constant conversions normalize into the result domain without retaining the scalar overload.
/// Structural identity does not decide polynomial equivalence.
///
/// Auxiliary expressions cannot be used as base expressions:
///
/// ```compile_fail
/// use miden_stark::air::symbolic::{AuxInput, SymbolicExpression};
/// use p3_goldilocks::Goldilocks;
/// let _: SymbolicExpression<Goldilocks> = AuxInput::Challenge { index: 0 }.into();
/// ```
///
/// Even when both domains use the same numerical field, their handles are distinct:
///
/// ```compile_fail
/// use miden_stark::air::symbolic::{SymbolicExpression, SymbolicExpressionExt};
/// use p3_goldilocks::Goldilocks;
/// let extension = SymbolicExpressionExt::<Goldilocks, Goldilocks>::from(Goldilocks::new(1));
/// let _: SymbolicExpression<Goldilocks> = extension;
/// ```
#[derive(Clone, Debug)]
pub struct Expr<F, EF = F, D = Base> {
    raw: RawExpr<F, EF>,
    marker: PhantomData<D>,
}
#[derive(Clone, Debug)]
enum RawExpr<F, EF> {
    BaseConstant { value: F, domain: ExpressionDomain },
    ExtensionConstant(EF),
    BaseInput(BaseInput),
    AuxInput(AuxInput),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Node(Arc<Node<F, EF>>),
}
#[derive(Debug)]
struct Node<F, EF> {
    domain: ExpressionDomain,
    degree_multiple: usize,
    op: Op<F, EF>,
}
#[derive(Debug)]
enum Op<F, EF> {
    Lift(RawExpr<F, EF>),
    Mul {
        x: RawExpr<F, EF>,
        y: RawExpr<F, EF>,
    },
    Neg(RawExpr<F, EF>),
    Sum(Box<[RawExpr<F, EF>]>),
    Product(Box<[RawExpr<F, EF>]>),
    LinearCombination {
        values: Box<[RawExpr<F, EF>]>,
        coefficients: Box<[RawExpr<F, EF>]>,
    },
    Exp {
        x: RawExpr<F, EF>,
        power: u64,
    },
    ExpPowerOf2 {
        x: RawExpr<F, EF>,
        power_log: usize,
    },
    ScalePow2 {
        x: RawExpr<F, EF>,
        exponent: i128,
    },
    BoolCheck(RawExpr<F, EF>),
}
/// Invalid expression structure or an unrepresentable structural degree bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpressionError {
    DegreeOverflow,
    InvalidDomain,
    InvalidLength,
    InvalidScale,
    CharacteristicTwo,
}
impl fmt::Display for ExpressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DegreeOverflow => "symbolic polynomial degree overflow",
            Self::InvalidDomain => "invalid symbolic operand domain",
            Self::InvalidLength => "mismatched symbolic operand lengths",
            Self::InvalidScale => "power-of-two scale exponent exceeds u64 magnitude",
            Self::CharacteristicTwo => "division by two in characteristic two",
        })
    }
}
impl core::error::Error for ExpressionError {}

impl<F, EF> RawExpr<F, EF> {
    fn domain(&self) -> ExpressionDomain {
        match self {
            RawExpr::BaseConstant { domain, .. } => *domain,
            RawExpr::ExtensionConstant(_) | RawExpr::AuxInput(_) => ExpressionDomain::Extension,
            RawExpr::Node(node) => node.domain,
            _ => ExpressionDomain::Base,
        }
    }
    fn degree_multiple(&self) -> usize {
        match self {
            RawExpr::BaseInput(input) => input.degree_multiple(),
            RawExpr::AuxInput(input) => input.degree_multiple(),
            RawExpr::IsFirstRow | RawExpr::IsLastRow => 1,
            RawExpr::Node(node) => node.degree_multiple,
            _ => 0,
        }
    }
}
impl<F: Field, EF: ExtensionField<F>> RawExpr<F, EF> {
    fn constant(&self) -> Option<EF> {
        match self {
            RawExpr::BaseConstant { value, .. } => Some(EF::from(*value)),
            RawExpr::ExtensionConstant(value) => Some(*value),
            RawExpr::Node(node) => match &node.op {
                Op::Lift(value) => value.constant(),
                _ => None,
            },
            _ => None,
        }
    }
    fn from_constant(domain: ExpressionDomain, value: EF) -> Self {
        if let Some(value) = value.as_base() {
            RawExpr::BaseConstant { value, domain }
        } else {
            assert_eq!(
                domain,
                ExpressionDomain::Extension,
                "extension constant in base expression"
            );
            RawExpr::ExtensionConstant(value)
        }
    }
    fn node(domain: ExpressionDomain, op: Op<F, EF>) -> Result<Self, ExpressionError> {
        validate_op(domain, &op)?;
        // Validate the encoded source/result domains before erasing a constant lift.
        if let Op::Lift(value) = &op
            && let Some(value) = value.constant()
        {
            return Ok(Self::from_constant(domain, value));
        }
        match op {
            Op::Neg(value) => return Ok(value.negated()),
            Op::Sum(values) => return Ok(Self::sum(domain, values.into_vec())),
            _ => {},
        }
        let degree_multiple = traversal::op_degree(&op, |value| Ok(value.degree_multiple()))?;
        Ok(RawExpr::Node(Arc::new(Node { domain, degree_multiple, op })))
    }

    fn negated(self) -> Self {
        let domain = self.domain();
        if let Some(value) = self.constant() {
            return Self::from_constant(domain, -value);
        }
        if let RawExpr::Node(node) = &self
            && let Op::Neg(value) = &node.op
        {
            return value.clone();
        }
        let degree_multiple = self.degree_multiple();
        RawExpr::Node(Arc::new(Node {
            domain,
            degree_multiple,
            op: Op::Neg(self),
        }))
    }

    /// Fold only direct terms. Retaining nested sums makes construction independent
    /// of Arc ownership and keeps binary accumulation linear in the number of terms.
    fn sum(domain: ExpressionDomain, values: impl IntoIterator<Item = Self>) -> Self {
        let values = values.into_iter();
        let mut terms = Vec::with_capacity(values.size_hint().0);
        let mut constant = EF::ZERO;
        let mut degree_multiple = 0;
        for value in values {
            assert_eq!(value.domain(), domain, "invalid symbolic sum domain");
            if let Some(value) = value.constant() {
                constant += value;
            } else {
                degree_multiple = degree_multiple.max(value.degree_multiple());
                terms.push(value);
            }
        }
        if !constant.is_zero() {
            terms.push(Self::from_constant(domain, constant));
        }
        match terms.len() {
            0 => Self::from_constant(domain, EF::ZERO),
            1 => terms.pop().unwrap(),
            _ => RawExpr::Node(Arc::new(Node {
                domain,
                degree_multiple,
                op: Op::Sum(terms.into_boxed_slice()),
            })),
        }
    }

    fn additive(self, rhs: Self) -> Self {
        let domain = self.domain();
        // Updating a two-term sum's constant tail is bounded work, even when
        // the prefix is shared. Larger sums retain their explicit boundaries.
        if let Some(right) = rhs.constant()
            && let RawExpr::Node(node) = &self
            && let Op::Sum(values) = &node.op
            && values.len() == 2
            && let Some(left) = values[1].constant()
        {
            return Self::sum(
                domain,
                [values[0].clone(), Self::from_constant(domain, left + right)],
            );
        }
        Self::sum(domain, [self, rhs])
    }
}
fn validate_op<F: Field, EF: ExtensionField<F>>(
    domain: ExpressionDomain,
    op: &Op<F, EF>,
) -> Result<(), ExpressionError> {
    let same = |value: &RawExpr<F, EF>| value.domain() == domain;
    let valid = match op {
        Op::Lift(value) => {
            domain == ExpressionDomain::Extension && value.domain() == ExpressionDomain::Base
        },
        Op::Mul { x, y } => same(x) && same(y),
        Op::Neg(x) | Op::Exp { x, .. } | Op::ExpPowerOf2 { x, .. } | Op::BoolCheck(x) => same(x),
        Op::ScalePow2 { x, exponent } => {
            if exponent.unsigned_abs() > u128::from(u64::MAX) {
                return Err(ExpressionError::InvalidScale);
            }
            if *exponent < 0 && F::TWO.is_zero() {
                return Err(ExpressionError::CharacteristicTwo);
            }
            same(x)
        },
        Op::Sum(values) | Op::Product(values) => values.iter().all(same),
        Op::LinearCombination { values, coefficients } => {
            if values.len() != coefficients.len() {
                return Err(ExpressionError::InvalidLength);
            }
            values.iter().all(same) && coefficients.iter().all(same)
        },
    };
    if valid {
        Ok(())
    } else {
        Err(ExpressionError::InvalidDomain)
    }
}

impl<F: Field, EF: ExtensionField<F>, D: Domain> Expr<F, EF, D> {
    fn from_raw(raw: RawExpr<F, EF>) -> Self {
        assert_eq!(raw.domain(), D::DOMAIN, "invalid symbolic expression domain");
        Self { raw, marker: PhantomData }
    }
    fn operation(op: Op<F, EF>) -> Self {
        Self::from_raw(RawExpr::node(D::DOMAIN, op).expect("valid symbolic operation and degree"))
    }
    pub fn as_ref(&self) -> ExprRef<'_, F, EF> {
        ExprRef { raw: &self.raw }
    }
    pub fn view(&self) -> ExprView<'_, F, EF> {
        self.as_ref().view()
    }
    #[cfg(test)]
    pub(crate) fn set_cached_degree_for_test(&mut self, degree: usize) {
        let RawExpr::Node(node) = &mut self.raw else {
            panic!("only operation nodes have a degree cache");
        };
        Arc::get_mut(node).expect("test operation is uniquely owned").degree_multiple = degree;
    }

    pub fn degree_multiple(&self) -> usize {
        self.raw.degree_multiple()
    }
    pub fn degree_multiple_with_transition(&self, transition_degree: usize) -> usize {
        self.as_ref().degree_multiple_with_transition(transition_degree)
    }
    pub fn poly_degree(&self, trace_len: usize, periodic_periods: &[usize]) -> usize {
        self.as_ref().poly_degree(trace_len, periodic_periods)
    }
    pub fn checked_poly_degree(
        &self,
        trace_len: usize,
        periodic_periods: &[usize],
    ) -> Result<usize, ExpressionError> {
        self.as_ref().checked_poly_degree(trace_len, periodic_periods)
    }
    pub fn evaluate<R: PrimeCharacteristicRing>(
        &self,
        leaf: impl FnMut(ExprRef<'_, F, EF>, ExprView<'_, F, EF>) -> R,
    ) -> R {
        self.as_ref().evaluate(leaf)
    }
    pub fn is_first_row() -> Self {
        Self::base_leaf(RawExpr::IsFirstRow)
    }
    pub fn is_last_row() -> Self {
        Self::base_leaf(RawExpr::IsLastRow)
    }
    pub fn is_transition() -> Self {
        Self::base_leaf(RawExpr::IsTransition)
    }
    fn base_leaf(raw: RawExpr<F, EF>) -> Self {
        if D::DOMAIN == ExpressionDomain::Base {
            Self::from_raw(raw)
        } else {
            Self::operation(Op::Lift(raw))
        }
    }
    fn binary(self, rhs: Self, kind: Binary) -> Self {
        match kind {
            Binary::Add => {
                return Self::from_raw(self.raw.additive(rhs.raw));
            },
            Binary::Sub => {
                return Self::from_raw(self.raw.additive(rhs.raw.negated()));
            },
            Binary::Mul => {},
        }
        if let (Some(x), Some(y)) = (self.raw.constant(), rhs.raw.constant()) {
            return Self::from_raw(RawExpr::from_constant(D::DOMAIN, x * y));
        }
        if self.raw.constant().is_some_and(|value| value.is_zero())
            || rhs.raw.constant().is_some_and(|value| value.is_zero())
        {
            return Self::ZERO;
        }
        if rhs.raw.constant().is_some_and(|value| value.is_one()) {
            return self;
        }
        if self.raw.constant().is_some_and(|value| value.is_one()) {
            return rhs;
        }
        Self::operation(Op::Mul { x: self.raw, y: rhs.raw })
    }
    fn unary(
        self,
        op: impl FnOnce(RawExpr<F, EF>) -> Op<F, EF>,
        constant: impl FnOnce(EF) -> EF,
    ) -> Self {
        if let Some(value) = self.raw.constant() {
            return Self::from_raw(RawExpr::from_constant(D::DOMAIN, constant(value)));
        }
        Self::operation(op(self.raw))
    }
    fn sum_values(values: impl IntoIterator<Item = RawExpr<F, EF>>) -> Self {
        Self::from_raw(RawExpr::sum(D::DOMAIN, values))
    }
    fn product_values(values: Vec<RawExpr<F, EF>>) -> Self {
        if values.is_empty() {
            return Self::ONE;
        }
        if values.len() == 1 {
            return Self::from_raw(values.into_iter().next().unwrap());
        }
        if let Some(value) = values
            .iter()
            .try_fold(EF::ONE, |product, value| Some(product * value.constant()?))
        {
            return Self::from_raw(RawExpr::from_constant(D::DOMAIN, value));
        }
        Self::operation(Op::Product(values.into_boxed_slice()))
    }
    fn linear_combination(values: Vec<RawExpr<F, EF>>, coefficients: Vec<RawExpr<F, EF>>) -> Self {
        assert_eq!(values.len(), coefficients.len(), "linear-combination lengths differ");
        if values.is_empty() {
            return Self::ZERO;
        }
        if let Some(value) = values
            .iter()
            .zip(&coefficients)
            .try_fold(EF::ZERO, |sum, (value, coefficient)| {
                Some(sum + value.constant()? * coefficient.constant()?)
            })
        {
            return Self::from_raw(RawExpr::from_constant(D::DOMAIN, value));
        }
        Self::operation(Op::LinearCombination {
            values: values.into_boxed_slice(),
            coefficients: coefficients.into_boxed_slice(),
        })
    }
}

#[derive(Clone, Copy)]
enum Binary {
    Add,
    Sub,
    Mul,
}
impl<F: Field, EF: ExtensionField<F>, D: Domain> From<F> for Expr<F, EF, D> {
    fn from(value: F) -> Self {
        Self::from_raw(RawExpr::from_constant(D::DOMAIN, EF::from(value)))
    }
}
impl<F: Field, EF: ExtensionField<F>, D: Domain> From<BaseInput> for Expr<F, EF, D> {
    fn from(input: BaseInput) -> Self {
        Self::base_leaf(RawExpr::BaseInput(input))
    }
}
impl<F: Field, EF: ExtensionField<F>> From<AuxInput> for Expr<F, EF, Extension> {
    fn from(input: AuxInput) -> Self {
        Self::from_raw(RawExpr::AuxInput(input))
    }
}
impl<F: Field, EF: ExtensionField<F>> From<Expr<F, EF, Base>> for Expr<F, EF, Extension> {
    fn from(value: Expr<F, EF, Base>) -> Self {
        Self::operation(Op::Lift(value.raw))
    }
}
impl<F: Field, EF: ExtensionField<F>, D: Domain> Default for Expr<F, EF, D> {
    fn default() -> Self {
        Self::ZERO
    }
}
impl<F: Field, EF: ExtensionField<F>, D: Domain> Dup for Expr<F, EF, D> {
    fn dup(&self) -> Self {
        self.clone()
    }
}
impl<F: Field, EF: ExtensionField<F>, D: Domain> PrimeCharacteristicRing for Expr<F, EF, D> {
    type PrimeSubfield = F::PrimeSubfield;
    const ZERO: Self = Self {
        raw: RawExpr::BaseConstant { value: F::ZERO, domain: D::DOMAIN },
        marker: PhantomData,
    };
    const ONE: Self = Self {
        raw: RawExpr::BaseConstant { value: F::ONE, domain: D::DOMAIN },
        marker: PhantomData,
    };
    const TWO: Self = Self {
        raw: RawExpr::BaseConstant { value: F::TWO, domain: D::DOMAIN },
        marker: PhantomData,
    };
    const NEG_ONE: Self = Self {
        raw: RawExpr::BaseConstant { value: F::NEG_ONE, domain: D::DOMAIN },
        marker: PhantomData,
    };
    fn from_prime_subfield(value: Self::PrimeSubfield) -> Self {
        F::from_prime_subfield(value).into()
    }
    fn double(&self) -> Self {
        self.mul_2exp_u64(1)
    }
    fn halve(&self) -> Self {
        self.div_2exp_u64(1)
    }
    fn square(&self) -> Self {
        self.exp_u64(2)
    }
    fn cube(&self) -> Self {
        self.exp_u64(3)
    }
    fn bool_check(&self) -> Self {
        self.clone().unary(Op::BoolCheck, |value| value.bool_check())
    }
    fn exp_u64(&self, power: u64) -> Self {
        match power {
            0 => Self::ONE,
            1 => self.clone(),
            _ => self.clone().unary(|x| Op::Exp { x, power }, |value| value.exp_u64(power)),
        }
    }
    fn exp_const_u64<const POWER: u64>(&self) -> Self {
        self.exp_u64(POWER)
    }
    fn exp_power_of_2(&self, power_log: usize) -> Self {
        if power_log == 0 {
            return self.clone();
        }
        self.clone()
            .unary(|x| Op::ExpPowerOf2 { x, power_log }, |value| value.exp_power_of_2(power_log))
    }
    fn mul_2exp_u64(&self, exp: u64) -> Self {
        if exp == 0 {
            return self.clone();
        }
        self.clone().unary(
            |x| Op::ScalePow2 { x, exponent: i128::from(exp) },
            |value| value.mul_2exp_u64(exp),
        )
    }
    fn div_2exp_u64(&self, exp: u64) -> Self {
        assert!(!F::TWO.is_zero(), "division by two in characteristic two");
        if exp == 0 {
            return self.clone();
        }
        self.clone().unary(
            |x| Op::ScalePow2 { x, exponent: -i128::from(exp) },
            |value| value.div_2exp_u64(exp),
        )
    }
    fn sum_array<const N: usize>(input: &[Self]) -> Self {
        assert_eq!(N, input.len());
        Self::sum_values(input.iter().map(|value| value.raw.clone()))
    }
    fn dot_product<const N: usize>(lhs: &[Self; N], rhs: &[Self; N]) -> Self {
        Self::linear_combination(
            lhs.iter().map(|v| v.raw.clone()).collect(),
            rhs.iter().map(|v| v.raw.clone()).collect(),
        )
    }
}

macro_rules! binary_operator {
    ($trait:ident, $method:ident, $kind:ident, $assign:ident, $assign_method:ident) => {
        impl<F: Field, EF: ExtensionField<F>, D: Domain, T: Into<Self>> ops::$trait<T>
            for Expr<F, EF, D>
        {
            type Output = Self;
            fn $method(self, rhs: T) -> Self {
                self.binary(rhs.into(), Binary::$kind)
            }
        }
        impl<F: Field, EF: ExtensionField<F>, D: Domain, T: Into<Self>> ops::$assign<T>
            for Expr<F, EF, D>
        {
            fn $assign_method(&mut self, rhs: T) {
                let value = core::mem::take(self);
                *self = value.binary(rhs.into(), Binary::$kind);
            }
        }
    };
}
binary_operator!(Add, add, Add, AddAssign, add_assign);
binary_operator!(Sub, sub, Sub, SubAssign, sub_assign);
binary_operator!(Mul, mul, Mul, MulAssign, mul_assign);
impl<F: Field, EF: ExtensionField<F>, D: Domain> ops::Neg for Expr<F, EF, D> {
    type Output = Self;
    fn neg(self) -> Self {
        Self::from_raw(self.raw.negated())
    }
}
impl<F: Field, EF: ExtensionField<F>, D: Domain, T: Into<Self>> Sum<T> for Expr<F, EF, D> {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        Self::sum_values(iter.map(|value| value.into().raw))
    }
}
impl<F: Field, EF: ExtensionField<F>, D: Domain, T: Into<Self>> Product<T> for Expr<F, EF, D> {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        Self::product_values(iter.map(|value| value.into().raw).collect())
    }
}
impl<F: Field, EF: ExtensionField<F>, D: Domain> Algebra<F> for Expr<F, EF, D> {
    fn mixed_dot_product<const N: usize>(values: &[Self; N], coefficients: &[F; N]) -> Self {
        Self::linear_combination(
            values.iter().map(|v| v.raw.clone()).collect(),
            coefficients.iter().map(|v| Self::from(*v).raw).collect(),
        )
    }
    fn batched_linear_combination(values: &[Self], coefficients: &[F]) -> Self {
        Self::linear_combination(
            values.iter().map(|v| v.raw.clone()).collect(),
            coefficients.iter().map(|v| Self::from(*v).raw).collect(),
        )
    }
}
impl<F: Field, EF: ExtensionField<F>> Algebra<Expr<F, EF, Base>> for Expr<F, EF, Extension> {
    fn mixed_dot_product<const N: usize>(
        values: &[Self; N],
        coefficients: &[Expr<F, EF, Base>; N],
    ) -> Self {
        Self::linear_combination(
            values.iter().map(|v| v.raw.clone()).collect(),
            coefficients.iter().map(|v| Self::from(v.clone()).raw).collect(),
        )
    }
    fn batched_linear_combination(values: &[Self], coefficients: &[Expr<F, EF, Base>]) -> Self {
        Self::linear_combination(
            values.iter().map(|v| v.raw.clone()).collect(),
            coefficients.iter().map(|v| Self::from(v.clone()).raw).collect(),
        )
    }
}
impl<F: Field + InjectiveMonomial<N>, EF: ExtensionField<F>, const N: u64> InjectiveMonomial<N>
    for Expr<F, EF, Base>
{
}

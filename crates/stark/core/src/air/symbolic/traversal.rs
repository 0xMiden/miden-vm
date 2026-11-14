//! Borrowed inspection and memoized traversal of the shared symbolic representation.
use super::{AuxInput, BaseInput, ExpressionDomain, ExpressionError, Op, RawExpr};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

/// A borrowed expression independent of its compile-time domain marker.
#[derive(Debug)]
pub struct ExprRef<'a, F, EF> {
    pub(super) raw: &'a RawExpr<F, EF>,
}
impl<F, EF> Copy for ExprRef<'_, F, EF> {}
impl<F, EF> Clone for ExprRef<'_, F, EF> {
    fn clone(&self) -> Self {
        *self
    }
}
/// A borrowed ordered list of expression operands.
#[derive(Debug)]
pub struct ExprList<'a, F, EF> {
    values: &'a [RawExpr<F, EF>],
}
impl<F, EF> Copy for ExprList<'_, F, EF> {}
impl<F, EF> Clone for ExprList<'_, F, EF> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, F, EF> ExprList<'a, F, EF> {
    pub fn len(self) -> usize {
        self.values.len()
    }
    pub fn is_empty(self) -> bool {
        self.values.is_empty()
    }
    pub fn get(self, index: usize) -> Option<ExprRef<'a, F, EF>> {
        self.values.get(index).map(|raw| ExprRef { raw })
    }
    pub fn iter(self) -> impl ExactSizeIterator<Item = ExprRef<'a, F, EF>> + DoubleEndedIterator {
        self.values.iter().map(|raw| ExprRef { raw })
    }
}
/// Complete borrowed view. Operation children belong to the result domain;
/// dynamic base-to-extension conversions are represented by explicit lifts.
#[derive(Debug)]
pub enum ExprView<'a, F, EF> {
    BaseConstant(&'a F),
    ExtensionConstant(&'a EF),
    BaseInput(BaseInput),
    AuxInput(AuxInput),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Lift {
        value: ExprRef<'a, F, EF>,
    },
    Add {
        x: ExprRef<'a, F, EF>,
        y: ExprRef<'a, F, EF>,
    },
    Sub {
        x: ExprRef<'a, F, EF>,
        y: ExprRef<'a, F, EF>,
    },
    Mul {
        x: ExprRef<'a, F, EF>,
        y: ExprRef<'a, F, EF>,
    },
    Neg {
        x: ExprRef<'a, F, EF>,
    },
    Sum {
        values: ExprList<'a, F, EF>,
    },
    Product {
        values: ExprList<'a, F, EF>,
    },
    LinearCombination {
        values: ExprList<'a, F, EF>,
        coefficients: ExprList<'a, F, EF>,
    },
    Exp {
        x: ExprRef<'a, F, EF>,
        power: u64,
    },
    ExpPowerOf2 {
        x: ExprRef<'a, F, EF>,
        power_log: usize,
    },
    ScalePow2 {
        x: ExprRef<'a, F, EF>,
        exponent: i128,
    },
    BoolCheck {
        x: ExprRef<'a, F, EF>,
    },
}
impl<'a, F, EF> ExprRef<'a, F, EF> {
    pub fn domain(self) -> ExpressionDomain {
        self.raw.domain()
    }
    /// Identity of a shared scalar operation; inline leaves have no allocation identity.
    pub fn identity(self) -> Option<usize> {
        match self.raw {
            RawExpr::Node(node) => Some(Arc::as_ptr(node) as usize),
            _ => None,
        }
    }
    pub fn degree_multiple(self) -> usize {
        self.raw.degree_multiple()
    }
    pub fn view(self) -> ExprView<'a, F, EF> {
        let child = |raw| ExprRef { raw };
        match self.raw {
            RawExpr::BaseConstant { value, .. } => ExprView::BaseConstant(value),
            RawExpr::ExtensionConstant(value) => ExprView::ExtensionConstant(value),
            RawExpr::BaseInput(input) => ExprView::BaseInput(*input),
            RawExpr::AuxInput(input) => ExprView::AuxInput(*input),
            RawExpr::IsFirstRow => ExprView::IsFirstRow,
            RawExpr::IsLastRow => ExprView::IsLastRow,
            RawExpr::IsTransition => ExprView::IsTransition,
            RawExpr::Node(node) => match &node.op {
                Op::Lift(value) => ExprView::Lift { value: child(value) },
                Op::Add { x, y } => ExprView::Add { x: child(x), y: child(y) },
                Op::Sub { x, y } => ExprView::Sub { x: child(x), y: child(y) },
                Op::Mul { x, y } => ExprView::Mul { x: child(x), y: child(y) },
                Op::Neg(x) => ExprView::Neg { x: child(x) },
                Op::Sum(values) => ExprView::Sum { values: ExprList { values } },
                Op::Product(values) => ExprView::Product { values: ExprList { values } },
                Op::LinearCombination { values, coefficients } => ExprView::LinearCombination {
                    values: ExprList { values },
                    coefficients: ExprList { values: coefficients },
                },
                Op::Exp { x, power } => ExprView::Exp { x: child(x), power: *power },
                Op::ExpPowerOf2 { x, power_log } => {
                    ExprView::ExpPowerOf2 { x: child(x), power_log: *power_log }
                },
                Op::ScalePow2 { x, exponent } => {
                    ExprView::ScalePow2 { x: child(x), exponent: *exponent }
                },
                Op::BoolCheck(x) => ExprView::BoolCheck { x: child(x) },
            },
        }
    }
    pub fn children(self) -> ExprChildren<'a, F, EF> {
        ExprChildren { expression: self, index: 0 }
    }
    /// Fold each shared scalar operation once. Child values follow `children()` order:
    /// Linear-combination values precede their coefficients.
    pub fn fold<T: Clone>(self, mut visit: impl FnMut(Self, ExprView<'a, F, EF>, &[T]) -> T) -> T {
        fn walk<'a, F, EF, T: Clone>(
            expression: ExprRef<'a, F, EF>,
            cache: &mut BTreeMap<usize, T>,
            visit: &mut impl FnMut(ExprRef<'a, F, EF>, ExprView<'a, F, EF>, &[T]) -> T,
        ) -> T {
            if let Some(value) = expression.identity().and_then(|key| cache.get(&key)) {
                return value.clone();
            }
            let values: Vec<T> =
                expression.children().map(|child| walk(child, cache, visit)).collect();
            let value = visit(expression, expression.view(), &values);
            if let Some(key) = expression.identity() {
                cache.insert(key, value.clone());
            }
            value
        }
        walk(self, &mut BTreeMap::new(), &mut visit)
    }
    /// Apply checked structural polynomial degree rules to caller-supplied leaf bounds.
    /// Shared operation nodes are visited once, and errors stop the traversal.
    pub fn checked_degree_with(
        self,
        mut leaf: impl FnMut(Self, ExprView<'a, F, EF>) -> Result<usize, ExpressionError>,
    ) -> Result<usize, ExpressionError> {
        fn walk<'a, F, EF>(
            expression: ExprRef<'a, F, EF>,
            cache: &mut BTreeMap<usize, usize>,
            leaf: &mut impl FnMut(
                ExprRef<'a, F, EF>,
                ExprView<'a, F, EF>,
            ) -> Result<usize, ExpressionError>,
        ) -> Result<usize, ExpressionError> {
            if let Some(degree) = expression.identity().and_then(|key| cache.get(&key)) {
                return Ok(*degree);
            }
            let degree = match expression.raw {
                RawExpr::Node(node) => {
                    op_degree(&node.op, |raw| walk(ExprRef { raw }, cache, leaf))?
                },
                _ => leaf(expression, expression.view())?,
            };
            if let Some(key) = expression.identity() {
                cache.insert(key, degree);
            }
            Ok(degree)
        }
        walk(self, &mut BTreeMap::new(), &mut leaf)
    }
    pub fn degree_multiple_with_transition(self, transition_degree: usize) -> usize {
        if transition_degree == 0 {
            return self.degree_multiple();
        }
        self.checked_degree_with(|expression, view| {
            Ok(if matches!(view, ExprView::IsTransition) {
                transition_degree
            } else {
                expression.degree_multiple()
            })
        })
        .expect("symbolic degree overflow")
    }
    pub fn checked_poly_degree(
        self,
        trace_len: usize,
        periodic_periods: &[usize],
    ) -> Result<usize, ExpressionError> {
        self.checked_degree_with(|_, view| {
            Ok(match view {
                ExprView::BaseInput(input) => input.poly_degree(trace_len, periodic_periods),
                ExprView::AuxInput(input) => input.poly_degree(trace_len),
                ExprView::IsFirstRow | ExprView::IsLastRow => trace_len.saturating_sub(1),
                ExprView::IsTransition => 1,
                _ => 0,
            })
        })
    }
    pub fn poly_degree(self, trace_len: usize, periodic_periods: &[usize]) -> usize {
        self.checked_poly_degree(trace_len, periodic_periods)
            .expect("symbolic polynomial degree overflow")
    }
    /// Evaluate in any ring, with a caller-defined interpretation of source leaves.
    /// The source domain stays independent of the evaluation ring (including OOD values).
    pub fn evaluate<R: PrimeCharacteristicRing>(
        self,
        mut leaf: impl FnMut(Self, ExprView<'a, F, EF>) -> R,
    ) -> R {
        self.fold(|expression, view, values: &[R]| match view {
            ExprView::Lift { .. } => values[0].dup(),
            ExprView::Add { .. } => values[0].dup() + values[1].dup(),
            ExprView::Sub { .. } => values[0].dup() - values[1].dup(),
            ExprView::Mul { .. } => values[0].dup() * values[1].dup(),
            ExprView::Neg { .. } => -values[0].dup(),
            ExprView::Sum { .. } => values.iter().cloned().sum(),
            ExprView::Product { .. } => values.iter().cloned().product(),
            ExprView::LinearCombination { values: inputs, .. } => values[..inputs.len()]
                .iter()
                .zip(&values[inputs.len()..])
                .map(|(a, b)| a.dup() * b.dup())
                .sum(),
            ExprView::Exp { power, .. } => values[0].exp_u64(power),
            ExprView::ExpPowerOf2 { power_log, .. } => values[0].exp_power_of_2(power_log),
            ExprView::ScalePow2 { exponent, .. } => {
                if exponent < 0 {
                    values[0].div_2exp_u64((-exponent) as u64)
                } else {
                    values[0].mul_2exp_u64(exponent as u64)
                }
            },
            ExprView::BoolCheck { .. } => values[0].bool_check(),
            _ => leaf(expression, view),
        })
    }
}

/// Iterator over the immediate child expressions, without allocating a child list.
pub struct ExprChildren<'a, F, EF> {
    expression: ExprRef<'a, F, EF>,
    index: usize,
}
impl<'a, F, EF> Iterator for ExprChildren<'a, F, EF> {
    type Item = ExprRef<'a, F, EF>;
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        self.index += 1;
        match self.expression.view() {
            ExprView::Lift { value } => (index == 0).then_some(value),
            ExprView::Neg { x }
            | ExprView::Exp { x, .. }
            | ExprView::ExpPowerOf2 { x, .. }
            | ExprView::ScalePow2 { x, .. }
            | ExprView::BoolCheck { x } => (index == 0).then_some(x),
            ExprView::Add { x, y, .. }
            | ExprView::Sub { x, y, .. }
            | ExprView::Mul { x, y, .. } => match index {
                0 => Some(x),
                1 => Some(y),
                _ => None,
            },
            ExprView::Sum { values } | ExprView::Product { values } => values.get(index),
            ExprView::LinearCombination { values, coefficients, .. } => {
                if index < values.len() {
                    values.get(index)
                } else {
                    coefficients.get(index - values.len())
                }
            },
            _ => None,
        }
    }
}

pub(super) fn op_degree<'a, F, EF>(
    op: &'a Op<F, EF>,
    mut degree: impl FnMut(&'a RawExpr<F, EF>) -> Result<usize, ExpressionError>,
) -> Result<usize, ExpressionError> {
    let add = |a: usize, b: usize| a.checked_add(b).ok_or(ExpressionError::DegreeOverflow);
    match op {
        Op::Lift(x) | Op::Neg(x) | Op::ScalePow2 { x, .. } => degree(x),
        Op::Add { x, y, .. } | Op::Sub { x, y, .. } => Ok(degree(x)?.max(degree(y)?)),
        Op::Mul { x, y, .. } => add(degree(x)?, degree(y)?),
        Op::Sum(values) => values.iter().try_fold(0, |acc, value| Ok(acc.max(degree(value)?))),
        Op::Product(values) => values.iter().try_fold(0, |acc, value| add(acc, degree(value)?)),
        Op::LinearCombination { values, coefficients, .. } => values
            .iter()
            .zip(coefficients.iter())
            .try_fold(0, |acc, (a, b)| Ok(acc.max(add(degree(a)?, degree(b)?)?))),
        Op::Exp { x, power } => {
            let d = degree(x)?;
            if d == 0 {
                Ok(0)
            } else {
                usize::try_from(*power)
                    .ok()
                    .and_then(|power| d.checked_mul(power))
                    .ok_or(ExpressionError::DegreeOverflow)
            }
        },
        Op::ExpPowerOf2 { x, power_log } => {
            let d = degree(x)?;
            if d == 0 {
                Ok(0)
            } else {
                u32::try_from(*power_log)
                    .ok()
                    .and_then(|shift| {
                        1usize.checked_shl(shift).and_then(|factor| d.checked_mul(factor))
                    })
                    .ok_or(ExpressionError::DegreeOverflow)
            }
        },
        Op::BoolCheck(x) => degree(x)?.checked_mul(2).ok_or(ExpressionError::DegreeOverflow),
    }
}

pub(super) fn to_base<F: Field, EF: ExtensionField<F>>(
    raw: &RawExpr<F, EF>,
) -> Option<RawExpr<F, EF>> {
    fn walk<F: Field, EF: ExtensionField<F>>(
        raw: &RawExpr<F, EF>,
        cache: &mut BTreeMap<usize, RawExpr<F, EF>>,
    ) -> Option<RawExpr<F, EF>> {
        if raw.domain() == ExpressionDomain::Base {
            return Some(raw.clone());
        }
        match raw {
            RawExpr::BaseConstant { value, .. } => Some(RawExpr::BaseConstant {
                value: *value,
                domain: ExpressionDomain::Base,
            }),
            RawExpr::Node(node) => {
                let key = Arc::as_ptr(node) as usize;
                if let Some(value) = cache.get(&key) {
                    return Some(value.clone());
                }
                let result = match &node.op {
                    Op::Lift(value) => Some(value.clone()),
                    Op::Neg(x) => {
                        RawExpr::node(ExpressionDomain::Base, Op::Neg(walk(x, cache)?)).ok()
                    },
                    Op::Add { x, y, .. } => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::Add { x: walk(x, cache)?, y: walk(y, cache)? },
                    )
                    .ok(),
                    Op::Sub { x, y, .. } => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::Sub { x: walk(x, cache)?, y: walk(y, cache)? },
                    )
                    .ok(),
                    Op::Mul { x, y, .. } => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::Mul { x: walk(x, cache)?, y: walk(y, cache)? },
                    )
                    .ok(),
                    Op::Sum(values) => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::Sum(
                            values
                                .iter()
                                .map(|v| walk(v, cache))
                                .collect::<Option<Vec<_>>>()?
                                .into_boxed_slice(),
                        ),
                    )
                    .ok(),
                    Op::Product(values) => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::Product(
                            values
                                .iter()
                                .map(|v| walk(v, cache))
                                .collect::<Option<Vec<_>>>()?
                                .into_boxed_slice(),
                        ),
                    )
                    .ok(),
                    Op::LinearCombination { values, coefficients, .. } => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::LinearCombination {
                            values: values
                                .iter()
                                .map(|v| walk(v, cache))
                                .collect::<Option<Vec<_>>>()?
                                .into_boxed_slice(),
                            coefficients: coefficients
                                .iter()
                                .map(|v| walk(v, cache))
                                .collect::<Option<Vec<_>>>()?
                                .into_boxed_slice(),
                        },
                    )
                    .ok(),
                    Op::Exp { x, power } => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::Exp { x: walk(x, cache)?, power: *power },
                    )
                    .ok(),
                    Op::ExpPowerOf2 { x, power_log } => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::ExpPowerOf2 {
                            x: walk(x, cache)?,
                            power_log: *power_log,
                        },
                    )
                    .ok(),
                    Op::ScalePow2 { x, exponent } => RawExpr::node(
                        ExpressionDomain::Base,
                        Op::ScalePow2 { x: walk(x, cache)?, exponent: *exponent },
                    )
                    .ok(),
                    Op::BoolCheck(x) => {
                        RawExpr::node(ExpressionDomain::Base, Op::BoolCheck(walk(x, cache)?)).ok()
                    },
                }?;
                cache.insert(key, result.clone());
                Some(result)
            },
            _ => None,
        }
    }
    walk(raw, &mut BTreeMap::new())
}

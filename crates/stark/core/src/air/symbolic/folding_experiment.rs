//! Temporary host-only construction policies for the folding benchmark.
//! No override selects the production strict-nested policy. `Current` explicitly
//! reproduces the earlier aggregate-constant and bounded-tail folding baseline.

use alloc::{sync::Arc, vec::Vec};
use std::cell::Cell;

use p3_field::{ExtensionField, Field};

use super::{ExpressionDomain, Node, Op, RawExpr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Current,
    StrictNested,
    AdjacentNested,
    LeftAppend,
    FullFlatten,
}

impl Policy {
    pub const ALL: [Self; 5] = [
        Self::Current,
        Self::StrictNested,
        Self::AdjacentNested,
        Self::LeftAppend,
        Self::FullFlatten,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::StrictNested => "strict_nested",
            Self::AdjacentNested => "adjacent_nested",
            Self::LeftAppend => "left_append",
            Self::FullFlatten => "full_flatten",
        }
    }
}

std::thread_local! {
    static ACTIVE: Cell<Option<Policy>> = const { Cell::new(None) };
}

pub(super) fn current() -> Option<Policy> {
    ACTIVE.with(Cell::get)
}

/// Capture synchronously on this thread; nested scopes and unwinding restore the prior policy.
pub fn with_policy<R>(policy: Policy, capture: impl FnOnce() -> R) -> R {
    struct Restore(Option<Policy>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(self.0));
        }
    }
    let _restore = Restore(ACTIVE.with(|active| active.replace(Some(policy))));
    capture()
}

impl<F: Field, EF: ExtensionField<F>> RawExpr<F, EF> {
    pub(super) fn experiment_sum(
        domain: ExpressionDomain,
        values: Vec<Self>,
        policy: Policy,
    ) -> Self {
        if policy == Policy::Current {
            return Self::experiment_legacy_sum(domain, values);
        }
        if policy == Policy::StrictNested {
            return Self::sum(domain, values);
        }
        fn flatten<F: Field, EF: ExtensionField<F>>(
            value: RawExpr<F, EF>,
            out: &mut Vec<RawExpr<F, EF>>,
        ) {
            if let RawExpr::Node(node) = &value
                && let Op::Sum(children) = &node.op
            {
                for child in children.iter() {
                    flatten(child.clone(), out);
                }
                return;
            }
            out.push(value);
        }

        let values = if policy == Policy::FullFlatten {
            let mut flattened = Vec::new();
            for value in values {
                flatten(value, &mut flattened);
            }
            flattened
        } else {
            values
        };
        let mut terms = Vec::with_capacity(values.len());
        let mut constant = EF::ZERO;
        for value in values {
            assert_eq!(value.domain(), domain, "invalid symbolic sum domain");
            if let Some(value_constant) = value.constant() {
                // Keep a pending run at its original location rather than gathering
                // constants from opposite sides of a dynamic term.
                constant += value_constant;
            } else {
                if !constant.is_zero() {
                    terms.push(Self::from_constant(domain, constant));
                    constant = EF::ZERO;
                }
                terms.push(value);
            }
        }
        if !constant.is_zero() {
            terms.push(Self::from_constant(domain, constant));
        }
        match terms.len() {
            0 => Self::from_constant(domain, EF::ZERO),
            1 => terms.pop().unwrap(),
            _ => {
                let degree_multiple = terms.iter().map(Self::degree_multiple).max().unwrap();
                RawExpr::Node(Arc::new(Node {
                    domain,
                    degree_multiple,
                    op: Op::Sum(terms.into_boxed_slice()),
                }))
            },
        }
    }

    // Preserve the old benchmark baseline exclusively in this feature-gated module.
    fn experiment_legacy_sum(domain: ExpressionDomain, values: Vec<Self>) -> Self {
        let mut terms = Vec::with_capacity(values.len());
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

    pub(super) fn experiment_additive(self, rhs: Self, subtract: bool, policy: Policy) -> Self {
        let domain = self.domain();
        // Check the authored RHS before subtraction introduces Neg(Sum).
        let rhs_was_sum = matches!(&rhs, RawExpr::Node(node) if matches!(&node.op, Op::Sum(_)));
        let rhs = if subtract { rhs.negated() } else { rhs };
        if matches!(policy, Policy::Current | Policy::AdjacentNested)
            && let Some(right) = rhs.constant()
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
        if policy == Policy::LeftAppend
            && !rhs_was_sum
            && let RawExpr::Node(node) = &self
            && let Op::Sum(values) = &node.op
        {
            return Self::sum(domain, values.iter().cloned().chain(core::iter::once(rhs)));
        }
        Self::sum(domain, [self, rhs])
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    use super::*;
    use crate::air::symbolic::{BaseInput, ExprView, RowOffset, SymbolicExpression};

    type B = SymbolicExpression<Goldilocks>;

    fn input(column: usize) -> B {
        BaseInput::Main { row: RowOffset::Current, column }.into()
    }

    fn value(expression: &B) -> Goldilocks {
        expression.evaluate(|_, view| match view {
            ExprView::BaseInput(input) => Goldilocks::new(input.index() as u64 + 2),
            ExprView::BaseConstant(value) => *value,
            _ => panic!("unexpected leaf"),
        })
    }

    #[test]
    fn no_override_uses_strict_but_current_remains_reproducible() {
        assert_eq!(current(), None);
        let build = || input(0) + Goldilocks::ONE + Goldilocks::TWO;
        let default = build();
        let strict = with_policy(Policy::StrictNested, build);
        assert_eq!(serde_json::to_value(&default).unwrap(), serde_json::to_value(strict).unwrap());
        let legacy = with_policy(Policy::Current, build);
        assert_eq!(value(&default), value(&legacy));
        let ExprView::Sum { values } = legacy.view() else {
            panic!("legacy sum")
        };
        assert!(
            matches!(values.get(1).unwrap().view(), ExprView::BaseConstant(c) if *c == Goldilocks::new(3))
        );
        let ExprView::Sum { values } = default.view() else {
            panic!("default sum")
        };
        assert!(matches!(values.get(0).unwrap().view(), ExprView::Sum { .. }));
        assert_eq!(current(), None);
    }

    #[test]
    fn policies_isolate_constant_aggregation_and_preserve_values() {
        for policy in Policy::ALL {
            with_policy(policy, || {
                let explicit: B = [input(0), B::ONE, input(1), B::TWO].into_iter().sum();
                assert_eq!(value(&explicit), Goldilocks::new(8));
                match explicit.view() {
                    ExprView::Sum { values } => {
                        assert_eq!(values.len(), if policy == Policy::Current { 3 } else { 4 });
                    },
                    _ => panic!("expected reduction"),
                }
                let tail = input(0) + Goldilocks::ONE + Goldilocks::TWO;
                assert_eq!(value(&tail), Goldilocks::new(5));
                match tail.view() {
                    ExprView::Sum { values } => {
                        assert_eq!(values.len(), 2);
                        assert_eq!(
                            matches!(values.get(0).unwrap().view(), ExprView::Sum { .. }),
                            policy == Policy::StrictNested,
                        );
                    },
                    _ => panic!("expected sum"),
                }
                let constants: B = [B::ONE, B::TWO].into_iter().sum();
                assert!(
                    matches!(constants.view(), ExprView::BaseConstant(c) if *c == Goldilocks::new(3))
                );
            });
        }
    }

    #[test]
    fn left_append_preserves_original_sum_rhs_including_subtraction() {
        with_policy(Policy::LeftAppend, || {
            let left = input(0) + input(1);
            let right = input(2) + input(3);
            for subtract in [false, true] {
                let combined = if subtract {
                    left.clone() - right.clone()
                } else {
                    left.clone() + right.clone()
                };
                let ExprView::Sum { values } = combined.view() else {
                    panic!("sum")
                };
                assert_eq!(values.len(), 2);
                assert_eq!(values.get(0).unwrap().identity(), left.as_ref().identity());
                if subtract {
                    assert!(
                        matches!(values.get(1).unwrap().view(), ExprView::Neg { x } if x.identity() == right.as_ref().identity())
                    );
                } else {
                    assert_eq!(values.get(1).unwrap().identity(), right.as_ref().identity());
                }
            }
            // This policy deliberately bypasses even a shared left prefix when RHS is not a sum.
            let appended = left.clone() + input(2);
            assert!(matches!(appended.view(), ExprView::Sum { values } if values.len() == 3));
            assert_eq!(value(&appended), Goldilocks::new(9));
        });
    }

    #[test]
    fn full_flatten_keeps_negated_sum_as_one_term_and_scopes_restore() {
        with_policy(Policy::FullFlatten, || {
            let left = input(0) + input(1);
            let right = input(2) + input(3);
            let positive = left.clone() + right.clone();
            assert!(matches!(positive.view(), ExprView::Sum { values } if values.len() == 4));
            let negative = left - right;
            assert_eq!(value(&negative), -Goldilocks::new(4));
            assert!(
                matches!(negative.view(), ExprView::Sum { values } if values.len() == 3 && matches!(values.get(2).unwrap().view(), ExprView::Neg { x } if matches!(x.view(), ExprView::Sum { .. })))
            );
            let _ =
                std::panic::catch_unwind(|| with_policy(Policy::StrictNested, || panic!("scope")));
            assert_eq!(current(), Some(Policy::FullFlatten));
        });
        assert_eq!(current(), None);
    }
}

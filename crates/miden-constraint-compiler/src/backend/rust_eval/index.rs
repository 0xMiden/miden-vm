//! Temporary indexing of borrowed source expressions for native scheduling.
//!
//! The source expressions own all operation semantics. This table supplies dense
//! IDs and canonical child IDs without copying operations into another AST.
use std::{
    collections::HashMap,
    mem::{Discriminant, discriminant},
};

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{BasedVectorSpace, ExtensionField};
use miden_stark::air::{
    Assertion,
    symbolic::{AuxInput, BaseInput, ExprRef, ExprView, ExpressionDomain},
};

use crate::ir::Class;

type View<'a> = ExprView<'a, Felt, QuadFelt>;

pub(super) struct IndexedExpression<'a> {
    pub expression: ExprRef<'a, Felt, QuadFelt>,
    pub children: Box<[usize]>,
}

pub(super) struct ExpressionIndex<'a> {
    pub nodes: Vec<IndexedExpression<'a>>,
    pub roots: Vec<(usize, Class)>,
}

// Exact keys, rather than allocation identities or arithmetic equivalence, recover
// structural CSE while keeping distinct authored scalar overloads and boundaries.
#[derive(PartialEq, Eq, Hash)]
struct Key<'a> {
    domain: ExpressionDomain,
    operation: Discriminant<View<'a>>,
    parameters: Vec<u8>,
    children: Box<[usize]>,
}

impl<'a> ExpressionIndex<'a> {
    pub fn new(assertions: &'a [Assertion<Felt, QuadFelt>]) -> Self {
        let mut index = Self {
            nodes: Vec::new(),
            roots: vec![(0, Class::Base); assertions.len()],
        };
        let mut interner = HashMap::new();
        let mut memo = HashMap::new();
        // Match the established base-first discovery order. Roots retain source
        // assertion order so emitted constraints keep their alpha assignment.
        for extension in [false, true] {
            for (ordinal, assertion) in assertions.iter().enumerate() {
                let expression = match assertion {
                    Assertion::Base(value) if !extension => value.as_ref(),
                    Assertion::Extension(value) if extension => value.as_ref(),
                    _ => continue,
                };
                let id = index.insert(expression, &mut interner, &mut memo);
                index.roots[ordinal] = (id, index.class(id));
            }
        }
        index
    }

    fn insert(
        &mut self,
        expression: ExprRef<'a, Felt, QuadFelt>,
        interner: &mut HashMap<Key<'a>, usize>,
        memo: &mut HashMap<usize, usize>,
    ) -> usize {
        if let Some(id) = expression.identity().and_then(|identity| memo.get(&identity)) {
            return *id;
        }
        let children: Box<[_]> =
            expression.children().map(|child| self.insert(child, interner, memo)).collect();
        let key = Key {
            domain: expression.domain(),
            operation: discriminant(&expression.view()),
            parameters: parameters(expression.view()),
            children: children.clone(),
        };
        let id = *interner.entry(key).or_insert_with(|| {
            let id = self.nodes.len();
            self.nodes.push(IndexedExpression { expression, children });
            id
        });
        if let Some(identity) = expression.identity() {
            memo.insert(identity, id);
        }
        id
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn node(&self, id: usize) -> ExprRef<'a, Felt, QuadFelt> {
        self.nodes[id].expression
    }
    pub fn children(&self, id: usize) -> &[usize] {
        &self.nodes[id].children
    }
    pub fn class(&self, id: usize) -> Class {
        match self.node(id).domain() {
            ExpressionDomain::Base => Class::Base,
            ExpressionDomain::Extension => Class::Ext,
        }
    }
    pub fn constant(&self, id: usize) -> Option<u64> {
        match self.node(id).view() {
            ExprView::BaseConstant(value) => Some(value.as_canonical_u64()),
            ExprView::ExtensionConstant(value) => {
                let base: Option<Felt> = value.as_base();
                base.map(|value| value.as_canonical_u64())
            },
            ExprView::Lift { .. } => self.constant(self.children(id)[0]),
            _ => None,
        }
    }
    pub fn challenge_dependencies(&self) -> Vec<bool> {
        let mut only = Vec::with_capacity(self.len());
        for node in &self.nodes {
            only.push(match node.expression.view() {
                ExprView::BaseConstant(_)
                | ExprView::ExtensionConstant(_)
                | ExprView::AuxInput(AuxInput::Challenge { .. }) => true,
                ExprView::BaseInput(_)
                | ExprView::AuxInput(_)
                | ExprView::IsFirstRow
                | ExprView::IsLastRow
                | ExprView::IsTransition => false,
                _ => node.children.iter().all(|&child| only[child]),
            });
        }
        only
    }
}

fn parameters(view: View<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let word = |bytes: &mut Vec<u8>, value: usize| bytes.extend_from_slice(&value.to_le_bytes());
    match view {
        ExprView::BaseConstant(value) => {
            bytes.extend_from_slice(&value.as_canonical_u64().to_le_bytes())
        },
        ExprView::ExtensionConstant(value) => {
            let coefficients: &[Felt] = value.as_basis_coefficients_slice();
            for coefficient in coefficients {
                bytes.extend_from_slice(&coefficient.as_canonical_u64().to_le_bytes());
            }
        },
        ExprView::BaseInput(input) => match input {
            BaseInput::Main { row, column } | BaseInput::Preprocessed { row, column } => {
                bytes.push(if matches!(input, BaseInput::Main { .. }) { 0 } else { 1 });
                word(&mut bytes, row.index());
                word(&mut bytes, column);
            },
            BaseInput::Public { index } | BaseInput::Periodic { index } => {
                bytes.push(if matches!(input, BaseInput::Public { .. }) {
                    2
                } else {
                    3
                });
                word(&mut bytes, index);
            },
        },
        ExprView::AuxInput(input) => match input {
            AuxInput::Trace { row, column } => {
                bytes.push(0);
                word(&mut bytes, row.index());
                word(&mut bytes, column);
            },
            AuxInput::Challenge { index } | AuxInput::Export { index } => {
                bytes.push(if matches!(input, AuxInput::Challenge { .. }) {
                    1
                } else {
                    2
                });
                word(&mut bytes, index);
            },
        },
        ExprView::Add { coefficient_domain, .. }
        | ExprView::Sub { coefficient_domain, .. }
        | ExprView::Mul { coefficient_domain, .. }
        | ExprView::LinearCombination { coefficient_domain, .. } => {
            bytes.push(coefficient_domain as u8)
        },
        ExprView::Exp { power, .. } => bytes.extend_from_slice(&power.to_le_bytes()),
        ExprView::ExpPowerOf2 { power_log, .. } => word(&mut bytes, power_log),
        ExprView::ScalePow2 { exponent, .. } => bytes.extend_from_slice(&exponent.to_le_bytes()),
        ExprView::Lift { .. }
        | ExprView::Neg { .. }
        | ExprView::Sum { .. }
        | ExprView::Product { .. }
        | ExprView::BoolCheck { .. }
        | ExprView::IsFirstRow
        | ExprView::IsLastRow
        | ExprView::IsTransition => {},
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use miden_crypto::field::PrimeCharacteristicRing;
    use miden_stark::air::symbolic::{RowOffset, SymbolicExpression, SymbolicExpressionExt};

    type B = SymbolicExpression<Felt, QuadFelt>;
    type E = SymbolicExpressionExt<Felt, QuadFelt>;
    fn main() -> B {
        BaseInput::Main { row: RowOffset::Current, column: 0 }.into()
    }

    #[test]
    fn cse_uses_structure_and_retains_domains_overloads_and_operation_parameters() {
        let a = main() + main();
        let b = main() + main();
        assert_ne!(a.as_ref().identity(), b.as_ref().identity());
        let assertions = vec![
            Assertion::Base(a),
            Assertion::Base(b),
            Assertion::Base(main() * Felt::from_u64(3)),
            Assertion::Base(main() * B::from_u64(3)),
            Assertion::Base(main().exp_u64(3)),
            Assertion::Base(main().exp_u64(5)),
            Assertion::Extension(E::from(main())),
        ];
        let index = ExpressionIndex::new(&assertions);
        assert_eq!(index.roots[0], index.roots[1]);
        assert_ne!(index.roots[2], index.roots[3]);
        assert_ne!(index.roots[4], index.roots[5]);
        assert_eq!(index.roots[6].1, Class::Ext);
    }

    #[test]
    fn dependency_classification_keeps_namespaces_and_non_challenge_inputs_distinct() {
        let challenge: E = AuxInput::Challenge { index: 0 }.into();
        let export: E = AuxInput::Export { index: 0 }.into();
        let assertions = vec![
            Assertion::Extension(challenge.square()),
            Assertion::Extension(export.square()),
            Assertion::Base(BaseInput::Public { index: 0 }.into()),
            Assertion::Base(BaseInput::Periodic { index: 0 }.into()),
            Assertion::Base(BaseInput::Preprocessed { row: RowOffset::Current, column: 0 }.into()),
            Assertion::Base(main()),
        ];
        let index = ExpressionIndex::new(&assertions);
        let only = index.challenge_dependencies();
        assert!(only[index.roots[0].0]);
        for &(root, _) in &index.roots[1..] {
            assert!(!only[root]);
        }
        let roots: std::collections::HashSet<_> = index.roots.iter().map(|&(id, _)| id).collect();
        assert_eq!(roots.len(), assertions.len());
    }
}

//! Canonical indexing of borrowed source expressions for arithmetic lowering and native scheduling.
//!
//! The source expressions own all operation semantics. This table supplies dense
//! IDs and canonical child IDs without copying operations into another AST.
use std::{
    collections::{HashMap, HashSet},
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

pub(crate) struct IndexedExpression<'a> {
    pub(crate) expression: ExprRef<'a, Felt, QuadFelt>,
    pub(crate) children: Box<[usize]>,
}

pub(crate) struct ExpressionIndex<'a> {
    pub(crate) nodes: Vec<IndexedExpression<'a>>,
    pub(crate) roots: Vec<(usize, Class)>,
}

// Exact keys, rather than allocation identities or arithmetic equivalence, recover
// structural CSE after source normalization while keeping operation boundaries.
#[derive(PartialEq, Eq, Hash)]
struct Key<'a> {
    domain: ExpressionDomain,
    operation: Discriminant<View<'a>>,
    parameters: Vec<u8>,
    children: Box<[usize]>,
}

impl<'a> ExpressionIndex<'a> {
    pub(crate) fn new(assertions: &'a [Assertion<Felt, QuadFelt>]) -> Self {
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

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }
    pub(crate) fn node(&self, id: usize) -> ExprRef<'a, Felt, QuadFelt> {
        self.nodes[id].expression
    }
    pub(crate) fn children(&self, id: usize) -> &[usize] {
        &self.nodes[id].children
    }
    pub(crate) fn class(&self, id: usize) -> Class {
        match self.node(id).domain() {
            ExpressionDomain::Base => Class::Base,
            ExpressionDomain::Extension => Class::Ext,
        }
    }
    /// The native operand type before embedding a base value into the extension.
    /// Base constants and explicit lifts remain usable through `E: Algebra<B>`.
    pub(crate) fn value_class(&self, id: usize) -> Class {
        match self.node(id).view() {
            ExprView::BaseConstant(_) | ExprView::Lift { .. } => Class::Base,
            _ => self.class(id),
        }
    }
    pub(crate) fn constant(&self, id: usize) -> Option<u64> {
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
    pub(crate) fn challenge_dependencies(&self) -> Vec<bool> {
        self.preparation_dependencies(false)
    }
    pub(crate) fn uniform_dependencies(&self) -> Vec<bool> {
        self.preparation_dependencies(true)
    }
    fn preparation_dependencies(&self, all_uniform: bool) -> Vec<bool> {
        let mut only = Vec::with_capacity(self.len());
        for node in &self.nodes {
            only.push(match node.expression.view() {
                ExprView::BaseConstant(_)
                | ExprView::ExtensionConstant(_)
                | ExprView::AuxInput(AuxInput::Challenge { .. }) => true,
                ExprView::BaseInput(BaseInput::Public { .. })
                | ExprView::AuxInput(AuxInput::Export { .. }) => all_uniform,
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
        ExprView::Exp { power, .. } => bytes.extend_from_slice(&power.to_le_bytes()),
        ExprView::ExpPowerOf2 { power_log, .. } => word(&mut bytes, power_log),
        ExprView::ScalePow2 { exponent, .. } => bytes.extend_from_slice(&exponent.to_le_bytes()),
        ExprView::Lift { .. }
        | ExprView::Mul { .. }
        | ExprView::LinearCombination { .. }
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

/// Source allocation identities eligible for left-only associative lowering.
/// Exact structural use counts also protect independently allocated identical computations.
pub(crate) fn left_flattenable_sum_identities(
    assertions: &[Assertion<Felt, QuadFelt>],
) -> HashSet<usize> {
    fn aliases(
        expression: ExprRef<'_, Felt, QuadFelt>,
        canonical: usize,
        index: &ExpressionIndex<'_>,
        mapped: &mut HashMap<usize, usize>,
    ) {
        if let Some(identity) = expression.identity()
            && let Some(previous) = mapped.insert(identity, canonical)
        {
            debug_assert_eq!(previous, canonical);
            return;
        }
        for (child, &id) in expression.children().zip(index.children(canonical)) {
            aliases(child, id, index, mapped);
        }
    }

    let index = ExpressionIndex::new(assertions);
    let uniform = index.uniform_dependencies();
    let mut uses = vec![0usize; index.len()];
    for id in 0..index.len() {
        for &child in index.children(id) {
            uses[child] += 1;
        }
    }
    let mut mapped = HashMap::new();
    for (assertion, &(id, _)) in assertions.iter().zip(&index.roots) {
        uses[id] += 1;
        match assertion {
            Assertion::Base(value) => aliases(value.as_ref(), id, &index, &mut mapped),
            Assertion::Extension(value) => aliases(value.as_ref(), id, &index, &mut mapped),
        }
    }
    mapped
        .into_iter()
        .filter_map(|(identity, id)| {
            (uses[id] == 1 && !uniform[id] && matches!(index.node(id).view(), ExprView::Sum { .. }))
                .then_some(identity)
        })
        .collect()
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
    fn cse_normalizes_constant_spellings_and_retains_domains_and_operation_parameters() {
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
        assert_eq!(index.roots[2], index.roots[3]);
        assert_ne!(index.roots[4], index.roots[5]);
        assert_eq!(index.roots[6].1, Class::Ext);
    }

    #[test]
    fn extension_constants_and_linear_combinations_share_normalized_structure() {
        use miden_crypto::field::Algebra;

        let scalar = Felt::from_u64(7);
        let value = E::from(AuxInput::Trace { row: RowOffset::Current, column: 0 });
        let coefficients = [Felt::from_u64(7), Felt::from_u64(11)];
        let base_coefficients = coefficients.map(B::from);
        let extension_coefficients = coefficients.map(E::from);
        let base_values = [main(), main().square()];
        let extension_values = [value.clone(), value.clone().square()];
        let assertions = vec![
            Assertion::Extension(value.clone() * scalar),
            Assertion::Extension(value.clone() * B::from(scalar)),
            Assertion::Extension(value.clone() * E::from(scalar)),
            Assertion::Extension(value * E::extension_constant(QuadFelt::from(scalar))),
            Assertion::Base(B::dot_product(&base_values, &base_coefficients)),
            Assertion::Base(<B as Algebra<Felt>>::mixed_dot_product(&base_values, &coefficients)),
            Assertion::Extension(E::dot_product(&extension_values, &extension_coefficients)),
            Assertion::Extension(<E as Algebra<B>>::mixed_dot_product(
                &extension_values,
                &base_coefficients,
            )),
            Assertion::Extension(<E as Algebra<Felt>>::mixed_dot_product(
                &extension_values,
                &coefficients,
            )),
        ];
        let index = ExpressionIndex::new(&assertions);
        for root in &index.roots[1..4] {
            assert_eq!(*root, index.roots[0]);
        }
        assert_eq!(index.roots[4], index.roots[5]);
        assert_eq!(index.roots[6], index.roots[7]);
        assert_eq!(index.roots[6], index.roots[8]);
    }

    #[test]
    fn uniform_dependencies_include_public_values_and_exports_without_row_inputs() {
        let public: B = BaseInput::Public { index: 0 }.into();
        let export: E = AuxInput::Export { index: 0 }.into();
        let assertions = vec![
            Assertion::Base(public.square()),
            Assertion::Extension(export.square()),
            Assertion::Extension(E::from(public) + export),
            Assertion::Base(main()),
            Assertion::Base(BaseInput::Periodic { index: 0 }.into()),
            Assertion::Base(B::is_first_row()),
        ];
        let index = ExpressionIndex::new(&assertions);
        let uniform = index.uniform_dependencies();
        for &(root, _) in &index.roots[..3] {
            assert!(uniform[root]);
        }
        for &(root, _) in &index.roots[3..] {
            assert!(!uniform[root]);
        }
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

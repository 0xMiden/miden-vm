//! Owned authored expressions and their deterministic arithmetic lowering.
//!
//! The symbolic expressions remain the source representation for native code
//! generation. Their arithmetic graph is derived once for ACE and algebraic
//! analyses. Source allocation identity only memoizes authored sharing; the
//! graph builder independently interns structurally identical arithmetic.

use std::collections::HashMap;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{BasedVectorSpace, PrimeCharacteristicRing};
use miden_stark::air::{
    Assertion,
    symbolic::{AuxInput, BaseInput, ExprRef, ExprView, ExpressionDomain},
};

use super::{
    CapturedConstraints, Class, Graph, GraphBuilder, Leaf, Node, NodeId, OpCounts, OpKind,
};

/// One immutable authored capture and its derived arithmetic representation.
#[derive(Debug)]
pub struct CapturedProgram {
    assertions: Vec<Assertion<Felt, QuadFelt>>,
    graph: Graph,
    constraints: CapturedConstraints,
}

impl CapturedProgram {
    pub fn assertions(&self) -> &[Assertion<Felt, QuadFelt>] {
        &self.assertions
    }

    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    pub fn constraints(&self) -> &CapturedConstraints {
        &self.constraints
    }

    pub fn into_lowered(self) -> (Graph, CapturedConstraints) {
        (self.graph, self.constraints)
    }

    pub(crate) fn from_assertions(assertions: Vec<Assertion<Felt, QuadFelt>>) -> Self {
        let mut graph = GraphBuilder::new();
        let constraints = lower_assertions_into(&assertions, &mut graph);
        Self {
            assertions,
            graph: graph.freeze(),
            constraints,
        }
    }
}

pub(crate) fn lower_assertions_into(
    assertions: &[Assertion<Felt, QuadFelt>],
    graph: &mut GraphBuilder,
) -> CapturedConstraints {
    let mut lower = Lowering {
        graph,
        memo: HashMap::new(),
        base: OpCounts::default(),
        ext: OpCounts::default(),
    };
    let mut base_roots = Vec::new();
    let mut ext_roots = Vec::new();
    let mut base_global_indices = Vec::new();
    let mut ext_global_indices = Vec::new();
    // Preserve the established discovery order independently of global
    // assertion ordinals: every base root first, then every extension root.
    for (ordinal, assertion) in assertions.iter().enumerate() {
        if let Assertion::Base(value) = assertion {
            base_roots.push(lower.expression(value.as_ref()));
            base_global_indices.push(ordinal);
        }
    }
    for (ordinal, assertion) in assertions.iter().enumerate() {
        if let Assertion::Extension(value) = assertion {
            ext_roots.push(lower.expression(value.as_ref()));
            ext_global_indices.push(ordinal);
        }
    }
    CapturedConstraints {
        base_roots,
        ext_roots,
        base_global_indices,
        ext_global_indices,
        naive_base: lower.base,
        naive_ext: lower.ext,
    }
}

struct Lowering<'a> {
    graph: &'a mut GraphBuilder,
    // Every source expression stays alive throughout this walk. Shared Arc
    // addresses therefore cannot be reused and never define structural CSE.
    memo: HashMap<usize, NodeId>,
    base: OpCounts,
    ext: OpCounts,
}

impl Lowering<'_> {
    fn expression(&mut self, expression: ExprRef<'_, Felt, QuadFelt>) -> NodeId {
        let identity = expression.identity();
        if let Some(value) = identity.and_then(|identity| self.memo.get(&identity).copied()) {
            return value;
        }
        let class = match expression.domain() {
            ExpressionDomain::Base => Class::Base,
            ExpressionDomain::Extension => Class::Ext,
        };
        let value = match expression.view() {
            ExprView::BaseConstant(value) => {
                self.graph.leaf(Leaf::BaseConst(value.as_canonical_u64()))
            },
            ExprView::ExtensionConstant(value) => {
                let coefficients: &[Felt] = value.as_basis_coefficients_slice();
                self.graph.leaf(Leaf::ExtConst([
                    coefficients[0].as_canonical_u64(),
                    coefficients[1].as_canonical_u64(),
                ]))
            },
            ExprView::BaseInput(input) => self.graph.leaf(match input {
                BaseInput::Main { row, column } => {
                    Leaf::Main { offset: row.index(), index: column }
                },
                BaseInput::Preprocessed { row, column } => {
                    Leaf::Preprocessed { offset: row.index(), index: column }
                },
                BaseInput::Public { index } => Leaf::Public(index),
                BaseInput::Periodic { index } => Leaf::Periodic(index),
            }),
            ExprView::AuxInput(input) => self.graph.leaf(match input {
                AuxInput::Trace { row, column } => Leaf::Aux { offset: row.index(), index: column },
                AuxInput::Challenge { index } => Leaf::Challenge(index),
                AuxInput::Export { index } => Leaf::PermValue(index),
            }),
            ExprView::IsFirstRow => self.graph.leaf(Leaf::IsFirst),
            ExprView::IsLastRow => self.graph.leaf(Leaf::IsLast),
            ExprView::IsTransition => self.graph.leaf(Leaf::IsTransition),
            ExprView::Lift { value } => self.expression(value),
            ExprView::Add { x, y, .. }
            | ExprView::Sub { x, y, .. }
            | ExprView::Mul { x, y, .. } => {
                let x = self.expression(x);
                let y = self.expression(y);
                let op = match expression.view() {
                    ExprView::Add { .. } => OpKind::Add,
                    ExprView::Sub { .. } => OpKind::Sub,
                    _ => OpKind::Mul,
                };
                self.op(class, op, x, Some(y))
            },
            ExprView::Neg { x } => {
                let x = self.expression(x);
                self.op(class, OpKind::Neg, x, None)
            },
            ExprView::Sum { values } => {
                let values: Vec<_> = values.iter().map(|value| self.expression(value)).collect();
                self.sum(class, &values)
            },
            ExprView::Product { values } => {
                let values: Vec<_> = values.iter().map(|value| self.expression(value)).collect();
                match values.split_first() {
                    None => self.scalar(class, Felt::ONE),
                    Some((&first, rest)) => rest
                        .iter()
                        .fold(first, |acc, &value| self.op(class, OpKind::Mul, acc, Some(value))),
                }
            },
            ExprView::LinearCombination { values, coefficients, .. } => {
                // Discover all value operands before coefficients, matching the
                // source traversal; primitive products follow in pair order.
                let values: Vec<_> = values.iter().map(|value| self.expression(value)).collect();
                let coefficients: Vec<_> =
                    coefficients.iter().map(|value| self.expression(value)).collect();
                let products: Vec<_> = values
                    .iter()
                    .zip(&coefficients)
                    .map(|(&value, &coefficient)| {
                        self.op(class, OpKind::Mul, value, Some(coefficient))
                    })
                    .collect();
                self.sum(class, &products)
            },
            ExprView::Exp { x, mut power } => {
                let mut current = self.expression(x);
                let mut result = self.scalar(class, Felt::ONE);
                while power != 0 {
                    if power & 1 != 0 {
                        result = self.op(class, OpKind::Mul, result, Some(current));
                    }
                    power >>= 1;
                    if power != 0 {
                        current = self.op(class, OpKind::Mul, current, Some(current));
                    }
                }
                result
            },
            ExprView::ExpPowerOf2 { x, power_log } => {
                let x = self.expression(x);
                (0..power_log).fold(x, |value, _| self.op(class, OpKind::Mul, value, Some(value)))
            },
            ExprView::ScalePow2 { x, exponent } => {
                let x = self.expression(x);
                let mut power = exponent.unsigned_abs();
                let mut current = if exponent < 0 { Felt::ONE.halve() } else { Felt::TWO };
                let mut coefficient = Felt::ONE;
                while power != 0 {
                    if power & 1 != 0 {
                        coefficient *= current;
                    }
                    power >>= 1;
                    if power != 0 {
                        current = current.square();
                    }
                }
                let coefficient = self.scalar(class, coefficient);
                self.op(class, OpKind::Mul, x, Some(coefficient))
            },
            ExprView::BoolCheck { x } => {
                let x = self.expression(x);
                let one = self.scalar(class, Felt::ONE);
                let difference = self.op(class, OpKind::Sub, x, Some(one));
                self.op(class, OpKind::Mul, x, Some(difference))
            },
        };
        let value = self.promote(class, value);
        if let Some(identity) = identity {
            self.memo.insert(identity, value);
        }
        value
    }

    fn constant(&self, id: NodeId) -> Option<Felt> {
        match self.graph.node(id) {
            Node::Leaf(Leaf::BaseConst(value)) => Some(Felt::from_u64(value)),
            Node::Leaf(Leaf::ExtConst([value, 0])) => Some(Felt::from_u64(value)),
            Node::Leaf(Leaf::ExtBase(value)) => self.constant(value),
            _ => None,
        }
    }

    fn scalar(&mut self, class: Class, value: Felt) -> NodeId {
        let value = self.graph.leaf(Leaf::BaseConst(value.as_canonical_u64()));
        match class {
            Class::Base => value,
            Class::Ext => self.graph.leaf(Leaf::ExtBase(value)),
        }
    }

    fn class(&self, id: NodeId) -> Class {
        match self.graph.node(id) {
            Node::Op { class, .. } => class,
            Node::Leaf(
                Leaf::Aux { .. } | Leaf::Challenge(_) | Leaf::PermValue(_) | Leaf::ExtConst(_),
            ) => Class::Ext,
            Node::Leaf(Leaf::ExtBase(value)) => self.class(value),
            Node::Leaf(_) => Class::Base,
        }
    }

    fn promote(&mut self, class: Class, value: NodeId) -> NodeId {
        if class == Class::Ext
            && self.class(value) == Class::Base
            && !matches!(self.graph.node(value), Node::Leaf(Leaf::ExtBase(_)))
        {
            self.graph.leaf(Leaf::ExtBase(value))
        } else {
            value
        }
    }

    fn op(&mut self, class: Class, op: OpKind, x: NodeId, y: Option<NodeId>) -> NodeId {
        let x = self.promote(class, x);
        let y = y.map(|value| self.promote(class, value));
        let a = self.constant(x);
        let b = y.and_then(|y| self.constant(y));
        if let Some(value) = match op {
            OpKind::Neg => a.map(|a| -a),
            OpKind::Add => a.zip(b).map(|(a, b)| a + b),
            OpKind::Sub => a.zip(b).map(|(a, b)| a - b),
            OpKind::Mul => a.zip(b).map(|(a, b)| a * b),
        } {
            return self.scalar(class, value);
        }
        let zero = Some(Felt::ZERO);
        let one = Some(Felt::ONE);
        match op {
            OpKind::Add if a == zero => return y.unwrap(),
            OpKind::Add | OpKind::Sub if b == zero => return x,
            OpKind::Sub if a == zero => return self.op(class, OpKind::Neg, y.unwrap(), None),
            OpKind::Mul if a == zero || b == zero => return self.scalar(class, Felt::ZERO),
            OpKind::Mul if a == one => return y.unwrap(),
            OpKind::Mul if b == one => return x,
            _ => {},
        }
        let counts = match class {
            Class::Base => &mut self.base,
            Class::Ext => &mut self.ext,
        };
        counts.bump(op);
        self.graph.op(class, op, x, y).0
    }

    fn sum(&mut self, class: Class, inputs: &[NodeId]) -> NodeId {
        match inputs {
            [] => self.scalar(class, Felt::ZERO),
            [value] => *value,
            [a, b] => self.op(class, OpKind::Add, *a, Some(*b)),
            _ => {
                let middle = inputs.len().next_power_of_two() / 2;
                let a = self.sum(class, &inputs[..middle]);
                let b = self.sum(class, &inputs[middle..]);
                self.op(class, OpKind::Add, a, Some(b))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_crypto::field::Algebra;
    use miden_stark::air::symbolic::{
        RowOffset, SymbolicExpression, SymbolicExpressionExt,
    };

    use super::*;
    use crate::{
        ir::op_counts,
        testing::{assert_program_lowering, eval_graph},
    };

    type B = SymbolicExpression<Felt, QuadFelt>;
    type E = SymbolicExpressionExt<Felt, QuadFelt>;

    fn main(column: usize) -> B {
        B::from(BaseInput::Main { row: RowOffset::Current, column })
    }

    #[test]
    fn normalized_constant_spellings_preserve_arithmetic_lowering() {
        let a = main(0);
        let e = E::from(AuxInput::Challenge { index: 0 });
        let scalar = Felt::from_u64(7);
        let program = CapturedProgram::from_assertions(vec![
            Assertion::Base(a.clone() * scalar),
            Assertion::Base(a * B::from(scalar)),
            Assertion::Extension(e.clone() * scalar),
            Assertion::Extension(e.clone() * B::from(scalar)),
            Assertion::Extension(e * E::extension_constant(QuadFelt::from(scalar))),
        ]);
        assert_eq!(program.constraints().base_roots[0], program.constraints().base_roots[1]);
        for &root in &program.constraints().ext_roots[1..] {
            assert_eq!(root, program.constraints().ext_roots[0]);
        }
        for seed in [0, 42, u64::MAX] {
            assert_program_lowering(&program, seed);
        }
    }

    #[test]
    fn source_sharing_and_structural_cse_have_distinct_operation_counts() {
        let (a, b) = (main(0), main(1));
        let shared = a.clone() + b.clone();
        let shared_program = CapturedProgram::from_assertions(vec![
            Assertion::Base(shared.clone()),
            Assertion::Base(shared),
        ]);
        let distinct_program = CapturedProgram::from_assertions(vec![
            Assertion::Base(a.clone() + b.clone()),
            Assertion::Base(a + b),
        ]);
        assert_eq!(shared_program.graph(), distinct_program.graph());
        assert_eq!(
            shared_program.constraints().base_roots,
            distinct_program.constraints().base_roots
        );
        assert_eq!(shared_program.constraints().naive_base.add, 1);
        assert_eq!(distinct_program.constraints().naive_base.add, 2);
        assert_eq!(op_counts(shared_program.graph()).0.add, 1);
        assert_eq!(op_counts(distinct_program.graph()).0.add, 1);
        for program in [&shared_program, &distinct_program] {
            assert_program_lowering(program, 0x243f6a8885a308d3);
        }
    }

    #[test]
    fn default_quadratic_square_keeps_scalar_semantics_and_dependencies() {
        let (a, b) = (main(0), main(1));
        let challenge = E::from(AuxInput::Challenge { index: 0 });
        let squared = <E as Algebra<B>>::quadratic_extension_square(
            &[challenge.clone(), challenge.clone() + E::ONE],
            a.clone(),
        );
        let lc = <B as Algebra<Felt>>::mixed_dot_product(
            &[a.clone().square(), b.clone().bool_check()],
            &[Felt::from_u64(3), Felt::from_u64(9)],
        );
        let program = CapturedProgram::from_assertions(vec![
            Assertion::Extension(squared[0].clone()),
            Assertion::Base(lc),
            Assertion::Extension(squared[1].clone()),
            Assertion::Base(a.exp_u64(7) + b.exp_power_of_2(3).div_2exp_u64(19)),
        ]);
        assert_eq!(program.constraints().base_global_indices, [1, 3]);
        assert_eq!(program.constraints().ext_global_indices, [0, 2]);
        let row_dependencies: Vec<_> = program
            .assertions()
            .iter()
            .filter_map(|assertion| {
                let Assertion::Extension(expression) = assertion else {
                    return None;
                };
                Some(expression.as_ref().fold(|_, view, children: &[bool]| {
                    matches!(view, ExprView::BaseInput(BaseInput::Main { .. }))
                        || children.iter().any(|&value| value)
                }))
            })
            .collect();
        assert_eq!(row_dependencies, [true, false]);
        for seed in [0, 1, 0x243f6a8885a308d3, u64::MAX] {
            assert_program_lowering(&program, seed);
            let values = eval_graph(program.graph(), seed);
            let input = |expected| {
                let (id, _) = program
                    .graph()
                    .iter()
                    .find(|(_, node)| *node == Node::Leaf(expected))
                    .expect("source input is retained");
                values[id.index()]
            };
            let x = input(Leaf::Challenge(0));
            let y = x + QuadFelt::ONE;
            let w = input(Leaf::Main { offset: 0, index: 0 });
            assert_eq!(
                values[program.constraints().ext_roots[0].index()],
                x.square() + w * y.square()
            );
            assert_eq!(values[program.constraints().ext_roots[1].index()], x * y.double());
        }
    }
}

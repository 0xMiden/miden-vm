//! Shared reference oracles for generated evaluator tests.

use std::collections::HashMap;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing};
use miden_lifted_stark::air::{
    AirBuilder, ExtensionBuilder, LiftedAir, PermutationAirBuilder, RowWindow,
    symbolic::AirLayout,
};
use p3_field::{PackedField, PackedValue};

use crate::ir::{Class, Graph, Leaf, Node, OpKind};

/// Canonical id per node: a second hash-cons pass with `Add`/`Mul` children
/// sorted, so two nodes get equal canonical ids iff their subgraphs are
/// structurally identical modulo commutative operand order.
pub fn canonical_ids(graph: &Graph) -> Vec<usize> {
    #[derive(PartialEq, Eq, Hash)]
    enum Key {
        Leaf(Leaf),
        Lift(usize),
        Op(Class, OpKind, usize, Option<usize>),
    }
    let mut interner: HashMap<Key, usize> = HashMap::new();
    let mut canon: Vec<usize> = Vec::with_capacity(graph.len());
    for (_, node) in graph.iter() {
        let key = match node {
            Node::Leaf(Leaf::ExtBase(inner)) => Key::Lift(canon[inner.index()]),
            Node::Leaf(leaf) => Key::Leaf(leaf),
            Node::Op { class, op, x, y } => {
                let a = canon[x.index()];
                let b = y.map(|y| canon[y.index()]);
                match (op, b) {
                    (OpKind::Add | OpKind::Mul, Some(b)) => {
                        Key::Op(class, op, a.min(b), Some(a.max(b)))
                    },
                    _ => Key::Op(class, op, a, b),
                }
            },
        };
        let next = interner.len();
        canon.push(*interner.entry(key).or_insert(next));
    }
    canon
}

/// Evaluate every node of `graph`, assigning each leaf a value derived from its
/// content and `seed` (so identical leaves in different graphs agree), with
/// constants evaluating to themselves. Base values live embedded in `QuadFelt`;
/// the algebra is exact either way.
pub fn eval_graph(graph: &Graph, seed: u64) -> Vec<QuadFelt> {
    eval_graph_with(graph, |leaf| leaf_value(seed, leaf))
}

fn eval_graph_with(graph: &Graph, mut leaf_value: impl FnMut(Leaf) -> QuadFelt) -> Vec<QuadFelt> {
    let mut values: Vec<QuadFelt> = Vec::with_capacity(graph.len());
    for (_, node) in graph.iter() {
        let value = match node {
            Node::Leaf(Leaf::ExtBase(inner)) => values[inner.index()],
            Node::Leaf(leaf) => leaf_value(leaf),
            Node::Op { op, x, y, .. } => {
                let xv = values[x.index()];
                match (op, y) {
                    (OpKind::Add, Some(y)) => xv + values[y.index()],
                    (OpKind::Sub, Some(y)) => xv - values[y.index()],
                    (OpKind::Mul, Some(y)) => xv * values[y.index()],
                    (OpKind::Neg, None) => -xv,
                    _ => unreachable!("op arity is enforced by the graph builder"),
                }
            },
        };
        values.push(value);
    }
    values
}

fn leaf_value(seed: u64, leaf: Leaf) -> QuadFelt {
    let base = |tag: u64, a: u64| QuadFelt::from(Felt::from_u64(mix(seed, tag, a, 0)));
    let ext = |tag: u64, a: u64| quad(mix(seed, tag, a, 0), mix(seed, tag, a, 1));
    // One tag per leaf kind; windowed inputs use one per row offset.
    match leaf {
        Leaf::Preprocessed { offset, index } => base(12 + offset as u64, index as u64),
        Leaf::Main { offset, index } => base(1 + offset as u64, index as u64),
        Leaf::Public(i) => base(3, i as u64),
        Leaf::Periodic(i) => base(4, i as u64),
        Leaf::IsFirst => base(5, 0),
        Leaf::IsLast => base(6, 0),
        Leaf::IsTransition => base(7, 0),
        Leaf::BaseConst(c) => QuadFelt::from(Felt::from_u64(c)),
        Leaf::Aux { offset, index } => ext(8 + offset as u64, index as u64),
        Leaf::Challenge(i) => ext(10, i as u64),
        Leaf::PermValue(i) => ext(11, i as u64),
        Leaf::ExtConst([c0, c1]) => quad(c0, c1),
        Leaf::ExtBase(_) => unreachable!("handled in eval_graph"),
    }
}

fn quad(c0: u64, c1: u64) -> QuadFelt {
    let coeffs = [Felt::from_u64(c0), Felt::from_u64(c1)];
    <QuadFelt as BasedVectorSpace<Felt>>::from_basis_coefficients_slice(&coeffs)
        .expect("two coefficients form a QuadFelt")
}

/// splitmix64-style mixer over a packed leaf key.
fn mix(seed: u64, tag: u64, a: u64, b: u64) -> u64 {
    let mut x = seed
        .wrapping_add(tag.wrapping_mul(0x9e3779b97f4a7c15))
        .wrapping_add(a.wrapping_mul(0xbf58476d1ce4e5b9))
        .wrapping_add(b.wrapping_mul(0x94d049bb133111eb));
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// Concrete full-field inputs shared by scalar and packed evaluator checks and timing.
/// Lane `i` uses `seed + i`, with scalar public values shared across lanes. Selectors and
/// limb columns deliberately need not be valid trace values.
pub struct EvaluationInputs<P, PE> {
    main: [Vec<P>; 2],
    preprocessed: [Vec<P>; 2],
    aux: [Vec<PE>; 2],
    public: Vec<Felt>,
    periodic: Vec<P>,
    challenges: Vec<PE>,
    values: Vec<PE>,
    selectors: [P; 3],
}

impl<P, PE> EvaluationInputs<P, PE>
where
    P: PackedField<Scalar = Felt>,
    PE: Algebra<P> + Algebra<QuadFelt> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    pub fn new(layout: AirLayout, seed: u64) -> Self {
        let base = |leaf| {
            P::from_fn(|lane| {
                leaf_value(seed.wrapping_add(lane as u64), leaf).as_basis_coefficients_slice()[0]
            })
        };
        let ext = |leaf| {
            PE::from_basis_coefficients_fn(|coefficient| {
                P::from_fn(|lane| {
                    leaf_value(seed.wrapping_add(lane as u64), leaf).as_basis_coefficients_slice()
                        [coefficient]
                })
            })
        };
        Self {
            main: core::array::from_fn(|offset| {
                (0..layout.main_width).map(|index| base(Leaf::Main { offset, index })).collect()
            }),
            preprocessed: core::array::from_fn(|offset| {
                (0..layout.preprocessed_width)
                    .map(|index| base(Leaf::Preprocessed { offset, index }))
                    .collect()
            }),
            aux: core::array::from_fn(|offset| {
                (0..layout.permutation_width)
                    .map(|index| ext(Leaf::Aux { offset, index }))
                    .collect()
            }),
            public: (0..layout.num_public_values)
                .map(|index| leaf_value(seed, Leaf::Public(index)).as_basis_coefficients_slice()[0])
                .collect(),
            periodic: (0..layout.num_periodic_columns)
                .map(|index| base(Leaf::Periodic(index)))
                .collect(),
            challenges: (0..layout.num_permutation_challenges)
                .map(|index| ext(Leaf::Challenge(index)))
                .collect(),
            values: (0..layout.num_permutation_values)
                .map(|index| ext(Leaf::PermValue(index)))
                .collect(),
            selectors: [base(Leaf::IsFirst), base(Leaf::IsLast), base(Leaf::IsTransition)],
        }
    }

    pub fn builder(&self) -> EvaluationBuilder<'_, P, PE> {
        EvaluationBuilder {
            main: RowWindow::from_two_rows(&self.main[0], &self.main[1]),
            preprocessed: RowWindow::from_two_rows(&self.preprocessed[0], &self.preprocessed[1]),
            aux: RowWindow::from_two_rows(&self.aux[0], &self.aux[1]),
            inputs: self,
            base_constraints: Vec::new(),
            ext_constraints: Vec::new(),
            base_indices: Vec::new(),
            ext_indices: Vec::new(),
        }
    }
}

/// Collects actual field assertions, retaining their global order and base/extension class.
pub struct EvaluationBuilder<'a, P, PE> {
    main: RowWindow<'a, P>,
    preprocessed: RowWindow<'a, P>,
    aux: RowWindow<'a, PE>,
    inputs: &'a EvaluationInputs<P, PE>,
    pub base_constraints: Vec<P>,
    pub ext_constraints: Vec<PE>,
    pub base_indices: Vec<usize>,
    pub ext_indices: Vec<usize>,
}

impl<P, PE> EvaluationBuilder<'_, P, PE> {
    /// Retain allocations between timing iterations.
    pub fn clear(&mut self) {
        self.base_constraints.clear();
        self.ext_constraints.clear();
        self.base_indices.clear();
        self.ext_indices.clear();
    }
}

impl<'a, P, PE> AirBuilder for EvaluationBuilder<'a, P, PE>
where
    P: PackedField<Scalar = Felt>,
    PE: Algebra<P> + Algebra<QuadFelt> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    type F = Felt;
    type Expr = P;
    type Var = P;
    type MainWindow = RowWindow<'a, P>;
    type PreprocessedWindow = RowWindow<'a, P>;
    type PublicVar = Felt;
    type PeriodicVar = P;
    fn main(&self) -> Self::MainWindow {
        self.main
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }
    fn public_values(&self) -> &[Felt] {
        &self.inputs.public
    }
    fn periodic_values(&self) -> &[P] {
        &self.inputs.periodic
    }
    fn is_first_row(&self) -> P {
        self.inputs.selectors[0]
    }
    fn is_last_row(&self) -> P {
        self.inputs.selectors[1]
    }
    fn is_transition(&self) -> P {
        self.inputs.selectors[2]
    }
    fn assert_zero<I: Into<P>>(&mut self, value: I) {
        self.base_indices.push(self.base_constraints.len() + self.ext_constraints.len());
        self.base_constraints.push(value.into());
    }
}
impl<P, PE> ExtensionBuilder for EvaluationBuilder<'_, P, PE>
where
    P: PackedField<Scalar = Felt>,
    PE: Algebra<P> + Algebra<QuadFelt> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    type EF = QuadFelt;
    type ExprEF = PE;
    type VarEF = PE;
    fn assert_zero_ext<I: Into<PE>>(&mut self, value: I) {
        self.ext_indices.push(self.base_constraints.len() + self.ext_constraints.len());
        self.ext_constraints.push(value.into());
    }
}
impl<'a, P, PE> PermutationAirBuilder for EvaluationBuilder<'a, P, PE>
where
    P: PackedField<Scalar = Felt>,
    PE: Algebra<P> + Algebra<QuadFelt> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    type MP = RowWindow<'a, PE>;
    type RandomVar = PE;
    type PermutationVar = PE;
    fn permutation(&self) -> Self::MP {
        self.aux
    }
    fn permutation_randomness(&self) -> &[PE] {
        &self.inputs.challenges
    }
    fn permutation_values(&self) -> &[PE] {
        &self.inputs.values
    }
}

/// Compare real scalar and packed evaluations with independently captured graph values,
/// including global assertion order and class. Packed lanes receive distinct full-field inputs.
pub fn assert_concrete_evaluation<A: LiftedAir<Felt, QuadFelt>>(
    air: &A,
    graph: &Graph,
    captured: &crate::ir::CapturedConstraints,
    seed: u64,
) {
    type P = <Felt as miden_crypto::field::Field>::Packing;
    type PE = <QuadFelt as miden_crypto::field::ExtensionField<Felt>>::ExtensionPacking;
    let scalar_inputs = EvaluationInputs::<Felt, QuadFelt>::new(air.air_layout(), seed);
    let mut scalar = scalar_inputs.builder();
    air.eval(&mut scalar);
    assert_eq!(scalar.base_indices, captured.base_global_indices);
    assert_eq!(scalar.ext_indices, captured.ext_global_indices);
    let packed_inputs = EvaluationInputs::<P, PE>::new(air.air_layout(), seed);
    let mut packed = packed_inputs.builder();
    air.eval(&mut packed);
    assert_eq!(packed.base_indices, captured.base_global_indices);
    assert_eq!(packed.ext_indices, captured.ext_global_indices);
    for lane in 0..P::WIDTH {
        let oracle = eval_graph_with(graph, |leaf| {
            // Public values are shared scalar inputs across the SIMD lanes.
            let leaf_seed = if matches!(leaf, Leaf::Public(_)) {
                seed
            } else {
                seed.wrapping_add(lane as u64)
            };
            leaf_value(leaf_seed, leaf)
        });
        for (index, root) in captured.base_roots.iter().enumerate() {
            let expected: Felt = oracle[root.index()].as_basis_coefficients_slice()[0];
            assert_eq!(
                packed.base_constraints[index].as_slice()[lane],
                expected,
                "base assertion {index}, lane {lane}"
            );
            if lane == 0 {
                assert_eq!(scalar.base_constraints[index], expected);
            }
        }
        for (index, root) in captured.ext_roots.iter().enumerate() {
            let expected = oracle[root.index()];
            let actual = QuadFelt::from_basis_coefficients_fn(|coefficient| {
                <PE as BasedVectorSpace<P>>::as_basis_coefficients_slice(
                    &packed.ext_constraints[index],
                )[coefficient]
                    .as_slice()[lane]
            });
            assert_eq!(actual, expected, "extension assertion {index}, lane {lane}");
            if lane == 0 {
                assert_eq!(scalar.ext_constraints[index], expected);
            }
        }
    }
}

/// Times scalar and packed field evaluation with reused input/output allocations.
/// Build in release mode; input generation and graph capture are outside the timed region.
pub fn time_evaluation<A: LiftedAir<Felt, QuadFelt>>(
    air: &A,
    iterations: usize,
) -> [std::time::Duration; 2] {
    fn measure<A, P, PE>(air: &A, iterations: usize) -> std::time::Duration
    where
        A: LiftedAir<Felt, QuadFelt>,
        P: PackedField<Scalar = Felt>,
        PE: Algebra<P> + Algebra<QuadFelt> + BasedVectorSpace<P> + Copy + Send + Sync,
    {
        let inputs = EvaluationInputs::<P, PE>::new(air.air_layout(), 0x243f6a8885a308d3);
        let mut builder = inputs.builder();
        air.eval(&mut builder);
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            builder.clear();
            air.eval(std::hint::black_box(&mut builder));
            std::hint::black_box((&builder.base_constraints, &builder.ext_constraints));
        }
        start.elapsed()
    }
    [
        measure::<A, Felt, QuadFelt>(air, iterations),
        measure::<
            A,
            <Felt as miden_crypto::field::Field>::Packing,
            <QuadFelt as miden_crypto::field::ExtensionField<Felt>>::ExtensionPacking,
        >(air, iterations),
    ]
}

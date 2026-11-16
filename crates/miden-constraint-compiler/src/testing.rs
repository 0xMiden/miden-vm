//! Shared reference oracles for generated evaluator tests.

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing};
use miden_stark::air::{
    self, AirKernel, Assertion,
    symbolic::{AuxInput, BaseInput, ExprView},
};
use p3_field::{PackedField, PackedValue};

use crate::ir::{CapturedProgram, Graph, Leaf, Node, OpKind};

/// Degree of every assertion in each class, preserving its local order. This
/// uses the builder's symbolic degree rules independently of the optimizer IR.
pub fn constraint_degrees<A: air::LiftedAir<F = Felt>>(air: &A) -> [Vec<usize>; 2] {
    assertion_degrees(air::capture_with::<_, QuadFelt>(air).expect("authored source capture"))
}

/// Degree observations of actual prepared execution, used only as a comparison subject.
pub fn kernel_constraint_degrees<K: AirKernel<F = Felt>>(kernel: &K) -> [Vec<usize>; 2] {
    let captured = air::capture_from_spec::<Felt, QuadFelt>(
        kernel.descriptor().spec().as_borrowed(),
        |frame, inputs, sink| {
            kernel
                .bind(inputs)
                .expect("symbolic dimensions match descriptor")
                .eval(frame, sink);
        },
    )
    .expect("prepared kernel capture");
    assertion_degrees(captured)
}

fn assertion_degrees(captured: air::Capture<Felt, QuadFelt>) -> [Vec<usize>; 2] {
    let mut classes = [Vec::new(), Vec::new()];
    for assertion in captured.assertions {
        match assertion {
            air::Assertion::Base(expression) => classes[0].push(expression.degree_multiple()),
            air::Assertion::Extension(expression) => classes[1].push(expression.degree_multiple()),
        }
    }
    classes
}

/// Compare the generated kernel's checked metadata and observed assertion layout to its source.
pub fn assert_kernel_descriptor<A: air::LiftedAir<F = Felt>, K: AirKernel<F = Felt>>(
    source: &A,
    kernel: &K,
) {
    let captured = air::capture_with::<_, QuadFelt>(source).expect("authored source capture");
    let expected = &captured.descriptor;
    let actual = kernel.descriptor();
    let (a, e) = (actual.spec(), expected.spec());
    assert_eq!(
        (a.main_width, a.aux_width, a.num_public_values, a.num_challenges, a.num_exports),
        (e.main_width, e.aux_width, e.num_public_values, e.num_challenges, e.num_exports),
    );
    assert_eq!(a.preprocessed, e.preprocessed);
    assert_eq!(a.periodic_columns, e.periodic_columns);
    assert_eq!(actual.fingerprint(), expected.fingerprint());
    let (a, e) = (actual.analysis(), expected.analysis());
    assert_eq!(a.counts(), e.counts());
    assert_eq!(a.raw_degrees(), e.raw_degrees());
    assert_eq!(a.layout(), e.layout());
    assert_eq!(a.degree_profile().ops(), e.degree_profile().ops());
    assert_eq!(a.degree_profile().roots(), e.degree_profile().roots());
    for ordinal in 0..e.layout().total_constraints() {
        assert_eq!(actual.label(ordinal), expected.label(ordinal));
    }
    let observed = air::capture_from_spec::<Felt, QuadFelt>(
        actual.spec().as_borrowed(),
        |frame, inputs, sink| {
            kernel
                .bind(inputs)
                .expect("symbolic dimensions match descriptor")
                .eval(frame, sink);
        },
    )
    .expect("prepared kernel capture");
    assert_eq!(observed.descriptor.analysis().layout(), e.layout());
    let geometry = kernel.geometry();
    assert_eq!(geometry.main_width, expected.spec().main_width);
    assert_eq!(geometry.aux_width, expected.spec().aux_width);
    assert_eq!(geometry.preprocessed_width, expected.spec().preprocessed_width());
    assert_eq!(geometry.raw_degrees, e.raw_degrees());
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

/// Compare the owned source expressions with independently evaluated lowered
/// roots, checking each assertion's class, global ordinal, and value.
pub fn assert_program_lowering(program: &CapturedProgram, seed: u64) {
    let lowered = eval_graph(program.graph(), seed);
    let constraints = program.constraints();
    let (mut base_index, mut ext_index) = (0, 0);
    for (ordinal, assertion) in program.assertions().iter().enumerate() {
        let (expression, root, global) = match assertion {
            Assertion::Base(expression) => {
                let index = base_index;
                base_index += 1;
                (
                    expression.as_ref(),
                    constraints.base_roots[index],
                    constraints.base_global_indices[index],
                )
            },
            Assertion::Extension(expression) => {
                let index = ext_index;
                ext_index += 1;
                (
                    expression.as_ref(),
                    constraints.ext_roots[index],
                    constraints.ext_global_indices[index],
                )
            },
        };
        assert_eq!(global, ordinal, "lowered assertion order differs");
        assert_eq!(eval_expression(expression, seed), lowered[root.index()], "assertion {ordinal}");
    }
    assert_eq!(base_index, constraints.base_roots.len());
    assert_eq!(base_index, constraints.base_global_indices.len());
    assert_eq!(ext_index, constraints.ext_roots.len());
    assert_eq!(ext_index, constraints.ext_global_indices.len());
}

/// Evaluate the source operation vocabulary independently of compiler scheduling.
pub(crate) fn eval_expression(
    expression: miden_stark::air::symbolic::ExprRef<'_, Felt, QuadFelt>,
    seed: u64,
) -> QuadFelt {
    expression.evaluate(|_, view| {
        let leaf = match view {
            ExprView::BaseConstant(value) => return QuadFelt::from(*value),
            ExprView::ExtensionConstant(value) => return *value,
            ExprView::BaseInput(input) => match input {
                BaseInput::Main { row, column } => {
                    Leaf::Main { offset: row.index(), index: column }
                },
                BaseInput::Preprocessed { row, column } => {
                    Leaf::Preprocessed { offset: row.index(), index: column }
                },
                BaseInput::Public { index } => Leaf::Public(index),
                BaseInput::Periodic { index } => Leaf::Periodic(index),
            },
            ExprView::AuxInput(input) => match input {
                AuxInput::Trace { row, column } => Leaf::Aux { offset: row.index(), index: column },
                AuxInput::Challenge { index } => Leaf::Challenge(index),
                AuxInput::Export { index } => Leaf::PermValue(index),
            },
            ExprView::IsFirstRow => Leaf::IsFirst,
            ExprView::IsLastRow => Leaf::IsLast,
            ExprView::IsTransition => Leaf::IsTransition,
            _ => unreachable!("source evaluation interprets operations independently"),
        };
        leaf_value(seed, leaf)
    })
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
    public: Vec<P>,
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
    pub fn new(spec: &air::AirSpec<'_, Felt>, seed: u64) -> Self {
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
                (0..spec.main_width).map(|index| base(Leaf::Main { offset, index })).collect()
            }),
            preprocessed: core::array::from_fn(|offset| {
                (0..spec.preprocessed_width())
                    .map(|index| base(Leaf::Preprocessed { offset, index }))
                    .collect()
            }),
            aux: core::array::from_fn(|offset| {
                (0..spec.aux_width).map(|index| ext(Leaf::Aux { offset, index })).collect()
            }),
            public: (0..spec.num_public_values)
                .map(|index| {
                    P::broadcast(
                        leaf_value(seed, Leaf::Public(index)).as_basis_coefficients_slice()[0],
                    )
                })
                .collect(),
            periodic: (0..spec.periodic_columns.len())
                .map(|index| base(Leaf::Periodic(index)))
                .collect(),
            challenges: (0..spec.num_challenges).map(|index| ext(Leaf::Challenge(index))).collect(),
            values: (0..spec.num_exports).map(|index| ext(Leaf::PermValue(index))).collect(),
            selectors: [base(Leaf::IsFirst), base(Leaf::IsLast), base(Leaf::IsTransition)],
        }
    }

    pub fn frame(&self) -> air::AirFrame<'_, P, PE> {
        air::AirFrame {
            main: air::Rows {
                current: &self.main[0],
                next: &self.main[1],
            },
            preprocessed: air::Rows {
                current: &self.preprocessed[0],
                next: &self.preprocessed[1],
            },
            aux: air::Rows {
                current: &self.aux[0],
                next: &self.aux[1],
            },
            periodic: &self.periodic,
            selectors: air::Selectors {
                first: self.selectors[0],
                last: self.selectors[1],
                transition: self.selectors[2],
            },
        }
    }

    pub fn inputs(&self) -> air::UniformInputs<'_, P, PE> {
        air::UniformInputs {
            public_values: &self.public,
            challenges: &self.challenges,
            exports: &self.values,
        }
    }
}

/// Concrete assertion collector, independent of row and uniform input ownership.
pub struct EvaluationBuilder<P, PE> {
    pub base_constraints: Vec<P>,
    pub ext_constraints: Vec<PE>,
    pub base_indices: Vec<usize>,
    pub ext_indices: Vec<usize>,
}

impl<P, PE> Default for EvaluationBuilder<P, PE> {
    fn default() -> Self {
        Self {
            base_constraints: Vec::new(),
            ext_constraints: Vec::new(),
            base_indices: Vec::new(),
            ext_indices: Vec::new(),
        }
    }
}

impl<P, PE> EvaluationBuilder<P, PE> {
    /// Retain allocations between timing iterations.
    pub fn clear(&mut self) {
        self.base_constraints.clear();
        self.ext_constraints.clear();
        self.base_indices.clear();
        self.ext_indices.clear();
    }
}

impl<P, PE> air::LiftedAirBuilder for EvaluationBuilder<P, PE>
where
    P: PackedField<Scalar = Felt>,
    PE: Algebra<P>,
{
    type F = Felt;
    type Expr = P;
    type ExtExpr = PE;

    fn emit_base(&mut self, value: P, _meta: air::ConstraintMeta<'_>) {
        self.base_indices.push(self.base_constraints.len() + self.ext_constraints.len());
        self.base_constraints.push(value);
    }

    fn emit_ext(&mut self, value: PE, _meta: air::ConstraintMeta<'_>) {
        self.ext_indices.push(self.base_constraints.len() + self.ext_constraints.len());
        self.ext_constraints.push(value);
    }
}

/// Compare two runtime kernels directly on identical scalar and packed inputs.
/// Assertion classes, global order, duplicates, and zero residuals are retained.
/// No symbolic capture or arithmetic graph supplies the expected values.
pub fn assert_concrete_evaluations_equal<S: AirKernel<F = Felt>, K: AirKernel<F = Felt>>(
    source: &S,
    generated: &K,
    seed: u64,
) {
    fn compare<S, K, P, PE>(source: &S, generated: &K, seed: u64)
    where
        S: AirKernel<F = Felt>,
        K: AirKernel<F = Felt>,
        P: PackedField<Scalar = Felt>,
        PE: Algebra<P> + Algebra<QuadFelt> + BasedVectorSpace<P> + Copy + Send + Sync,
    {
        let inputs = EvaluationInputs::<P, PE>::new(source.descriptor().spec(), seed);
        let mut expected = EvaluationBuilder::default();
        source
            .bind(inputs.inputs())
            .expect("source dimensions match its descriptor")
            .eval(&inputs.frame(), &mut expected);
        let mut actual = EvaluationBuilder::default();
        generated
            .bind(inputs.inputs())
            .expect("generated dimensions match the source inputs")
            .eval(&inputs.frame(), &mut actual);
        assert_eq!(actual.base_indices, expected.base_indices, "base assertion order");
        assert_eq!(actual.ext_indices, expected.ext_indices, "extension assertion order");
        assert_eq!(actual.base_constraints.len(), expected.base_constraints.len());
        assert_eq!(actual.ext_constraints.len(), expected.ext_constraints.len());
        for (index, (actual, expected)) in
            actual.base_constraints.iter().zip(&expected.base_constraints).enumerate()
        {
            assert_eq!(actual.as_slice(), expected.as_slice(), "base assertion {index}");
        }
        for (index, (actual, expected)) in
            actual.ext_constraints.iter().zip(&expected.ext_constraints).enumerate()
        {
            for (coefficient, (actual, expected)) in
                <PE as BasedVectorSpace<P>>::as_basis_coefficients_slice(actual)
                    .iter()
                    .zip(<PE as BasedVectorSpace<P>>::as_basis_coefficients_slice(expected))
                    .enumerate()
            {
                assert_eq!(
                    actual.as_slice(),
                    expected.as_slice(),
                    "extension assertion {index}, coefficient {coefficient}"
                );
            }
        }
    }
    type P = <Felt as miden_crypto::field::Field>::Packing;
    type PE = <QuadFelt as miden_crypto::field::ExtensionField<Felt>>::ExtensionPacking;
    compare::<_, _, Felt, QuadFelt>(source, generated, seed);
    compare::<_, _, P, PE>(source, generated, seed);
}

/// Compare actual scalar/packed kernel execution to independently captured source graph values.
/// Public inputs are shared across lanes; other namespaces use distinct full-field lane seeds.
pub fn assert_concrete_evaluation<K: AirKernel<F = Felt>>(
    kernel: &K,
    graph: &Graph,
    captured: &crate::ir::CapturedConstraints,
    seed: u64,
) {
    type P = <Felt as miden_crypto::field::Field>::Packing;
    type PE = <QuadFelt as miden_crypto::field::ExtensionField<Felt>>::ExtensionPacking;
    let spec = kernel.descriptor().spec();
    let scalar_inputs = EvaluationInputs::<Felt, QuadFelt>::new(spec, seed);
    let packed_inputs = EvaluationInputs::<P, PE>::new(spec, seed);
    let mut scalar = EvaluationBuilder::default();
    kernel
        .bind(scalar_inputs.inputs())
        .expect("scalar dimensions")
        .eval(&scalar_inputs.frame(), &mut scalar);
    let mut packed = EvaluationBuilder::default();
    kernel
        .bind(packed_inputs.inputs())
        .expect("packed dimensions")
        .eval(&packed_inputs.frame(), &mut packed);
    for (base, ext) in [
        (&scalar.base_indices, &scalar.ext_indices),
        (&packed.base_indices, &packed.ext_indices),
    ] {
        assert_eq!(base, &captured.base_global_indices);
        assert_eq!(ext, &captured.ext_global_indices);
    }
    assert_eq!(scalar.base_constraints.len(), captured.base_roots.len());
    assert_eq!(scalar.ext_constraints.len(), captured.ext_roots.len());
    assert_eq!(packed.base_constraints.len(), captured.base_roots.len());
    assert_eq!(packed.ext_constraints.len(), captured.ext_roots.len());
    for lane in 0..P::WIDTH {
        let oracle = eval_graph_with(graph, |leaf| {
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

/// Times reused scalar/packed execution; binding, source capture and allocations precede the timer.
pub fn time_evaluation<K: AirKernel<F = Felt>>(
    kernel: &K,
    iterations: usize,
) -> [std::time::Duration; 2] {
    fn measure<K, P, PE>(kernel: &K, iterations: usize) -> std::time::Duration
    where
        K: AirKernel<F = Felt>,
        P: PackedField<Scalar = Felt>,
        PE: Algebra<P> + Algebra<QuadFelt> + BasedVectorSpace<P> + Copy + Send + Sync,
    {
        let inputs = EvaluationInputs::<P, PE>::new(kernel.descriptor().spec(), 0x243f6a8885a308d3);
        let mut sink = EvaluationBuilder::default();
        let session = kernel.bind(inputs.inputs()).expect("timing dimensions");
        let frame = inputs.frame();
        session.eval(&frame, &mut sink);
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            sink.clear();
            session.eval(std::hint::black_box(&frame), &mut sink);
            std::hint::black_box((&sink.base_constraints, &sink.ext_constraints));
        }
        start.elapsed()
    }
    [
        measure::<K, Felt, QuadFelt>(kernel, iterations),
        measure::<
            K,
            <Felt as miden_crypto::field::Field>::Packing,
            <QuadFelt as miden_crypto::field::ExtensionField<Felt>>::ExtensionPacking,
        >(kernel, iterations),
    ]
}

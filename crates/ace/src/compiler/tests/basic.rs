use std::borrow::Cow;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::PrimeCharacteristicRing;
use miden_stark::air::{self, LiftedAir as _, LiftedAirBuilder as _};
use p3_field::Dup;
use p3_matrix::dense::RowMajorMatrix;

use super::common::{eval_dag, eval_periodic_values, eval_quotient};
use crate::{
    InputKey, InputLayout,
    compiler::{
        AceCircuit, AceConfig, LayoutKind,
        circuit::emit_circuit,
        dag::NodeKind,
        pipeline::{build_ace_dag_for_air, build_canonical_multi_air_ace_circuit},
        testing::eval_native_constraints,
    },
};

// Base and extension field types for tests.
type F = Felt;
type EF = QuadFelt;

struct MockAir;

#[derive(Clone, Copy)]
enum Selector {
    None,
    First,
    Last,
    Transition,
}

#[derive(Clone, Copy)]
struct TestAir {
    public: usize,
    preprocessed: usize,
    main: usize,
    aux: usize,
    boundaries: usize,
    period: usize,
    selector: Selector,
}

impl TestAir {
    fn simple() -> Self {
        Self {
            public: 0,
            preprocessed: 0,
            main: 1,
            aux: 0,
            boundaries: 0,
            period: 0,
            selector: Selector::None,
        }
    }
}

impl air::LiftedAir for TestAir {
    type F = F;

    fn spec(&self) -> air::AirSpec<'_, F> {
        let periodic_columns: Cow<'_, [Vec<F>]> = if self.period == 0 {
            Cow::Borrowed(&[][..])
        } else {
            let mut column = vec![F::ZERO; self.period];
            column[1] = F::ONE;
            Cow::Owned(vec![column])
        };
        air::AirSpec {
            main_width: self.main,
            aux_width: self.aux,
            num_public_values: self.public,
            num_challenges: 2,
            num_exports: self.boundaries,
            preprocessed: (self.preprocessed > 0)
                .then_some(air::PreprocessedSpec { width: self.preprocessed, log_height: 2 }),
            periodic_columns,
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        // Reconstruction-owned synthetic fixture data: the old fixture declared width only.
        (self.preprocessed > 0)
            .then(|| RowMajorMatrix::new(vec![F::ZERO; 4 * self.preprocessed], self.preprocessed))
    }

    fn eval<AB: air::LiftedAirBuilder<F = F>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let mut expression = frame.main.current[self.main - 1].dup();
        for value in inputs.public_values {
            expression += value.dup();
        }
        if self.preprocessed > 0 {
            expression += frame.preprocessed.current[self.preprocessed - 1].dup();
        }
        if self.period > 0 {
            expression += frame.periodic[0].dup();
        }
        match self.selector {
            Selector::None => builder.assert_zero(expression),
            Selector::First => builder.when(frame.first_row()).assert_zero(expression),
            Selector::Last => builder.when(frame.last_row()).assert_zero(expression),
            Selector::Transition => builder.when(frame.transition()).assert_zero(expression),
        }
        if self.aux > 0 {
            let mut expression = frame.aux.current[self.aux - 1].dup();
            if self.boundaries > 0 {
                expression += inputs.export(self.boundaries - 1);
            }
            builder.assert_zero_ext(expression);
        }
    }
}

impl air::LiftedAir for MockAir {
    type F = F;

    fn spec(&self) -> air::AirSpec<'_, F> {
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 1,
            num_challenges: 2,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Owned(vec![vec![F::ONE]]),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = F>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let a = frame.main.current[0].dup();
        let b = frame.main.next[0].dup();
        builder.assert_zero(a.dup() + inputs.public(0));
        builder.assert_zero_ext(inputs.challenge(0) + frame.aux.current[0].dup());
        builder.when(frame.transition()).assert_zero(b - a.dup());
        let a_ext = AB::ExtExpr::from(a);
        let per_ext = AB::ExtExpr::from(frame.periodic[0].dup());
        builder.assert_zero_ext(per_ext - a_ext);
    }
}

struct MockPreprocessedAir;

impl air::LiftedAir for MockPreprocessedAir {
    type F = F;

    fn spec(&self) -> air::AirSpec<'_, F> {
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 2,
            num_exports: 0,
            preprocessed: Some(air::PreprocessedSpec { width: 1, log_height: 2 }),
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new(vec![F::ZERO; 4], 1))
    }

    fn eval<AB: air::LiftedAirBuilder<F = F>>(
        &self,
        frame: &air::Frame<'_, AB>,
        _inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        builder.assert_zero(frame.preprocessed.current[0].dup() + frame.preprocessed.next[0].dup());
    }
}

struct MockPeriodicAir;

impl air::LiftedAir for MockPeriodicAir {
    type F = F;

    fn spec(&self) -> air::AirSpec<'_, F> {
        // Preserve sparse period128 and dense period8 data and their lowering choices.
        let mut sparse_col = vec![F::ZERO; 128];
        sparse_col[0] = F::new_unchecked(7);
        sparse_col[50] = F::new_unchecked(11);
        sparse_col[100] = F::new_unchecked(13);
        let dense_col = [2u64, 3, 5, 7, 11, 13, 17, 19].into_iter().map(F::new_unchecked).collect();
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 1,
            num_challenges: 2,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Owned(vec![sparse_col, dense_col]),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = F>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        builder.assert_zero(frame.main.current[0].dup() + inputs.public(0));
        builder.assert_zero_ext(inputs.challenge(0) + frame.aux.current[0].dup());
        let per0 = AB::ExtExpr::from(frame.periodic[0].dup());
        let per1 = AB::ExtExpr::from(frame.periodic[1].dup());
        builder.assert_zero_ext(per0 + per1);
    }
}

/// Many period-32 small-integer columns, so their period adopts the shared Lagrange basis, next
/// to a mostly-one column combined through the basis complement, a constant column, and a sparse
/// period-128 column that keep their standalone forms.
struct MockSharedBasisAir;

const SHARED_BASIS_COLUMNS: usize = 12;

fn shared_basis_columns() -> Vec<Vec<F>> {
    let mut columns: Vec<Vec<F>> = (0..SHARED_BASIS_COLUMNS)
        .map(|column| {
            (0..32u64)
                .map(|row| F::new_unchecked((row * (column as u64 + 3) + column as u64) % 17))
                .collect()
        })
        .collect();
    let mut mostly_one = vec![F::ONE; 32];
    mostly_one[3] = F::ZERO;
    mostly_one[20] = F::new_unchecked(6);
    columns.push(mostly_one);
    columns.push(vec![F::new_unchecked(9)]);
    let mut sparse = vec![F::ZERO; 128];
    sparse[17] = F::new_unchecked(23);
    columns.push(sparse);
    columns
}

impl air::LiftedAir for MockSharedBasisAir {
    type F = F;

    fn spec(&self) -> air::AirSpec<'_, F> {
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 1,
            num_challenges: 2,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Owned(shared_basis_columns()),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = F>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let a = frame.main.current[0].dup();
        builder.assert_zero(a.dup() + inputs.public(0));
        builder.assert_zero_ext(inputs.challenge(0) + frame.aux.current[0].dup());
        let a_ext = AB::ExtExpr::from(a);
        for value in frame.periodic {
            builder.assert_zero_ext(AB::ExtExpr::from(value.dup()) * a_ext.dup());
        }
    }
}

fn ef(x: u64) -> EF {
    EF::from(F::new_unchecked(x))
}

fn set_input(circuit: &AceCircuit<EF>, inputs: &mut [EF], key: InputKey, value: EF) {
    inputs[circuit.layout().index(key).unwrap()] = value;
}

fn build_inputs(layout: &InputLayout) -> Vec<EF> {
    let mut inputs = vec![EF::ZERO; layout.total_inputs];
    let mut set = |key, value| {
        let idx = layout.index(key).unwrap();
        inputs[idx] = value;
    };

    set(InputKey::Public(0), ef(5));
    set(InputKey::AuxRandAlpha, ef(7));
    set(InputKey::AuxRandBeta, ef(11));
    set(InputKey::Main { offset: 0, index: 0 }, ef(3));
    set(InputKey::Main { offset: 1, index: 0 }, ef(9));
    set(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }, ef(11));
    set(InputKey::AuxCoord { offset: 0, index: 0, coord: 1 }, ef(101));
    set(InputKey::AuxCoord { offset: 1, index: 0, coord: 0 }, ef(12));
    set(InputKey::AuxCoord { offset: 1, index: 0, coord: 1 }, ef(102));
    set(InputKey::Alpha, ef(17));
    set(InputKey::ZPowN, ef(19));
    set(InputKey::ZK, ef(23));
    set(InputKey::IsFirst, ef(47));
    set(InputKey::IsLast, ef(43));
    set(InputKey::IsTransition, ef(2) - ef(3));
    set(InputKey::Reserved, ef(53));
    set(InputKey::Weight0, ef(31));
    set(InputKey::F, ef(37));
    set(InputKey::S0, ef(41));

    set(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 }, ef(2));
    set(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 1 }, ef(3));
    set(InputKey::QuotientChunkCoord { offset: 0, chunk: 1, coord: 0 }, ef(5));
    set(InputKey::QuotientChunkCoord { offset: 0, chunk: 1, coord: 1 }, ef(7));

    inputs
}

#[test]
fn multi_air_uses_canonical_offsets_and_stable_selectors() {
    let airs = [
        TestAir {
            preprocessed: 1,
            main: 1,
            aux: 1,
            boundaries: 1,
            selector: Selector::First,
            ..TestAir::simple()
        },
        TestAir {
            preprocessed: 2,
            main: 3,
            aux: 2,
            boundaries: 2,
            selector: Selector::Last,
            ..TestAir::simple()
        },
        TestAir {
            preprocessed: 3,
            main: 5,
            aux: 3,
            boundaries: 1,
            selector: Selector::Transition,
            ..TestAir::simple()
        },
    ];
    let circuit = build_canonical_multi_air_ace_circuit(
        &airs,
        AceConfig {
            num_quotient_chunks: 1,
            layout: LayoutKind::Masm,
        },
        4,
    )
    .unwrap();

    assert_eq!(
        (
            circuit.layout().counts.preprocessed_width,
            circuit.layout().counts.width,
            circuit.layout().counts.aux_width,
            circuit.layout().counts.num_aux_boundary,
        ),
        (12, 16, 8, 4)
    );

    let values = [
        (InputKey::Alpha, 1),
        (InputKey::IsFirstAir(0), 2),
        (InputKey::IsLastAir(1), 3),
        (InputKey::IsTransitionAir(2), 5),
        (InputKey::Preprocessed { offset: 0, index: 0 }, 3),
        (InputKey::Preprocessed { offset: 0, index: 5 }, 4),
        (InputKey::Preprocessed { offset: 0, index: 10 }, 7),
        (InputKey::Main { offset: 0, index: 0 }, 2),
        (InputKey::Main { offset: 0, index: 6 }, 7),
        (InputKey::Main { offset: 0, index: 12 }, 6),
    ];
    let mut inputs = vec![EF::ZERO; circuit.layout().total_inputs];
    for (key, value) in values.into_iter().chain([
        (InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }, 2),
        (InputKey::AuxCoord { offset: 0, index: 3, coord: 1 }, 3),
        (InputKey::AuxCoord { offset: 0, index: 6, coord: 0 }, 5),
        (InputKey::AuxBusBoundary(0), 7),
        (InputKey::AuxBusBoundary(2), 11),
        (InputKey::AuxBusBoundary(3), 13),
        (InputKey::ZPowN, 19),
        (InputKey::Weight0, 7),
        (InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 }, 2),
        (InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 1 }, 3),
    ]) {
        set_input(&circuit, &mut inputs, key, ef(value));
    }

    // The per-AIR constraints give 19, 44 + 3u and 83, where u is the extension-field basis.
    // With one quotient chunk, q*v = 7 * (2 + 3u) * (19 - 1) = 252 + 378u.
    let quotient_binding = EF::new([F::from_u64(252), F::from_u64(378)]);
    for (order, coefficients, expected) in [
        ([2, 0, 1], [10, 1, 100], EF::new([F::from_u64(8_534), F::from_u64(3)])),
        ([0, 1, 2], [100, 10, 1], EF::new([F::from_u64(2_423), F::from_u64(30)])),
    ] {
        for (i, coefficient) in coefficients.into_iter().enumerate() {
            set_input(&circuit, &mut inputs, InputKey::MultiAirFoldCoeff(i), ef(coefficient));
        }
        let expected = expected - quotient_binding;
        assert_eq!(circuit.eval(&inputs).unwrap(), expected);
        assert_eq!(
            crate::compiler::testing::eval_multi_air_constraints(
                &airs,
                circuit.layout(),
                &inputs,
                &order,
                ef(10),
                4,
            ),
            expected,
        );
    }
    circuit.to_ace().expect("multi-AIR root must be MASM encodable");
}

#[test]
fn multi_air_concatenates_distinct_public_inputs() {
    let airs = [0, 1, 0, 2, 0].map(|public| TestAir { public, ..TestAir::simple() });
    let order = [3, 0, 4, 1, 2];
    let beta = ef(3);
    let roots = [ef(1), ef(13), ef(3), ef(34), ef(5)];
    let expected = order.iter().fold(EF::ZERO, |acc, &i| acc * beta + roots[i]);
    for layout in [LayoutKind::Native, LayoutKind::Masm] {
        let circuit = build_canonical_multi_air_ace_circuit(
            &airs,
            AceConfig { num_quotient_chunks: 1, layout },
            1,
        )
        .unwrap();
        assert_eq!(circuit.layout().counts.num_public, 3);
        let mut inputs = vec![EF::ZERO; circuit.layout().total_inputs];
        for (i, value) in [11, 13, 17].into_iter().enumerate() {
            set_input(&circuit, &mut inputs, InputKey::Public(i), ef(value));
        }
        for i in 0..airs.len() {
            set_input(
                &circuit,
                &mut inputs,
                InputKey::Main { offset: 0, index: i },
                ef(i as u64 + 1),
            );
        }
        for (position, i) in order.into_iter().enumerate() {
            let coefficient = beta.exp_u64((order.len() - 1 - position) as u64);
            set_input(&circuit, &mut inputs, InputKey::MultiAirFoldCoeff(i), coefficient);
        }
        assert_eq!(circuit.eval(&inputs).unwrap(), expected);
        assert_eq!(
            crate::compiler::testing::eval_multi_air_constraints(
                &airs,
                circuit.layout(),
                &inputs,
                &order,
                beta,
                1,
            ),
            expected,
        );
    }
}

#[test]
fn mixed_air_periods_use_one_shared_basis() {
    let airs = [
        TestAir { period: 4, ..TestAir::simple() },
        TestAir { period: 32, ..TestAir::simple() },
    ];
    let circuit = build_canonical_multi_air_ace_circuit(
        &airs,
        AceConfig {
            num_quotient_chunks: 1,
            layout: LayoutKind::Native,
        },
        1,
    )
    .unwrap();
    let mut inputs = vec![EF::ZERO; circuit.layout().total_inputs];
    let z_k = ef(3);
    set_input(&circuit, &mut inputs, InputKey::ZK, z_k);
    set_input(&circuit, &mut inputs, InputKey::MultiAirFoldCoeff(0), ef(7));
    set_input(&circuit, &mut inputs, InputKey::MultiAirFoldCoeff(1), ef(1));

    let mut period_four_point = z_k;
    for _ in 0..3 {
        period_four_point *= period_four_point;
    }
    let period_four = eval_periodic_values(&airs[0].spec().periodic_columns, period_four_point)[0];
    let period_thirty_two = eval_periodic_values(&airs[1].spec().periodic_columns, z_k)[0];
    let expected = period_four * ef(7) + period_thirty_two;
    assert_eq!(circuit.eval(&inputs).unwrap(), expected);
    assert_eq!(
        crate::compiler::testing::eval_multi_air_constraints(
            &airs,
            circuit.layout(),
            &inputs,
            &[0, 1],
            ef(7),
            1,
        ),
        expected,
    );
    assert_ne!(period_four, eval_periodic_values(&airs[0].spec().periodic_columns, z_k)[0]);
}

#[test]
fn multi_air_rejects_empty_airs_and_invalid_alignment() {
    let config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
    };
    let airs = [TestAir { aux: 1, ..TestAir::simple() }];
    assert!(build_canonical_multi_air_ace_circuit::<TestAir>(&[], config, 2).is_err());
    assert!(build_canonical_multi_air_ace_circuit(&airs, config, 0).is_err());
    assert!(build_canonical_multi_air_ace_circuit(&airs, config, 3).is_err());
}

#[test]
fn test_preprocessed_entries_lower_to_input_keys() {
    let air = MockPreprocessedAir;
    let config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();

    assert_eq!(artifacts.layout.counts.preprocessed_width, 1);
    assert!(artifacts.layout.index(InputKey::Preprocessed { offset: 0, index: 0 }).is_some());
    assert!(artifacts.layout.index(InputKey::Preprocessed { offset: 1, index: 0 }).is_some());
    assert!(artifacts.dag.nodes().iter().any(|node| matches!(
        node,
        NodeKind::Input(InputKey::Preprocessed { offset: 0, index: 0 })
    )));
    assert!(artifacts.dag.nodes().iter().any(|node| matches!(
        node,
        NodeKind::Input(InputKey::Preprocessed { offset: 1, index: 0 })
    )));
}

#[test]
fn test_preprocessed_inputs_affect_dag_and_circuit_eval() {
    let air = MockPreprocessedAir;
    let config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let mut inputs = vec![EF::ZERO; layout.total_inputs];
    inputs[layout.index(InputKey::Preprocessed { offset: 0, index: 0 }).unwrap()] = ef(13);
    inputs[layout.index(InputKey::Preprocessed { offset: 1, index: 0 }).unwrap()] = ef(17);

    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();
    let dag_value = eval_dag(artifacts.dag.nodes(), artifacts.dag.root(), &inputs, &layout);
    let circuit_value = circuit.eval(&inputs).expect("circuit eval");

    assert_eq!(dag_value, ef(30));
    assert_eq!(circuit_value, dag_value);
}

#[test]
fn test_verifier_dag_matches_manual_eval() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let spec = air.spec();
    let periodic_columns = &spec.periodic_columns;
    let periodic_values = eval_periodic_values(periodic_columns, z_k);

    let acc = eval_native_constraints(&air, &spec, &inputs, &layout, &periodic_values);
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - EF::ONE;
    let expected = acc - eval_quotient(&layout, &inputs) * vanishing;

    let actual = eval_dag(artifacts.dag.nodes(), artifacts.dag.root(), &inputs, &layout);
    assert_eq!(actual, expected);
}

/// Cross-checks the DAG's periodic-column lowering against the independent
/// `eval_periodic_values` reference (dense IDFT + Horner) for a column pair chosen
/// so one column resolves via the sparse Lagrange path (period 128, 3/128 nonzero)
/// and the other via the dense Horner path (period 8, fully dense) — see
/// `build_periodic_nodes` in `dag/periodic.rs`.
#[test]
fn test_sparse_and_dense_periodic_paths_match_manual_eval() {
    let air = MockPeriodicAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let spec = air.spec();
    let periodic_columns = &spec.periodic_columns;
    let periodic_values = eval_periodic_values(periodic_columns, z_k);

    let acc = eval_native_constraints(&air, &spec, &inputs, &layout, &periodic_values);
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - EF::ONE;
    let expected = acc - eval_quotient(&layout, &inputs) * vanishing;

    let actual = eval_dag(artifacts.dag.nodes(), artifacts.dag.root(), &inputs, &layout);
    assert_eq!(actual, expected);

    let circuit = emit_circuit(&artifacts.dag, layout).unwrap();
    let circuit_value = circuit.eval(&inputs).expect("circuit eval");
    assert_eq!(circuit_value, actual);
}

/// The shared-basis lowering must agree with the independent dense reference, and the
/// representation choice must actually exercise it alongside the standalone forms.
#[test]
fn test_shared_lagrange_basis_periodic_path_matches_manual_eval() {
    use crate::compiler::dag::{PeriodicColumn, PeriodicColumnData};

    let data = PeriodicColumnData::<EF>::from_periodic_columns(shared_basis_columns());
    let columns = data.columns();
    assert!(
        columns[..SHARED_BASIS_COLUMNS]
            .iter()
            .all(|column| matches!(column, PeriodicColumn::Basis { period: 32, .. })),
        "dense small-integer columns of one period must share its basis"
    );
    assert!(
        matches!(&columns[SHARED_BASIS_COLUMNS], PeriodicColumn::Basis { offset, .. } if *offset == EF::ONE),
        "a mostly-one column must be combined through the basis complement"
    );
    assert!(matches!(columns[SHARED_BASIS_COLUMNS + 2], PeriodicColumn::Sparse { .. }));

    let air = MockSharedBasisAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let spec = air.spec();
    let periodic_columns = &spec.periodic_columns;
    let periodic_values = eval_periodic_values(periodic_columns, z_k);

    let acc = eval_native_constraints(&air, &spec, &inputs, &layout, &periodic_values);
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - EF::ONE;
    let expected = acc - eval_quotient(&layout, &inputs) * vanishing;

    let actual = eval_dag(artifacts.dag.nodes(), artifacts.dag.root(), &inputs, &layout);
    assert_eq!(actual, expected);

    let circuit = emit_circuit(&artifacts.dag, layout).unwrap();
    assert_eq!(circuit.eval(&inputs).expect("circuit eval"), actual);
}

/// Constant columns and repeats of another column add nothing to the basis savings of their
/// period: the DAG folds a constant column to a single constant and shares a repeat's nodes. A
/// lone one-hot column saves too little over the period-8 basis to adopt it, and adding either
/// kind of column must not change that.
#[test]
fn test_constant_and_repeated_periodic_columns_do_not_count_toward_shared_basis() {
    use crate::compiler::dag::{PeriodicColumn, PeriodicColumnData};

    let mut one_hot = vec![F::ZERO; 8];
    one_hot[5] = F::ONE;
    let with_constants =
        vec![one_hot.clone(), vec![F::new_unchecked(2); 8], vec![F::new_unchecked(3); 8]];
    let repeated = vec![one_hot; 4];

    for (case, columns) in [("constant", with_constants), ("repeated", repeated)] {
        let data = PeriodicColumnData::<EF>::from_periodic_columns(columns);
        assert!(
            data.columns()
                .iter()
                .all(|column| !matches!(column, PeriodicColumn::Basis { .. })),
            "{case} columns must not push a period onto the shared basis"
        );
    }
}

#[test]
fn test_emitted_circuit_matches_dag_eval() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);

    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();
    let dag_value = eval_dag(artifacts.dag.nodes(), artifacts.dag.root(), &inputs, &layout);
    let circuit_value = circuit.eval(&inputs).expect("circuit eval");
    assert_eq!(circuit_value, dag_value);
}

#[test]
fn pipeline_rejects_zero_quotient_chunks() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 0,
        layout: LayoutKind::Native,
    };

    let err = build_ace_dag_for_air(&air, config).unwrap_err();
    assert!(
        matches!(err, crate::AceError::InvalidInputLayout { .. }),
        "expected InvalidInputLayout, got {err:?}"
    );
}

#[test]
fn test_encoded_circuit_structure() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();

    let encoded = circuit.to_ace().unwrap();
    assert!(encoded.size_in_felt().is_multiple_of(8));
    assert_eq!(encoded.num_inputs(), layout.total_inputs);
}

#[test]
fn stream_geometry_rejects_the_node_id_packing_bound() {
    use crate::compiler::encode::StreamGeometry;

    // Valid streams have an even node count because READ and EVAL rows are word-aligned. Thus,
    // 2^30 - 2 is the largest realizable shape below the runtime's strict 2^30-wire bound.
    let below_limit = StreamGeometry::from_counts((1 << 30) - 8, 2, 4);
    assert!(below_limit.validate().is_ok(), "the largest aligned shape must validate");

    let at_limit = StreamGeometry::from_counts((1 << 30) - 6, 2, 4);
    assert!(at_limit.validate().is_err(), "a shape with 2^30 nodes must be rejected");
}

#[test]
fn canonical_builder_air_count_is_independent_of_order_maps() {
    for num_airs in [1, crate::MAX_ORDER_AIRS + 1] {
        let airs = vec![TestAir::simple(); num_airs];
        let circuit = build_canonical_multi_air_ace_circuit(
            &airs,
            AceConfig {
                num_quotient_chunks: 1,
                layout: LayoutKind::Masm,
            },
            8,
        )
        .expect("canonical circuit");
        let mut inputs = vec![EF::ZERO; circuit.layout().total_inputs];
        for i in 0..num_airs {
            set_input(
                &circuit,
                &mut inputs,
                InputKey::Main { offset: 0, index: 8 * i },
                ef((i + 1) as u64),
            );
            set_input(&circuit, &mut inputs, InputKey::MultiAirFoldCoeff(i), EF::ONE);
        }
        assert_eq!(circuit.eval(&inputs).unwrap(), ef((num_airs * (num_airs + 1) / 2) as u64));
        circuit.to_ace().expect("canonical circuit must encode");
    }
}

#[test]
fn compiled_relation_reuses_capture_and_pads_each_air_row() {
    use crate::compiler::{CapturedAir, CompiledRelation};
    let first = TestAir {
        main: 3,
        aux: 1,
        preprocessed: 2,
        ..TestAir::simple()
    };
    let second = TestAir {
        main: 5,
        aux: 3,
        boundaries: 2,
        period: 4,
        ..TestAir::simple()
    };
    let captures = [
        CapturedAir::new_native(&first).unwrap(),
        CapturedAir::new_native(&second).unwrap(),
    ];
    let relation = CompiledRelation::from_captured(&[&captures[0], &captures[1]], 8).unwrap();
    assert_eq!(relation.geometry().main_width, 16);
    assert_eq!(relation.geometry().preprocessed_width, 8);
    assert_eq!(relation.geometry().aux_width, 16);
    assert_eq!(relation.geometry().airs[1].main.offset, 8);
    assert_eq!(relation.geometry().airs[1].aux.raw_width, 6);
    assert_eq!(relation.geometry().num_constraints, 4);
    assert_eq!(relation.geometry().num_quotient_chunks, 1);
    assert_eq!(relation.geometry().quotient_width, 8);
    assert_eq!(relation.geometry().shared_period, 4);
    let circuit = relation.build_circuit(LayoutKind::Masm).unwrap();
    assert_eq!(circuit.layout.quotient_width(), 8);
    assert!(core::ptr::eq(relation.airs()[0], &captures[0]));
    assert!(CompiledRelation::from_captured(&[], 8).is_err());
    assert!(CompiledRelation::from_captured(&[&captures[0]], 0).is_err());
}

#[test]
fn captured_degrees_match_symbolic_selector_and_extension_semantics() {
    use miden_stark::air::ConstraintDegrees;

    use crate::compiler::CapturedAir;
    for selector in [Selector::None, Selector::First, Selector::Last, Selector::Transition] {
        let air = TestAir {
            selector,
            period: 4,
            aux: 1,
            boundaries: 1,
            ..TestAir::simple()
        };
        let captured = CapturedAir::new_native(&air).unwrap();
        let base = match selector {
            Selector::First | Selector::Last => 2,
            Selector::None | Selector::Transition => 1,
        };
        assert_eq!(captured.degrees(), ConstraintDegrees { base, ext: 1 });
        assert_eq!(captured.constraint_counts().base, 1);
        assert_eq!(captured.constraint_counts().ext, 1);
    }
}

#[test]
fn relation_geometry_concatenates_public_windows_and_rejects_width_overflow() {
    use crate::compiler::{CapturedAir, CompiledRelation};
    let first = CapturedAir::new_native(&TestAir { public: 2, ..TestAir::simple() }).unwrap();
    let mut second = CapturedAir::new_native(&TestAir { public: 1, ..TestAir::simple() }).unwrap();
    let relation = CompiledRelation::from_captured(&[&first, &second], 8).unwrap();
    assert_eq!(relation.geometry().num_public, 3);
    assert_eq!(relation.geometry().airs[0].public_offset, 0);
    assert_eq!(relation.geometry().airs[0].num_public, 2);
    assert_eq!(relation.geometry().airs[1].public_offset, 2);
    assert_eq!(relation.geometry().airs[1].num_public, 1);

    // Intentionally inject invalid crate-private metadata to exercise defensive geometry checks.
    // Production callers can only read a capture's metadata through immutable getters.
    second.counts.num_public = usize::MAX;
    assert!(CompiledRelation::from_captured(&[&first, &second], 8).is_err());
    second.counts.num_public = 1;
    second.counts.width = usize::MAX;
    assert!(CompiledRelation::from_captured(&[&first, &second], 8).is_err());
    second.counts.width = 1;
    second.counts.aux_width = 1;
    assert!(CompiledRelation::from_captured(&[&second], 3).is_err());
}

struct CountedCubicAir {
    eval_count: std::sync::atomic::AtomicUsize,
}

impl air::LiftedAir for CountedCubicAir {
    type F = F;

    fn spec(&self) -> air::AirSpec<'_, F> {
        air::AirSpec {
            main_width: 1,
            aux_width: 0,
            num_public_values: 0,
            num_challenges: 2,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = F>>(
        &self,
        frame: &air::Frame<'_, AB>,
        _inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        self.eval_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let x = frame.main.current[0].dup();
        builder.assert_zero(x.dup() * x.dup() * x);
    }
}

#[test]
fn repeated_artifact_generation_evaluates_the_air_only_during_capture() {
    use crate::compiler::{CapturedAir, CompiledRelation};
    let air = CountedCubicAir {
        eval_count: std::sync::atomic::AtomicUsize::new(0),
    };
    let captured = CapturedAir::new_native(&air).unwrap();
    assert_eq!(captured.degrees().base, 3);
    let relation = CompiledRelation::from_captured(&[&captured], 8).unwrap();
    assert_eq!(relation.geometry().num_quotient_chunks, 2);
    for layout in [LayoutKind::Native, LayoutKind::Masm] {
        let circuit = relation.build_circuit(layout).unwrap();
        assert_eq!(circuit.layout().quotient_width(), 8);
        assert_eq!(circuit.layout().counts.num_quotient_chunks, 2);
    }
    assert_eq!(air.eval_count.load(std::sync::atomic::Ordering::Relaxed), 1);
}

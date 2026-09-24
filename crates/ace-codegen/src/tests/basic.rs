use std::borrow::Cow;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::PrimeCharacteristicRing,
    stark::{
        air::{
            AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess,
            symbolic::{AirLayout, SymbolicAirBuilder},
        },
        matrix::{Matrix, RowMajorMatrix},
    },
};

use super::common::{eval_dag, eval_folded_constraints, eval_periodic_values, eval_quotient};
use crate::{
    AceCircuit, AceConfig, InputKey, InputLayout, LayoutKind,
    circuit::{AceNode, emit_circuit},
    dag::NodeKind,
    pipeline::{build_ace_dag_for_air, build_multi_air_ace_circuit},
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
            preprocessed: 0,
            main: 1,
            aux: 0,
            boundaries: 0,
            period: 0,
            selector: Selector::None,
        }
    }
}

impl BaseAir<F> for TestAir {
    fn width(&self) -> usize {
        self.main
    }

    fn preprocessed_width(&self) -> usize {
        self.preprocessed
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        if self.period == 0 {
            return Cow::Borrowed(&[]);
        }
        let mut column = vec![F::ZERO; self.period];
        column[1] = F::ONE;
        Cow::Owned(vec![column])
    }
}

impl LiftedAir<F, EF> for TestAir {
    fn num_randomness(&self) -> usize {
        2
    }

    fn aux_width(&self) -> usize {
        self.aux
    }

    fn num_aux_values(&self) -> usize {
        self.boundaries
    }

    fn build_aux_trace(
        &self,
        _main: &RowMajorMatrix<F>,
        _air_inputs: &[F],
        _aux_inputs: &[F],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        unreachable!("ACE codegen tests do not build concrete traces")
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        let mut expression: AB::Expr = {
            let main = builder.main();
            main.current_slice()[self.main - 1].into()
        };
        if self.preprocessed > 0 {
            let preprocessed: AB::Expr = {
                let trace = builder.preprocessed();
                trace.current_slice()[self.preprocessed - 1].into()
            };
            expression += preprocessed;
        }
        if self.period > 0 {
            let periodic: AB::Expr = builder.periodic_values()[0].into();
            expression += periodic;
        }

        match self.selector {
            Selector::None => builder.assert_zero(expression),
            Selector::First => builder.when_first_row().assert_zero(expression),
            Selector::Last => builder.when_last_row().assert_zero(expression),
            Selector::Transition => builder.when_transition().assert_zero(expression),
        }

        if self.aux > 0 {
            let mut expression: AB::ExprEF = {
                let aux = builder.permutation();
                aux.current_slice()[self.aux - 1].into()
            };
            if self.boundaries > 0 {
                let boundary: AB::ExprEF =
                    builder.permutation_values()[self.boundaries - 1].clone().into();
                expression += boundary;
            }
            builder.assert_zero_ext(expression);
        }
    }
}

impl BaseAir<F> for MockAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        1
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Owned(vec![vec![Felt::ONE]])
    }
}

struct MockPreprocessedAir;

impl BaseAir<F> for MockPreprocessedAir {
    fn width(&self) -> usize {
        1
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new(vec![Felt::ZERO; 4], 1))
    }

    fn preprocessed_width(&self) -> usize {
        1
    }
}

impl LiftedAir<F, EF> for MockPreprocessedAir {
    fn num_randomness(&self) -> usize {
        2
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        _air_inputs: &[F],
        _aux_inputs: &[F],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        (RowMajorMatrix::new(vec![EF::ZERO; main.height()], 1), Vec::new())
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        let preprocessed = builder.preprocessed();
        let curr = preprocessed.current_slice()[0];
        let next = preprocessed.next_slice()[0];
        builder.assert_zero(curr + next);
    }
}

impl LiftedAir<F, EF> for MockAir {
    fn num_randomness(&self) -> usize {
        2
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        1
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        _air_inputs: &[F],
        _aux_inputs: &[F],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        (RowMajorMatrix::new(vec![EF::ZERO; main.height()], 1), vec![EF::ZERO])
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        let main = builder.main();
        let a = main.current_slice()[0];
        let b = main.next_slice()[0];
        let pub0 = builder.public_values()[0];
        let rand0 = builder.permutation_randomness()[0];
        let aux0 = builder.permutation().current_slice()[0];
        let per0 = builder.periodic_values()[0];

        builder.assert_zero(a.into() + pub0.into());
        builder.assert_zero_ext(rand0.into() + aux0.into());
        builder.when_transition().assert_zero(b - a);
        let a_expr: AB::Expr = a.into();
        let a_ext: AB::ExprEF = a_expr.into();
        let per_expr: AB::ExprEF = per0.into().into();
        builder.assert_zero_ext(per_expr - a_ext);
    }
}

struct MockPeriodicAir;

impl BaseAir<F> for MockPeriodicAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        1
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        // Period 128, mostly zero: cheaper to evaluate via the sparse Lagrange path.
        let mut sparse_col = vec![Felt::ZERO; 128];
        sparse_col[0] = Felt::new_unchecked(7);
        sparse_col[50] = Felt::new_unchecked(11);
        sparse_col[100] = Felt::new_unchecked(13);

        // Period 8, fully dense: cheaper to evaluate via the Horner path.
        let dense_col: Vec<Felt> =
            [2u64, 3, 5, 7, 11, 13, 17, 19].into_iter().map(Felt::new_unchecked).collect();

        Cow::Owned(vec![sparse_col, dense_col])
    }
}

impl LiftedAir<F, EF> for MockPeriodicAir {
    fn num_randomness(&self) -> usize {
        2
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        1
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        _air_inputs: &[F],
        _aux_inputs: &[F],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        (RowMajorMatrix::new(vec![EF::ZERO; main.height()], 1), vec![EF::ZERO])
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        let main = builder.main();
        let a = main.current_slice()[0];
        let pub0 = builder.public_values()[0];
        let rand0 = builder.permutation_randomness()[0];
        let aux0 = builder.permutation().current_slice()[0];
        let per0 = builder.periodic_values()[0];
        let per1 = builder.periodic_values()[1];

        builder.assert_zero(a.into() + pub0.into());
        builder.assert_zero_ext(rand0.into() + aux0.into());

        let per0_ext: AB::ExprEF = per0.into().into();
        let per1_ext: AB::ExprEF = per1.into().into();
        builder.assert_zero_ext(per0_ext + per1_ext);
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
fn multi_air_uses_proof_order_offsets_and_stable_selectors() {
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
    let circuit = build_multi_air_ace_circuit(
        &airs,
        &[2, 0, 1],
        AceConfig {
            num_quotient_chunks: 1,
            layout: LayoutKind::Masm,
            num_airs: 3,
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
        (InputKey::MultiAirFoldBeta, 10),
        (InputKey::IsFirstAir(0), 2),
        (InputKey::IsLastAir(1), 3),
        (InputKey::IsTransitionAir(2), 5),
        (InputKey::Preprocessed { offset: 0, index: 4 }, 3),
        (InputKey::Preprocessed { offset: 0, index: 9 }, 4),
        (InputKey::Preprocessed { offset: 0, index: 2 }, 7),
        (InputKey::Main { offset: 0, index: 8 }, 2),
        (InputKey::Main { offset: 0, index: 14 }, 7),
        (InputKey::Main { offset: 0, index: 4 }, 6),
    ];
    let offset_only = [
        InputKey::AuxCoord { offset: 0, index: 4, coord: 0 },
        InputKey::AuxCoord { offset: 0, index: 7, coord: 1 },
        InputKey::AuxCoord { offset: 0, index: 2, coord: 0 },
        InputKey::AuxBusBoundary(1),
        InputKey::AuxBusBoundary(3),
        InputKey::AuxBusBoundary(0),
    ];
    let references: Vec<_> = circuit
        .operations
        .iter()
        .flat_map(|op| [op.lhs, op.rhs])
        .filter_map(|node| match node {
            AceNode::Input(index) => Some(index),
            _ => None,
        })
        .collect();
    for key in values.iter().map(|&(key, _)| key).chain(offset_only) {
        let index = circuit.layout().index(key).unwrap();
        assert!(references.contains(&index), "missing {key:?}");
    }

    let mut inputs = vec![EF::ZERO; circuit.layout().total_inputs];
    for (key, value) in values {
        set_input(&circuit, &mut inputs, key, ef(value));
    }

    // Stable accumulators are 10, 33, and 65; proof order [2, 0, 1] folds to 6,633.
    assert_eq!(circuit.eval(&inputs).unwrap(), ef(6_633));
    circuit.to_ace().expect("multi-AIR root must be MASM encodable");
}

#[test]
fn mixed_air_periods_use_one_shared_basis() {
    let airs = [
        TestAir { period: 4, ..TestAir::simple() },
        TestAir { period: 32, ..TestAir::simple() },
    ];
    let circuit = build_multi_air_ace_circuit(
        &airs,
        &[0, 1],
        AceConfig {
            num_quotient_chunks: 1,
            layout: LayoutKind::Native,
            num_airs: 2,
        },
        1,
    )
    .unwrap();
    let mut inputs = vec![EF::ZERO; circuit.layout().total_inputs];
    let z_k = ef(3);
    set_input(&circuit, &mut inputs, InputKey::ZK, z_k);
    set_input(&circuit, &mut inputs, InputKey::MultiAirFoldBeta, ef(7));

    let mut period_four_point = z_k;
    for _ in 0..3 {
        period_four_point *= period_four_point;
    }
    let period_four = eval_periodic_values(&airs[0].periodic_columns(), period_four_point)[0];
    let period_thirty_two = eval_periodic_values(&airs[1].periodic_columns(), z_k)[0];
    assert_eq!(circuit.eval(&inputs).unwrap(), period_four * ef(7) + period_thirty_two);
    assert_ne!(period_four, eval_periodic_values(&airs[0].periodic_columns(), z_k)[0]);
}

#[test]
fn multi_air_rejects_invalid_proof_orders() {
    let airs = [TestAir::simple(), TestAir::simple()];
    let config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
        num_airs: 2,
    };

    assert!(build_multi_air_ace_circuit(&airs, &[0], config, 2).is_err());
    assert!(build_multi_air_ace_circuit(&airs, &[0, 0], config, 2).is_err());
    assert!(build_multi_air_ace_circuit(&airs, &[0, 2], config, 2).is_err());
}

#[test]
fn test_preprocessed_entries_lower_to_input_keys() {
    let air = MockPreprocessedAir;
    let config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
        num_airs: 1,
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
        num_airs: 1,
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
        num_airs: 1,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_columns = air.periodic_columns();
    let periodic_values = eval_periodic_values(&periodic_columns, z_k);

    let air_layout = AirLayout {
        preprocessed_width: layout.counts.preprocessed_width,
        main_width: layout.counts.width,
        num_public_values: layout.counts.num_public,
        permutation_width: layout.counts.aux_width,
        num_permutation_challenges: layout.counts.num_randomness,
        num_permutation_values: air.num_aux_values(),
        num_periodic_columns: periodic_columns.len(),
    };
    let mut builder = SymbolicAirBuilder::<F, EF>::new(air_layout);
    air.eval(&mut builder);

    let acc = eval_folded_constraints(
        &builder.base_constraints(),
        &builder.extension_constraints(),
        &builder.constraint_layout(),
        &inputs,
        &layout,
        &periodic_values,
    );
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
/// `build_periodic_nodes` in `dag/lower.rs`.
#[test]
fn test_sparse_and_dense_periodic_paths_match_manual_eval() {
    let air = MockPeriodicAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
        num_airs: 1,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_columns = air.periodic_columns();
    let periodic_values = eval_periodic_values(&periodic_columns, z_k);

    let air_layout = AirLayout {
        preprocessed_width: 0,
        main_width: layout.counts.width,
        num_public_values: layout.counts.num_public,
        permutation_width: layout.counts.aux_width,
        num_permutation_challenges: layout.counts.num_randomness,
        num_permutation_values: air.num_aux_values(),
        num_periodic_columns: periodic_columns.len(),
    };
    let mut builder = SymbolicAirBuilder::<F, EF>::new(air_layout);
    air.eval(&mut builder);

    let acc = eval_folded_constraints(
        &builder.base_constraints(),
        &builder.extension_constraints(),
        &builder.constraint_layout(),
        &inputs,
        &layout,
        &periodic_values,
    );
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - EF::ONE;
    let expected = acc - eval_quotient(&layout, &inputs) * vanishing;

    let actual = eval_dag(artifacts.dag.nodes(), artifacts.dag.root(), &inputs, &layout);
    assert_eq!(actual, expected);

    let circuit = emit_circuit(&artifacts.dag, layout).unwrap();
    let circuit_value = circuit.eval(&inputs).expect("circuit eval");
    assert_eq!(circuit_value, actual);
}

#[test]
fn test_emitted_circuit_matches_dag_eval() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
        num_airs: 1,
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
fn pipeline_rejects_zero_airs() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
        num_airs: 0,
    };

    let err = build_ace_dag_for_air(&air, config).unwrap_err();
    assert!(
        matches!(err, crate::AceError::InvalidInputLayout { .. }),
        "expected InvalidInputLayout, got {err:?}"
    );
}

#[test]
fn pipeline_rejects_zero_quotient_chunks() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 0,
        layout: LayoutKind::Native,
        num_airs: 1,
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
        num_airs: 1,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();

    let encoded = circuit.to_ace().unwrap();
    assert!(encoded.size_in_felt().is_multiple_of(8));
    assert_eq!(encoded.num_inputs(), layout.total_inputs);
}

fn mixed_factoring_airs() -> [TestAir; 3] {
    [
        TestAir {
            preprocessed: 2,
            main: 2,
            aux: 1,
            boundaries: 1,
            selector: Selector::First,
            ..TestAir::simple()
        },
        TestAir {
            main: 3,
            aux: 2,
            boundaries: 2,
            period: 4,
            ..TestAir::simple()
        },
        TestAir {
            preprocessed: 3,
            main: 1,
            aux: 1,
            boundaries: 1,
            selector: Selector::Transition,
            ..TestAir::simple()
        },
    ]
}

/// Shared driver: for every order, the factored circuit must match the independent
/// unfactored builder by layout, by evaluation on a deterministic input vector, and by
/// its encode-only shuffle slice against the assembled stream — with anti-vacuity guards
/// on both the evaluated values and the encoded sections.
fn assert_factored_matches_unfactored_for_orders<const N: usize>(
    airs: &[TestAir],
    config: AceConfig,
    alignment: usize,
    orders: &[[usize; N]],
    mut state: u64,
) {
    use crate::pipeline::build_factored_multi_air_ace_circuit;

    let factored = build_factored_multi_air_ace_circuit(airs, config, alignment).expect("factored");
    let mut buffer = crate::ShuffleEncodeBuffer::new();
    let mut sections = Vec::new();
    let mut distinct_values = std::collections::BTreeSet::new();
    for order in orders {
        let assembled = factored.circuit_for_order(order).expect("assembled circuit");
        let reference =
            build_multi_air_ace_circuit(airs, order, config, alignment).expect("reference circuit");
        assert_eq!(
            assembled.layout().total_inputs,
            reference.layout().total_inputs,
            "layouts must agree for {order:?}"
        );

        // Both circuits read the same proof-order input vector; fill it deterministically.
        let inputs: Vec<EF> = (0..assembled.layout().total_inputs)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                ef(state >> 33)
            })
            .collect();

        let value = assembled.eval(&inputs).expect("factored eval");
        assert_eq!(
            value,
            reference.eval(&inputs).expect("reference eval"),
            "factored and unfactored circuits disagree for {order:?}"
        );
        distinct_values.insert(format!("{value:?}"));

        // The encode-only registry path must reproduce the assembled stream's shuffle slice.
        let full = assembled.to_ace().expect("factored circuit must be MASM encodable");
        let const_felts = full.num_constants() * crate::EXT_DEGREE;
        let shuffle_len = factored.num_shuffle_ops();
        let encoded = factored
            .encode_shuffle_section_for_order(order, &mut buffer)
            .expect("fast path");
        assert_eq!(
            encoded,
            &full.instructions()[const_felts..const_felts + shuffle_len],
            "shuffle-only encoding diverges from the assembled stream for {order:?}"
        );
        sections.push(encoded.to_vec());
    }
    // Different orders weight the accumulators differently, so a shuffle that collapses to
    // the identity for every order would make the equality above vacuous.
    assert!(distinct_values.len() > 1, "orders must not all evaluate identically");
    // Keep the fixture non-vacuous: its distinct orders should not collapse to one shuffle.
    assert_pairwise_distinct_sections(orders, &sections);
}

#[test]
fn factored_multi_air_matches_unfactored_for_every_order_with_preprocessed() {
    // A deliberately mixed AIR set: distinct widths per kind, one AIR without preprocessed
    // columns between two with them (exercising the zero-width offset accumulation), plus a
    // periodic column and per-AIR selectors. The unfactored builder places inputs and folds
    // in proof order directly; the factored builder must reproduce it through the shuffle
    // section for every permutation, including the preprocessed region.
    let airs = mixed_factoring_airs();
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Masm,
        num_airs: 3,
    };
    let orders: [[usize; 3]; 6] =
        [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];

    assert_factored_matches_unfactored_for_orders(&airs, config, 4, &orders, 0x00dd_f00d_1234_5678);
}

/// Assert that no two proof orders produced the same shuffle-section encoding.
fn assert_pairwise_distinct_sections<const N: usize>(
    orders: &[[usize; N]],
    sections: &[Vec<Felt>],
) {
    assert_eq!(orders.len(), sections.len(), "one section per order");
    for i in 0..sections.len() {
        for j in i + 1..sections.len() {
            assert_ne!(
                sections[i], sections[j],
                "orders {:?} and {:?} encode identical shuffle sections — their registry \
                 leaves would collide",
                orders[i], orders[j]
            );
        }
    }
}

#[test]
fn factored_circuits_match_unfactored_beyond_three_airs() {
    // At three AIRs `for e in 2..num_fold_coeffs` runs exactly once, so the chained power
    // node `Operation(powers_start + (e - 2))` is only ever evaluated at offset 0 and the
    // shuffle padding loop never executes. Both matter at the ten-chiplet precompile width.
    //
    // This compares against the independent unfactored builder rather than against the
    // factored circuit's own encoding: `assemble` and `encode_shuffle_section` share
    // `emit_shuffle_ops`, so an encoding-vs-encoding check cannot see a defect in the
    // shared emitter — a wrong power-chain stride is invisible to it and shows up only
    // here.
    let airs: [TestAir; 5] = core::array::from_fn(|i| TestAir {
        main: 2 + i,
        aux: 1 + (i % 2),
        boundaries: 1,
        ..TestAir::simple()
    });
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: 5,
    };
    let orders = [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 0, 4, 1, 3], [1, 4, 0, 3, 2]];

    assert_factored_matches_unfactored_for_orders(&airs, config, 8, &orders, 0x51ed_9a77_0f13_c0de);
}

#[test]
fn packed_leaves_match_the_scalar_path() {
    use crate::{
        FactoredCircuitFactory, PackedLeafScratch, ShuffleEncodeBuffer, factory::LEAF_LANES,
        pipeline::build_factored_multi_air_ace_circuit,
    };

    // Five AIRs so the fold power chain is live, and batch sizes chosen to exercise
    // both full chunks and the duplicate-padded tail for any LEAF_LANES.
    let airs: [TestAir; 5] = core::array::from_fn(|i| TestAir {
        main: 2 + i,
        aux: 1 + (i % 2),
        boundaries: 1,
        ..TestAir::simple()
    });
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: 5,
    };
    let factored = build_factored_multi_air_ace_circuit(&airs, config, 8).expect("factored");
    let factory = FactoredCircuitFactory::new(factored).expect("factory");

    let orders: Vec<[usize; 5]> = vec![
        [0, 1, 2, 3, 4],
        [4, 3, 2, 1, 0],
        [2, 0, 4, 1, 3],
        [1, 4, 0, 3, 2],
        [3, 2, 4, 0, 1],
        [0, 2, 1, 4, 3],
        [4, 0, 3, 2, 1],
    ];
    let mut buffer = ShuffleEncodeBuffer::new();
    let scalar: Vec<_> = orders
        .iter()
        .map(|order| factory.leaf_for_order(order, &mut buffer).expect("scalar leaf"))
        .collect();

    let mut scratch = PackedLeafScratch::new();
    // Every prefix length: covers batch sizes below, at, and above LEAF_LANES,
    // including tails that pad lanes with the duplicated last order.
    for take in 1..=orders.len() {
        let refs: Vec<&[usize]> = orders[..take].iter().map(<[usize; 5]>::as_slice).collect();
        let mut packed = Vec::new();
        factory
            .leaves_for_orders(&refs, &mut scratch, &mut packed)
            .expect("packed leaves");
        assert_eq!(
            packed,
            scalar[..take],
            "packed leaves diverge from the scalar path at batch size {take} (lanes: {LEAF_LANES})"
        );
    }
}

#[test]
fn stream_geometry_rejects_the_node_id_packing_bound() {
    use crate::encode::StreamGeometry;

    // Valid streams have an even node count because READ and EVAL rows are word-aligned. Thus,
    // 2^30 - 2 is the largest realizable shape below the runtime's strict 2^30-wire bound.
    let below_limit = StreamGeometry::from_counts((1 << 30) - 8, 2, 4);
    assert!(below_limit.validate().is_ok(), "the largest aligned shape must validate");

    let at_limit = StreamGeometry::from_counts((1 << 30) - 6, 2, 4);
    assert!(at_limit.validate().is_err(), "a shape with 2^30 nodes must be rejected");
}

#[test]
fn encode_shuffle_section_rejects_layouts_the_encoder_rejects() {
    use crate::pipeline::build_factored_multi_air_ace_circuit;

    // The encode-only path never builds an `AceCircuit`, so it must reproduce `to_ace`'s
    // preconditions itself. Otherwise it would hand back felts for a stream the encoder —
    // and therefore the chiplet — refuses, and a registry over those leaves would commit to
    // circuits that can never be evaluated.
    let airs = [
        TestAir {
            main: 2,
            aux: 1,
            boundaries: 0,
            ..TestAir::simple()
        },
        TestAir {
            main: 3,
            aux: 1,
            boundaries: 0,
            ..TestAir::simple()
        },
    ];
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
        num_airs: 2,
    };
    let factored = build_factored_multi_air_ace_circuit(&airs, config, 1).expect("factored");

    // Native layouts do not pad the READ section, so this one lands on an odd input count.
    // If that ever stops holding, the test is no longer exercising the guard.
    assert!(
        !factored.layout().total_inputs.is_multiple_of(2),
        "test needs an unaligned READ layout to exercise the guard"
    );

    let order = [0, 1];
    assert!(
        factored.circuit_for_order(&order).expect("assembled").to_ace().is_err(),
        "to_ace must reject an unaligned READ layout"
    );

    let mut buffer = crate::ShuffleEncodeBuffer::new();
    assert!(
        factored.encode_shuffle_section_for_order(&order, &mut buffer).is_err(),
        "the encode-only path must reject exactly what to_ace rejects"
    );
}

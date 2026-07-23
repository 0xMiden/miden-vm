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

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        if self.period == 0 {
            return Vec::new();
        }
        let mut column = vec![F::ZERO; self.period];
        column[1] = F::ONE;
        vec![column]
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
        unimplemented!("ACE codegen tests do not build concrete traces")
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

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        vec![vec![Felt::ONE]]
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

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        // Period 128, mostly zero: cheaper to evaluate via the sparse Lagrange path.
        let mut sparse_col = vec![Felt::ZERO; 128];
        sparse_col[0] = Felt::new_unchecked(7);
        sparse_col[50] = Felt::new_unchecked(11);
        sparse_col[100] = Felt::new_unchecked(13);

        // Period 8, fully dense: cheaper to evaluate via the Horner path.
        let dense_col: Vec<Felt> =
            [2u64, 3, 5, 7, 11, 13, 17, 19].into_iter().map(Felt::new_unchecked).collect();

        vec![sparse_col, dense_col]
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
    let circuit = build_multi_air_ace_circuit::<_, F, EF>(
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
    let circuit = build_multi_air_ace_circuit::<_, F, EF>(
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

    assert!(build_multi_air_ace_circuit::<_, F, EF>(&airs, &[0], config, 2).is_err());
    assert!(build_multi_air_ace_circuit::<_, F, EF>(&airs, &[0, 0], config, 2).is_err());
    assert!(build_multi_air_ace_circuit::<_, F, EF>(&airs, &[0, 2], config, 2).is_err());
}

#[test]
fn test_preprocessed_entries_lower_to_input_keys() {
    let air = MockPreprocessedAir;
    let config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
        num_airs: 1,
    };
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();

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
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
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
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
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
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
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
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
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

    let err = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap_err();
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

    let err = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap_err();
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
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();

    let encoded = circuit.to_ace().unwrap();
    assert!(encoded.size_in_felt().is_multiple_of(8));
    assert_eq!(encoded.num_inputs(), layout.total_inputs);
}

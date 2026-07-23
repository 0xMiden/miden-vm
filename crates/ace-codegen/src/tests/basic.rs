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
    AceConfig, InputKey, InputLayout, LayoutKind,
    circuit::emit_circuit,
    dag::NodeKind,
    pipeline::{build_ace_dag_for_air, build_ace_dags_for_airs},
};

// Base and extension field types for tests.
type F = Felt;
type EF = QuadFelt;

struct MockAir;

struct PeriodicAir {
    period: usize,
}

impl BaseAir<F> for PeriodicAir {
    fn width(&self) -> usize {
        1
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut column = vec![Felt::ZERO; self.period];
        column[1] = Felt::ONE;
        vec![column]
    }
}

impl LiftedAir<F, EF> for PeriodicAir {
    fn num_randomness(&self) -> usize {
        2
    }

    fn aux_width(&self) -> usize {
        0
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        _main: &RowMajorMatrix<F>,
        _air_inputs: &[F],
        _aux_inputs: &[F],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        unimplemented!("periodic lowering test does not build traces")
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        let periodic: AB::Expr = builder.periodic_values()[0].into();
        builder.assert_zero(periodic);
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
fn mixed_air_periods_use_one_derived_shared_period() {
    let airs = [PeriodicAir { period: 4 }, PeriodicAir { period: 32 }];
    let config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
        num_airs: 1,
    };
    let artifacts = build_ace_dags_for_airs::<_, F, EF>(&airs, config).unwrap();
    let shared_period = airs
        .iter()
        .flat_map(BaseAir::periodic_columns)
        .map(|column| column.len())
        .max()
        .unwrap();
    assert_eq!(shared_period, 32);

    let z_k = ef(3);
    for (air, artifacts) in airs.iter().zip(&artifacts) {
        let mut inputs = vec![EF::ZERO; artifacts.layout.total_inputs];
        inputs[artifacts.layout.index(InputKey::ZK).unwrap()] = z_k;

        let ratio = shared_period / air.period;
        let mut column_point = z_k;
        for _ in 0..ratio.ilog2() {
            column_point *= column_point;
        }
        let expected = eval_periodic_values(&air.periodic_columns(), column_point)[0];
        let actual =
            eval_dag(artifacts.dag.nodes(), artifacts.dag.root(), &inputs, &artifacts.layout);
        assert_eq!(actual, expected, "period-{} AIR", air.period);

        if air.period < shared_period {
            let incorrectly_local = eval_periodic_values(&air.periodic_columns(), z_k)[0];
            assert_ne!(actual, incorrectly_local, "regression must distinguish local lowering");
        }
    }
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

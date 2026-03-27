use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::PrimeCharacteristicRing,
    stark::air::{
        AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess,
        symbolic::{AirLayout, SymbolicAirBuilder},
    },
};

use super::common::{eval_dag, eval_folded_constraints, eval_periodic_values, eval_quotient};
use crate::{
    AceConfig, InputKey, InputLayout, LayoutKind, circuit::emit_circuit,
    pipeline::build_ace_dag_for_air,
};

// Base and extension field types for tests.
type F = Felt;
type EF = QuadFelt;

struct MockAir;

impl BaseAir<F> for MockAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl LiftedAir<F, EF> for MockAir {
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        vec![vec![Felt::ONE]]
    }

    fn num_randomness(&self) -> usize {
        2
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        1
    }

    fn num_var_len_public_inputs(&self) -> usize {
        0
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

fn ef(x: u64) -> EF {
    EF::from(F::new(x))
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
    set(InputKey::Gamma, ef(53));
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
fn test_verifier_dag_matches_manual_eval() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_vlpi_groups: 0,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_values = eval_periodic_values(&air.periodic_columns(), z_k);

    let air_layout = AirLayout {
        preprocessed_width: 0,
        main_width: layout.counts.width,
        num_public_values: layout.counts.num_public,
        permutation_width: layout.counts.aux_width,
        num_permutation_challenges: layout.counts.num_randomness,
        num_permutation_values: air.num_aux_values(),
        num_periodic_columns: layout.counts.num_periodic,
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

    let actual = eval_dag(&artifacts.dag.nodes, artifacts.dag.root, &inputs, &layout);
    assert_eq!(actual, expected);
}

#[test]
fn test_emitted_circuit_matches_dag_eval() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_vlpi_groups: 0,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);

    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();
    let dag_value = eval_dag(&artifacts.dag.nodes, artifacts.dag.root, &inputs, &layout);
    let circuit_value = circuit.eval(&inputs).expect("circuit eval");
    assert_eq!(circuit_value, dag_value);
}

#[test]
fn test_encoded_circuit_structure() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_vlpi_groups: 0,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();

    let encoded = circuit.to_ace().unwrap();
    assert!(encoded.size_in_felt().is_multiple_of(8));
    assert_eq!(encoded.num_inputs(), layout.total_inputs);
}

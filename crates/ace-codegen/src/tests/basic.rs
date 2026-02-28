use miden_core::{Felt, field::QuadFelt};
use p3_field::PrimeCharacteristicRing;
use p3_miden_air::{BusType, Matrix, MidenAir, MidenAirBuilder};

use super::common::{eval_dag, eval_expr, eval_periodic_values, eval_quotient};
use crate::{
    AceConfig, InputKey, InputLayout, LayoutKind, builder::RecordingAirBuilder,
    circuit::emit_circuit, pipeline::build_ace_dag_for_air,
};

// Base and extension field types for tests.
type F = Felt;
type EF = QuadFelt;

struct MockAir;

impl MidenAir<F, EF> for MockAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        1
    }

    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn periodic_table(&self) -> Vec<Vec<F>> {
        vec![vec![F::ONE]]
    }

    fn bus_types(&self) -> &[BusType] {
        static BUS_TYPES: [BusType; 1] = [BusType::Multiset];
        &BUS_TYPES
    }

    fn eval<AB: MidenAirBuilder<F = F>>(&self, builder: &mut AB) {
        let main = builder.main();
        let a = main.row_slice(0).unwrap()[0].clone();
        let b = main.row_slice(1).unwrap()[0].clone();
        let pub0 = builder.public_values()[0];
        let rand0 = builder.permutation_randomness()[0];
        let aux0 = builder.permutation().row_slice(0).unwrap()[0];
        let aux_b = builder.aux_bus_boundary_values()[0];
        let per0 = builder.periodic_evals()[0];

        builder.assert_zero(a.clone().into() + pub0.into());
        builder.assert_zero_ext(rand0.into() + aux0.into() + aux_b.into());
        builder.when_transition().assert_zero(b - a.clone());
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
    set(InputKey::AuxBusBoundary(0), ef(13));
    set(InputKey::Z, ef(2));
    set(InputKey::Alpha, ef(17));
    set(InputKey::GInv, ef(3));
    set(InputKey::ZPowN, ef(19));
    set(InputKey::GInv2, ef(5));
    set(InputKey::ZK, ef(23));
    set(InputKey::Weight0, ef(31));
    set(InputKey::G, ef(37));
    set(InputKey::S0, ef(41));
    set(InputKey::InvZMinusGInv, ef(43));
    set(InputKey::InvZMinusOne, ef(47));
    set(InputKey::InvVanishing, ef(2));

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
        num_aux_inputs: 14,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_values = eval_periodic_values(&air.periodic_table(), z_k);

    let mut builder = RecordingAirBuilder::<F, EF>::new(
        0,
        layout.counts.width,
        layout.counts.aux_width,
        layout.counts.num_randomness,
        layout.counts.num_public,
        layout.counts.num_periodic,
    );
    air.eval(&mut builder);
    let dag = artifacts.dag;

    let alpha = inputs[layout.index(InputKey::Alpha).unwrap()];
    let inv_vanishing = inputs[layout.index(InputKey::InvVanishing).unwrap()];

    let mut acc = EF::ZERO;
    for c in builder.constraints() {
        let val = eval_expr(c, &inputs, &layout, &periodic_values);
        acc = acc * alpha + val;
    }
    let folded = acc * inv_vanishing;
    let quotient = eval_quotient(&layout, &inputs);
    let expected = folded - quotient;

    let actual = eval_dag(&dag.nodes, dag.root, &inputs, &layout);
    assert_eq!(actual, expected);
}

#[test]
fn test_emitted_circuit_matches_dag_eval() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_aux_inputs: 14,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = build_inputs(&layout);

    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();
    let dag_value = eval_dag(&artifacts.dag.nodes, artifacts.dag.root, &inputs, &layout);
    let circuit_value = circuit.eval(&inputs);
    assert_eq!(circuit_value, dag_value);
}

#[test]
fn test_encoded_circuit_structure() {
    let air = MockAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_aux_inputs: 14,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();

    let encoded = circuit.to_ace().unwrap();
    assert!(encoded.size_in_felt().is_multiple_of(8));
    assert_eq!(encoded.num_inputs(), layout.total_inputs);
}

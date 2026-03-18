use miden_air::{LiftedAir, ProcessorAir};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::PrimeCharacteristicRing;

use super::common::{eval_dag, eval_expr, eval_periodic_values, eval_quotient, fill_inputs};
use crate::{
    AceConfig, InputKey, LayoutKind, builder::RecordingAirBuilder, pipeline::build_ace_dag_for_air,
};

#[test]
fn processor_air_dag_matches_manual_eval() {
    let air = ProcessorAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_vlpi_groups: 0,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = fill_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_values =
        eval_periodic_values(&LiftedAir::<Felt, QuadFelt>::periodic_columns(&air), z_k);

    let mut builder = RecordingAirBuilder::<Felt, QuadFelt>::new(
        0,
        layout.counts.width,
        layout.counts.aux_width,
        layout.counts.num_randomness,
        layout.counts.num_public,
        layout.counts.num_periodic,
        LiftedAir::<Felt, QuadFelt>::num_aux_values(&air),
    );
    LiftedAir::<Felt, QuadFelt>::eval(&air, &mut builder);

    let alpha = inputs[layout.index(InputKey::Alpha).unwrap()];
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];

    let mut acc = QuadFelt::ZERO;
    for c in builder.constraints() {
        let val = eval_expr::<Felt, QuadFelt>(c, &inputs, &layout, &periodic_values);
        acc = acc * alpha + val;
    }
    let vanishing = z_pow_n - QuadFelt::ONE;
    let quotient = eval_quotient(&layout, &inputs);
    let expected = acc - quotient * vanishing;

    let actual = eval_dag(&artifacts.dag.nodes, artifacts.dag.root, &inputs, &layout);
    assert_eq!(actual, expected);
}

#[test]
#[allow(clippy::print_stdout)]
fn processor_air_chiplet_rows() {
    let air = ProcessorAir;
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 1,
        layout: LayoutKind::Masm,
    };

    let circuit =
        crate::pipeline::build_ace_circuit_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
    let encoded = circuit.to_ace().unwrap();
    let read_rows = encoded.num_read_rows();
    let eval_rows = encoded.num_eval_rows();
    let total_rows = read_rows + eval_rows;

    println!(
        "ACE chiplet rows (ProcessorAir): read={}, eval={}, total={}, inputs={}, constants={}, nodes={}",
        read_rows,
        eval_rows,
        total_rows,
        encoded.num_inputs(),
        encoded.num_constants(),
        encoded.num_nodes()
    );
}

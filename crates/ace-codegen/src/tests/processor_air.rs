use miden_air::{MidenAir, ProcessorAir};
use miden_core::{Felt, field::QuadFelt};
use p3_field::PrimeCharacteristicRing;

use super::common::{eval_dag, eval_expr, eval_periodic_values, eval_quotient, fill_inputs};
use crate::{
    AceConfig, InputKey, LayoutKind, build_ace_circuit_for_air, builder::RecordingAirBuilder,
    pipeline::build_ace_dag_for_air,
};

#[test]
fn processor_air_dag_matches_manual_eval() {
    let air = ProcessorAir::default();
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_aux_inputs: 14,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = fill_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_values = eval_periodic_values(
        &<ProcessorAir as MidenAir<Felt, QuadFelt>>::periodic_table(&air),
        z_k,
    );

    let mut builder = RecordingAirBuilder::<Felt, QuadFelt>::new(
        0,
        layout.counts.width,
        layout.counts.aux_width,
        layout.counts.num_randomness,
        layout.counts.num_public,
        layout.counts.num_periodic,
    );
    MidenAir::<Felt, QuadFelt>::eval(&air, &mut builder);

    let alpha = inputs[layout.index(InputKey::Alpha).unwrap()];
    let inv_vanishing = inputs[layout.index(InputKey::InvVanishing).unwrap()];

    let mut acc = QuadFelt::ZERO;
    for c in builder.constraints() {
        let val = eval_expr(c, &inputs, &layout, &periodic_values);
        acc = acc * alpha + val;
    }
    let folded = acc * inv_vanishing;
    let quotient = eval_quotient(&layout, &inputs);
    let expected = folded - quotient;

    let actual = eval_dag(&artifacts.dag.nodes, artifacts.dag.root, &inputs, &layout);
    assert_eq!(actual, expected);
}

#[test]
#[allow(clippy::print_stdout)]
fn processor_air_chiplet_rows() {
    let air = ProcessorAir::default();
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_aux_inputs: 14,
        layout: LayoutKind::Masm,
    };

    let circuit = build_ace_circuit_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
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

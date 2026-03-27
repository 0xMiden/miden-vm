use miden_air::{LiftedAir, ProcessorAir};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::PrimeCharacteristicRing,
    stark::air::symbolic::{AirLayout, SymbolicAirBuilder},
};

use super::common::{
    eval_dag, eval_folded_constraints, eval_periodic_values, eval_quotient, fill_inputs,
};
use crate::{AceConfig, InputKey, LayoutKind, pipeline::build_ace_dag_for_air};

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

    let air_layout = AirLayout {
        preprocessed_width: 0,
        main_width: layout.counts.width,
        num_public_values: layout.counts.num_public,
        permutation_width: layout.counts.aux_width,
        num_permutation_challenges: layout.counts.num_randomness,
        num_permutation_values: LiftedAir::<Felt, QuadFelt>::num_aux_values(&air),
        num_periodic_columns: layout.counts.num_periodic,
    };
    let mut builder = SymbolicAirBuilder::<Felt, QuadFelt>::new(air_layout);
    LiftedAir::<Felt, QuadFelt>::eval(&air, &mut builder);

    let acc = eval_folded_constraints(
        &builder.base_constraints(),
        &builder.extension_constraints(),
        &builder.constraint_layout(),
        &inputs,
        &layout,
        &periodic_values,
    );
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - QuadFelt::ONE;
    let expected = acc - eval_quotient(&layout, &inputs) * vanishing;

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

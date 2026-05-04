use miden_ace_codegen::{
    AceConfig, AceError, EXT_DEGREE, InputKey, LayoutKind, build_ace_circuit_for_air,
    build_ace_dag_for_air, emit_circuit,
    testing::{
        eval_dag, eval_folded_constraints, eval_periodic_values, eval_quotient, fill_inputs,
        zps_for_chunk,
    },
};
use miden_air::{LiftedAir, ProcessorAir};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::{Field, PrimeCharacteristicRing},
    stark::air::symbolic::{AirLayout, SymbolicAirBuilder},
};

#[test]
fn processor_air_dag_matches_manual_eval() {
    let air = ProcessorAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_vlpi_groups: 0,
        layout: LayoutKind::Native,
        is_multi_air: false,
    };
    let artifacts = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs: Vec<QuadFelt> = fill_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_values = eval_periodic_values::<Felt, QuadFelt>(
        &LiftedAir::<Felt, QuadFelt>::periodic_columns(&air),
        z_k,
    );

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
    let expected = acc - eval_quotient::<Felt, QuadFelt>(&layout, &inputs) * vanishing;

    let actual = eval_dag(&artifacts.dag, &inputs, &layout).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn processor_air_dag_rejects_mismatched_layout() {
    let air = ProcessorAir;
    let dag_config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 0,
        layout: LayoutKind::Native,
        is_multi_air: false,
    };
    let layout_config = AceConfig {
        num_quotient_chunks: 1,
        num_vlpi_groups: 0,
        layout: LayoutKind::Native,
        is_multi_air: false,
    };

    let dag = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, dag_config).unwrap().dag;
    let wrong_layout =
        build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, layout_config).unwrap().layout;
    let inputs: Vec<QuadFelt> = fill_inputs(&wrong_layout);

    let err = eval_dag(&dag, &inputs, &wrong_layout).unwrap_err();
    assert!(
        matches!(err, AceError::InvalidInputLayout { .. }),
        "expected InvalidInputLayout, got {err:?}"
    );
}

#[test]
#[allow(clippy::print_stdout)]
fn processor_air_chiplet_rows() {
    let air = ProcessorAir;
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 1,
        layout: LayoutKind::Masm,
        is_multi_air: false,
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

#[test]
fn synthetic_ood_adjusts_quotient_to_zero() {
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 0,
        layout: LayoutKind::Masm,
        is_multi_air: false,
    };

    let artifacts =
        build_ace_dag_for_air::<_, Felt, QuadFelt>(&ProcessorAir, config).expect("ace dag");
    let circuit = emit_circuit(&artifacts.dag, artifacts.layout.clone()).expect("ace circuit");

    let mut inputs: Vec<QuadFelt> = fill_inputs(&artifacts.layout);
    let root = circuit.eval(&inputs).expect("circuit eval");

    let z_pow_n = inputs[artifacts.layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - QuadFelt::ONE;
    let zps_0 = zps_for_chunk::<Felt, QuadFelt>(&artifacts.layout, &inputs, 0);
    let delta = root * (zps_0 * vanishing).inverse();

    let idx = artifacts
        .layout
        .index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
        .unwrap();
    inputs[idx] += delta;

    let result = circuit.eval(&inputs).expect("circuit eval");
    assert!(result.is_zero(), "ACE circuit must evaluate to zero");
}

#[test]
fn quotient_next_inputs_do_not_affect_eval() {
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 0,
        layout: LayoutKind::Masm,
        is_multi_air: false,
    };

    let artifacts =
        build_ace_dag_for_air::<_, Felt, QuadFelt>(&ProcessorAir, config).expect("ace dag");
    let circuit = emit_circuit(&artifacts.dag, artifacts.layout.clone()).expect("ace circuit");

    let mut inputs: Vec<QuadFelt> = fill_inputs(&artifacts.layout);

    let root = circuit.eval(&inputs).expect("circuit eval");
    let z_pow_n = inputs[artifacts.layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - QuadFelt::ONE;
    let zps_0 = zps_for_chunk::<Felt, QuadFelt>(&artifacts.layout, &inputs, 0);
    let delta = root * (zps_0 * vanishing).inverse();
    let idx = artifacts
        .layout
        .index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
        .unwrap();
    inputs[idx] += delta;
    assert!(
        circuit.eval(&inputs).expect("circuit eval").is_zero(),
        "precondition: zero root"
    );

    for chunk in 0..artifacts.layout.counts.num_quotient_chunks {
        for coord in 0..EXT_DEGREE {
            let idx = artifacts
                .layout
                .index(InputKey::QuotientChunkCoord { offset: 1, chunk, coord })
                .unwrap();
            inputs[idx] += QuadFelt::from(Felt::new_unchecked(123 + (chunk * 7 + coord) as u64));
        }
    }

    let result = circuit.eval(&inputs).expect("circuit eval");
    assert!(result.is_zero(), "quotient_next should not affect ACE eval");
}

#[test]
fn multi_air_ace_circuit_builds_and_has_multi_air_beta_slot() {
    use miden_air::ace::build_multi_air_ace_circuit;

    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 1,
        layout: LayoutKind::Masm,
        is_multi_air: true,
    };

    let circuit = build_multi_air_ace_circuit::<QuadFelt>(config).expect("multi-AIR ACE circuit");
    let layout = circuit.layout();

    // Combined main width = NUM_CORE_COLS (51) + CHIPLETS_WIDTH (22) = 73, matching the
    // unified ProcessorAir trace width. The combined aux width is 4 + 3 = 7.
    assert_eq!(
        layout.counts.width,
        73,
        "combined main width must equal CoreAir.width() + ChipletsAir.width()"
    );
    assert_eq!(layout.counts.aux_width, 7, "combined aux_width = 4 + 3");
    assert_eq!(layout.counts.num_aux_boundary, 2, "one boundary slot per AIR");

    // The combined layout reserves the new MultiAirBeta slot in stark_vars.
    let beta_idx = layout
        .index(InputKey::MultiAirBeta)
        .expect("multi-air layout exposes MultiAirBeta");
    assert!(beta_idx < layout.total_inputs, "MultiAirBeta slot must be within layout bounds");
}

#[test]
fn multi_air_ace_circuit_emits_consistently() {
    use miden_air::ace::build_multi_air_ace_circuit;

    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 1,
        layout: LayoutKind::Masm,
        is_multi_air: true,
    };

    // Just check the ACE encoding is well-formed (size_in_felt is rate-aligned).
    let circuit = build_multi_air_ace_circuit::<QuadFelt>(config).expect("multi-AIR ACE circuit");
    let encoded = circuit.to_ace().expect("encoded multi-AIR circuit");
    assert!(
        encoded.size_in_felt().is_multiple_of(8),
        "encoded multi-AIR circuit must be 8-felt aligned for adv_pipe"
    );
}

#[test]
fn multi_air_ace_circuit_evaluates_without_panic() {
    use miden_air::ace::build_multi_air_ace_circuit;

    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 1,
        layout: LayoutKind::Masm,
        is_multi_air: true,
    };

    let circuit = build_multi_air_ace_circuit::<QuadFelt>(config).expect("multi-AIR ACE circuit");
    let layout = circuit.layout();

    // Fill all input slots with deterministic non-zero values. We don't expect the
    // circuit to evaluate to zero for arbitrary inputs — only that every slot
    // referenced by the DAG is in-range (i.e., no `wiring bus` panic), which is the
    // failure mode that surfaces if the chiplets-side index rewrite was wrong.
    let inputs: Vec<QuadFelt> = fill_inputs(layout);
    let _root = circuit.eval(&inputs).expect("multi-AIR circuit eval must not panic");
}

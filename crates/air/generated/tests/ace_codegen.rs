use miden_ace::{
    AceError, EXT_DEGREE, InputKey,
    compiler::{
        AceConfig, LayoutKind, build_ace_dag_for_air, emit_circuit,
        testing::{
            eval_dag, eval_native_constraints, eval_periodic_values, eval_quotient, fill_inputs,
            zps_for_chunk,
        },
    },
};
use miden_air_definitions::vm::{AIRS, MIDEN_AIR_COUNT, MidenAir};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{Field, PrimeCharacteristicRing};
use miden_stark::air::LiftedAir;

/// The DAG's evaluation on arbitrary inputs must equal an independently
/// computed reference: folded constraints minus recomposed quotient times
/// vanishing. This anchors the lowered DAG to the constraint semantics rather
/// than to any particular lowering implementation.
fn assert_dag_matches_manual_eval(air: MidenAir) {
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs: Vec<QuadFelt> = fill_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let spec = air.spec();
    let periodic_columns = &spec.periodic_columns;
    let periodic_values = eval_periodic_values::<Felt, QuadFelt>(periodic_columns, z_k);

    let acc = eval_native_constraints(&air, &spec, &inputs, &layout, &periodic_values);
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - QuadFelt::ONE;
    let expected = acc - eval_quotient::<Felt, QuadFelt>(&layout, &inputs) * vanishing;

    let actual = eval_dag(&artifacts.dag, &inputs, &layout).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn all_airs_dag_matches_manual_eval() {
    for air in AIRS {
        assert_dag_matches_manual_eval(air);
    }
}

#[test]
fn core_air_dag_rejects_mismatched_layout() {
    let air = MidenAir::Core;
    let dag_config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Native,
    };
    let layout_config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
    };

    let dag = build_ace_dag_for_air(&air, dag_config).unwrap().dag;
    let wrong_layout = build_ace_dag_for_air(&air, layout_config).unwrap().layout;
    let inputs: Vec<QuadFelt> = fill_inputs(&wrong_layout);

    let err = eval_dag(&dag, &inputs, &wrong_layout).unwrap_err();
    assert!(
        matches!(err, AceError::InvalidInputLayout { .. }),
        "expected InvalidInputLayout, got {err:?}"
    );
}

#[test]
fn quotient_next_inputs_do_not_affect_eval() {
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
    };

    let artifacts = build_ace_dag_for_air(&MidenAir::Core, config).expect("ace dag");
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
fn multi_air_ace_circuit_has_aligned_trace_regions_and_per_air_slots() {
    use miden_air_definitions::compiler::vm::build_canonical_multi_air_ace_circuit;

    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
    };

    let circuit = build_canonical_multi_air_ace_circuit(config).expect("multi-AIR ACE circuit");
    let layout = circuit.layout();

    const LMCS_ALIGNMENT: usize = 8;
    let expected_preprocessed_width = AIRS
        .iter()
        .map(|air| air.spec().preprocessed_width().next_multiple_of(LMCS_ALIGNMENT))
        .sum::<usize>();
    let expected_main_width = AIRS
        .iter()
        .map(|air| air.spec().main_width.next_multiple_of(LMCS_ALIGNMENT))
        .sum::<usize>();
    // Aux-trace widths concatenate each per-AIR coordinate region after LMCS
    // alignment, then convert back to extension-field columns.
    let expected_aux_width = AIRS
        .iter()
        .map(|air| {
            (air.spec().aux_width * EXT_DEGREE).next_multiple_of(LMCS_ALIGNMENT) / EXT_DEGREE
        })
        .sum::<usize>();
    let expected_aux_boundary = AIRS.iter().map(|air| air.spec().num_exports).sum::<usize>();

    assert_eq!(layout.counts.preprocessed_width, expected_preprocessed_width);
    assert_eq!(
        layout.counts.width, expected_main_width,
        "combined main width must be sum of per-AIR LMCS-aligned widths"
    );
    assert_eq!(
        layout.counts.aux_width, expected_aux_width,
        "combined aux width must be sum of per-AIR LMCS-aligned widths"
    );
    assert_eq!(layout.counts.num_aux_boundary, expected_aux_boundary);

    for air_index in 0..MIDEN_AIR_COUNT {
        for key in [
            InputKey::MultiAirFoldCoeff(air_index),
            InputKey::IsFirstAir(air_index),
            InputKey::IsLastAir(air_index),
            InputKey::IsTransitionAir(air_index),
        ] {
            let idx =
                layout.index(key).unwrap_or_else(|| panic!("multi-air layout exposes {key:?}"));
            assert!(idx < layout.total_inputs, "{key:?} slot must be within layout bounds");
        }
    }
    assert!(layout.index(InputKey::IsFirstAir(MIDEN_AIR_COUNT)).is_none());
}

/// The recursive verifier's canonical entry point must be a thin wrapper over the canonical
/// builder: same encoding, same commitment, and no dependence on the proof order.
///
/// The order-invariance itself is established by the cross-order fold sweep below. This test binds
/// the production entry point to the exact circuit used by that sweep.
#[test]
fn recursive_verifier_circuit_matches_the_canonical_builder() {
    use miden_air_definitions::compiler::vm::{
        build_canonical_multi_air_ace_circuit, build_recursive_verifier_ace_circuit,
    };
    use miden_core::crypto::hash::Eidos;

    let produced = build_recursive_verifier_ace_circuit().expect("recursive ACE circuit");

    let canonical = build_canonical_multi_air_ace_circuit(AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
    })
    .expect("canonical circuit");
    let encoded = canonical.to_ace().expect("encode canonical circuit");

    assert_eq!(produced.num_inputs, encoded.num_vars());
    assert_eq!(produced.num_eval_gates, encoded.num_eval_rows());
    assert_eq!(produced.stream_len, encoded.size_in_felt());
    assert_eq!(produced.instructions, encoded.instructions());
    assert_eq!(produced.commitment, Eidos::hash_elements(encoded.instructions()));

    // The stream is loaded with `adv_pipe`, which consumes eight felts per iteration.
    assert!(produced.stream_len.is_multiple_of(8));

    // Calling it twice must be deterministic.
    let produced_again = build_recursive_verifier_ace_circuit().expect("recursive ACE circuit");
    assert_eq!(produced, produced_again);
}

/// Checks the canonical circuit against a direct AIR fold for every VM proof order.
#[test]
fn canonical_circuit_matches_every_vm_proof_order() {
    use miden_air_definitions::compiler::vm::build_canonical_multi_air_ace_circuit;

    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
    };
    let canonical = build_canonical_multi_air_ace_circuit(config).expect("canonical circuit");
    let canonical_layout = canonical.layout();

    // Nonzero quotient openings exercise the shared quotient binding.
    let base: Vec<QuadFelt> = fill_inputs(canonical_layout);

    let beta = QuadFelt::from_u64(97);
    let mut canonical_roots: Vec<QuadFelt> = Vec::new();
    for tag in 0..miden_ace::factorial(MIDEN_AIR_COUNT) as u32 {
        let order = miden_ace::order_from_tag(tag, MIDEN_AIR_COUNT).expect("VM permutation tag");
        // Canonical circuit: trace values stay put, only the fold coefficients move. The AIR at
        // proof position `k` carries `beta^(N - 1 - k)`, matching the proof-order Horner fold.
        let mut canonical_inputs = base.clone();
        for (position, air) in order.iter().copied().enumerate() {
            let idx = canonical_layout.index(InputKey::MultiAirFoldCoeff(air)).expect("coeff slot");
            canonical_inputs[idx] = beta.exp_u64((MIDEN_AIR_COUNT - 1 - position) as u64);
        }
        let canonical_root = canonical.eval(&canonical_inputs).expect("canonical eval");

        let direct = miden_ace::compiler::testing::eval_multi_air_constraints(
            &AIRS,
            canonical_layout,
            &canonical_inputs,
            &order,
            beta,
            8,
        );
        assert_eq!(canonical_root, direct, "direct symbolic evaluation for order {order:?}");
        canonical_roots.push(canonical_root);
    }

    // Distinct roots ensure this fixture distinguishes every proof order.
    for (i, left) in canonical_roots.iter().enumerate() {
        for (j, right) in canonical_roots.iter().enumerate().skip(i + 1) {
            assert_ne!(left, right, "orders {i} and {j} fold identically");
        }
    }
}

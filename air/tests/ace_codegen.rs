use miden_ace_codegen::{
    AceConfig, AceDag, AceError, EXT_DEGREE, InputKey, InputLayout, LayoutKind, NodeKind,
    PeriodicColumnData, build_ace_dag_for_air, build_verifier_dag, emit_circuit,
    testing::{
        eval_dag, eval_folded_constraints, eval_periodic_values, eval_quotient, fill_inputs,
        zps_for_chunk,
    },
};
use miden_air::{AIRS, BaseAir, HandwrittenMidenAir, LiftedAir, MIDEN_AIR_COUNT, MidenAir};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::{Field, PrimeCharacteristicRing},
    stark::air::symbolic::{AirLayout, SymbolicAirBuilder},
};

fn air_layout_for(air: MidenAir, layout: &InputLayout) -> AirLayout {
    AirLayout {
        preprocessed_width: BaseAir::<Felt>::preprocessed_width(&air),
        main_width: layout.counts.width,
        num_public_values: layout.counts.num_public,
        permutation_width: layout.counts.aux_width,
        num_permutation_challenges: layout.counts.num_randomness,
        num_permutation_values: LiftedAir::<Felt, QuadFelt>::num_aux_values(&air),
        num_periodic_columns: air.periodic_columns().len(),
    }
}

/// The DAG's evaluation on arbitrary inputs must equal an independently
/// computed reference: folded constraints minus recomposed quotient times
/// vanishing. This anchors the lowered DAG to the constraint semantics rather
/// than to any particular lowering implementation.
fn assert_dag_matches_manual_eval(air: MidenAir) {
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air(&HandwrittenMidenAir(air), config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs: Vec<QuadFelt> = fill_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_columns = air.periodic_columns();
    let periodic_values = eval_periodic_values::<Felt, QuadFelt>(&periodic_columns, z_k);

    let mut builder = SymbolicAirBuilder::<Felt, QuadFelt>::new(air_layout_for(air, &layout));
    air.eval_handwritten(&mut builder);

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
fn synthetic_ood_adjusts_quotient_to_zero() {
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

    let result = circuit.eval(&inputs).expect("circuit eval");
    assert!(result.is_zero(), "ACE circuit must evaluate to zero");
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
    use miden_air::ace::build_canonical_multi_air_ace_circuit;

    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
    };

    let circuit = build_canonical_multi_air_ace_circuit(config).expect("multi-AIR ACE circuit");
    let layout = circuit.layout();

    const LMCS_ALIGNMENT: usize = 8;
    let expected_preprocessed_width = AIRS
        .iter()
        .map(|air| BaseAir::<Felt>::preprocessed_width(air).next_multiple_of(LMCS_ALIGNMENT))
        .sum::<usize>();
    let expected_main_width = AIRS
        .iter()
        .map(|air| BaseAir::<Felt>::width(air).next_multiple_of(LMCS_ALIGNMENT))
        .sum::<usize>();
    // Aux-trace widths concatenate each per-AIR coordinate region after LMCS
    // alignment, then convert back to extension-field columns.
    let expected_aux_width = AIRS
        .iter()
        .map(|air| {
            (LiftedAir::<Felt, QuadFelt>::aux_width(air) * EXT_DEGREE)
                .next_multiple_of(LMCS_ALIGNMENT)
                / EXT_DEGREE
        })
        .sum::<usize>();
    let expected_aux_boundary =
        AIRS.iter().map(LiftedAir::<Felt, QuadFelt>::num_aux_values).sum::<usize>();

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

/// A DAG node relabeled by index: `NodeId` embeds a per-builder dag id, so
/// nodes from two builders can only be compared through their indices.
#[derive(Debug, PartialEq)]
enum Norm {
    Input(InputKey),
    Constant(QuadFelt),
    Add(usize, usize),
    Sub(usize, usize),
    Mul(usize, usize),
    Neg(usize),
}

fn normalized(dag: &AceDag<QuadFelt>) -> (Vec<Norm>, usize) {
    let nodes = dag
        .nodes
        .iter()
        .map(|node| match *node {
            NodeKind::Input(key) => Norm::Input(key),
            NodeKind::Constant(value) => Norm::Constant(value),
            NodeKind::Add(a, b) => Norm::Add(a.index(), b.index()),
            NodeKind::Sub(a, b) => Norm::Sub(a.index(), b.index()),
            NodeKind::Mul(a, b) => Norm::Mul(a.index(), b.index()),
            NodeKind::Neg(a) => Norm::Neg(a.index()),
        })
        .collect();
    (nodes, dag.root().index())
}

/// Node-for-node differential: the IR-driven lowering must replicate the
/// symbolic-tree lowering's `DagBuilder` interning order exactly (the order is
/// digest-visible). Compares the complete single-AIR verifier DAGs — periodic
/// evaluation, constraint bodies, alpha fold, quotient wrapping — and localizes
/// the first mismatching node.
#[test]
fn ir_lowering_matches_symbolic_lowering_node_for_node() {
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
    };
    for air in AIRS {
        // Production path: handwritten capture -> IR -> DAG.
        let artifacts = build_ace_dag_for_air(&HandwrittenMidenAir(air), config).unwrap();

        // Anchor: the original symbolic-tree lowering over the same constraints.
        let mut builder =
            SymbolicAirBuilder::<Felt, QuadFelt>::new(air_layout_for(air, &artifacts.layout));
        air.eval_handwritten(&mut builder);
        let periodic_columns = BaseAir::<Felt>::periodic_columns(&air);
        let periodic_data = (!periodic_columns.is_empty())
            .then(|| PeriodicColumnData::from_periodic_columns::<Felt>(periodic_columns.to_vec()));
        let tree_dag = build_verifier_dag(
            &builder.base_constraints(),
            &builder.extension_constraints(),
            &builder.constraint_layout(),
            &artifacts.layout,
            periodic_data.as_ref(),
            periodic_columns.iter().map(Vec::len).max().unwrap_or(1),
        );

        let (tree_nodes, tree_root) = normalized(&tree_dag);
        let (ir_nodes, ir_root) = normalized(&artifacts.dag);
        for (i, (tree, ir)) in tree_nodes.iter().zip(&ir_nodes).enumerate() {
            assert_eq!(tree, ir, "first mismatch at node {i}");
        }
        assert_eq!(tree_nodes.len(), ir_nodes.len(), "node counts differ");
        assert_eq!(tree_root, ir_root, "roots differ");
    }
}

/// The recursive verifier's canonical entry point must be a thin wrapper over the canonical
/// builder: same encoding, same commitment, and no dependence on the proof order.
///
/// The order-invariance itself is established by the cross-order fold sweep below. This test binds
/// the production entry point to the exact circuit used by that sweep.
#[test]
fn recursive_verifier_circuit_matches_the_canonical_builder() {
    use miden_air::ace::{
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

    // The cached circuit is what the advice builder serves, and it is reachable across crates.
    #[cfg(feature = "std")]
    assert_eq!(*miden_air::ace::shared_recursive_circuit(), produced);
}

/// Checks the canonical circuit against a direct AIR fold for every VM proof order.
#[test]
fn canonical_circuit_matches_every_vm_proof_order() {
    use miden_air::{
        AIRS, MIDEN_AIR_COUNT, ProofOrder, ace::build_canonical_multi_air_ace_circuit,
    };

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
    for order in ProofOrder::variants() {
        // Canonical circuit: trace values stay put, only the fold coefficients move. The AIR at
        // proof position `k` carries `beta^(N - 1 - k)`, matching the proof-order Horner fold.
        let mut canonical_inputs = base.clone();
        for (position, air) in order.airs().iter().copied().enumerate() {
            let idx = canonical_layout
                .index(InputKey::MultiAirFoldCoeff(air.instance_index()))
                .expect("coeff slot");
            canonical_inputs[idx] = beta.exp_u64((MIDEN_AIR_COUNT - 1 - position) as u64);
        }
        let canonical_root = canonical.eval(&canonical_inputs).expect("canonical eval");

        let direct = miden_ace_codegen::testing::eval_multi_air_constraints(
            &AIRS.map(HandwrittenMidenAir),
            canonical_layout,
            &canonical_inputs,
            &order.airs().iter().map(|air| air.instance_index()).collect::<Vec<_>>(),
            beta,
            8,
        );
        assert_eq!(canonical_root, direct, "direct symbolic evaluation for {}", order.file_stem());
        canonical_roots.push(canonical_root);
    }

    // Distinct roots ensure this fixture distinguishes every proof order.
    for (i, left) in canonical_roots.iter().enumerate() {
        for (j, right) in canonical_roots.iter().enumerate().skip(i + 1) {
            assert_ne!(left, right, "orders {i} and {j} fold identically");
        }
    }
}

use miden_ace_codegen::{
    AceConfig, AceDag, AceError, EXT_DEGREE, InputKey, LayoutKind, NodeKind, PeriodicColumnData,
    build_ace_dag_for_air, build_verifier_dag_from_ir, emit_circuit,
    testing::{
        eval_dag, eval_folded_constraints, eval_periodic_values, eval_quotient, fill_inputs,
        zps_for_chunk,
    },
};
use miden_air::{AIRS, BaseAir, LiftedAir, MIDEN_AIR_COUNT, MidenAir};
use miden_constraint_compiler::ir::capture;
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::{Field, PrimeCharacteristicRing},
    stark::air::symbolic::{AirLayout, SymbolicAirBuilder},
};

/// The DAG's evaluation on arbitrary inputs must equal an independently
/// computed reference: folded constraints minus recomposed quotient times
/// vanishing. This anchors the lowered DAG to the constraint semantics rather
/// than to any particular lowering implementation.
fn assert_dag_matches_manual_eval(air: MidenAir) {
    let config = AceConfig {
        num_quotient_chunks: 2,
        layout: LayoutKind::Native,
        num_airs: 1,
    };
    let artifacts = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs: Vec<QuadFelt> = fill_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_columns = air.periodic_columns();
    let periodic_values = eval_periodic_values::<Felt, QuadFelt>(&periodic_columns, z_k);

    let air_layout = AirLayout {
        preprocessed_width: 0,
        main_width: layout.counts.width,
        num_public_values: layout.counts.num_public,
        permutation_width: layout.counts.aux_width,
        num_permutation_challenges: layout.counts.num_randomness,
        num_permutation_values: LiftedAir::<Felt, QuadFelt>::num_aux_values(&air),
        num_periodic_columns: periodic_columns.len(),
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
        num_airs: 1,
    };
    let layout_config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
        num_airs: 1,
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
fn synthetic_ood_adjusts_quotient_to_zero() {
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: 1,
    };

    let artifacts =
        build_ace_dag_for_air::<_, Felt, QuadFelt>(&MidenAir::Core, config).expect("ace dag");
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
        num_airs: 1,
    };

    let artifacts =
        build_ace_dag_for_air::<_, Felt, QuadFelt>(&MidenAir::Core, config).expect("ace dag");
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
fn multi_air_ace_circuit_builds_and_has_multi_air_fold_beta_slots() {
    use miden_air::{ProofOrder, ace::build_multi_air_ace_circuit_for_order};

    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    };

    let circuit =
        build_multi_air_ace_circuit_for_order::<QuadFelt>(config, &ProofOrder::instance_order())
            .expect("multi-AIR ACE circuit");
    let layout = circuit.layout();

    // Combined main width is each per-AIR width aligned to the LMCS rate:
    // aligned(51) + aligned(22) + aligned(16) = 56 + 24 + 16 = 96.
    assert_eq!(
        layout.counts.width, 96,
        "combined main width must be sum of per-AIR LMCS-aligned widths"
    );
    assert_eq!(
        layout.counts.aux_width, 12,
        "combined aux_width = aligned(4) + aligned(3) + aligned(1) = 12 EFs"
    );
    assert_eq!(layout.counts.num_aux_boundary, 3, "one boundary slot per AIR");

    let beta = layout
        .index(InputKey::MultiAirFoldBeta)
        .expect("multi-air layout exposes folding beta");
    assert!(beta < layout.total_inputs, "beta slot must be within layout bounds");

    for key in [
        InputKey::IsFirstAir(0),
        InputKey::IsLastAir(0),
        InputKey::IsTransitionAir(0),
        InputKey::IsFirstAir(1),
        InputKey::IsLastAir(1),
        InputKey::IsTransitionAir(1),
        InputKey::IsFirstAir(2),
        InputKey::IsLastAir(2),
        InputKey::IsTransitionAir(2),
    ] {
        let idx = layout.index(key).unwrap_or_else(|| panic!("multi-air layout exposes {key:?}"));
        assert!(idx < layout.total_inputs, "{key:?} slot must be within layout bounds");
    }
    assert!(layout.index(InputKey::IsFirstAir(3)).is_none());
}

#[test]
fn multi_air_ace_circuit_emits_consistently() {
    use miden_air::{ProofOrder, ace::build_multi_air_ace_circuit_for_order};

    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    };

    for order in ProofOrder::variants() {
        // Check that the ACE encoding is well-formed and rate-aligned.
        let circuit =
            build_multi_air_ace_circuit_for_order::<QuadFelt>(config, &order).expect("ACE circuit");
        let encoded = circuit.to_ace().expect("encoded multi-AIR circuit");
        assert!(
            encoded.size_in_felt().is_multiple_of(8),
            "encoded multi-AIR circuit must be 8-felt aligned for adv_pipe"
        );
    }
}

#[test]
fn multi_air_ace_circuit_evaluates_without_panic() {
    use miden_air::{ProofOrder, ace::build_multi_air_ace_circuit_for_order};

    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    };

    for order in ProofOrder::variants() {
        let circuit = build_multi_air_ace_circuit_for_order::<QuadFelt>(config, &order)
            .expect("multi-AIR ACE circuit");
        let layout = circuit.layout();

        // Fill all input slots with deterministic non-zero values. We don't expect the
        // circuit to evaluate to zero for arbitrary inputs; this only checks that every
        // DAG input reference is in range.
        let inputs: Vec<QuadFelt> = fill_inputs(layout);
        let _root = circuit.eval(&inputs).expect("multi-AIR circuit eval must not panic");
    }
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
        num_airs: 1,
    };
    for air in AIRS {
        let artifacts = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();

        let (graph, constraints) = capture(&air);
        let periodic_columns = BaseAir::<Felt>::periodic_columns(&air);
        let periodic_data = (!periodic_columns.is_empty())
            .then(|| PeriodicColumnData::from_periodic_columns::<Felt>(periodic_columns.to_vec()));
        let ir_dag = build_verifier_dag_from_ir(
            &graph,
            &constraints,
            &artifacts.layout,
            periodic_data.as_ref(),
        );

        let (tree_nodes, tree_root) = normalized(&artifacts.dag);
        let (ir_nodes, ir_root) = normalized(&ir_dag);
        for (i, (tree, ir)) in tree_nodes.iter().zip(&ir_nodes).enumerate() {
            assert_eq!(tree, ir, "first mismatch at node {i}");
        }
        assert_eq!(tree_nodes.len(), ir_nodes.len(), "node counts differ");
        assert_eq!(tree_root, ir_root, "roots differ");
    }
}

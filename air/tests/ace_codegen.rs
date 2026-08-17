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
        preprocessed_width: 0,
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
        num_airs: 1,
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
        num_airs: 1,
    };
    let layout_config = AceConfig {
        num_quotient_chunks: 1,
        layout: LayoutKind::Native,
        num_airs: 1,
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
        num_airs: 1,
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
        num_airs: 1,
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
fn multi_air_ace_circuit_builds_and_has_multi_air_fold_beta_slots() {
    use miden_air::{ProofOrder, ace::build_multi_air_ace_circuit_for_order};

    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    };

    let circuit = build_multi_air_ace_circuit_for_order(config, &ProofOrder::instance_order())
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
        let circuit = build_multi_air_ace_circuit_for_order(config, &order).expect("ACE circuit");
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
        let circuit =
            build_multi_air_ace_circuit_for_order(config, &order).expect("multi-AIR ACE circuit");
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

#[test]
fn recursive_ace_factory_and_factoring_match_the_one_shot_builder() {
    use miden_air::{
        ProofOrder,
        ace::{RecursiveAceCircuitFactory, build_recursive_verifier_ace_circuit},
    };
    use miden_core::crypto::hash::Poseidon2;

    // The loader's two `repeat` counts are generated from this split, so pin it to the real
    // constants+shuffle boundary instead of trusting the value the struct reports.
    let factored = miden_air::ace::build_factored_multi_air_ace_circuit(AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    })
    .expect("factored circuit");
    let expected_prefix_len = factored
        .circuit_for_order(&ProofOrder::instance_order())
        .expect("canonical circuit")
        .to_ace()
        .expect("encoded circuit")
        .num_constants()
        * EXT_DEGREE
        + factored.num_shuffle_ops();

    let factory = RecursiveAceCircuitFactory::new().expect("factory");
    let mut reference: Option<(usize, Vec<_>)> = None;
    for order in ProofOrder::variants() {
        let circuit = build_recursive_verifier_ace_circuit(&order).expect("recursive ACE circuit");
        let resumed = factory.circuit_for_order(&order).expect("factory circuit");
        assert_eq!(resumed, circuit, "factory diverges for {}", order.file_stem());

        // Both segments must be proper adv_pipe-aligned stream slices.
        assert_eq!(
            circuit.shuffle_prefix_len, expected_prefix_len,
            "stream prefix must end exactly at the shuffle/common boundary"
        );
        assert!(circuit.shuffle_prefix_len.is_multiple_of(8));
        assert!(circuit.shuffle_prefix_len < circuit.stream_len);
        assert_eq!(circuit.stream_len, circuit.instructions.len());

        // The registry leaf binds both segment digests.
        let (prefix, common) = circuit.instructions.split_at(circuit.shuffle_prefix_len);
        assert_eq!(circuit.shuffle_commitment, Poseidon2::hash_elements(prefix));
        assert_eq!(circuit.common_commitment, Poseidon2::hash_elements(common));
        assert_eq!(
            circuit.commitment,
            Poseidon2::merge(&[circuit.shuffle_commitment, circuit.common_commitment])
        );

        // The common section must be byte-identical across proof orders; only the
        // shuffle section may differ.
        match &reference {
            None => reference = Some((circuit.shuffle_prefix_len, common.to_vec())),
            Some((prefix_len, common_reference)) => {
                assert_eq!(circuit.shuffle_prefix_len, *prefix_len);
                assert_eq!(
                    common,
                    common_reference,
                    "common section differs for {}",
                    order.file_stem()
                );
            },
        }
    }
}

/// Recompute each AIR's aligned block widths in the combined READ layout.
///
/// Deliberately independent of the codegen: widths come straight from the AIR definitions and
/// the documented LMCS alignment, so this cross-checks the production placement rather than
/// mirroring it.
fn air_block_widths() -> [(usize, usize, usize); MIDEN_AIR_COUNT] {
    const LMCS_ALIGNMENT: usize = 8;
    let mut widths = [(0usize, 0usize, 0usize); MIDEN_AIR_COUNT];
    for air in AIRS {
        let aux_coords = <MidenAir as LiftedAir<Felt, QuadFelt>>::aux_width(&air) * EXT_DEGREE;
        widths[air.instance_index()] = (
            <MidenAir as BaseAir<Felt>>::width(&air).next_multiple_of(LMCS_ALIGNMENT),
            aux_coords.next_multiple_of(LMCS_ALIGNMENT) / EXT_DEGREE,
            <MidenAir as LiftedAir<Felt, QuadFelt>>::num_aux_values(&air),
        );
    }
    widths
}

/// Start of each AIR's main/aux/boundary block when the blocks are concatenated in `order`.
fn air_block_offsets(
    widths: &[(usize, usize, usize); MIDEN_AIR_COUNT],
    order: &miden_air::ProofOrder,
) -> [(usize, usize, usize); MIDEN_AIR_COUNT] {
    let mut offsets = [(0usize, 0usize, 0usize); MIDEN_AIR_COUNT];
    let (mut main, mut aux, mut boundary) = (0usize, 0usize, 0usize);
    for air in order.airs().iter().copied() {
        let i = air.instance_index();
        offsets[i] = (main, aux, boundary);
        main += widths[i].0;
        aux += widths[i].1;
        boundary += widths[i].2;
    }
    offsets
}

/// Solve for polynomial coefficients (ascending degree) from `(point, value)` samples.
fn interpolate_coefficients(samples: &[(QuadFelt, QuadFelt)]) -> Vec<QuadFelt> {
    let n = samples.len();
    let mut matrix: Vec<Vec<QuadFelt>> = samples
        .iter()
        .map(|&(x, y)| {
            let mut row = Vec::with_capacity(n + 1);
            let mut power = QuadFelt::ONE;
            for _ in 0..n {
                row.push(power);
                power *= x;
            }
            row.push(y);
            row
        })
        .collect();

    for col in 0..n {
        let pivot = (col..n)
            .find(|&r| matrix[r][col] != QuadFelt::ZERO)
            .expect("sample points must be distinct");
        matrix.swap(col, pivot);
        let inv = matrix[col][col].inverse();
        for value in matrix[col].iter_mut() {
            *value *= inv;
        }
        let pivot_row = matrix[col].clone();
        for (row, values) in matrix.iter_mut().enumerate() {
            if row == col {
                continue;
            }
            let factor = values[col];
            if factor == QuadFelt::ZERO {
                continue;
            }
            for (target, &source) in values.iter_mut().zip(pivot_row.iter()).skip(col) {
                *target -= source * factor;
            }
        }
    }

    (0..n).map(|row| matrix[row][n]).collect()
}

#[test]
fn factored_circuits_reproduce_the_canonical_fold_for_every_proof_order() {
    use miden_air::{AIRS, ProofOrder, ace::build_factored_multi_air_ace_circuit};

    // Every proof order gets its own registry leaf, but end-to-end tests only ever produce a
    // couple of them, so a per-order routing or fold-weight error would otherwise ship unseen.
    // For each order this reconstructs the expected evaluation from the canonical circuit alone:
    // the per-AIR accumulators are recovered by interpolating the canonical evaluation in the
    // fold challenge, and each order must then reproduce the fold those accumulators imply.
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    };
    let factored = build_factored_multi_air_ace_circuit(config).expect("factored circuit");
    let layout = factored.layout().clone();

    let widths = air_block_widths();
    let canonical_offsets = air_block_offsets(&widths, &ProofOrder::instance_order());

    // Canonical slot -> proof slot for every value the shuffle must route. Derived per AIR from
    // block offsets, so it does not depend on the codegen's slot enumeration order.
    let routing = |order: &ProofOrder| -> Vec<(usize, usize)> {
        let proof_offsets = air_block_offsets(&widths, order);
        let mut pairs = Vec::new();
        let mut push = |canonical: InputKey, proof: InputKey| {
            pairs.push((
                layout.index(canonical).expect("canonical slot"),
                layout.index(proof).expect("proof slot"),
            ));
        };
        for air in AIRS {
            let i = air.instance_index();
            let (main_w, aux_w, boundary_w) = widths[i];
            let (canonical_main, canonical_aux, canonical_boundary) = canonical_offsets[i];
            let (proof_main, proof_aux, proof_boundary) = proof_offsets[i];
            for offset in 0..2 {
                for column in 0..main_w {
                    push(
                        InputKey::Main { offset, index: canonical_main + column },
                        InputKey::Main { offset, index: proof_main + column },
                    );
                }
                for column in 0..aux_w {
                    for coord in 0..EXT_DEGREE {
                        push(
                            InputKey::AuxCoord {
                                offset,
                                index: canonical_aux + column,
                                coord,
                            },
                            InputKey::AuxCoord { offset, index: proof_aux + column, coord },
                        );
                    }
                }
            }
            for value in 0..boundary_w {
                push(
                    InputKey::AuxBusBoundary(canonical_boundary + value),
                    InputKey::AuxBusBoundary(proof_boundary + value),
                );
            }
        }
        pairs
    };

    // Zero the quotient openings so the shared `q * v` binding drops out and the evaluation is
    // exactly the fold of the per-AIR accumulators.
    let mut base: Vec<QuadFelt> = fill_inputs(&layout);
    for chunk in 0..layout.counts.num_quotient_chunks {
        for offset in 0..2 {
            for coord in 0..EXT_DEGREE {
                let key = InputKey::QuotientChunkCoord { offset, chunk, coord };
                base[layout.index(key).expect("quotient slot")] = QuadFelt::ZERO;
            }
        }
    }

    let beta_slot = layout.index(InputKey::MultiAirFoldBeta).expect("fold beta slot");
    let canonical_circuit = factored
        .circuit_for_order(&ProofOrder::instance_order())
        .expect("canonical circuit");
    let eval_at =
        |circuit: &miden_ace_codegen::AceCircuit<QuadFelt>, inputs: &[QuadFelt], beta: QuadFelt| {
            let mut inputs = inputs.to_vec();
            inputs[beta_slot] = beta;
            circuit.eval(&inputs).expect("circuit eval")
        };

    // Recover the per-AIR accumulators: the canonical evaluation is
    // `sum_j acc_j * beta^(N - 1 - j)`, a degree-(N-1) polynomial in beta.
    let points: Vec<QuadFelt> =
        (1..=MIDEN_AIR_COUNT).map(|i| QuadFelt::from_u64(i as u64)).collect();
    let samples: Vec<(QuadFelt, QuadFelt)> = points
        .iter()
        .map(|&beta| (beta, eval_at(&canonical_circuit, &base, beta)))
        .collect();
    let coefficients = interpolate_coefficients(&samples);
    // `acc_j` sits at degree `N - 1 - j`.
    let acc: Vec<QuadFelt> =
        (0..MIDEN_AIR_COUNT).map(|j| coefficients[MIDEN_AIR_COUNT - 1 - j]).collect();

    // Guard the interpolation itself: an unmodelled beta dependence would break this.
    let probe = QuadFelt::from_u64(97);
    let predicted_canonical: QuadFelt = (0..MIDEN_AIR_COUNT)
        .map(|j| acc[j] * probe.exp_u64((MIDEN_AIR_COUNT - 1 - j) as u64))
        .sum();
    assert_eq!(
        eval_at(&canonical_circuit, &base, probe),
        predicted_canonical,
        "canonical evaluation is not the expected fold of per-AIR accumulators"
    );
    assert!(
        acc.iter().all(|value| *value != QuadFelt::ZERO),
        "degenerate accumulators would make this test vacuous"
    );

    for order in ProofOrder::variants() {
        let circuit = factored.circuit_for_order(&order).expect("ordered circuit");

        // Place each AIR's values where the proof order puts them.
        let mut inputs = base.clone();
        for (canonical_slot, proof_slot) in routing(&order) {
            inputs[proof_slot] = base[canonical_slot];
        }

        // The AIR at proof position k carries beta^(N - 1 - k).
        let mut exponent = [0usize; MIDEN_AIR_COUNT];
        for (position, air) in order.airs().iter().copied().enumerate() {
            exponent[air.instance_index()] = MIDEN_AIR_COUNT - 1 - position;
        }

        for &beta in points.iter().chain(core::iter::once(&probe)) {
            let expected: QuadFelt =
                (0..MIDEN_AIR_COUNT).map(|j| acc[j] * beta.exp_u64(exponent[j] as u64)).sum();
            assert_eq!(
                eval_at(&circuit, &inputs, beta),
                expected,
                "{} does not reproduce the canonical accumulators folded in proof order",
                order.file_stem()
            );
        }
    }
}

/// The registry-entry constructor checks circuit-to-leaf coherence. This test checks that
/// every served leaf and path authenticate under the protocol root.
#[test]
fn registry_entry_paths_authenticate_under_the_protocol_root() {
    use miden_air::{ProofOrder, ace::recursive_registry_entry, config::ACE_CIRCUIT_REGISTRY_ROOT};

    for order in ProofOrder::variants() {
        let entry = recursive_registry_entry(&order).expect("registry entry must build");
        let (_, leaf, path) = entry.into_parts();
        assert_eq!(
            path.compute_root(u64::from(order.tag()), leaf)
                .expect("path must fold to a root"),
            miden_core::Word::new(ACE_CIRCUIT_REGISTRY_ROOT),
            "the served path must authenticate the leaf under the protocol root"
        );
    }
}

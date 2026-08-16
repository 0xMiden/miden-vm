//! Unit tests for internal DAG + circuit helpers.

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{Field, PrimeCharacteristicRing};
use proptest::prelude::*;

use crate::{
    AceCircuit, InputCounts, InputKey, InputLayout,
    circuit::emit_circuit,
    dag::{DagBuilder, normalize_dag},
};

/// Minimal layout with only public inputs populated.
fn minimal_layout(num_public: usize) -> InputLayout {
    let counts = InputCounts {
        preprocessed_width: 0,
        width: 0,
        aux_width: 0,
        num_aux_boundary: 0,
        num_public,
        num_randomness: 2,
        num_quotient_chunks: 1,
    };
    InputLayout::new(counts)
}

fn build_inputs(layout: &InputLayout, values: &[(InputKey, QuadFelt)]) -> Vec<QuadFelt> {
    let mut inputs = vec![QuadFelt::ZERO; layout.total_inputs];
    for (key, value) in values {
        let idx = layout.index(*key).expect("input key in layout");
        inputs[idx] = *value;
    }
    inputs
}

#[test]
fn ace_simple_circuit_matches_hand_eval() {
    // (a + b) * a - c == 0
    let layout = minimal_layout(3);

    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    let c = builder.input(InputKey::Public(2));
    let sum = builder.add(a, b);
    let prod = builder.mul(sum, a);
    let root = builder.sub(prod, c);

    let dag = builder.build(root);

    let circuit: AceCircuit<QuadFelt> = emit_circuit(&dag, layout.clone()).expect("emit circuit");

    let a_val = QuadFelt::from(Felt::new_unchecked(3));
    let b_val = QuadFelt::from(Felt::new_unchecked(5));
    let c_val = (a_val + b_val) * a_val; // satisfies equation

    let inputs = build_inputs(
        &layout,
        &[
            (InputKey::Public(0), a_val),
            (InputKey::Public(1), b_val),
            (InputKey::Public(2), c_val),
        ],
    );

    let result = circuit.eval(&inputs).expect("circuit eval");
    assert!(result.is_zero());
}

#[test]
fn ace_simple_circuit_with_shared_terms() {
    // (a + b) * c - (a * c + b * c) == 0
    let layout = minimal_layout(3);

    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    let c = builder.input(InputKey::Public(2));

    let sum = builder.add(a, b);
    let lhs = builder.mul(sum, c);
    let ac = builder.mul(a, c);
    let bc = builder.mul(b, c);
    let rhs = builder.add(ac, bc);
    let root = builder.sub(lhs, rhs);

    let dag = builder.build(root);

    let circuit: AceCircuit<QuadFelt> = emit_circuit(&dag, layout.clone()).expect("emit circuit");

    let a_val = QuadFelt::from(Felt::new_unchecked(7));
    let b_val = QuadFelt::from(Felt::new_unchecked(2));
    let c_val = QuadFelt::from(Felt::new_unchecked(11));

    let inputs = build_inputs(
        &layout,
        &[
            (InputKey::Public(0), a_val),
            (InputKey::Public(1), b_val),
            (InputKey::Public(2), c_val),
        ],
    );

    let result = circuit.eval(&inputs).expect("circuit eval");
    assert!(result.is_zero());
}

proptest! {
    #[test]
    fn absorbed_negations_preserve_extension_field_evaluation(coords in any::<[u64; 4]>()) {
        let layout = minimal_layout(2);
        let a = QuadFelt::new([Felt::from_u64(coords[0]), Felt::from_u64(coords[1])]);
        let b = QuadFelt::new([Felt::from_u64(coords[2]), Felt::from_u64(coords[3])]);
        let inputs = build_inputs(
            &layout,
            &[(InputKey::Public(0), a), (InputKey::Public(1), b)],
        );

        for (negate_left, expected) in [(false, a - b), (true, b - a)] {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let a = builder.input(InputKey::Public(0));
            let b = builder.input(InputKey::Public(1));
            let root = if negate_left {
                let neg_a = builder.neg(a);
                builder.add(neg_a, b)
            } else {
                let neg_b = builder.neg(b);
                builder.add(a, neg_b)
            };
            let mut dag = builder.build(root);
            dag.compact();
            let circuit = emit_circuit(&dag, layout.clone()).expect("emit normalized circuit");

            prop_assert_eq!(circuit.eval(&inputs).expect("evaluate normalized circuit"), expected);
        }

        let mut builder = DagBuilder::<QuadFelt>::new();
        let a_id = builder.input(InputKey::Public(0));
        let b_id = builder.input(InputKey::Public(1));
        let neg_b = builder.neg(b_id);
        let root = builder.sub(a_id, neg_b);
        let mut dag = builder.build(root);
        dag.compact();
        let circuit = emit_circuit(&dag, layout).expect("emit normalized circuit");
        prop_assert_eq!(circuit.eval(&inputs).expect("evaluate normalized circuit"), a + b);
    }

    #[test]
    fn add_sub_cancellations_preserve_extension_field_evaluation(coords in any::<[u64; 4]>()) {
        let layout = minimal_layout(2);
        let a = QuadFelt::new([Felt::from_u64(coords[0]), Felt::from_u64(coords[1])]);
        let b = QuadFelt::new([Felt::from_u64(coords[2]), Felt::from_u64(coords[3])]);
        let inputs = build_inputs(
            &layout,
            &[(InputKey::Public(0), a), (InputKey::Public(1), b)],
        );

        for (form, expected) in [(0, a), (1, b), (2, b), (3, QuadFelt::ZERO)] {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let a_id = builder.input(InputKey::Public(0));
            let b_id = builder.input(InputKey::Public(1));
            let root = match form {
                0 => {
                    let difference = builder.sub(a_id, b_id);
                    builder.add(difference, b_id)
                },
                1 => {
                    let sum = builder.add(a_id, b_id);
                    builder.sub(sum, a_id)
                },
                2 => {
                    let difference = builder.sub(a_id, b_id);
                    builder.sub(a_id, difference)
                },
                3 => builder.sub(a_id, a_id),
                _ => unreachable!(),
            };
            let mut dag = builder.build(root);
            dag.compact();
            let circuit = emit_circuit(&dag, layout.clone()).expect("emit normalized circuit");

            prop_assert_eq!(circuit.eval(&inputs).expect("evaluate normalized circuit"), expected);
        }
    }

    #[test]
    fn dag_normalization_preserves_extension_field_evaluation(
        coords in any::<[u64; 8]>(),
        subtract_products in any::<bool>(),
        multiply_chain in any::<bool>(),
        factor_order in 0usize..4,
    ) {
        let layout = minimal_layout(4);
        let values = [
            QuadFelt::new([Felt::from_u64(coords[0]), Felt::from_u64(coords[1])]),
            QuadFelt::new([Felt::from_u64(coords[2]), Felt::from_u64(coords[3])]),
            QuadFelt::new([Felt::from_u64(coords[4]), Felt::from_u64(coords[5])]),
            QuadFelt::new([Felt::from_u64(coords[6]), Felt::from_u64(coords[7])]),
        ];
        let inputs = build_inputs(
            &layout,
            &[
                (InputKey::Public(0), values[0]),
                (InputKey::Public(1), values[1]),
                (InputKey::Public(2), values[2]),
                (InputKey::Public(3), values[3]),
            ],
        );

        let mut builder = DagBuilder::<QuadFelt>::new();
        let creation_order = match factor_order {
            0 => [3, 0, 1, 2],
            1 => [0, 1, 2, 3],
            2 => [0, 3, 1, 2],
            3 => [1, 3, 0, 2],
            _ => unreachable!(),
        };
        for index in creation_order {
            builder.input(InputKey::Public(index));
        }
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let c = builder.input(InputKey::Public(2));
        let factor = builder.input(InputKey::Public(3));

        let existing = if multiply_chain { builder.mul(a, c) } else { builder.add(a, c) };
        let nested = if multiply_chain { builder.mul(a, b) } else { builder.add(a, b) };
        let target = if multiply_chain {
            builder.mul(nested, c)
        } else {
            builder.add(nested, c)
        };
        let af = builder.mul(a, factor);
        let bf = builder.mul(b, factor);
        let products = if subtract_products { builder.sub(af, bf) } else { builder.add(af, bf) };
        let tail = builder.add(target, products);
        let root = builder.add(existing, tail);
        let mut dag = builder.build(root);
        dag.compact();

        let original = emit_circuit(&dag, layout.clone()).expect("emit original circuit");
        let normalized_dag = normalize_dag(dag);
        let normalized_len = normalized_dag.nodes.len();
        let normalized_dag = normalize_dag(normalized_dag);
        prop_assert_eq!(normalized_dag.nodes.len(), normalized_len);
        let normalized =
            emit_circuit(&normalized_dag, layout).expect("emit normalized circuit");
        prop_assert!(normalized.operations.len() < original.operations.len());
        prop_assert_eq!(
            normalized.eval(&inputs).expect("evaluate normalized circuit"),
            original.eval(&inputs).expect("evaluate original circuit"),
        );
    }
}

#[test]
fn compact_removes_dead_nodes() {
    // add(const_3, const_5) folds to const_8, leaving const_3 and const_5
    // orphaned since nothing else references them.
    let layout = minimal_layout(1);

    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let three = builder.constant(QuadFelt::from(Felt::new_unchecked(3)));
    let five = builder.constant(QuadFelt::from(Felt::new_unchecked(5)));
    let eight = builder.add(three, five);
    let root = builder.mul(a, eight);

    let mut dag = builder.build(root);
    let before = dag.nodes().len();
    dag.compact();
    let after = dag.nodes().len();

    assert!(
        after < before,
        "compact should remove dead nodes: before={before}, after={after}"
    );
    // Only Input(Public(0)), Constant(8), and the Mul remain reachable.
    assert_eq!(after, 3);

    let circuit: AceCircuit<QuadFelt> = emit_circuit(&dag, layout.clone()).expect("emit circuit");
    // Without compaction the orphaned Constant(3) and Constant(5) would still be
    // deduplicated into the emitted circuit's constant pool alongside Constant(8).
    assert_eq!(
        circuit.constants.len(),
        1,
        "orphaned constants must not reach the emitted circuit"
    );

    let a_val = QuadFelt::from(Felt::new_unchecked(2));
    let inputs = build_inputs(&layout, &[(InputKey::Public(0), a_val)]);
    let result = circuit.eval(&inputs).expect("circuit eval");
    assert_eq!(result, a_val * QuadFelt::from(Felt::new_unchecked(8)));
}

#[test]
fn compact_removes_dead_operation_subtree() {
    // A Mul built on top of `root` but never wired into anything else is a dead
    // subtree: compaction must drop it, not just fold away dead constants.
    let layout = minimal_layout(2);

    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    let root = builder.add(a, b);
    let _dead = builder.mul(root, b);

    let mut dag = builder.build(root);
    let before = dag.nodes().len();
    dag.compact();
    let after = dag.nodes().len();

    assert!(
        after < before,
        "compact should remove the dead Mul subtree: before={before}, after={after}"
    );
    // Only Input(Public(0)), Input(Public(1)), and the Add remain reachable.
    assert_eq!(after, 3);

    let circuit: AceCircuit<QuadFelt> = emit_circuit(&dag, layout.clone()).expect("emit circuit");
    // Without compaction the dead Mul would still be emitted as a second operation.
    assert_eq!(circuit.operations.len(), 1, "dead Mul must not reach the emitted circuit");

    let a_val = QuadFelt::from(Felt::new_unchecked(4));
    let b_val = QuadFelt::from(Felt::new_unchecked(9));
    let inputs =
        build_inputs(&layout, &[(InputKey::Public(0), a_val), (InputKey::Public(1), b_val)]);
    let result = circuit.eval(&inputs).expect("circuit eval");
    assert_eq!(result, a_val + b_val);
}

#[test]
#[should_panic(expected = "DAG node must come from this DagBuilder")]
fn compact_rejects_stale_node_ids() {
    // A NodeId issued before a compaction that removes nodes must not resolve
    // afterwards: such a compaction renumbers indices and stamps a fresh
    // dag_id, so provenance checks reject the stale id instead of resolving it
    // to whichever node now sits at its old index.
    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let three = builder.constant(QuadFelt::from(Felt::new_unchecked(3)));
    let five = builder.constant(QuadFelt::from(Felt::new_unchecked(5)));
    let eight = builder.add(three, five);
    let root = builder.mul(a, eight);
    // Constant folding orphans `three` at build time and compaction removes
    // it, while its old index stays in range afterwards — the exact shape
    // that would alias a different node.
    let stale = three;

    let mut dag = builder.build(root);
    dag.compact();
    assert!(
        stale.index() < dag.nodes().len(),
        "test premise broken: the stale index must stay in range so the \
         provenance check, not the bounds check, is what rejects it"
    );

    let mut resumed = DagBuilder::from_dag(dag);
    let _ = resumed.neg(stale);
}

#[test]
fn compact_preserves_already_compact_dag() {
    // A DAG with no dead nodes must be unchanged by compaction.
    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    let root = builder.add(a, b);

    let mut dag = builder.build(root);
    let before = dag.nodes().len();
    dag.compact();
    assert_eq!(dag.nodes().len(), before);
}

#[test]
fn ace_encoding_rejects_non_final_root() {
    let layout = minimal_layout(2);

    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    let root = builder.add(a, b);
    let _dead_op = builder.mul(root, b);

    let dag = builder.build(root);
    let circuit = emit_circuit(&dag, layout).expect("emit circuit");
    let err = circuit.to_ace().expect_err("non-final root should be rejected");

    assert!(
        matches!(
            err,
            crate::AceError::InvalidInputLayout { ref message }
                if message.contains("root must be the last operation")
        ),
        "expected non-final root layout error, got {err:?}"
    );
}

/// A constant-zero left operand still produces a `Sub` when the right operand is a
/// non-constant product. This pins the degenerate accumulator case of the root invariant
/// documented at `reemit_air_root`.
#[test]
fn sub_interns_a_real_root_for_a_constant_left_operand() {
    let mut builder = DagBuilder::<QuadFelt>::new();
    let zero = builder.constant(QuadFelt::ZERO);
    let q = builder.input(InputKey::Public(0));
    let v = builder.input(InputKey::Public(1));
    let qv = builder.mul(q, v);
    let root = builder.sub(zero, qv);
    let dag = builder.build(root);

    assert_eq!(dag.root(), root, "the subtraction must be the DAG root");
    assert!(
        matches!(dag.nodes[root.index()], crate::dag::NodeKind::Sub(a, b) if a == zero && b == qv),
        "a constant left operand must not rewrite the root away from Sub"
    );
}

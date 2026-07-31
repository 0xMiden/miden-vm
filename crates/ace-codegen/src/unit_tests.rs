//! Unit tests for internal DAG + circuit helpers.

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{Field, PrimeCharacteristicRing};

use crate::{
    AceCircuit, InputCounts, InputKey, InputLayout, circuit::emit_circuit, dag::DagBuilder,
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

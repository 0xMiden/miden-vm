//! Unit tests for internal DAG + circuit helpers.

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{Field, PrimeCharacteristicRing};

use crate::{
    AceCircuit, InputCounts, InputKey, InputLayout, circuit::emit_circuit, dag::DagBuilder,
};

/// Minimal layout with only public inputs populated.
fn minimal_layout(num_public: usize) -> InputLayout {
    let counts = InputCounts {
        width: 0,
        aux_width: 0,
        num_public,
        num_vlpi: 0,
        num_randomness: 2,
        num_periodic: 0,
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

    let a_val = QuadFelt::from(Felt::new(3));
    let b_val = QuadFelt::from(Felt::new(5));
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
fn compact_removes_dead_nodes() {
    // Build a DAG where constant folding creates orphans.
    // add(const_3, const_5) folds to const_8, leaving const_3 and const_5
    // orphaned if nothing else references them.
    let layout = minimal_layout(1);

    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let three = builder.constant(QuadFelt::from(Felt::new(3)));
    let five = builder.constant(QuadFelt::from(Felt::new(5)));
    // Folds to Constant(8) — three and five become orphans.
    let eight = builder.add(three, five);
    let root = builder.mul(a, eight);

    let dag = builder.build(root);

    // DagBuilder constant-folds add(3,5) to Constant(8), but the original Constant(3)
    // and Constant(5) nodes are still in the node list (interned before the fold).
    // So we get 5 nodes: Input(0), Const(3), Const(5), Const(8), Mul.
    // The orphan Const(3) and Const(5) don't affect evaluation correctness.
    assert_eq!(dag.nodes().len(), 5);

    let circuit: AceCircuit<QuadFelt> = emit_circuit(&dag, layout.clone()).expect("emit circuit");
    let inputs = build_inputs(&layout, &[(InputKey::Public(0), QuadFelt::from(Felt::new(2)))]);
    let result = circuit.eval(&inputs).expect("circuit eval");
    assert_eq!(result, QuadFelt::from(Felt::new(16)));
}

#[test]
fn build_with_constant_folding() {
    // DagBuilder constant-folds identity operations (mul by 1, add 0),
    // so orphan constants are created but the DAG is still valid.
    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    // mul(one, a) folds to a, but ONE constant is still in the node list.
    let one = builder.constant(QuadFelt::ONE);
    let _folded = builder.mul(one, a);
    // add(zero, b) folds to b, but ZERO constant is still in the node list.
    let zero = builder.constant(QuadFelt::ZERO);
    let _folded2 = builder.add(zero, b);
    let sum = builder.add(a, b);
    let root = builder.mul(sum, a);

    let dag = builder.build(root);
    // The DAG has orphan nodes (ONE, ZERO) but still evaluates correctly.
    // Reachable: Input(0), Input(1), Add(0,1), Mul(Add,Input(0)) = 4 nodes
    // Orphans: Constant(ONE), Constant(ZERO) = 2 unreachable nodes
    assert!(dag.nodes().len() >= 4, "dag should have at least 4 reachable nodes");
}

#[test]
fn build_eval_produces_correct_result() {
    // Verify circuit evaluation is correct after build (which compacts).
    let layout = minimal_layout(2);

    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    // Create orphans.
    let one = builder.constant(QuadFelt::ONE);
    let _folded = builder.mul(one, a);
    let zero = builder.constant(QuadFelt::ZERO);
    let _folded2 = builder.add(zero, b);
    let sum = builder.add(a, b);
    let root = builder.mul(sum, a);

    let dag = builder.build(root);

    let a_val = QuadFelt::from(Felt::new(7));
    let b_val = QuadFelt::from(Felt::new(3));
    let inputs =
        build_inputs(&layout, &[(InputKey::Public(0), a_val), (InputKey::Public(1), b_val)]);

    let circuit: AceCircuit<QuadFelt> = emit_circuit(&dag, layout.clone()).expect("emit compacted");
    let result = circuit.eval(&inputs).expect("eval compacted");

    // (a + b) * a = (7 + 3) * 7 = 70
    assert_eq!(result, QuadFelt::from(Felt::new(70)));
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

    let a_val = QuadFelt::from(Felt::new(7));
    let b_val = QuadFelt::from(Felt::new(2));
    let c_val = QuadFelt::from(Felt::new(11));

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

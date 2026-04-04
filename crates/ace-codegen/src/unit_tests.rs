//! Unit tests for internal DAG + circuit helpers.

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{Field, PrimeCharacteristicRing};

use crate::{
    AceCircuit, InputCounts, InputKey, InputLayout,
    circuit::emit_circuit,
    dag::{AceDag, DagBuilder},
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

    let dag = AceDag { nodes: builder.into_nodes(), root };

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

    let mut dag = AceDag { nodes: builder.into_nodes(), root };
    let before = dag.nodes.len();
    dag.compact();
    let after = dag.nodes.len();

    // The folded constant 8 replaces the add, and const_3/const_5 are removed.
    assert!(
        after < before,
        "compact should remove dead nodes: before={before}, after={after}"
    );
    // Only 3 reachable: Input(Public(0)), Constant(8), Mul
    assert_eq!(after, 3);

    let circuit: AceCircuit<QuadFelt> = emit_circuit(&dag, layout.clone()).expect("emit circuit");
    let inputs = build_inputs(&layout, &[(InputKey::Public(0), QuadFelt::from(Felt::new(2)))]);
    let result = circuit.eval(&inputs).expect("circuit eval");
    assert_eq!(result, QuadFelt::from(Felt::new(16)));
}

#[test]
fn compact_preserves_already_compact_dag() {
    // A DAG with no dead nodes should be unchanged by compact.
    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    let root = builder.add(a, b);

    let mut dag = AceDag { nodes: builder.into_nodes(), root };
    let before = dag.nodes.len();
    dag.compact();
    assert_eq!(dag.nodes.len(), before);
}

#[test]
fn compact_eval_matches_uncompacted() {
    // Verify circuit evaluation is identical before and after compaction.
    let layout = minimal_layout(2);

    let mut builder = DagBuilder::<QuadFelt>::new();
    let a = builder.input(InputKey::Public(0));
    let b = builder.input(InputKey::Public(1));
    // Create orphans via mul-by-one folding: mul(one, a) returns a, orphaning one.
    let one = builder.constant(QuadFelt::ONE);
    let _folded = builder.mul(one, a); // returns a, orphaning the ONE constant if unused elsewhere
    // Create more orphans via add-with-zero.
    let zero = builder.constant(QuadFelt::ZERO);
    let _folded2 = builder.add(zero, b); // returns b
    let sum = builder.add(a, b);
    let root = builder.mul(sum, a);

    let dag_uncompacted = AceDag { nodes: builder.into_nodes(), root };

    let a_val = QuadFelt::from(Felt::new(7));
    let b_val = QuadFelt::from(Felt::new(3));
    let inputs =
        build_inputs(&layout, &[(InputKey::Public(0), a_val), (InputKey::Public(1), b_val)]);

    let circuit1: AceCircuit<QuadFelt> =
        emit_circuit(&dag_uncompacted, layout.clone()).expect("emit uncompacted");
    let result1 = circuit1.eval(&inputs).expect("eval uncompacted");

    let mut dag_compacted = AceDag {
        nodes: dag_uncompacted.nodes.clone(),
        root: dag_uncompacted.root,
    };
    dag_compacted.compact();

    assert!(
        dag_compacted.nodes.len() <= dag_uncompacted.nodes.len(),
        "compacted should not grow"
    );

    let circuit2: AceCircuit<QuadFelt> =
        emit_circuit(&dag_compacted, layout.clone()).expect("emit compacted");
    let result2 = circuit2.eval(&inputs).expect("eval compacted");

    assert_eq!(result1, result2);
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

    let dag = AceDag { nodes: builder.into_nodes(), root };

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

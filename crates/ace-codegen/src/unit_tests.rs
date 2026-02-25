//! Unit tests for internal DAG + circuit helpers.

use miden_core::{Felt, field::QuadFelt};
use p3_field::{Field, PrimeCharacteristicRing};

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
        num_randomness: 1,
        num_randomness_inputs: 1,
        num_periodic: 0,
        num_aux_inputs: 14,
        num_quotient_chunks: 1,
        ext_degree: 2,
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

    let result = circuit.eval(&inputs);
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

    let result = circuit.eval(&inputs);
    assert!(result.is_zero());
}

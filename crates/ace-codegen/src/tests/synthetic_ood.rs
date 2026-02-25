//! Synthetic OOD tests derived from the air-script ACE test strategy.
//!
//! The air-script tests correct a random quotient so the ACE circuit evaluates
//! to zero. Here we apply the same idea to the Miden VM quotient recomposition
//! (barycentric chunk kernel) and keep the tests independent of the prover.

use miden_air::ProcessorAir;
use miden_core::{Felt, field::QuadFelt};
use p3_field::Field;

use super::common::{eval_quotient, fill_inputs, zps_for_chunk};
use crate::{
    AceConfig, InputKey, LayoutKind, circuit::emit_circuit, pipeline::build_ace_dag_for_air,
};

#[test]
fn synthetic_ood_adjusts_quotient_to_zero() {
    let air = ProcessorAir::default();
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_aux_inputs: 14,
        layout: LayoutKind::Masm,
    };

    let artifacts = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, config).expect("ace dag");
    let circuit = emit_circuit(&artifacts.dag, artifacts.layout.clone()).expect("ace circuit");

    let mut inputs = fill_inputs(&artifacts.layout);
    let root = circuit.eval(&inputs);

    let zps_0 = zps_for_chunk(&artifacts.layout, &inputs, 0);
    let delta = root * zps_0.inverse();

    let idx = artifacts
        .layout
        .index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
        .unwrap();
    inputs[idx] += delta;

    let result = circuit.eval(&inputs);
    assert!(result.is_zero(), "ACE circuit must evaluate to zero");

    // Sanity check: recomposition is well-defined and stable.
    let quotient = eval_quotient(&artifacts.layout, &inputs);
    assert_eq!(quotient, eval_quotient(&artifacts.layout, &inputs));
}

#[test]
fn quotient_next_inputs_do_not_affect_eval() {
    let air = ProcessorAir::default();
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_aux_inputs: 14,
        layout: LayoutKind::Masm,
    };

    let artifacts = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, config).expect("ace dag");
    let circuit = emit_circuit(&artifacts.dag, artifacts.layout.clone()).expect("ace circuit");

    let mut inputs = fill_inputs(&artifacts.layout);

    let root = circuit.eval(&inputs);
    let zps_0 = zps_for_chunk(&artifacts.layout, &inputs, 0);
    let delta = root * zps_0.inverse();
    let idx = artifacts
        .layout
        .index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
        .unwrap();
    inputs[idx] += delta;
    assert!(circuit.eval(&inputs).is_zero(), "precondition: zero root");

    // Mutate all quotient_next inputs; evaluation should remain zero.
    for chunk in 0..artifacts.layout.counts.num_quotient_chunks {
        for coord in 0..artifacts.layout.counts.ext_degree {
            let idx = artifacts
                .layout
                .index(InputKey::QuotientChunkCoord { offset: 1, chunk, coord })
                .unwrap();
            inputs[idx] += QuadFelt::from(Felt::new(123 + (chunk * 7 + coord) as u64));
        }
    }

    let result = circuit.eval(&inputs);
    assert!(result.is_zero(), "quotient_next should not affect ACE eval");
}

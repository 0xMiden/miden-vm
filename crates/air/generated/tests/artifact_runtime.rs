//! Staged-artifact delivery and runtime evaluation checks, independent of AIR capture/lowering.
//!
//! This test intentionally imports neither authored AIR nor compiler APIs. The second evaluator
//! decodes packed u64 instructions directly and compares every runtime gate and wire fan-out.

use miden_ace::{EncodedCircuit, EvaluationTrace};
use miden_core::{
    Felt, Word,
    field::{BasedVectorSpace, QuadFelt},
    serde::{Deserializable, Serializable},
};

fn check_runtime(bytes: &[u8], accepted: Word) {
    let encoded = EncodedCircuit::from_canonical_bytes(bytes).expect("staged canonical artifact");
    assert_eq!(encoded.to_canonical_bytes(), bytes, "artifact delivery must be canonical");
    assert_eq!(encoded.circuit_hash(), accepted, "staged stream must retain the accepted pin");

    let num_nodes = encoded.num_nodes();
    let constant_felts = 2 * encoded.num_constants();
    let instructions = &encoded.instructions()[constant_felts..];
    for seed in [1u64, 0x5a17_92e3, 0xd1ff_e2e7] {
        let mut state = seed;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            Felt::new_unchecked(state % 0xffff_ffff_0000_0001)
        };
        let mut values: Vec<QuadFelt> =
            (0..encoded.num_inputs()).map(|_| QuadFelt::new([next(), next()])).collect();
        values.extend(
            encoded.instructions()[..constant_felts]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| QuadFelt::new([pair[0], pair[1]])),
        );
        assert_eq!(values.len(), encoded.num_vars());

        let mut runtime =
            EvaluationTrace::new(encoded.num_read_rows() as u32, encoded.num_eval_rows() as u32);
        for (row, pair) in values.as_chunks::<2>().0.iter().enumerate() {
            let left = pair[0].as_basis_coefficients_slice();
            let right = pair[1].as_basis_coefficients_slice();
            runtime.do_read(
                Felt::from_u32((row * 4) as u32),
                Word::new([left[0], left[1], right[0], right[1]]),
            );
        }
        let mut multiplicities = vec![0u32; num_nodes];
        for (index, &instruction) in instructions.iter().enumerate() {
            // Independent instruction interpretation: no miden_ace decoder or compiler lowering.
            let packed = instruction.as_canonical_u64();
            let left_id = (packed & 0x3fff_ffff) as usize;
            let right_id = ((packed >> 30) & 0x3fff_ffff) as usize;
            let left_index = num_nodes - 1 - left_id;
            let right_index = num_nodes - 1 - right_id;
            let value = match packed >> 60 {
                0 => values[left_index] - values[right_index],
                1 => values[left_index] * values[right_index],
                2 => values[left_index] + values[right_index],
                tag => panic!("invalid operation {tag}"),
            };
            multiplicities[left_index] += 1;
            multiplicities[right_index] += 1;
            values.push(value);
            runtime
                .do_eval(Felt::from_u32((4 * encoded.num_read_rows() + index) as u32), instruction)
                .expect("staged sequential instruction");
            let record = &runtime.eval_nodes()[index];
            assert_eq!(record.id_0, Felt::from_u32((num_nodes - values.len()) as u32));
            assert_eq!(
                record.v_0, value,
                "runtime gate {index} differs from independent interpreter"
            );
            assert_eq!(record.v_1, values[left_index]);
            assert_eq!(record.v_2, values[right_index]);
        }
        assert_eq!(runtime.output_value(), values.last().copied());
        assert_eq!(runtime.multiplicities().collect::<Vec<_>>(), multiplicities);
        assert_eq!(EvaluationTrace::read_from_bytes(&runtime.to_bytes()).unwrap(), runtime);
    }
}

#[test]
fn vm_staged_stream_matches_runtime_and_accepted_digest() {
    let artifacts = miden_air::vm::artifacts::recursive_circuit().unwrap();
    assert_eq!(artifacts.commitment, Word::new(miden_air::config::ACE_CIRCUIT_DIGEST));
    check_runtime(miden_air::vm::artifacts::ENCODED_ACE, artifacts.commitment);
}

#[test]
fn precompile_staged_stream_matches_runtime_and_accepted_digest() {
    let artifacts = miden_air::precompile::artifacts::recursive_circuit().unwrap();
    let accepted =
        Word::new(miden_air::precompile::artifacts::ACE_CIRCUIT_DIGEST.map(Felt::new_unchecked));
    assert_eq!(artifacts.commitment, accepted);
    check_runtime(miden_air::precompile::artifacts::ENCODED_ACE, accepted);
}

//! Circuit adapters and embedded recursive-verifier instructions.
pub use miden_air_source::vm::ace::*;

/// `(READ variables, evaluation gates, stream length)` of the build-compiled VM circuit.
pub const ACE_CIRCUIT_SHAPE: (usize, usize, usize) =
    include!(concat!(env!("OUT_DIR"), "/ace_circuit_shape.rs"));

/// Encoded instruction stream of the build-compiled VM circuit, as canonical felt values.
pub static ACE_INSTRUCTIONS: &[u64] = &include!(concat!(env!("OUT_DIR"), "/ace_instructions.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_circuit_matches_independent_capture() {
        let independent = build_recursive_verifier_ace_circuit().unwrap();
        assert_eq!(
            ACE_CIRCUIT_SHAPE,
            (independent.num_inputs, independent.num_eval_gates, independent.stream_len)
        );
        assert_eq!(
            miden_core::Word::new(crate::vm::config::ACE_CIRCUIT_DIGEST),
            independent.commitment
        );
        let instructions: alloc::vec::Vec<u64> = independent
            .instructions
            .iter()
            .map(miden_core::Felt::as_canonical_u64)
            .collect();
        assert_eq!(ACE_INSTRUCTIONS, instructions);
    }
}

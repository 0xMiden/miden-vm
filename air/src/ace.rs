//! Circuit adapters and embedded recursive-verifier instructions.

pub use miden_ace_codegen::RecursiveAceCircuit;

/// `(READ variables, evaluation gates, stream length)` of the build-compiled VM circuit.
const ACE_CIRCUIT_SHAPE: (usize, usize, usize) =
    include!(concat!(env!("OUT_DIR"), "/ace_circuit_shape.rs"));

/// Encoded instruction stream of the build-compiled VM circuit, as canonical felt values.
static ACE_INSTRUCTIONS: &[u64] = &include!(concat!(env!("OUT_DIR"), "/ace_instructions.rs"));

/// Materialize the build-compiled VM circuit without symbolic AIR capture at runtime.
///
/// The commitment is the pinned [`crate::config::ACE_CIRCUIT_DIGEST`]; the recursive verifier
/// rejects a stream that does not hash to it.
pub fn compiled_recursive_circuit() -> RecursiveAceCircuit {
    let (num_inputs, num_eval_gates, stream_len) = ACE_CIRCUIT_SHAPE;
    RecursiveAceCircuit {
        num_inputs,
        num_eval_gates,
        stream_len,
        commitment: miden_core::Word::new(crate::config::ACE_CIRCUIT_DIGEST),
        instructions: ACE_INSTRUCTIONS
            .iter()
            .copied()
            .map(miden_core::Felt::new_unchecked)
            .collect(),
    }
}

/// Returns the process-wide build-compiled VM circuit.
#[cfg(feature = "std")]
pub fn shared_recursive_circuit() -> &'static RecursiveAceCircuit {
    static CIRCUIT: std::sync::OnceLock<RecursiveAceCircuit> = std::sync::OnceLock::new();
    CIRCUIT.get_or_init(compiled_recursive_circuit)
}

#[cfg(test)]
mod tests {
    use miden_air_definitions::compiler::vm::build_recursive_verifier_ace_circuit;

    use super::*;

    #[test]
    fn embedded_circuit_matches_independent_capture() {
        let independent = build_recursive_verifier_ace_circuit().unwrap();
        assert_eq!(compiled_recursive_circuit(), independent);
        #[cfg(feature = "std")]
        assert_eq!(shared_recursive_circuit(), &independent);
    }
}

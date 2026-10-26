//! Materialization and caching of the VM relation's embedded recursive circuit.
pub use miden_air::vm::ace::RecursiveAceCircuit;
use miden_air::vm::ace::{ACE_CIRCUIT_SHAPE, ACE_INSTRUCTIONS};

/// Materialize the build-compiled VM circuit without symbolic AIR capture at runtime.
///
/// The commitment is the pinned [`miden_air::vm::config::ACE_CIRCUIT_DIGEST`]; the recursive
/// verifier rejects a stream that does not hash to it.
pub fn compiled_recursive_circuit() -> RecursiveAceCircuit {
    let (num_inputs, num_eval_gates, stream_len) = ACE_CIRCUIT_SHAPE;
    RecursiveAceCircuit {
        num_inputs,
        num_eval_gates,
        stream_len,
        commitment: miden_core::Word::new(miden_air::vm::config::ACE_CIRCUIT_DIGEST),
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use miden_air_definitions::compiler::vm::build_recursive_verifier_ace_circuit;

    #[test]
    fn cached_circuit_matches_independent_authored_capture() {
        let authored =
            build_recursive_verifier_ace_circuit().expect("authored recursive ACE circuit");
        assert_eq!(*super::shared_recursive_circuit(), authored);
    }
}

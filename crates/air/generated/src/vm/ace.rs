//! Runtime access to the canonical recursive-verifier circuit.
//!
//! Circuit construction lives in authored tooling. This process-wide cache remains here until
//! VM setup and recursive-input ownership move into the STARK backend.

#[cfg(feature = "std")]
use miden_air_source::vm::codegen::{RecursiveAceCircuit, build_recursive_verifier_ace_circuit};

/// Returns the process-wide canonical circuit shared by every proof order.
#[cfg(feature = "std")]
pub fn shared_recursive_circuit() -> &'static RecursiveAceCircuit {
    static CIRCUIT: std::sync::OnceLock<RecursiveAceCircuit> = std::sync::OnceLock::new();
    CIRCUIT.get_or_init(|| {
        build_recursive_verifier_ace_circuit().expect("recursive-verifier ACE circuit must build")
    })
}

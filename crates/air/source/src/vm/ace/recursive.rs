use miden_ace::{AceConfig, LayoutKind};
use miden_core::{Felt, field::QuadFelt};

use super::multi_air::build_canonical_multi_air_ace_circuit;
use crate::AIRS;

/// Number of quotient chunks the recursive verifier and its ACE circuit consume.
///
/// This is the symbolic derivation used by the lifted-STARK prover and verifier. The MASM
/// quotient-recomposition inputs depend on this value rather than the numerically equal blowup
/// factor.
fn recursive_verifier_num_quotient_chunks() -> usize {
    let max_log_quotient_degree = AIRS
        .iter()
        .map(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>)
        .max()
        .expect("the Miden AIR set is non-empty");
    1usize << max_log_quotient_degree
}

/// ACE codegen settings used by the recursive verifier's MASM evaluator.
pub fn recursive_verifier_ace_config() -> AceConfig {
    AceConfig {
        num_quotient_chunks: recursive_verifier_num_quotient_chunks(),
        layout: LayoutKind::Masm,
    }
}

pub use miden_ace::RecursiveAceCircuit;

/// Builds and encodes the order-invariant recursive-verifier ACE circuit.
///
/// The circuit does not depend on the proof order. Callers that need repeated access should use
/// [`shared_recursive_circuit`] rather than rebuild it for each proof.
pub fn build_recursive_verifier_ace_circuit() -> RecursiveAceCircuit {
    miden_ace::CompiledCircuit::from_circuit(build_canonical_multi_air_ace_circuit(
        recursive_verifier_ace_config(),
    ))
    .into()
}

/// Returns the process-wide canonical circuit shared by every proof order.
#[cfg(feature = "std")]
pub fn shared_recursive_circuit() -> &'static RecursiveAceCircuit {
    static CIRCUIT: std::sync::OnceLock<RecursiveAceCircuit> = std::sync::OnceLock::new();
    CIRCUIT.get_or_init(build_recursive_verifier_ace_circuit)
}

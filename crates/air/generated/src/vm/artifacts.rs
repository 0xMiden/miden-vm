//! Canonical production ACE generated ahead of use from authored equations.
use miden_ace::{AceError, EncodedCircuit, RecursiveAceCircuit};
pub const ENCODED_ACE: &[u8] = include_bytes!("../../artifacts/vm.ace");
pub fn recursive_circuit() -> Result<RecursiveAceCircuit, AceError> {
    let circuit: RecursiveAceCircuit =
        RecursiveAceCircuit::from(EncodedCircuit::from_canonical_bytes(ENCODED_ACE)?);
    if circuit.commitment != miden_core::Word::from(crate::config::ACE_CIRCUIT_DIGEST) {
        return Err(AceError::InvalidInputLayout {
            message: "packaged vm ACE disagrees with the accepted circuit digest".into(),
        });
    }
    Ok(circuit)
}
#[cfg(feature = "std")]
pub fn shared_recursive_circuit() -> &'static RecursiveAceCircuit {
    static CIRCUIT: std::sync::OnceLock<RecursiveAceCircuit> = std::sync::OnceLock::new();
    CIRCUIT.get_or_init(|| recursive_circuit().expect("packaged canonical ACE must decode"))
}

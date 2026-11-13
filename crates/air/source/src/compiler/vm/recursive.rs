use miden_ace::{
    RecursiveAceCircuit,
    compiler::{CapturedAir, CompiledRelation, LayoutKind},
};

use super::multi_air::LMCS_ALIGNMENT;
use crate::vm::AIRS;

/// Builds and encodes the order-invariant recursive-verifier ACE circuit.
///
/// The circuit does not depend on the proof order. Callers that need repeated access should use
/// the build-compiled `miden_vm_stark::setup::ace::shared_recursive_circuit` rather than rebuild it
/// for each proof.
pub fn build_recursive_verifier_ace_circuit() -> RecursiveAceCircuit {
    let captured = AIRS.map(|air| CapturedAir::new(&air));
    CompiledRelation::from_captured(&captured.each_ref(), LMCS_ALIGNMENT)
        .build_circuit(LayoutKind::Masm)
        .to_ace()
        .into()
}

#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub use miden_core::{
    deferred::DeferredRoot,
    proof::{HashFunction, StarkProof},
};
pub use miden_precompiles_air::security::{
    AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, SecurityReport,
    SecurityTerm,
};

#[cfg(any(test, feature = "std"))]
pub(crate) mod ace;
#[cfg(any(test, feature = "std"))]
pub(crate) mod ace_registry;
#[cfg(feature = "registry-tools")]
pub mod ace_registry_regen;
#[cfg(feature = "std")]
pub mod masm_verifier;
mod verify;

pub use verify::{VerifyError, verify_deferred};

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{Felt, Word, deferred::TRUE_DIGEST, proof::MAX_STARK_PROOF_BYTES};

    use super::*;

    #[test]
    fn verifies_pinned_eidos_proof() {
        const PROOF_BYTES: &[u8] = include_bytes!("../tests/fixtures/pvm_eidos_v0_31.bin");
        const ROOT: &str = include_str!("../tests/fixtures/pvm_eidos_v0_31.root");
        let root: [Felt; 4] = ROOT
            .split_ascii_whitespace()
            .map(|value| Felt::new_unchecked(value.parse().expect("root element must be a u64")))
            .collect::<Vec<_>>()
            .try_into()
            .expect("fixture root must contain four elements");
        let root = Word::new(root);
        let proof = StarkProof::new(PROOF_BYTES.to_vec(), HashFunction::Eidos);

        verify_deferred(&proof, root).expect("pinned Eidos proof must verify");
        assert!(verify_deferred(&proof, TRUE_DIGEST).is_err());
    }

    #[test]
    fn verify_deferred_enforces_fixed_stark_proof_size_ceiling() {
        let proof = StarkProof::new(vec![0; MAX_STARK_PROOF_BYTES + 1], HashFunction::Blake3_256);

        assert!(matches!(
            verify_deferred(&proof, TRUE_DIGEST),
            Err(VerifyError::ProofTooLarge { size: _, max: MAX_STARK_PROOF_BYTES })
        ));
    }
}

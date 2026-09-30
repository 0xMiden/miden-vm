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
    use alloc::vec;

    use miden_core::{Felt, Word, deferred::TRUE_DIGEST, proof::MAX_STARK_PROOF_BYTES};

    use super::*;

    fn pinned_keccak_root() -> Word {
        Word::new(
            [
                8727402973153492738,
                13033997996299931781,
                5394599319400709983,
                17469579631022355290,
            ]
            .map(Felt::new_unchecked),
        )
    }

    #[test]
    fn rejects_pinned_old_poseidon2_proof() {
        const PROOF_BYTES: &[u8] = include_bytes!("../tests/fixtures/pvm_poseidon2_v0_31.bin");
        let proof = StarkProof::new(PROOF_BYTES.to_vec(), HashFunction::Poseidon2);

        assert!(verify_deferred(&proof, pinned_keccak_root()).is_err());
        assert!(verify_deferred(&proof, TRUE_DIGEST).is_err());
    }

    #[test]
    fn verifies_pinned_current_poseidon2_proof() {
        // This proof uses the b"abc" Keccak witness from the precompile prover tests.
        const PROOF_BYTES: &[u8] = include_bytes!("../tests/fixtures/pvm_poseidon2_v0_35.bin");
        let proof = StarkProof::new(PROOF_BYTES.to_vec(), HashFunction::Poseidon2);

        verify_deferred(&proof, pinned_keccak_root()).expect("current Poseidon2 proof must verify");
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

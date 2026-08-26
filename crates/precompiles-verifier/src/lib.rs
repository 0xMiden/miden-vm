#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub use miden_core::{
    deferred::DeferredRoot,
    proof::{HashFunction, StarkProof},
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

    use miden_core::{deferred::TRUE_DIGEST, proof::MAX_STARK_PROOF_BYTES};

    use super::*;

    #[test]
    fn verify_deferred_enforces_fixed_stark_proof_size_ceiling() {
        let proof = StarkProof::new(vec![0; MAX_STARK_PROOF_BYTES + 1], HashFunction::Blake3_256);

        assert!(matches!(
            verify_deferred(&proof, TRUE_DIGEST),
            Err(VerifyError::ProofTooLarge { size: _, max: MAX_STARK_PROOF_BYTES })
        ));
    }
}

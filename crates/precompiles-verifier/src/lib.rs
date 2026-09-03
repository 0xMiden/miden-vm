#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub use miden_core::{
    deferred::DeferredRoot,
    proof::{HashFunction, StarkProof},
};
pub use miden_precompiles_air::security::ProofSecurityParameters;

#[cfg(any(test, feature = "std"))]
pub(crate) mod ace;
pub(crate) mod ace_constants;
#[cfg(feature = "constants-tools")]
pub mod ace_constants_regen;
#[cfg(feature = "std")]
pub mod masm_verifier;
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) mod pvm_ood_frames;
mod verify;

pub use verify::{VerifyError, verify_deferred};

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::{Felt, Word, deferred::TRUE_DIGEST, proof::MAX_STARK_PROOF_BYTES};

    use super::*;

    #[test]
    fn verifies_pinned_eidos_proof() {
        const PROOF_BYTES: &[u8] = include_bytes!("../tests/fixtures/pvm_eidos_v0_31.bin");
        let root = Word::new(
            [
                7489668467827568877,
                7373524072806342465,
                6727291966695309661,
                1978710426549110171,
            ]
            .map(Felt::new_unchecked),
        );
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

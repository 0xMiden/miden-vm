#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::boxed::Box;

use miden_air::{MidenMultiAir, PublicInputs, Statement, config};
use miden_core::{Felt, deferred::DeferredRoot, field::QuadFelt, proof::MAX_STARK_PROOF_BYTES};
use miden_crypto::stark::{
    StarkConfig, VerifierInstance, lmcs::Lmcs, proof::StarkProofData, verifier::VerifierError,
};
use miden_serde_utils::deserialize_schema_exact;
use serde::de::DeserializeOwned;
use serde_wincode::{SerdeCompat, wincode};

const STARK_SECURITY_LEVEL: u32 = 96;

// RE-EXPORTS
// ================================================================================================
mod exports {
    pub use miden_core::{
        Word,
        program::{ExecutionClaim, KernelDescriptor, ProgramInfo, StackInputs, StackOutputs},
        proof::{
            ExecutionProof, ExecutionProofError, HashFunction, PrecompileProof, StarkProof, VmProof,
        },
    };
    pub mod math {
        pub use miden_core::Felt;
    }
}
pub use exports::*;

pub mod recursive;

// VERIFIER
// ================================================================================================

/// Verifier for deferred and complete Miden execution proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier;

impl Verifier {
    /// Creates a verifier with the canonical verification limits.
    pub const fn new() -> Self {
        Self
    }

    /// Verifies a deferred or complete execution proof against its public claim.
    ///
    /// The VM STARK authenticates the carried precompile root in either state. Deferred witness
    /// data is checked for structural consistency but is not cryptographic evidence and is not
    /// verified as a STARK. Complete proofs additionally verify their aggregate precompile STARK
    /// when present. The outcome reports the minimum security level of the components actually
    /// verified and any authenticated precompile root that remains outstanding.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof structure is invalid or a required STARK rejects.
    pub fn verify(
        &self,
        claim: &ExecutionClaim,
        proof: &ExecutionProof,
    ) -> Result<VerificationOutcome, VerificationError> {
        proof.validate_structure().map_err(VerificationError::InvalidExecutionProof)?;

        match proof {
            ExecutionProof::Deferred { vm, .. } => {
                let security_level = self.verify_vm(claim, vm)?;
                Ok(VerificationOutcome::new(security_level, Some(vm.precompile_root())))
            },
            ExecutionProof::Complete { vm, precompile } => {
                let mut security_level = self.verify_vm(claim, vm)?;
                if let Some(precompile) = precompile {
                    security_level = security_level.min(self.verify_precompile(precompile)?);
                }
                Ok(VerificationOutcome::new(security_level, None))
            },
        }
    }

    fn verify_vm(&self, claim: &ExecutionClaim, proof: &VmProof) -> Result<u32, VerificationError> {
        let program_root = claim.program_root();
        let pub_inputs = PublicInputs::new(
            claim.to_program_info(),
            *claim.stack_inputs(),
            *claim.stack_outputs(),
            proof.precompile_root(),
        );
        let (public_values, aux_inputs) = pub_inputs.to_air_inputs();

        let stark_proof = proof.proof();
        let proof_bytes = stark_proof.bytes();
        let params = config::pcs_params();
        match stark_proof.hash_fn() {
            HashFunction::Blake3_256 => {
                let config = config::blake3_256_config(params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
            HashFunction::Rpo256 => {
                let config = config::rpo_config(params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
            HashFunction::Rpx256 => {
                let config = config::rpx_config(params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
            HashFunction::Poseidon2 => {
                let config = config::poseidon2_config(params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
            HashFunction::Keccak => {
                let config = config::keccak_config(params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
        }
        .map_err(|error| {
            VerificationError::StarkVerificationError(program_root, Box::new(error))
        })?;

        Ok(STARK_SECURITY_LEVEL)
    }

    fn verify_precompile(&self, proof: &PrecompileProof) -> Result<u32, VerificationError> {
        miden_precompiles_prover::verify_deferred(proof.proof(), proof.aggregate_root())?;
        Ok(STARK_SECURITY_LEVEL)
    }

    /// Verifies a multi-AIR STARK proof for the Miden VM statement.
    ///
    /// Pre-seeds the challenger with protocol parameters, AIR public values, and statement
    /// `aux_inputs` (program hash, final deferred root, and kernel-procedure digests). Then
    /// delegates to the lifted multi-AIR verifier.
    fn verify_stark_proof<SC>(
        &self,
        config: &SC,
        public_values: &[Felt],
        aux_inputs: &[Felt],
        proof_bytes: &[u8],
    ) -> Result<(), StarkVerificationError>
    where
        SC: StarkConfig<Felt, QuadFelt>,
        <SC::Lmcs as Lmcs>::Commitment: DeserializeOwned,
    {
        if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
            return Err(StarkVerificationError::ProofTooLarge {
                size: proof_bytes.len(),
                max: MAX_STARK_PROOF_BYTES,
            });
        }

        let proof_encoding_config = wincode::config::Configuration::default()
            .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
        let proof = deserialize_schema_exact::<SerdeCompat<StarkProofData<Felt, QuadFelt, SC>>, _>(
            proof_bytes,
            proof_encoding_config,
        )?;

        let mut challenger = config.challenger();
        config::observe_protocol_params(config.pcs(), &mut challenger);

        // `air_inputs` are the public values read by the AIRs (stack i/o); `aux_inputs` are the
        // statement inputs read during observation/boundary correction. The lifted verifier absorbs
        // both into Fiat-Shamir internally, and derives the multi-AIR ordering deterministically
        // from the proof's per-AIR trace heights.
        let statement = Statement::<Felt, QuadFelt, _>::new(
            MidenMultiAir::new(),
            public_values.to_vec(),
            aux_inputs.to_vec(),
        )
        .map_err(|error| StarkVerificationError::Verifier(VerifierError::from(error)))?;

        VerifierInstance::new(config, &statement, None)
            .expect("Miden AIRs declare no preprocessed columns")
            .verify(&proof, challenger)?;
        Ok(())
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of fully verifying an execution proof and all supplied STARKs.
#[must_use = "verification may leave an outstanding precompile obligation"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationOutcome {
    security_level: u32,
    outstanding_precompile_root: Option<DeferredRoot>,
}

impl VerificationOutcome {
    const fn new(security_level: u32, outstanding_precompile_root: Option<DeferredRoot>) -> Self {
        Self {
            security_level,
            outstanding_precompile_root,
        }
    }

    /// Returns the minimum security level of the STARK components that were verified.
    pub const fn security_level(&self) -> u32 {
        self.security_level
    }

    /// Returns whether this verified outcome has no outstanding precompile obligation.
    ///
    /// Unlike [`ExecutionProof::is_complete`], this result is produced only after full structural
    /// validation and verification of every supplied STARK.
    pub const fn is_complete(&self) -> bool {
        self.outstanding_precompile_root.is_none()
    }

    /// Returns the authenticated precompile root that remains to be proved, if any.
    pub const fn outstanding_precompile_root(&self) -> Option<DeferredRoot> {
        self.outstanding_precompile_root
    }
}

// ERRORS
// ================================================================================================

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to verify VM STARK proof for program with hash {0}")]
    StarkVerificationError(Word, #[source] Box<StarkVerificationError>),
    #[error("execution proof has invalid structure: {0}")]
    InvalidExecutionProof(#[source] ExecutionProofError),
    #[error("failed to verify aggregate precompile STARK proof: {0}")]
    PrecompileStarkVerification(#[from] miden_precompiles_prover::VerifyError),
}

/// Errors that can occur during low-level STARK proof verification.
#[derive(Debug, thiserror::Error)]
pub enum StarkVerificationError {
    #[error("failed to deserialize proof: {0}")]
    Deserialization(#[from] wincode::error::ReadError),
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    #[error(transparent)]
    Verifier(#[from] VerifierError),
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::deferred::{DeferredStateWire, TRUE_DIGEST};

    use super::*;

    #[test]
    fn exact_serde_decoding_rejects_trailing_bytes() {
        let encoding_config = wincode::config::Configuration::default()
            .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
        let mut encoded =
            <SerdeCompat<u8> as wincode::config::Serialize<_>>::serialize(&7, encoding_config)
                .expect("u8 serialization must succeed");
        encoded.push(0);

        let err = deserialize_schema_exact::<SerdeCompat<u8>, _>(&encoded, encoding_config)
            .expect_err("trailing bytes must be rejected");
        assert!(matches!(err, wincode::error::ReadError::TrailingBytes));
    }

    fn claim() -> ExecutionClaim {
        ExecutionClaim::from_program_info(
            ProgramInfo::default(),
            StackInputs::default(),
            StackOutputs::default(),
        )
    }

    fn root(value: u64) -> Word {
        [
            Felt::new(value).unwrap(),
            Felt::new(0).unwrap(),
            Felt::new(0).unwrap(),
            Felt::new(0).unwrap(),
        ]
        .into()
    }

    fn vm_proof(precompile_root: Word) -> VmProof {
        VmProof::from_parts(StarkProof::new(vec![0, 0], HashFunction::Blake3_256), precompile_root)
    }

    fn precompile_proof(roots: Vec<Word>) -> PrecompileProof {
        PrecompileProof::from_parts(StarkProof::new(vec![0, 0], HashFunction::Poseidon2), roots)
            .unwrap()
    }

    fn assert_invalid_shape(proof: &ExecutionProof, expected: ExecutionProofError) {
        let claim = claim();
        let error = Verifier::new().verify(&claim, proof).unwrap_err();
        let VerificationError::InvalidExecutionProof(error) = error else {
            panic!("expected execution proof structure error")
        };
        assert_eq!(error, expected);
    }

    #[test]
    fn verifier_revalidates_public_variants_before_stark_verification() {
        let precompile_root = root(1);

        assert_invalid_shape(
            &ExecutionProof::Deferred {
                vm: vm_proof(TRUE_DIGEST),
                precompile: DeferredStateWire::default(),
            },
            ExecutionProofError::DeferredTrueRoot,
        );
        assert_invalid_shape(
            &ExecutionProof::Complete {
                vm: vm_proof(precompile_root),
                precompile: None,
            },
            ExecutionProofError::MissingPrecompileProof,
        );
        assert_invalid_shape(
            &ExecutionProof::Complete {
                vm: vm_proof(TRUE_DIGEST),
                precompile: Some(precompile_proof(vec![precompile_root])),
            },
            ExecutionProofError::UnexpectedPrecompileProof,
        );
        assert_invalid_shape(
            &ExecutionProof::Complete {
                vm: vm_proof(root(99)),
                precompile: Some(precompile_proof(vec![precompile_root])),
            },
            ExecutionProofError::InsufficientPrecompileRootCoverage,
        );
    }

    #[test]
    fn malformed_execution_proof_round_trips_but_fails_verification() {
        let malformed = ExecutionProof::Complete { vm: vm_proof(root(1)), precompile: None };
        let bytes = malformed.to_bytes();
        let decoded = ExecutionProof::read_from_bytes(&bytes).unwrap();

        assert_eq!(decoded.to_bytes(), bytes);
        assert_invalid_shape(&decoded, ExecutionProofError::MissingPrecompileProof);
    }

    #[test]
    fn verification_outcome_reports_security_and_outstanding_root() {
        let outstanding_root = root(7);
        let deferred = VerificationOutcome::new(STARK_SECURITY_LEVEL, Some(outstanding_root));
        assert_eq!(deferred.security_level(), STARK_SECURITY_LEVEL);
        assert!(!deferred.is_complete());
        assert_eq!(deferred.outstanding_precompile_root(), Some(outstanding_root));

        let complete = VerificationOutcome::new(STARK_SECURITY_LEVEL, None);
        assert_eq!(complete.security_level(), STARK_SECURITY_LEVEL);
        assert!(complete.is_complete());
        assert_eq!(complete.outstanding_precompile_root(), None);
    }

    #[test]
    fn verifier_enforces_fixed_stark_proof_size_ceiling() {
        let proof = ExecutionProof::Complete {
            vm: VmProof::from_parts(
                StarkProof::new(vec![0; MAX_STARK_PROOF_BYTES + 1], HashFunction::Blake3_256),
                TRUE_DIGEST,
            ),
            precompile: None,
        };

        let error = Verifier::new().verify(&claim(), &proof).unwrap_err();
        let VerificationError::StarkVerificationError(_, source) = error else {
            panic!("expected oversized VM STARK proof to be rejected")
        };
        assert!(matches!(
            *source,
            StarkVerificationError::ProofTooLarge {
                size,
                max: MAX_STARK_PROOF_BYTES,
            } if size == MAX_STARK_PROOF_BYTES + 1
        ));
    }

    #[test]
    fn proof_encoding_config_rejects_oversized_native_vec_preallocation() {
        let proof_encoding_config = wincode::config::Configuration::default()
            .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
        let element_count = MAX_STARK_PROOF_BYTES + 1;
        let mut length_prefix = Vec::new();

        <usize as wincode::config::Serialize<_>>::serialize_into(
            &mut length_prefix,
            &element_count,
            proof_encoding_config,
        )
        .unwrap();
        let err = <Vec<u8> as wincode::config::Deserialize<_>>::deserialize(
            &length_prefix,
            proof_encoding_config,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            wincode::error::ReadError::PreallocationSizeLimit { needed, limit }
                if needed == element_count && limit == MAX_STARK_PROOF_BYTES
        ));
    }
}

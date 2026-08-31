#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::boxed::Box;

use miden_air::{MidenMultiAir, PublicInputs, Statement, config, security};
use miden_core::{
    Felt,
    deferred::{DeferredRoot, MAX_PRECOMPILE_ROOTS, TRUE_DIGEST, fold_deferred_root},
    field::QuadFelt,
    proof::MAX_STARK_PROOF_BYTES,
};
use miden_crypto::stark::{
    StarkConfig, VerifierInstance, lmcs::Lmcs, proof::StarkProofData, verifier::VerifierError,
};
use miden_serde_utils::deserialize_schema_exact;
use serde::de::DeserializeOwned;
use serde_wincode::{SerdeCompat, wincode};

// RE-EXPORTS
// ================================================================================================
mod exports {
    pub use miden_core::{
        Word,
        program::{ExecutionClaim, KernelDescriptor, ProgramInfo, StackInputs, StackOutputs},
        proof::{ExecutionProof, HashFunction, PrecompileProof, StarkProof, VmProof},
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
    /// The VM STARK authenticates the carried precompile root in either state. Deferred wire data
    /// is neither hydrated nor validated by the verifier. Complete proofs additionally verify the
    /// aggregate precompile STARK when the VM authenticated outstanding work. The outcome reports
    /// the minimum security level of the components actually verified and any authenticated
    /// precompile root that remains outstanding.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof structure is invalid or a required STARK rejects.
    pub fn verify(
        &self,
        claim: &ExecutionClaim,
        proof: &ExecutionProof,
    ) -> Result<VerificationOutcome, VerificationError> {
        let (vm, outstanding_root, precompile) = match proof {
            ExecutionProof::Deferred { vm, .. } => {
                let root = vm.precompile_root;
                if root == TRUE_DIGEST {
                    return Err(VerificationError::DeferredTrueRoot);
                }
                (vm, Some(root), None)
            },
            ExecutionProof::Complete { vm, precompile } => {
                let vm_root = vm.precompile_root;
                match precompile {
                    None if vm_root != TRUE_DIGEST => {
                        return Err(VerificationError::MissingPrecompileProof);
                    },
                    None => {},
                    Some(precompile) => self.validate_precompile(precompile, vm_root)?,
                }
                (vm, None, precompile.as_ref())
            },
        };

        self.preflight_vm_stark(claim, vm)?;
        if let Some(precompile) = precompile {
            self.preflight_precompile_stark(precompile)?;
        }

        let mut security_level = self.verify_vm(claim, vm)?;
        if let Some(precompile) = precompile {
            security_level =
                security_level.min(self.verify_precompile(precompile, vm.precompile_root)?);
        }

        Ok(VerificationOutcome::new(security_level, outstanding_root))
    }

    /// Verifies a precompile proof against an expected outstanding execution root.
    ///
    /// The expected root may occur anywhere in the proof's ordered constituent roots. All roots,
    /// including compatible extras and duplicate occurrences, are folded from the first root to
    /// derive the aggregate precompile STARK statement. On success, this returns the authenticated
    /// security level of the precompile STARK.
    ///
    /// The expected root and every constituent root must differ from [`TRUE_DIGEST`].
    ///
    /// # Errors
    ///
    /// Returns an error if the artifact shape or expected-root coverage is invalid, or if the
    /// precompile STARK rejects.
    pub fn verify_precompile(
        &self,
        proof: &PrecompileProof,
        expected_root: DeferredRoot,
    ) -> Result<u32, VerificationError> {
        self.validate_precompile(proof, expected_root)?;
        self.preflight_precompile_stark(proof)?;

        let aggregate_root = proof
            .roots
            .iter()
            .copied()
            .reduce(fold_deferred_root)
            .expect("precompile roots were checked to be non-empty");
        Ok(miden_precompiles_verifier::verify_deferred(&proof.proof, aggregate_root)?)
    }

    fn validate_precompile(
        &self,
        proof: &PrecompileProof,
        expected_root: DeferredRoot,
    ) -> Result<(), VerificationError> {
        let roots = &proof.roots;
        if roots.is_empty() {
            return Err(VerificationError::EmptyPrecompileRoots);
        }
        if roots.len() > MAX_PRECOMPILE_ROOTS {
            return Err(VerificationError::TooManyPrecompileRoots {
                roots: roots.len(),
                max: MAX_PRECOMPILE_ROOTS,
            });
        }
        if let Some(index) = roots.iter().position(|root| *root == TRUE_DIGEST) {
            return Err(VerificationError::SettledPrecompileRoot { index });
        }
        if expected_root == TRUE_DIGEST {
            return Err(VerificationError::UnexpectedPrecompileProof);
        }
        if !roots.contains(&expected_root) {
            return Err(VerificationError::InsufficientPrecompileRootCoverage);
        }

        Ok(())
    }

    fn preflight_vm_stark(
        &self,
        claim: &ExecutionClaim,
        proof: &VmProof,
    ) -> Result<(), VerificationError> {
        let size = proof.proof.bytes().len();
        if size > MAX_STARK_PROOF_BYTES {
            return Err(VerificationError::StarkVerificationError(
                claim.program_root(),
                Box::new(StarkVerificationError::ProofTooLarge {
                    size,
                    max: MAX_STARK_PROOF_BYTES,
                }),
            ));
        }
        Ok(())
    }

    fn preflight_precompile_stark(&self, proof: &PrecompileProof) -> Result<(), VerificationError> {
        let size = proof.proof.bytes().len();
        if size > MAX_STARK_PROOF_BYTES {
            return Err(VerificationError::PrecompileStarkVerification(
                miden_precompiles_verifier::VerifyError::ProofTooLarge {
                    size,
                    max: MAX_STARK_PROOF_BYTES,
                },
            ));
        }
        Ok(())
    }

    /// Verifies the Miden VM STARK proof and returns its conjectured security level in bits.
    ///
    /// The level depends on the proof's largest AIR trace height, its commitment scheme's column
    /// alignment (which varies by hash function), and its kernel procedure count (bound through
    /// the kernel witness) as well as its PCS parameters, so it is computed from the verified
    /// proof and claim rather than fixed by the parameter preset.
    fn verify_vm(&self, claim: &ExecutionClaim, proof: &VmProof) -> Result<u32, VerificationError> {
        let program_root = claim.program_root();
        let pub_inputs = PublicInputs::new(
            claim.to_program_info(),
            *claim.stack_inputs(),
            *claim.stack_outputs(),
            proof.precompile_root,
        );
        let (public_values, aux_inputs) = pub_inputs.to_air_inputs();

        let stark = &proof.proof;
        let proof_bytes = stark.bytes();
        let params = config::pcs_params();
        let num_kernel_procedures = claim.kernel().proc_hashes().len() as u32;
        match stark.hash_fn() {
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
        .map_err(|error| VerificationError::StarkVerificationError(program_root, Box::new(error)))
        .map(|(log_max_height, alignment)| {
            security::conjectured_security_level_for_alignment(
                params.num_queries() as u32,
                params.query_pow_bits() as u32,
                params.deep_pow_bits() as u32,
                params.folding_pow_bits() as u32,
                log_max_height,
                num_kernel_procedures,
                alignment,
            )
        })
    }

    /// Verifies a multi-AIR STARK proof for the Miden VM statement, returning the proof's largest
    /// AIR log height and the LMCS's column alignment for grading.
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
    ) -> Result<(u32, usize), StarkVerificationError>
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

        let log_max_height =
            u32::from(proof.log_trace_heights().iter().copied().max().unwrap_or(0));
        Ok((log_max_height, config.lmcs().alignment()))
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
    /// This result is produced only after verifier-owned shape validation and verification of every
    /// required STARK.
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
    #[error("a deferred execution proof cannot authenticate TRUE_DIGEST")]
    DeferredTrueRoot,
    #[error("a precompile proof must contain at least one constituent root")]
    EmptyPrecompileRoots,
    #[error("precompile proof contains too many roots: found {roots}, maximum is {max}")]
    TooManyPrecompileRoots { roots: usize, max: usize },
    #[error("precompile proof constituent root at index {index} is already settled")]
    SettledPrecompileRoot { index: usize },
    #[error("a precompile proof was supplied for an already settled VM obligation")]
    UnexpectedPrecompileProof,
    #[error("a precompile proof is required for a non-empty VM obligation")]
    MissingPrecompileProof,
    #[error("precompile proof roots do not cover the VM obligation")]
    InsufficientPrecompileRootCoverage,
    #[error("failed to verify aggregate precompile STARK proof: {0}")]
    PrecompileStarkVerification(#[from] miden_precompiles_verifier::VerifyError),
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

    use miden_core::deferred::DeferredStateWire;

    use super::*;

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
        VmProof {
            proof: StarkProof::new(vec![0, 0], HashFunction::Blake3_256),
            precompile_root,
        }
    }

    fn precompile_proof(roots: Vec<Word>) -> PrecompileProof {
        PrecompileProof {
            proof: StarkProof::new(vec![0, 0], HashFunction::Poseidon2),
            roots,
        }
    }

    fn complete(vm_root: Word, roots: Option<Vec<Word>>) -> ExecutionProof {
        ExecutionProof::Complete {
            vm: vm_proof(vm_root),
            precompile: roots.map(precompile_proof),
        }
    }

    #[test]
    fn verifier_owns_shape_policy() {
        type CheckError = fn(VerificationError) -> bool;

        let required = root(1);
        let cases: Vec<(ExecutionProof, CheckError)> = vec![
            (
                ExecutionProof::Deferred {
                    vm: vm_proof(TRUE_DIGEST),
                    precompile: DeferredStateWire::default(),
                },
                |error| matches!(error, VerificationError::DeferredTrueRoot),
            ),
            (complete(required, Some(vec![])), |error| {
                matches!(error, VerificationError::EmptyPrecompileRoots)
            }),
            (complete(required, Some(vec![required; MAX_PRECOMPILE_ROOTS + 1])), |error| {
                matches!(
                    error,
                    VerificationError::TooManyPrecompileRoots { roots, max }
                        if roots == MAX_PRECOMPILE_ROOTS + 1 && max == MAX_PRECOMPILE_ROOTS
                )
            }),
            (complete(required, Some(vec![root(2), TRUE_DIGEST, required])), |error| {
                matches!(error, VerificationError::SettledPrecompileRoot { index: 1 })
            }),
            (complete(required, None), |error| {
                matches!(error, VerificationError::MissingPrecompileProof)
            }),
            (complete(TRUE_DIGEST, Some(vec![required])), |error| {
                matches!(error, VerificationError::UnexpectedPrecompileProof)
            }),
            (complete(root(99), Some(vec![required])), |error| {
                matches!(error, VerificationError::InsufficientPrecompileRootCoverage)
            }),
        ];

        for (proof, check) in cases {
            let error = Verifier::new().verify(&claim(), &proof).unwrap_err();
            assert!(check(error));
        }
    }

    #[test]
    fn precompile_verifier_owns_artifact_shape_policy() {
        type CheckError = fn(VerificationError) -> bool;

        let required = root(1);
        let cases: Vec<(PrecompileProof, Word, CheckError)> = vec![
            (precompile_proof(vec![]), required, |error| {
                matches!(error, VerificationError::EmptyPrecompileRoots)
            }),
            (precompile_proof(vec![required; MAX_PRECOMPILE_ROOTS + 1]), required, |error| {
                matches!(
                    error,
                    VerificationError::TooManyPrecompileRoots { roots, max }
                        if roots == MAX_PRECOMPILE_ROOTS + 1 && max == MAX_PRECOMPILE_ROOTS
                )
            }),
            (precompile_proof(vec![required, TRUE_DIGEST]), required, |error| {
                matches!(error, VerificationError::SettledPrecompileRoot { index: 1 })
            }),
            (precompile_proof(vec![required]), TRUE_DIGEST, |error| {
                matches!(error, VerificationError::UnexpectedPrecompileProof)
            }),
            (precompile_proof(vec![required]), root(99), |error| {
                matches!(error, VerificationError::InsufficientPrecompileRootCoverage)
            }),
        ];

        for (proof, expected_root, check) in cases {
            let error = Verifier::new().verify_precompile(&proof, expected_root).unwrap_err();
            assert!(check(error));
        }
    }

    #[test]
    fn oversized_precompile_stark_is_rejected_before_vm_stark_verification() {
        let required = root(1);
        let proof = ExecutionProof::Complete {
            vm: vm_proof(required),
            precompile: Some(PrecompileProof {
                proof: StarkProof::new(vec![0; MAX_STARK_PROOF_BYTES + 1], HashFunction::Poseidon2),
                roots: vec![required],
            }),
        };

        let error = Verifier::new().verify(&claim(), &proof).unwrap_err();
        assert!(matches!(
            error,
            VerificationError::PrecompileStarkVerification(
                miden_precompiles_verifier::VerifyError::ProofTooLarge { size, max }
            ) if size == MAX_STARK_PROOF_BYTES + 1 && max == MAX_STARK_PROOF_BYTES
        ));
    }

    #[test]
    fn malformed_transport_round_trips_then_verifier_rejects_it() {
        let malformed = complete(root(1), Some(vec![]));
        let bytes = malformed.to_bytes();
        let decoded = ExecutionProof::read_from_bytes(&bytes).unwrap();

        assert_eq!(decoded.to_bytes(), bytes);
        assert!(matches!(
            Verifier::new().verify(&claim(), &decoded),
            Err(VerificationError::EmptyPrecompileRoots)
        ));
    }

    #[test]
    fn verifier_rejects_oversized_directly_constructed_vm_proof() {
        let proof = ExecutionProof::Complete {
            vm: VmProof {
                proof: StarkProof::new(
                    vec![0; MAX_STARK_PROOF_BYTES + 1],
                    HashFunction::Blake3_256,
                ),
                precompile_root: TRUE_DIGEST,
            },
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
    fn ordered_root_coverage_reaches_vm_stark_verification() {
        let vm_root = root(2);
        let proof = complete(vm_root, Some(vec![root(1), vm_root, root(3)]));

        let error = Verifier::new().verify(&claim(), &proof).unwrap_err();
        assert!(matches!(error, VerificationError::StarkVerificationError(..)));
    }
}

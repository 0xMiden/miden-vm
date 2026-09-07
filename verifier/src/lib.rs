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
    proof::{CURRENT_PVM_VERIFIER_ROOT, CURRENT_VM_VERIFIER_ROOT, MAX_STARK_PROOF_BYTES},
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
        proof::{
            ExecutionProof, ExecutionProofCompatibility, ExecutionProofCompatibilityError,
            HashFunction, PrecompileProof, PrecompileStatus, StarkProof, VmProof,
        },
    };
    pub mod math {
        pub use miden_core::Felt;
    }
}
pub use exports::*;
pub use miden_air::security::{
    AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, SecurityReport,
    SecurityTerm,
};

pub mod recursive;

struct VerifierSupport {
    format: u8,
    accepted_vm_roots: &'static [Word],
    accepted_pvm_roots: &'static [Word],
}

impl VerifierSupport {
    fn check(&self, proof: &ExecutionProof) -> Result<(), VerificationError> {
        let compatibility = proof.compatibility();
        if compatibility.format() != self.format {
            return Err(VerificationError::UnsupportedProofFormat(compatibility.format()));
        }
        if !roots_overlap(compatibility.vm_verifier_roots(), self.accepted_vm_roots) {
            return Err(VerificationError::IncompatibleVmVerifier);
        }
        if !roots_overlap(compatibility.pvm_verifier_roots(), self.accepted_pvm_roots) {
            return Err(VerificationError::IncompatiblePvmVerifier);
        }

        Ok(())
    }
}

const VERIFIER_SUPPORT_V1: VerifierSupport = VerifierSupport {
    format: ExecutionProofCompatibility::FORMAT_V1,
    accepted_vm_roots: &[CURRENT_VM_VERIFIER_ROOT],
    accepted_pvm_roots: &[CURRENT_PVM_VERIFIER_ROOT],
};

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

    /// Returns the compatibility declared by proofs produced by the current prover.
    pub fn proof_compatibility() -> ExecutionProofCompatibility {
        ExecutionProofCompatibility::current()
    }

    /// Verifies a deferred or complete versioned execution proof against its public claim.
    ///
    /// The VM STARK authenticates the carried precompile root in either state. For a deferred
    /// proof, the verifier does not inspect the carried `DeferredStateWire`; it verifies the VM
    /// STARK and returns the authenticated root as an outstanding obligation. The wire is
    /// prover-side data and is validated separately when converted into a precompile witness.
    /// Complete proofs that contain precompile work additionally verify the aggregate precompile
    /// STARK against the VM-authenticated root.
    ///
    /// The outcome reports the authenticated security parameters of the components actually
    /// verified and any precompile root that remains outstanding. Callers can use
    /// [`ProofSecurityParameters::conjectured_security_level`] to estimate each verified proof's
    /// conjectured security level, then apply their own acceptance policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof structure is invalid or a required STARK rejects.
    pub fn verify(
        &self,
        claim: &ExecutionClaim,
        proof: &ExecutionProof,
    ) -> Result<VerificationOutcome, VerificationError> {
        match proof.compatibility().format() {
            ExecutionProofCompatibility::FORMAT_V1 => {
                VERIFIER_SUPPORT_V1.check(proof)?;
                self.verify_v1(claim, proof)
            },
            format => Err(VerificationError::UnsupportedProofFormat(format)),
        }
    }

    /// Verifies an execution proof encoded with transport format 1.
    fn verify_v1(
        &self,
        claim: &ExecutionClaim,
        proof: &ExecutionProof,
    ) -> Result<VerificationOutcome, VerificationError> {
        let vm = proof.vm();
        let (outstanding_root, precompile) = match proof.precompile() {
            PrecompileStatus::Deferred(_) => {
                let root = vm.precompile_root;
                if root == TRUE_DIGEST {
                    return Err(VerificationError::DeferredTrueRoot);
                }
                (Some(root), None)
            },
            PrecompileStatus::Empty => {
                let vm_root = vm.precompile_root;
                if vm_root != TRUE_DIGEST {
                    return Err(VerificationError::MissingPrecompileProof);
                }
                (None, None)
            },
            PrecompileStatus::Proven(precompile) => {
                self.validate_precompile(precompile, vm.precompile_root)?;
                (None, Some(precompile))
            },
        };

        self.preflight_vm_stark(claim, vm)?;
        if let Some(precompile) = precompile {
            self.preflight_precompile_stark(precompile)?;
        }

        let vm_security_parameters = self.verify_vm(claim, vm)?;
        let precompile_security_parameters = precompile
            .map(|precompile| self.verify_precompile(precompile, vm.precompile_root))
            .transpose()?;

        Ok(VerificationOutcome::new(
            vm_security_parameters,
            precompile_security_parameters,
            outstanding_root,
        ))
    }

    /// Verifies a precompile proof against an expected outstanding execution root.
    ///
    /// The expected root may occur anywhere in the proof's ordered constituent roots. All roots,
    /// including compatible extras and duplicate occurrences, are folded from the first root to
    /// derive the aggregate precompile STARK statement. On success, this returns the precompile
    /// STARK's authenticated security parameters.
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
    ) -> Result<ProofSecurityParameters, VerificationError> {
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

    /// Verifies the Miden VM STARK proof and returns its authenticated security parameters.
    ///
    /// The returned parameters include the largest AIR trace height, the DEEP term count implied
    /// by the commitment scheme's column alignment, and the lookup boundary terms implied by the
    /// authenticated kernel. The PCS parameters and commitment collision resistance come from the
    /// configuration used to verify the proof.
    fn verify_vm(
        &self,
        claim: &ExecutionClaim,
        proof: &VmProof,
    ) -> Result<ProofSecurityParameters, VerificationError> {
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
        let pcs_params = config::pcs_params();
        let num_kernel_procedures = claim.kernel().proc_hashes().len() as u32;
        match stark.hash_fn() {
            HashFunction::Blake3_256 => {
                let config = config::blake3_256_config(pcs_params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
            HashFunction::Rpo256 => {
                let config = config::rpo_config(pcs_params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
            HashFunction::Rpx256 => {
                let config = config::rpx_config(pcs_params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
            HashFunction::Poseidon2 => {
                let config = config::poseidon2_config(pcs_params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
            HashFunction::Keccak => {
                let config = config::keccak_config(pcs_params, config::RELATION_DIGEST);
                self.verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
            },
        }
        .map_err(|error| VerificationError::StarkVerificationError(program_root, Box::new(error)))
        .map(|(log_max_height, alignment)| {
            security::proof_security_parameters(
                &pcs_params,
                log_max_height,
                num_kernel_procedures,
                alignment,
                stark.hash_fn().collision_resistance(),
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
    vm_security_parameters: ProofSecurityParameters,
    precompile_security_parameters: Option<ProofSecurityParameters>,
    outstanding_precompile_root: Option<DeferredRoot>,
}

impl VerificationOutcome {
    const fn new(
        vm_security_parameters: ProofSecurityParameters,
        precompile_security_parameters: Option<ProofSecurityParameters>,
        outstanding_precompile_root: Option<DeferredRoot>,
    ) -> Self {
        Self {
            vm_security_parameters,
            precompile_security_parameters,
            outstanding_precompile_root,
        }
    }

    /// Returns the authenticated security parameters of the verified MVM proof.
    pub const fn vm_security_parameters(&self) -> &ProofSecurityParameters {
        &self.vm_security_parameters
    }

    /// Returns the authenticated security parameters if verification included a PVM proof.
    pub const fn precompile_security_parameters(&self) -> Option<&ProofSecurityParameters> {
        self.precompile_security_parameters.as_ref()
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
    #[error("execution proof format {0} is not supported")]
    UnsupportedProofFormat(u8),
    #[error("execution proof does not name a compatible VM verifier")]
    IncompatibleVmVerifier,
    #[error("execution proof does not name a compatible PVM verifier")]
    IncompatiblePvmVerifier,
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

// HELPER FUNCTIONS
// ================================================================================================

fn roots_overlap(proof_roots: &[Word], accepted_roots: &[Word]) -> bool {
    proof_roots.iter().any(|root| accepted_roots.contains(root))
}

// TESTS
// ================================================================================================

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
        let precompile = match roots {
            Some(roots) => PrecompileStatus::Proven(precompile_proof(roots)),
            None => PrecompileStatus::Empty,
        };
        ExecutionProof::new(vm_proof(vm_root), precompile)
    }

    #[test]
    fn verifier_owns_shape_policy() {
        type CheckError = fn(VerificationError) -> bool;

        let required = root(1);
        let cases: Vec<(ExecutionProof, CheckError)> = vec![
            (
                ExecutionProof::new(
                    vm_proof(TRUE_DIGEST),
                    PrecompileStatus::Deferred(DeferredStateWire::default()),
                ),
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
        let proof = ExecutionProof::new(
            vm_proof(required),
            PrecompileStatus::Proven(PrecompileProof {
                proof: StarkProof::new(vec![0; MAX_STARK_PROOF_BYTES + 1], HashFunction::Poseidon2),
                roots: vec![required],
            }),
        );

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
        let proof = ExecutionProof::new(
            VmProof {
                proof: StarkProof::new(
                    vec![0; MAX_STARK_PROOF_BYTES + 1],
                    HashFunction::Blake3_256,
                ),
                precompile_root: TRUE_DIGEST,
            },
            PrecompileStatus::Empty,
        );

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

    #[test]
    fn verifier_requires_compatible_vm_and_pvm_roots() {
        let proof = complete(TRUE_DIGEST, None);
        let incompatible_vm = ExecutionProof::from_parts(
            ExecutionProofCompatibility::new(
                vec![root(100)],
                VERIFIER_SUPPORT_V1.accepted_pvm_roots.to_vec(),
            )
            .unwrap(),
            proof.vm().clone(),
            proof.precompile().clone(),
        );
        let incompatible_pvm = ExecutionProof::from_parts(
            ExecutionProofCompatibility::new(
                VERIFIER_SUPPORT_V1.accepted_vm_roots.to_vec(),
                vec![root(200)],
            )
            .unwrap(),
            proof.vm().clone(),
            proof.precompile().clone(),
        );

        assert!(matches!(
            Verifier::new().verify(&claim(), &incompatible_vm),
            Err(VerificationError::IncompatibleVmVerifier)
        ));
        assert!(matches!(
            Verifier::new().verify(&claim(), &incompatible_pvm),
            Err(VerificationError::IncompatiblePvmVerifier)
        ));
    }

    #[test]
    fn current_proof_compatibility_excludes_verifier_history() {
        const OLD_VM_ROOT: Word = Word::new([
            Felt::new_unchecked(1),
            Felt::new_unchecked(0),
            Felt::new_unchecked(0),
            Felt::new_unchecked(0),
        ]);
        const OLD_PVM_ROOT: Word = Word::new([
            Felt::new_unchecked(2),
            Felt::new_unchecked(0),
            Felt::new_unchecked(0),
            Felt::new_unchecked(0),
        ]);
        const SUPPORT: VerifierSupport = VerifierSupport {
            format: ExecutionProofCompatibility::FORMAT_V1,
            accepted_vm_roots: &[OLD_VM_ROOT, CURRENT_VM_VERIFIER_ROOT],
            accepted_pvm_roots: &[OLD_PVM_ROOT, CURRENT_PVM_VERIFIER_ROOT],
        };

        let proof = complete(TRUE_DIGEST, None);

        assert_eq!(proof.compatibility().vm_verifier_roots(), &[CURRENT_VM_VERIFIER_ROOT]);
        assert_eq!(proof.compatibility().pvm_verifier_roots(), &[CURRENT_PVM_VERIFIER_ROOT]);

        let old_compatible = ExecutionProof::from_parts(
            ExecutionProofCompatibility::new(vec![OLD_VM_ROOT], vec![OLD_PVM_ROOT]).unwrap(),
            proof.vm().clone(),
            proof.precompile().clone(),
        );
        assert!(SUPPORT.check(&old_compatible).is_ok());
    }
}

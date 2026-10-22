//! Advice construction for the in-VM PVM STARK verifier.
//!
//! This module parses an Eidos PVM proof into the exact stack, Merkle-store, and advice-map
//! inputs consumed by `miden::core::sys::pvm::verify_proof`. The caller supplies the deferred claim
//! on the operand stack; its root is the PVM statement.

mod ace;
mod ace_constants;

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use miden_air::precompile::{
    ChipletAir, ChipletMultiAir, NUM_CHIPLETS, policy::precompile_pcs_params,
};
use miden_core::{
    Felt, Word,
    advice::AdviceInputs,
    deferred::{DeferredClaim, MAX_PRECOMPILE_ROOTS},
    field::QuadFelt,
    proof::{
        HashFunction, MAX_STARK_PROOF_BYTES, PrecompileProof, StarkProof as SerializedStarkProof,
    },
};
use miden_serde_utils::deserialize_schema_exact;
use miden_stark::{
    StarkConfig, VerifierInstance,
    air::{LiftedAir, Statement},
    config::observe_protocol_params,
    proof::{StarkProof, StarkProofData},
    recursive::advice::{
        AdviceError, MerkleAdvice, append_proof_payload, build_merkle_advice, package_for_request,
        security_parameter_words,
    },
};
use serde_wincode::SerdeCompat;

use self::ace::{proof_order_from_log_heights, shared_pvm_recursive_circuit};
use crate::setup::{
    commitments,
    config::{EidosConfig, eidos_config},
};

type Challenge = QuadFelt;
type EidosLmcs = <EidosConfig as StarkConfig<Felt, Challenge>>::Lmcs;

/// Inputs for verifying a PVM proof in MASM, stored under its request key.
///
/// The consumer supplies the expected deferred root on the operand stack, fetches the proof
/// stream from the advice map using the request key, and invokes `exec.pvm::verify_proof`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PvmRecursiveVerifierInputs {
    advice: AdviceInputs,
    claim_commitment: Word,
}

impl PvmRecursiveVerifierInputs {
    /// Builds a proof package addressed by the verifier and claim commitments.
    ///
    /// Uses [`PrecompileProof::aggregate_root`] as the proof's claim. The MASM caller must compute
    /// the expected root from the deferred work it needs to settle and pass that root to
    /// `pvm::verify_proof`. The STARK proof must use Eidos.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof cannot be converted into verifier advice.
    pub fn for_request(
        verifier_root: Word,
        proof: &PrecompileProof,
    ) -> Result<Self, PvmRecursiveVerifierInputsError> {
        if proof.roots.len() > MAX_PRECOMPILE_ROOTS {
            return Err(PvmRecursiveVerifierInputsError::UnsupportedRootCount {
                roots: proof.roots.len(),
            });
        }
        let root = proof
            .aggregate_root()
            .ok_or(PvmRecursiveVerifierInputsError::UnsupportedRootCount { roots: 0 })?;
        let claim = DeferredClaim::new(root);
        let advice = build_verifier_advice(&proof.proof, claim)?;
        Ok(Self::package(verifier_root, claim, advice))
    }

    /// Returns the packaged verifier advice.
    pub fn advice(&self) -> &AdviceInputs {
        &self.advice
    }

    /// Returns the claim commitment supplied to the verifier.
    pub fn claim_commitment(&self) -> Word {
        self.claim_commitment
    }

    /// Consumes these inputs into their packaged advice and claim commitment.
    pub fn into_parts(self) -> (AdviceInputs, Word) {
        (self.advice, self.claim_commitment)
    }

    fn package(verifier_root: Word, claim: DeferredClaim, advice: AdviceInputs) -> Self {
        let claim_commitment = claim.commitment();
        let advice = package_for_request(verifier_root, claim_commitment, advice);
        Self { advice, claim_commitment }
    }
}

/// Failures while parsing and adapting a PVM proof for the MASM verifier.
#[derive(Debug, thiserror::Error)]
pub enum PvmRecursiveVerifierInputsError {
    /// The constituent root list is empty or exceeds the library limit.
    #[error("precompile proof requires 1..={MAX_PRECOMPILE_ROOTS} roots, found {roots}")]
    UnsupportedRootCount { roots: usize },
    /// The MASM verifier implements the native Eidos transcript only.
    #[error("the PVM MASM verifier supports Eidos proofs only")]
    UnsupportedHashFunction,
    /// The serialized proof exceeds the adapter's allocation limit.
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    /// The serialized proof could not be decoded.
    #[error("proof deserialization error: {0}")]
    ProofDeserialization(String),
    /// The proof transcript could not be parsed against the PVM statement and setup.
    #[error(transparent)]
    Transcript(#[from] miden_stark::VerifierError),
    /// The trusted setup commitment did not match the PVM AIR declaration.
    #[error(transparent)]
    Preprocessed(#[from] miden_stark::PreprocessedValidationError),
    /// The parsed proof does not have the fixed twelve-chiplet shape expected by the wrapper.
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
}

impl From<AdviceError> for PvmRecursiveVerifierInputsError {
    fn from(error: AdviceError) -> Self {
        let message = match error {
            // Preserve the PVM adapter's existing public error description.
            AdviceError::InvalidMerklePaths => "invalid Merkle paths",
            error => error.message(),
        };
        Self::InvalidProofShape(message)
    }
}

fn build_verifier_advice(
    proof: &SerializedStarkProof,
    claim: DeferredClaim,
) -> Result<AdviceInputs, PvmRecursiveVerifierInputsError> {
    if proof.hash_fn() != HashFunction::Eidos {
        return Err(PvmRecursiveVerifierInputsError::UnsupportedHashFunction);
    }
    if proof.bytes().len() > MAX_STARK_PROOF_BYTES {
        return Err(PvmRecursiveVerifierInputsError::ProofTooLarge {
            size: proof.bytes().len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let config = eidos_config(
        precompile_pcs_params(),
        ace_constants::PVM_RELATION_DIGEST.map(Felt::new_unchecked),
    );
    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof_data: StarkProofData<Felt, Challenge, EidosConfig> =
        deserialize_schema_exact::<SerdeCompat<StarkProofData<Felt, Challenge, EidosConfig>>, _>(
            proof.bytes(),
            proof_encoding_config,
        )
        .map_err(|err| PvmRecursiveVerifierInputsError::ProofDeserialization(err.to_string()))?;

    let public_root = claim.root();
    let statement = Statement::new(
        ChipletMultiAir::new(),
        vec![(ChipletAir::TRANSCRIPT_EVAL_INDEX, public_root.as_elements().to_vec())],
        Vec::new(),
    )
    .map_err(|_| PvmRecursiveVerifierInputsError::InvalidProofShape("invalid PVM statement"))?;
    let verifier_instance =
        VerifierInstance::new(&config, &statement, Some(commitments::EIDOS.into()))?;
    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);
    let (stark, _digest) = StarkProof::from_data(&verifier_instance, &proof_data, challenger)?;

    build_advice(&config, &stark)
}

fn build_advice(
    config: &EidosConfig,
    stark: &StarkProof<Challenge, EidosLmcs>,
) -> Result<AdviceInputs, PvmRecursiveVerifierInputsError> {
    let log_heights: [u8; NUM_CHIPLETS] = stark.log_trace_heights().try_into().map_err(|_| {
        PvmRecursiveVerifierInputsError::InvalidProofShape("unexpected AIR-height count")
    })?;
    // Fixed-height instances must arrive at exactly their pinned height: the MASM verifier
    // opens the setup tree at the matching fixed depth, so any other value would let the
    // recursive and native verifiers disagree on proof shape.
    for (air, &log_height) in ChipletAir::all().iter().zip(&log_heights) {
        if air.fixed_log_height().is_some_and(|fixed| u32::from(log_height) != fixed) {
            return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
                "fixed-height AIR arrived at a different trace height",
            ));
        }
    }
    if stark.all_aux_values.len() != NUM_CHIPLETS {
        return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
            "unexpected number of aux-final groups",
        ));
    }
    // The MASM ingest scatters each chiplet's data from proof order to the canonical address read
    // by the circuit. Validate each group width and the proof-carried permutation against the
    // native stable (height, instance-index) order.
    let proof_order = proof_order_from_log_heights(&log_heights);
    let airs = ChipletAir::all();
    if stark.all_aux_values.iter().zip(proof_order).any(|(values, air_index)| {
        values.len() != <ChipletAir as LiftedAir<Felt, Challenge>>::num_aux_values(&airs[air_index])
    }) {
        return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
            "unexpected proof-ordered aux-final group width",
        ));
    }
    if stark
        .air_order()
        .iter()
        .map(|&index| usize::from(index))
        .ne(proof_order.iter().copied())
    {
        return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
            "proof ordering does not match the PVM height-sorted convention",
        ));
    }

    let mut advice_stack = security_parameter_words(config.pcs()).to_vec();
    advice_stack.extend(log_heights.iter().copied().map(Felt::from_u8));
    append_proof_payload(&mut advice_stack, stark)?;

    let (store, advice_map) = build_merkle_data(stark)?;
    Ok(AdviceInputs::default()
        .with_stack(advice_stack.into())
        .with_map(advice_map)
        .with_merkle_store(store))
}

fn build_merkle_data(
    stark: &StarkProof<Challenge, EidosLmcs>,
) -> Result<MerkleAdvice, PvmRecursiveVerifierInputsError> {
    let (store, mut advice_map) = build_merkle_advice(stark)?;

    // Serve the canonical circuit stream from the advice map under its commitment. MASM pins that
    // commitment to the compiled-in circuit digest.
    let circuit = shared_pvm_recursive_circuit();
    advice_map.push((circuit.commitment, circuit.instructions.clone()));

    Ok((store, advice_map))
}

#[cfg(test)]
mod tests {
    use miden_core::program::proof_request_key;

    use super::*;

    #[test]
    fn recursive_inputs_reject_non_eidos_proofs_before_parsing() {
        let proof = PrecompileProof {
            proof: SerializedStarkProof::new(Vec::new(), HashFunction::Blake3_256),
            roots: vec![Word::default()],
        };
        assert!(matches!(
            PvmRecursiveVerifierInputs::for_request(Word::default(), &proof),
            Err(PvmRecursiveVerifierInputsError::UnsupportedHashFunction),
        ));
    }

    #[test]
    fn recursive_inputs_reject_oversized_proofs_before_parsing() {
        let size = MAX_STARK_PROOF_BYTES + 1;
        let proof = PrecompileProof {
            proof: SerializedStarkProof::new(vec![0; size], HashFunction::Eidos),
            roots: vec![Word::default()],
        };
        assert!(matches!(
            PvmRecursiveVerifierInputs::for_request(Word::default(), &proof),
            Err(PvmRecursiveVerifierInputsError::ProofTooLarge {
                size: actual,
                max: MAX_STARK_PROOF_BYTES,
            }) if actual == size,
        ));
    }

    #[test]
    fn recursive_inputs_reject_invalid_root_counts_before_parsing() {
        let serialized = || SerializedStarkProof::new(Vec::new(), HashFunction::Eidos);
        for roots in [Vec::new(), vec![Word::default(); MAX_PRECOMPILE_ROOTS + 1]] {
            let root_count = roots.len();
            let proof = PrecompileProof { proof: serialized(), roots };
            assert!(matches!(
                PvmRecursiveVerifierInputs::for_request(Word::default(), &proof),
                Err(PvmRecursiveVerifierInputsError::UnsupportedRootCount { roots })
                    if roots == root_count,
            ));
        }
    }

    #[test]
    fn request_package_moves_the_proof_under_the_request_key() {
        let proof_stream: Vec<_> = [1, 2, 3, 4].map(Felt::new_unchecked).into();
        let deferred_root = Word::from([11u64, 12, 13, 14].map(Felt::new_unchecked));
        let claim = DeferredClaim::new(deferred_root);
        let verifier_root = Word::from([21u64, 22, 23, 24].map(Felt::new_unchecked));
        let existing = (
            Word::from([31u64, 32, 33, 34].map(Felt::new_unchecked)),
            vec![Felt::new_unchecked(7)],
        );
        let advice = AdviceInputs::default()
            .with_stack(proof_stream.clone().into())
            .with_map([existing.clone()]);
        let package = PvmRecursiveVerifierInputs::package(verifier_root, claim, advice);

        assert!(package.advice().stack().is_empty());
        assert_eq!(
            package.advice().map().get(&existing.0).map(AsRef::as_ref),
            Some(existing.1.as_slice())
        );
        assert_eq!(
            package
                .advice()
                .map()
                .get(&proof_request_key(verifier_root, claim.commitment()))
                .map(AsRef::as_ref),
            Some(proof_stream.as_slice()),
        );
        assert_eq!(package.claim_commitment(), claim.commitment());
    }

    /// Pins the complete packaged advice produced before extracting the shared writers.
    #[test]
    fn packaged_advice_matches_pre_extraction_bytes() {
        use miden_core::serde::Serializable;
        use miden_crypto::hash::blake::Blake3_256;

        let root: [Felt; 4] = include_str!("../../tests/fixtures/pvm_eidos_v1_0.root")
            .split_ascii_whitespace()
            .map(|value| Felt::new_unchecked(value.parse().unwrap()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let proof = PrecompileProof {
            proof: SerializedStarkProof::new(
                include_bytes!("../../tests/fixtures/pvm_eidos_v1_0.bin").to_vec(),
                HashFunction::Eidos,
            ),
            roots: vec![Word::new(root)],
        };
        let inputs = PvmRecursiveVerifierInputs::for_request(
            Word::new([21, 22, 23, 24].map(Felt::new_unchecked)),
            &proof,
        )
        .unwrap();
        assert!(inputs.advice().stack().is_empty());
        // Preserve every store entry while making HashMap iteration order irrelevant.
        let mut nodes: Vec<_> = inputs
            .advice()
            .store()
            .inner_nodes()
            .map(|node| (node.value, node.left, node.right))
            .collect();
        nodes.sort_unstable();
        let mut bytes = inputs.advice().map().to_bytes();
        bytes.extend(nodes.to_bytes());
        bytes.extend(inputs.claim_commitment().to_bytes());
        let digest: [u8; 32] = Blake3_256::hash(&bytes).into();
        assert_eq!(
            digest,
            [
                2, 117, 117, 128, 169, 228, 16, 254, 175, 30, 106, 79, 133, 7, 149, 126, 155, 16,
                19, 159, 160, 254, 137, 216, 205, 210, 6, 71, 49, 10, 207, 234,
            ],
            "shared advice writers must preserve the pre-extraction PVM encoding",
        );
    }
}

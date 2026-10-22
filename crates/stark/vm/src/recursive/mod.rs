//! Building the advice a MASM recursive verifier consumes to verify a Miden VM proof.
//!
//! `exec.vm::verify_proof` reads a STARK proof from the advice provider in a fixed
//! order. This module is the producer side of that ABI: it selects the VM component of an
//! [`ExecutionProof`] and packages it against its [`ExecutionClaim`] into the advice-stack stream,
//! the Merkle store, and the advice-map entries the verifier consumes. Its authenticated
//! precompile root is part of the VM statement; a completed precompile STARK is not verified here.
//!
//! Before calling `vm::verify_proof`, the consumer places this proof stream on top of the advice
//! stack:
//!
//!   security params (nq, query_pow, deep_pow, folding_pow) ->
//!   authenticated precompile root -> Miden AIR heights -> main commit -> aux commit ->
//!   aux finals -> quotient commit -> deep alpha -> OOD evals ->
//!   DEEP PoW witness -> FRI rounds -> FRI remainder -> query PoW witness
//!
//! [`RecursiveVerifierInputs::for_request`] stores this stream in the advice map under the verifier
//! and claim commitments. The consumer fetches it before calling `vm::verify_proof`. The consumer
//! also supplies the claim commitment; the advice map stores its 40-felt preimage under that
//! commitment, and `vm::verify_proof` authenticates the preimage before using it. The advice map
//! stores the flattened kernel procedure digests under the kernel commitment as well. Query rows,
//! the Merkle store, and the ACE circuit are content-addressed too.

use alloc::{
    string::{String, ToString},
    vec,
};

use miden_air::vm::{MIDEN_AIR_COUNT, MidenMultiAir, PublicInputs};
use miden_core::{
    Felt, Word,
    advice::AdviceInputs,
    field::QuadFelt,
    program::ExecutionClaim,
    proof::{ExecutionProof, HashFunction},
};
use miden_serde_utils::deserialize_schema_exact;
use miden_stark::{
    PreprocessedValidationError, StarkConfig, VerifierInstance,
    air::Statement,
    proof::{StarkProof, StarkProofData},
    recursive::advice::{
        AdviceError, MerkleAdvice, append_proof_payload, build_merkle_advice, package_for_request,
        security_parameter_words,
    },
    verifier::VerifierError as CryptoVerifierError,
};
use serde_wincode::{SerdeCompat, wincode};

use crate::{MAX_STARK_PROOF_BYTES, setup::config};

// TYPES
// ================================================================================================

type Challenge = QuadFelt;
type RecursiveConfig = config::EidosConfig;
type RecursiveLmcs = <RecursiveConfig as StarkConfig<Felt, Challenge>>::Lmcs;
type RecursiveProofData = StarkProofData<Felt, Challenge, RecursiveConfig>;

/// The And8 lookup trace is the verifier-fixed full byte-pair table.
const AND8_LOOKUP_LOG_HEIGHT: usize = 16;

/// Request-packaged inputs for MASM recursive verification.
///
/// Pass [`Self::claim_commitment`] on the operand stack. The consumer derives the request key,
/// fetches the proof stream from the advice map, and then invokes `exec.vm::verify_proof`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecursiveVerifierInputs {
    advice: AdviceInputs,
    claim_commitment: Word,
}

impl RecursiveVerifierInputs {
    /// Builds a proof package addressed by the verifier and claim commitments.
    ///
    /// The VM component must be an Eidos proof because the recursive verifier supports only
    /// Eidos STARKs.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof cannot be converted into verifier advice.
    pub fn for_request(
        verifier_root: Word,
        proof: &ExecutionProof,
        claim: &ExecutionClaim,
    ) -> Result<Self, RecursiveVerifierInputsError> {
        Ok(build_verifier_inputs(proof, claim)?.into_request_package(verifier_root))
    }

    /// Returns the VM advice inputs.
    pub fn advice(&self) -> &AdviceInputs {
        &self.advice
    }

    /// Returns the execution claim commitment.
    pub fn claim_commitment(&self) -> Word {
        self.claim_commitment
    }

    /// Consumes these inputs into their VM advice and claim commitment.
    pub fn into_parts(self) -> (AdviceInputs, Word) {
        (self.advice, self.claim_commitment)
    }

    /// Moves the proof stream into the advice map under
    /// `proof_request_key(verifier_root, claim_commitment)`, leaving the advice stack empty.
    fn into_request_package(mut self, verifier_root: Word) -> Self {
        self.advice = package_for_request(verifier_root, self.claim_commitment, self.advice);
        self
    }
}

/// Builds the raw advice consumed by `vm::verify_proof` before request packaging.
fn build_verifier_inputs(
    proof: &ExecutionProof,
    claim: &ExecutionClaim,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    let vm = proof.vm();
    let stark = &vm.proof;
    if stark.hash_fn() != HashFunction::Eidos {
        return Err(RecursiveVerifierInputsError::UnsupportedHashFunction(stark.hash_fn()));
    }
    let pub_inputs = PublicInputs::new(
        claim.to_program_info(),
        *claim.stack_inputs(),
        *claim.stack_outputs(),
        vm.precompile_root,
    );

    let claim_commitment = claim.commitment();
    let mut inputs = build_from_proof_bytes(stark.bytes(), &pub_inputs, claim_commitment)?;

    // The MASM verifier authenticates this preimage against the caller-provided commitment.
    inputs.advice = core::mem::take(&mut inputs.advice)
        .with_map([(claim_commitment, claim.to_elements().to_vec())]);

    let kernel = claim.kernel();
    // The MASM verifier derives the procedure count from the value length.
    let kernel_witness = Word::words_as_elements(kernel.proc_hashes()).to_vec();
    inputs.advice =
        core::mem::take(&mut inputs.advice).with_map([(kernel.commitment(), kernel_witness)]);

    Ok(inputs)
}

/// Errors returned while building the advice for recursive verification.
#[derive(Debug, thiserror::Error)]
pub enum RecursiveVerifierInputsError {
    #[error("proof deserialization error: {0}")]
    ProofDeserialization(String),
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
    #[error("statement assembly error: {0}")]
    StatementAssembly(String),
    #[error("preprocessed-trace validation failed: {0}")]
    Preprocessed(#[from] PreprocessedValidationError),
    #[error("recursive verification supports only Eidos proofs, got {0:?}")]
    UnsupportedHashFunction(HashFunction),
    #[error("transcript error: {0}")]
    Transcript(#[from] CryptoVerifierError),
}

impl From<AdviceError> for RecursiveVerifierInputsError {
    fn from(error: AdviceError) -> Self {
        Self::InvalidProofShape(error.message())
    }
}

/// The per-AIR log trace heights in the fixed instance order streamed to the verifier.
struct MidenTraceHeights {
    instance_log_heights: [usize; MIDEN_AIR_COUNT],
}

// ADVICE CONSTRUCTION
// ================================================================================================

fn build_from_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &PublicInputs,
    claim_commitment: Word,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    let config = config::eidos_config(config::pcs_params(), config::RELATION_DIGEST);

    let proof = deserialize_proof(proof_bytes)?;

    let (public_values, aux_inputs) = pub_inputs.to_air_inputs();
    let mut challenger = config.challenger();
    config::observe_protocol_params(config.pcs(), &mut challenger);

    let statement = Statement::<Felt, Challenge, _>::new(
        MidenMultiAir::new(),
        vec![(0, public_values)],
        aux_inputs,
    )
    .map_err(|e| RecursiveVerifierInputsError::StatementAssembly(e.to_string()))?;
    let preprocessed_commitment = Some(config::EIDOS_PREPROCESSED_COMMITMENT.into());
    let verifier_instance = VerifierInstance::new(&config, &statement, preprocessed_commitment)?;

    let (stark, _digest) = StarkProof::from_data(&verifier_instance, &proof, challenger)?;

    let heights = miden_trace_heights(&stark)?;

    build_advice(&config, &stark, heights, pub_inputs, claim_commitment)
}

/// Deserializes a wincode-encoded Eidos STARK proof, enforcing the total byte limit,
/// bounding preallocation, and rejecting trailing bytes.
fn deserialize_proof(
    proof_bytes: &[u8],
) -> Result<RecursiveProofData, RecursiveVerifierInputsError> {
    if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(RecursiveVerifierInputsError::ProofTooLarge {
            size: proof_bytes.len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    deserialize_schema_exact::<SerdeCompat<RecursiveProofData>, _>(proof_bytes, encoding_config)
        .map_err(|e| RecursiveVerifierInputsError::ProofDeserialization(e.to_string()))
}

fn miden_trace_heights(
    stark: &StarkProof<Challenge, RecursiveLmcs>,
) -> Result<MidenTraceHeights, RecursiveVerifierInputsError> {
    let log_heights = stark.log_trace_heights();
    let Ok(log_heights): Result<[u8; MIDEN_AIR_COUNT], _> = log_heights.try_into() else {
        return Err(RecursiveVerifierInputsError::InvalidProofShape(
            "unexpected number of AIR log heights",
        ));
    };
    Ok(MidenTraceHeights {
        instance_log_heights: log_heights.map(usize::from),
    })
}

/// Packs the parsed STARK transcript into the advice-stack stream, Merkle store, and advice map.
fn build_advice(
    config: &RecursiveConfig,
    stark: &StarkProof<Challenge, RecursiveLmcs>,
    heights: MidenTraceHeights,
    pub_inputs: &PublicInputs,
    claim_commitment: Word,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    if stark.all_aux_values.len() != MIDEN_AIR_COUNT {
        return Err(RecursiveVerifierInputsError::InvalidProofShape(
            "unexpected number of aux-final groups",
        ));
    }

    // This stream contains the verifier inputs derived from the proof. The claim preimage and
    // kernel witness live in the advice map and are authenticated by the verifier against
    // commitments supplied by the consumer.
    //
    // The section order below mirrors the consumption-order list in the module doc; both are
    // pinned against the MASM verifier by the stark e2e differential tests.

    let mut advice_stack = security_parameter_words(config.pcs()).to_vec();

    // Final deferred root, loaded by `public_inputs::stage_boundary_inputs`.
    advice_stack.extend_from_slice(pub_inputs.deferred_root().as_ref());

    if heights.instance_log_heights[3] != AND8_LOOKUP_LOG_HEIGHT {
        return Err(RecursiveVerifierInputsError::InvalidProofShape(
            "unexpected And8Lookup log height",
        ));
    }
    // The MASM wrapper hardcodes the trusted And8 table height and consumes only the three
    // execution-dependent heights from advice.
    for &height in &heights.instance_log_heights[..3] {
        advice_stack.push(Felt::new_unchecked(height as u64));
    }

    append_proof_payload(&mut advice_stack, stark)?;

    let (store, advice_map) = build_merkle_data(stark)?;

    let advice = AdviceInputs::default()
        .with_stack(advice_stack.into())
        .with_map(advice_map)
        .with_merkle_store(store);

    Ok(RecursiveVerifierInputs { advice, claim_commitment })
}

// MERKLE DATA
// ================================================================================================

/// Build the Merkle store and advice map from the DEEP and FRI opening proofs.
///
/// Each opening proof becomes a `PartialMerkleTree` (for the store) and `leaf_hash -> leaf_data`
/// entries (for the advice map). The verifier fetches authentication paths with `mtree_get` and
/// leaf data with `adv.push_mapval`.
fn build_merkle_data(
    stark: &StarkProof<Challenge, RecursiveLmcs>,
) -> Result<MerkleAdvice, RecursiveVerifierInputsError> {
    let (store, mut advice_map) = build_merkle_advice(stark)?;

    // One canonical circuit serves every proof order; the verifier authenticates it against the
    // pinned circuit digest.
    #[cfg(feature = "std")]
    {
        let circuit = crate::setup::ace::shared_recursive_circuit();
        advice_map.push((circuit.commitment, circuit.instructions.clone()));
    }
    #[cfg(not(feature = "std"))]
    {
        let circuit = crate::setup::ace::compiled_recursive_circuit();
        advice_map.push((circuit.commitment, circuit.instructions));
    }

    Ok((store, advice_map))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{
        crypto::merkle::{InnerNodeInfo, MerkleStore},
        program::{KernelDescriptor, ProgramInfo, StackInputs, StackOutputs, proof_request_key},
        proof::{PrecompileStatus, StarkProof as CoreStarkProof, VmProof},
    };
    use miden_stark::Preprocessed;

    use super::*;

    /// The top-level entry rejects non-Eidos proofs up front, before touching the proof bytes.
    #[test]
    fn recursive_verifier_inputs_reject_non_eidos_proofs() {
        let proof = ExecutionProof::new(
            VmProof {
                proof: CoreStarkProof::new(Vec::new(), HashFunction::Blake3_256),
                precompile_root: Word::default(),
            },
            PrecompileStatus::Empty,
        );
        let claim = ExecutionClaim::from_program_info(
            ProgramInfo::new(Word::default(), KernelDescriptor::default()),
            StackInputs::default(),
            StackOutputs::default(),
        );

        let err = RecursiveVerifierInputs::for_request(Word::default(), &proof, &claim)
            .expect_err("a Blake3 proof must be rejected");
        assert!(matches!(
            err,
            RecursiveVerifierInputsError::UnsupportedHashFunction(HashFunction::Blake3_256)
        ));
    }

    #[test]
    fn eidos_preprocessed_commitment_matches_recursive_verifier_constant() {
        let config = config::eidos_config(config::pcs_params(), config::RELATION_DIGEST);
        let statement = Statement::<Felt, Challenge, _>::new(
            MidenMultiAir::new(),
            vec![(0, vec![Felt::ZERO; miden_air::vm::NUM_PUBLIC_VALUES])],
            vec![],
        )
        .expect("valid Miden statement shape");
        let commitment: [u64; 4] = Preprocessed::build(&statement, &config)
            .expect("And8 declares a preprocessed table")
            .commitment()
            .into();

        let fixed = config::EIDOS_PREPROCESSED_COMMITMENT;
        assert_eq!(commitment, fixed);
    }

    #[test]
    fn proof_deserialization_rejects_oversized_input() {
        let proof_bytes = vec![0; MAX_STARK_PROOF_BYTES + 1];

        let err = deserialize_proof(&proof_bytes).expect_err("oversized proof must be rejected");
        assert!(matches!(
            err,
            RecursiveVerifierInputsError::ProofTooLarge {
                size,
                max: MAX_STARK_PROOF_BYTES,
            } if size == proof_bytes.len()
        ));
    }

    /// Request packaging is a pure repackaging: the proof stream moves — unchanged and in
    /// order — into the advice map under `proof_request_key(verifier_root, claim_commitment)`, and
    /// everything else is untouched.
    #[test]
    fn request_package_uses_proof_request_key() {
        let proof_stream: Vec<Felt> = (1..=8u64).map(Felt::new_unchecked).collect();
        let claim_commitment = Word::from([11u64, 12, 13, 14].map(Felt::new_unchecked));
        let verifier_root = Word::from([21u64, 22, 23, 24].map(Felt::new_unchecked));
        let query_entry = (
            Word::from([31u64, 32, 33, 34].map(Felt::new_unchecked)),
            vec![Felt::new_unchecked(7)],
        );
        let merkle_node = InnerNodeInfo {
            value: Word::from([41u64, 42, 43, 44].map(Felt::new_unchecked)),
            left: Word::from([51u64, 52, 53, 54].map(Felt::new_unchecked)),
            right: Word::from([61u64, 62, 63, 64].map(Felt::new_unchecked)),
        };
        let store: MerkleStore = [merkle_node].into_iter().collect();

        let advice = AdviceInputs::default()
            .with_stack(proof_stream.clone().into())
            .with_map([query_entry.clone()])
            .with_merkle_store(store.clone());
        let inputs = RecursiveVerifierInputs { advice, claim_commitment };

        let package = inputs.into_request_package(verifier_root);

        assert!(package.advice().stack().is_empty(), "the proof must leave the advice stack");
        assert_eq!(package.claim_commitment(), claim_commitment);
        assert_eq!(package.advice().store(), &store);
        assert_eq!(package.advice().map().len(), 2, "existing entries stay, proof entry added");
        assert_eq!(package.advice().map().get(&query_entry.0).unwrap().as_ref(), query_entry.1);
        assert_eq!(
            package
                .advice()
                .map()
                .get(&proof_request_key(verifier_root, claim_commitment))
                .unwrap()
                .as_ref(),
            proof_stream
        );
    }

    /// Pins complete packaged advice from before the shared-writer extraction. A single Rayon
    /// worker makes proof-of-work selection deterministic even in concurrent test builds.
    #[cfg(all(feature = "std", feature = "prover"))]
    #[test]
    fn packaged_advice_matches_pre_extraction_bytes() {
        use miden_core::serde::Serializable;
        use miden_crypto::hash::blake::Blake3_256;

        let inputs =
            rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap().install(|| {
                let program = miden_assembly::Assembler::default()
                    .assemble_program("advice_fixture", "begin push.5 push.8 add drop end")
                    .unwrap()
                    .unwrap_program();
                let witness = miden_processor::FastProcessor::new(StackInputs::default())
                    .execute_for_proving_sync(
                        &program,
                        &mut miden_processor::DefaultHost::default(),
                    )
                    .unwrap();
                let claim = witness.claim();
                let (vm, _) = witness.into_parts();
                let trace =
                    miden_processor::trace::build_trace(vm, &crate::memory::default_budget())
                        .unwrap();
                let vm_proof = crate::prover::prove(trace, HashFunction::Eidos).unwrap();
                let proof = ExecutionProof::new(vm_proof, PrecompileStatus::Empty);
                RecursiveVerifierInputs::for_request(
                    Word::new([21, 22, 23, 24].map(Felt::new_unchecked)),
                    &proof,
                    &claim,
                )
                .unwrap()
            });

        assert!(inputs.advice().stack().is_empty());
        // AdviceMap is ordered; MerkleStore uses HashMap under std, so sort its complete
        // contents before hashing. The map includes the unchanged serialized proof stream.
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
                64, 70, 184, 218, 212, 109, 150, 180, 81, 241, 9, 30, 165, 30, 99, 0, 217, 199,
                125, 94, 53, 49, 15, 43, 171, 24, 37, 8, 51, 53, 14, 87
            ],
        );
    }
}

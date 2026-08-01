//! Advice construction for the in-VM PVM STARK verifier.
//!
//! This module parses a Poseidon2 PVM proof into the exact stack, Merkle-store, and advice-map
//! inputs consumed by `miden::core::sys::pvm::verify_proof`. The deferred root is an operand of
//! that procedure, not advice: it is the statement the caller asks the verifier to authenticate.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use miden_core::{
    Felt, Word,
    crypto::merkle::MerkleStore,
    deferred::DeferredRoot,
    field::{BasedVectorSpace, QuadFelt},
    proof::{HashFunction, StarkProof as SerializedStarkProof},
};
use miden_crypto::{
    merkle::{MerklePath, PartialMerkleTree},
    stark::{
        StarkConfig,
        lmcs::{Lmcs, proof::BatchProofView},
        pcs::PcsProof,
        proof::{StarkProof, StarkProofData},
    },
};
use miden_lifted_air::Statement;
use miden_lifted_stark::VerifierInstance;
use serde_wincode::SerdeCompat;

use crate::{
    ace::{order_tag_from_log_heights, proof_order_from_log_heights},
    ace_registry::{factory, pvm_ace_registry_path},
    session::{ChipletMultiAir, MAX_STARK_PROOF_BYTES, NUM_CHIPLETS, preprocessed_cache},
    stark_config::{
        Poseidon2Config, observe_protocol_params, poseidon2_config, precompile_pcs_params,
    },
};

type Challenge = QuadFelt;
type P2Lmcs = <Poseidon2Config as StarkConfig<Felt, Challenge>>::Lmcs;

/// Complete nondeterministic input bundle for `miden::core::sys::pvm::verify_proof`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MasmVerifierInputs {
    /// Deferred-root limbs, in the order expected by `StackInputs::try_from_ints`.
    pub initial_stack: Vec<u64>,
    /// Sequential advice tape consumed by the verifier.
    pub advice_stack: Vec<u64>,
    /// Partial DEEP/FRI/setup/registry trees needed by `mtree_get`.
    pub store: MerkleStore,
    /// Opened row data and the selected ACE instruction stream, keyed by commitment.
    pub advice_map: Vec<(Word, Vec<Felt>)>,
}

/// Failures while parsing and adapting a PVM proof for the MASM verifier.
#[derive(Debug, thiserror::Error)]
pub enum MasmVerifierInputError {
    /// The MASM verifier implements the Poseidon2 transcript only.
    #[error("the PVM MASM verifier supports Poseidon2 proofs only")]
    UnsupportedHashFunction,
    /// The serialized proof exceeds the adapter's allocation limit.
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    /// The serialized proof could not be decoded.
    #[error("proof deserialization error: {0}")]
    ProofDeserialization(String),
    /// The proof transcript could not be parsed against the PVM statement and setup.
    #[error(transparent)]
    Transcript(#[from] miden_lifted_stark::VerifierError),
    /// The trusted setup commitment did not match the PVM AIR declaration.
    #[error(transparent)]
    Preprocessed(#[from] miden_lifted_stark::PreprocessedValidationError),
    /// The parsed proof does not have the fixed ten-chiplet shape expected by the wrapper.
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
}

type MerkleAdvice = (MerkleStore, Vec<(Word, Vec<Felt>)>);
type BatchMerkleResult = (Vec<PartialMerkleTree>, Vec<(Word, Vec<Felt>)>);

// `wincode::config::deserialize_exact` requires the schema type and decoded type to match;
// `SerdeCompat<T>` decodes to `T`, so enforce EOF around its reader directly.
fn deserialize_serde_exact<'de, T, C>(
    mut source: &'de [u8],
    _config: C,
) -> wincode::error::ReadResult<T>
where
    C: wincode::config::Config,
    T: serde::Deserialize<'de>,
{
    use wincode::{SchemaRead, io::Reader};

    let value = <SerdeCompat<T> as SchemaRead<'de, C>>::get(source.by_ref())?;
    if source.is_empty() {
        Ok(value)
    } else {
        Err(wincode::error::trailing_bytes())
    }
}

/// Deserialize a Poseidon2 PVM STARK proof and build the nondeterministic inputs for the MASM
/// verifier.
pub fn generate_masm_verifier_inputs(
    proof: &SerializedStarkProof,
    public_root: DeferredRoot,
) -> Result<MasmVerifierInputs, MasmVerifierInputError> {
    if proof.hash_fn() != HashFunction::Poseidon2 {
        return Err(MasmVerifierInputError::UnsupportedHashFunction);
    }
    if proof.bytes().len() > MAX_STARK_PROOF_BYTES {
        return Err(MasmVerifierInputError::InvalidProofShape("serialized proof exceeds 64 MiB"));
    }

    let config = poseidon2_config(
        precompile_pcs_params(),
        crate::ace_registry::PVM_RELATION_DIGEST.map(Felt::new_unchecked),
    );
    let preprocessed = preprocessed_cache::poseidon2(&config);
    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof_data: StarkProofData<Felt, Challenge, Poseidon2Config> =
        deserialize_serde_exact(proof.bytes(), proof_encoding_config)
            .map_err(|err| MasmVerifierInputError::ProofDeserialization(err.to_string()))?;

    let statement =
        Statement::new(ChipletMultiAir::new(), public_root.as_elements().to_vec(), Vec::new())
            .map_err(|_| MasmVerifierInputError::InvalidProofShape("invalid PVM statement"))?;
    let verifier_instance =
        VerifierInstance::new(&config, &statement, Some(preprocessed.commitment()))?;
    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);
    let (stark, _digest) = StarkProof::from_data(&verifier_instance, &proof_data, challenger)?;

    build_inputs(&config, &stark, public_root)
}

fn build_inputs(
    config: &Poseidon2Config,
    stark: &StarkProof<Challenge, P2Lmcs>,
    public_root: DeferredRoot,
) -> Result<MasmVerifierInputs, MasmVerifierInputError> {
    let log_heights: [u8; NUM_CHIPLETS] = stark
        .log_trace_heights()
        .try_into()
        .map_err(|_| MasmVerifierInputError::InvalidProofShape("unexpected AIR-height count"))?;
    if stark.all_aux_values.len() != NUM_CHIPLETS {
        return Err(MasmVerifierInputError::InvalidProofShape(
            "unexpected number of aux-final groups",
        ));
    }
    if stark.all_aux_values.iter().any(|values| values.len() != 1) {
        return Err(MasmVerifierInputError::InvalidProofShape("unexpected aux-final group width"));
    }

    // The registry and MASM wrapper implement the same stable (height, instance-index) order as
    // lifted-stark. Make that coupling executable so a future proof-order convention change fails
    // here rather than selecting a circuit for a different ordering.
    let proof_order = proof_order_from_log_heights(&log_heights);
    if stark
        .air_order()
        .iter()
        .map(|&index| usize::from(index))
        .ne(proof_order.iter().copied())
    {
        return Err(MasmVerifierInputError::InvalidProofShape(
            "proof ordering does not match the PVM registry convention",
        ));
    }

    let params = config.pcs();
    let initial_stack = public_root.as_elements().iter().map(Felt::as_canonical_u64).collect();
    let mut advice_stack = vec![
        params.num_queries() as u64,
        params.query_pow_bits() as u64,
        params.deep_pow_bits() as u64,
        params.folding_pow_bits() as u64,
    ];

    advice_stack.extend(log_heights.iter().copied().map(u64::from));
    advice_stack.extend(commitment_to_u64s(stark.main_commit));
    advice_stack.extend(commitment_to_u64s(stark.aux_commit));
    for aux_values in &stark.all_aux_values {
        advice_stack.extend(challenges_to_u64s(aux_values));
    }
    advice_stack.extend(commitment_to_u64s(stark.quotient_commit));

    let pcs = &stark.pcs_proof;
    let deep_alpha = pcs.deep_proof.challenge_columns;
    let deep_coeffs: &[Felt] = deep_alpha.as_basis_coefficients_slice();
    advice_stack.extend([deep_coeffs[1].as_canonical_u64(), deep_coeffs[0].as_canonical_u64()]);
    append_ood_evaluations(&mut advice_stack, pcs);
    advice_stack.push(pcs.deep_proof.pow_witness.as_canonical_u64());

    for round in &pcs.fri_proof.rounds {
        advice_stack.extend(commitment_to_u64s(round.commitment));
        advice_stack.push(round.pow_witness.as_canonical_u64());
    }
    advice_stack.extend(
        QuadFelt::flatten_to_base(pcs.fri_proof.final_poly.to_vec())
            .iter()
            .map(Felt::as_canonical_u64),
    );
    advice_stack.push(pcs.query_pow_witness.as_canonical_u64());

    let (store, advice_map) = build_merkle_data(config, stark, &log_heights, &proof_order)?;
    Ok(MasmVerifierInputs {
        initial_stack,
        advice_stack,
        store,
        advice_map,
    })
}

fn append_ood_evaluations<L>(advice_stack: &mut Vec<u64>, pcs: &PcsProof<Challenge, L>)
where
    L: Lmcs<F = Felt>,
{
    let mut local_values = Vec::new();
    let mut next_values = Vec::new();
    for group in &pcs.deep_proof.evals {
        for matrix in group {
            let width = matrix.width;
            let values = matrix.values.as_slice();
            local_values.extend_from_slice(&values[..width]);
            if values.len() > width {
                next_values.extend_from_slice(&values[width..2 * width]);
            }
        }
    }
    advice_stack.extend(challenges_to_u64s(&local_values));
    advice_stack.extend(challenges_to_u64s(&next_values));
}

fn build_merkle_data(
    config: &Poseidon2Config,
    stark: &StarkProof<Challenge, P2Lmcs>,
    log_heights: &[u8; NUM_CHIPLETS],
    proof_order: &[usize; NUM_CHIPLETS],
) -> Result<MerkleAdvice, MasmVerifierInputError> {
    let lmcs = config.lmcs();
    let mut partial_trees = Vec::new();
    let mut advice_map = Vec::new();

    // The first DEEP witness is the setup-fixed preprocessed tree. The remaining witnesses are
    // main, auxiliary, and quotient; preserving the parsed group order is part of the ABI.
    for batch_proof in stark.pcs_proof.deep_witnesses.iter() {
        let (trees, entries) = batch_proof_to_merkle(lmcs, batch_proof)?;
        partial_trees.extend(trees);
        advice_map.extend(entries);
    }
    for batch_proof in stark.pcs_proof.fri_witnesses.iter() {
        let (trees, entries) = batch_proof_to_merkle(lmcs, batch_proof)?;
        partial_trees.extend(trees);
        advice_map.extend(entries);
    }

    let mut store = MerkleStore::new();
    for tree in &partial_trees {
        store.extend(tree.inner_nodes());
    }

    let order_tag = order_tag_from_log_heights(log_heights);
    let (leaf, path) = pvm_ace_registry_path(order_tag).ok_or(
        MasmVerifierInputError::InvalidProofShape("ACE registry has no slot for this order tag"),
    )?;
    store.add_merkle_path(u64::from(order_tag), leaf, path).map_err(|_| {
        MasmVerifierInputError::InvalidProofShape("ACE registry path could not be stored")
    })?;

    let circuit = factory().circuit_for_order(proof_order).map_err(|_| {
        MasmVerifierInputError::InvalidProofShape("failed to build the selected ACE circuit")
    })?;
    if circuit.commitment != leaf {
        return Err(MasmVerifierInputError::InvalidProofShape(
            "selected ACE circuit does not match the registry leaf",
        ));
    }
    advice_map.push((leaf, circuit.encoded.instructions().to_vec()));

    Ok((store, advice_map))
}

fn batch_proof_to_merkle<L>(
    lmcs: &L,
    batch_proof: &L::BatchProof,
) -> Result<BatchMerkleResult, MasmVerifierInputError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + Into<[Felt; 4]> + PartialEq,
    L::BatchProof: BatchProofView<Felt, L::Commitment>,
{
    let mut paths = Vec::new();
    let mut advice_entries = Vec::new();
    for index in batch_proof.indices() {
        let rows = batch_proof
            .opening(index)
            .ok_or(MasmVerifierInputError::InvalidProofShape("missing opening for query index"))?;
        let siblings = batch_proof.path(index).ok_or(MasmVerifierInputError::InvalidProofShape(
            "missing Merkle path for query index",
        ))?;
        let salt = batch_proof.salt(index).ok_or(MasmVerifierInputError::InvalidProofShape(
            "missing LMCS salt for query index",
        ))?;
        if !salt.is_empty() {
            return Err(MasmVerifierInputError::InvalidProofShape(
                "hiding LMCS openings are unsupported by the MASM adapter",
            ));
        }
        let leaf_data = rows.as_slice().to_vec();
        let leaf_hash = lmcs.hash(rows.iter_rows());
        let leaf_word = Word::new(leaf_hash.into());
        let merkle_path =
            MerklePath::new(siblings.into_iter().map(|commit| Word::new(commit.into())).collect());
        paths.push((index as u64, leaf_word, merkle_path));
        advice_entries.push((leaf_word, leaf_data));
    }
    let tree = PartialMerkleTree::with_paths(paths)
        .map_err(|_| MasmVerifierInputError::InvalidProofShape("invalid Merkle paths"))?;
    Ok((vec![tree], advice_entries))
}

fn commitment_to_u64s<C: Copy + Into<[Felt; 4]>>(commitment: C) -> Vec<u64> {
    let felts: [Felt; 4] = commitment.into();
    felts.iter().map(Felt::as_canonical_u64).collect()
}

fn challenges_to_u64s(challenges: &[Challenge]) -> Vec<u64> {
    QuadFelt::flatten_to_base(challenges.to_vec())
        .iter()
        .map(Felt::as_canonical_u64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masm_input_builder_rejects_non_poseidon2_proofs_before_parsing() {
        let proof = SerializedStarkProof::new(Vec::new(), HashFunction::Rpo256);
        assert!(matches!(
            generate_masm_verifier_inputs(&proof, DeferredRoot::default()),
            Err(MasmVerifierInputError::UnsupportedHashFunction),
        ));
    }

    #[test]
    fn masm_input_builder_rejects_oversized_proofs_before_parsing() {
        let size = MAX_STARK_PROOF_BYTES + 1;
        let proof = SerializedStarkProof::new(vec![0; size], HashFunction::Poseidon2);
        assert!(matches!(
            generate_masm_verifier_inputs(&proof, DeferredRoot::default()),
            Err(MasmVerifierInputError::ProofTooLarge {
                size: actual,
                max: MAX_STARK_PROOF_BYTES,
            }) if actual == size,
        ));
    }

}

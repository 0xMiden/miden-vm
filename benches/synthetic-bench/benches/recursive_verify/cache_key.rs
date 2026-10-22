//! Cache identity for transaction proofs used by recursive benchmarks.

use miden_air::config::RELATION_DIGEST;
use miden_core::{
    crypto::hash::Blake3_256, proof::ExecutionProofCompatibility, serde::Serializable,
    utils::to_hex,
};
use miden_lifted_stark::pcs::PcsParams;
use miden_vm::{HashFunction, ProgramInfo};

const TX_PROOF_CACHE_KEY_VERSION: &[u8] = b"miden-synthetic-recursive-tx-proof-cache-v5-eidos";
pub(super) const INNER_PROOF_HASH: HashFunction = HashFunction::Eidos;

pub(super) fn tx_proof_cache_key(
    program_info: &ProgramInfo,
    stack_values: &[u64],
    compatibility: &ExecutionProofCompatibility,
) -> String {
    let mut program_bytes = Vec::new();
    program_bytes.extend_from_slice(&program_info.program_hash().as_bytes());
    for digest in program_info.kernel_procedures() {
        program_bytes.extend_from_slice(&digest.as_bytes());
    }

    let mut stack_bytes = Vec::with_capacity(stack_values.len() * 8);
    for value in stack_values {
        stack_bytes.extend_from_slice(&value.to_le_bytes());
    }
    let mut relation_digest_bytes = [0_u8; 32];
    for (chunk, element) in relation_digest_bytes
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(RELATION_DIGEST.iter())
    {
        chunk.copy_from_slice(&element.as_canonical_u64().to_le_bytes());
    }
    // Native verification checks these roots even when the MVM proof has no deferred work.
    let mut compatibility_bytes = vec![compatibility.format()];
    compatibility.vm_verifier_roots().write_into(&mut compatibility_bytes);
    compatibility.pvm_verifier_roots().write_into(&mut compatibility_bytes);
    let hash_fn_byte = [INNER_PROOF_HASH as u8];
    let parameters = pcs_params_bytes(&miden_air::config::pcs_params());
    let digest: [u8; 32] = Blake3_256::hash_iter(
        [
            TX_PROOF_CACHE_KEY_VERSION,
            env!("CARGO_PKG_VERSION").as_bytes(),
            relation_digest_bytes.as_slice(),
            compatibility_bytes.as_slice(),
            program_bytes.as_slice(),
            stack_bytes.as_slice(),
            hash_fn_byte.as_slice(),
            parameters.as_slice(),
        ]
        .into_iter(),
    )
    .into();
    to_hex(digest)
}

pub(super) fn pcs_params_bytes(params: &PcsParams) -> Vec<u8> {
    [
        u64::from(params.log_blowup()),
        u64::from(params.log_folding_arity()),
        u64::from(params.log_final_degree()),
        params.folding_pow_bits() as u64,
        params.deep_pow_bits() as u64,
        params.num_queries() as u64,
        params.query_pow_bits() as u64,
    ]
    .into_iter()
    .flat_map(u64::to_le_bytes)
    .collect()
}

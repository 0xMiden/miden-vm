//! Prepared native kernels for independently completed precompile source ports.

use miden_air_definitions::precompiles::ChipletAir as Source;

use crate::native_kernel::define_native_dispatch;

#[allow(clippy::eq_op)]
mod evaluators {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_evaluators.rs"));
}

mod descriptors {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_descriptors.rs"));
}

define_native_dispatch!(super::ChipletAir, Source, PvmPrepared;
    ChunkNodeSponge => (CHUNK_NODE_SPONGE_DESCRIPTOR, descriptor_chunk_node_sponge, CHUNK_NODE_SPONGE_GEOMETRY, precompute_chunk_node_sponge, eval_chunk_node_sponge, CHUNK_NODE_SPONGE_PREPARED_TERMS),
    EidosCompression => (EIDOS_DESCRIPTOR, descriptor_eidos_compression, EIDOS_COMPRESSION_GEOMETRY, precompute_eidos_compression, eval_eidos_compression, EIDOS_COMPRESSION_PREPARED_TERMS),
    KeccakRound => (KECCAK_ROUND_DESCRIPTOR, descriptor_keccak_round, KECCAK_ROUND_GEOMETRY, precompute_keccak_round, eval_keccak_round, KECCAK_ROUND_PREPARED_TERMS),
    BytePairLut => (BYTE_PAIR_LUT_DESCRIPTOR, descriptor_byte_pair_lut, BYTE_PAIR_LUT_GEOMETRY, precompute_byte_pair_lut, eval_byte_pair_lut, BYTE_PAIR_LUT_PREPARED_TERMS),
    TranscriptEval => (TRANSCRIPT_DESCRIPTOR, descriptor_transcript_eval, TRANSCRIPT_EVAL_GEOMETRY, precompute_transcript_eval, eval_transcript_eval, TRANSCRIPT_EVAL_PREPARED_TERMS),
    UintStoreMul => (UINT_STORE_MUL_DESCRIPTOR, descriptor_uint_store_mul, UINT_STORE_MUL_GEOMETRY, precompute_uint_store_mul, eval_uint_store_mul, UINT_STORE_MUL_PREPARED_TERMS),
    UintAdd => (UINT_ADD_DESCRIPTOR, descriptor_uint_add, UINT_ADD_GEOMETRY, precompute_uint_add, eval_uint_add, UINT_ADD_PREPARED_TERMS),
    EcPointStoreGroups => (EC_POINT_STORE_GROUPS_DESCRIPTOR, descriptor_ec_point_store_groups, EC_POINT_STORE_GROUPS_GEOMETRY, precompute_ec_point_store_groups, eval_ec_point_store_groups, EC_POINT_STORE_GROUPS_PREPARED_TERMS),
    EcGroupAdd => (EC_GROUP_ADD_DESCRIPTOR, descriptor_ec_group_add, EC_GROUP_ADD_GEOMETRY, precompute_ec_group_add, eval_ec_group_add, EC_GROUP_ADD_PREPARED_TERMS),
    EcMsm => (EC_MSM_DESCRIPTOR, descriptor_ec_msm, EC_MSM_GEOMETRY, precompute_ec_msm, eval_ec_msm, EC_MSM_PREPARED_TERMS),
    Sha512 => (SHA512_DESCRIPTOR, descriptor_sha512, SHA512_GEOMETRY, precompute_sha512, eval_sha512, SHA512_PREPARED_TERMS),
    Sha256 => (SHA256_DESCRIPTOR, descriptor_sha256, SHA256_GEOMETRY, precompute_sha256, eval_sha256, SHA256_PREPARED_TERMS),
);

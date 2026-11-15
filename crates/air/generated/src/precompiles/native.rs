//! Prepared native kernels for independently completed precompile source ports.

use crate::native_kernel::define_native_kernel;

#[allow(clippy::eq_op)]
mod evaluators {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_evaluators.rs"));
}

mod descriptors {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_descriptors.rs"));
}

define_native_kernel!(
    /// Generated execution of the EC group-addition relation.
    EcGroupAddKernel,
    descriptor_ec_group_add,
    precompute_ec_group_add,
    eval_ec_group_add,
    EC_GROUP_ADD_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the MSM storage and relation claims.
    EcMsmKernel,
    descriptor_ec_msm,
    precompute_ec_msm,
    eval_ec_msm,
    EC_MSM_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the combined chunk/node and shared-capacity sponge relation.
    ///
    /// The authored source retains the physical row overlays and witness construction.
    ChunkNodeSpongeKernel,
    descriptor_chunk_node_sponge,
    precompute_chunk_node_sponge,
    eval_chunk_node_sponge,
    CHUNK_NODE_SPONGE_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the EC point store with its merged group-table lookup.
    ///
    /// Curve records remain witness data authenticated by the external relation bindings.
    EcPointStoreGroupsKernel,
    descriptor_ec_point_store_groups,
    precompute_ec_point_store_groups,
    eval_ec_point_store_groups,
    EC_POINT_STORE_GROUPS_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the authored Keccak-round relation.
    ///
    /// Construction owns an embedded descriptor without source recapture or fixed-table building.
    /// Witness construction remains on the authored
    /// [`KeccakRoundAir`](miden_air_definitions::precompiles::hash::keccak::round::KeccakRoundAir).
    /// The canonical multi-AIR runtime selects its current wrapper until activation.
    KeccakRoundKernel,
    descriptor_keccak_round,
    precompute_keccak_round,
    eval_keccak_round,
    KECCAK_ROUND_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the composed SHA-256 relation and its shared lookup columns.
    ///
    /// Construction owns an embedded descriptor without source recapture or fixed-table building.
    /// Witness construction remains on the authored
    /// [`Sha256Air`](miden_air_definitions::precompiles::hash::sha256::Sha256Air).
    /// The canonical multi-AIR runtime selects its current wrapper until activation.
    Sha256Kernel,
    descriptor_sha256,
    precompute_sha256,
    eval_sha256,
    SHA256_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the composed SHA-512 relation and its shared lookup columns.
    ///
    /// Construction owns an embedded descriptor without source recapture or fixed-table building.
    /// Witness construction remains on the authored
    /// [`Sha512Air`](miden_air_definitions::precompiles::hash::sha512::Sha512Air).
    /// The canonical multi-AIR runtime selects its current wrapper until activation.
    Sha512Kernel,
    descriptor_sha512,
    precompute_sha512,
    eval_sha512,
    SHA512_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the combined uint storage and multiplication relation.
    ///
    /// Witness construction remains on the authored `UintStoreMulAir`.
    UintStoreMulKernel,
    descriptor_uint_store_mul,
    precompute_uint_store_mul,
    eval_uint_store_mul,
    UINT_STORE_MUL_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the authored uint addition relation.
    UintAddKernel,
    descriptor_uint_add,
    precompute_uint_add,
    eval_uint_add,
    UINT_ADD_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the PVM byte-pair table relation.
    ///
    /// Setup owns the fixed matrix; this kernel embeds only its shape and relation descriptor.
    BytePairLutKernel,
    descriptor_byte_pair_lut,
    precompute_byte_pair_lut,
    eval_byte_pair_lut,
    BYTE_PAIR_LUT_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the PVM Eidos compression relation and its fingerprint register.
    ///
    /// Witness construction remains on the authored
    /// [`EidosCompressionAir`](miden_air_definitions::precompiles::transcript::eidos::EidosCompressionAir).
    /// The descriptor is embedded; the canonical runtime retains its current wrapper until activation.
    EidosCompressionKernel,
    descriptor_eidos_compression,
    precompute_eidos_compression,
    eval_eidos_compression,
    EIDOS_COMPRESSION_PREPARED_TERMS
);

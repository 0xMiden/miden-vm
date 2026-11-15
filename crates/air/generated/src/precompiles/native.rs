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

//! STARK configuration for proving/verifying custom chiplet AIRs.
//!
//! This module provides a Poseidon2-based STARK configuration using `miden_core::Felt`
//! as the base field, matching Miden VM's field choice.

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::hash::poseidon2::Poseidon2Permutation256;
use miden_lifted_stark::{
    GenericStarkConfig,
    lmcs::config::LmcsConfig,
    pcs::PcsParams,
    proof::{StarkDigest, StarkProofData},
};
use miden_stateful_hasher::StatefulSponge;
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_symmetric::TruncatedPermutation;

// Sponge configuration.
const WIDTH: usize = 12;
const RATE: usize = 8;
const DIGEST: usize = 4;

/// Poseidon2 permutation type.
pub type Perm = Poseidon2Permutation256;

/// Stateful sponge for LMCS hashing.
pub type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

/// Compression function for Merkle tree construction.
pub type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;

/// Duplex challenger for Fiat-Shamir.
pub type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

/// Packed field type for SIMD.
pub type PackedFelt = <Felt as Field>::Packing;

/// LMCS configuration.
pub type Lmcs = LmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, WIDTH, DIGEST>;

/// DFT implementation.
pub type Dft = Radix2DitParallel<Felt>;

/// Full STARK configuration.
pub type TestConfig = GenericStarkConfig<Felt, QuadFelt, Lmcs, Dft, Challenger>;

/// A multi-AIR proof under [`TestConfig`] (the `proof` field of a
/// [`StarkOutput`](miden_lifted_stark::proof::StarkOutput)).
pub type TestProof = StarkProofData<Felt, QuadFelt, TestConfig>;

/// The prover/verifier digest under [`TestConfig`].
pub type TestDigest = StarkDigest<Felt, QuadFelt, TestConfig>;

/// Test PCS parameters (fast but insecure — for testing only).
///
/// Uses small values to keep proofs small and proving fast:
/// - log_blowup: 3 (blowup = 8, supports degree-8 constraints)
/// - log_folding_arity: 1 (arity = 2)
/// - log_final_degree: 3 (final poly = 8)
/// - num_queries: 4
pub fn test_pcs_params() -> PcsParams {
    PcsParams::new(
        3, // log_blowup (must be >= log_quotient_degree)
        1, // log_folding_arity
        3, // log_final_degree
        0, // folding_pow_bits
        0, // deep_pow_bits
        4, // num_queries
        0, // query_pow_bits
    )
    .expect("invalid test PCS params")
}

/// Create a fresh challenger for proving/verification.
pub fn test_challenger() -> Challenger {
    DuplexChallenger::new(Poseidon2Permutation256)
}

/// Create the LMCS instance.
pub fn test_lmcs() -> Lmcs {
    LmcsConfig::new(Sponge::new(Poseidon2Permutation256), Compress::new(Poseidon2Permutation256))
}

/// Create the full test STARK configuration.
pub fn test_config() -> TestConfig {
    GenericStarkConfig::new(test_pcs_params(), test_lmcs(), Dft::default(), test_challenger())
}

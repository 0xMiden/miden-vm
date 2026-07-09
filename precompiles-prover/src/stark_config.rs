//! STARK configuration for proving/verifying custom chiplet AIRs.
//!
//! This module provides both:
//! - production-style configuration factories matching the Miden VM hash-function surface and
//!   PCS/security parameters; and
//! - the legacy fast Poseidon2 test configuration used by local examples/tests.
//!
//! Production configs delegate to `miden_air::config`; callers pass the relation digest
//! explicitly. Callers should observe protocol parameters with [`observe_protocol_params`]
//! before proving or verifying.

pub use miden_air::config::{
    Blake3Config, KeccakConfig, Poseidon2Config, RelationDigest, RpoConfig, RpxConfig,
    blake3_256_config, keccak_config, observe_protocol_params, poseidon2_config, rpo_config,
    rpx_config,
};
use miden_core::Felt;
use miden_crypto::{
    field::Field,
    hash::poseidon2::Poseidon2Permutation256,
    stark::{
        GenericStarkConfig, challenger::DuplexChallenger, dft::Radix2DitParallel,
        hasher::StatefulSponge, lmcs::config::LmcsConfig, pcs::PcsParams,
        symmetric::TruncatedPermutation,
    },
};

// SHARED TYPES
// ================================================================================================

/// Precompile prover STARK configuration with pre-filled common type parameters.
pub type PrecompileStarkConfig<L, Ch> = miden_air::config::MidenStarkConfig<L, Ch>;

/// Packed field type for SIMD.
pub type PackedFelt = <Felt as Field>::Packing;

/// Number of inputs to the Merkle compression function.
const COMPRESSION_INPUTS: usize = 2;

// DOMAIN-SEPARATED FIAT-SHAMIR TRANSCRIPT
// ================================================================================================

/// PRECOMPILE_RELATION_DIGEST = Poseidon2::hash_elements([PROTOCOL_ID, CIRCUIT_COMMITMENT]).
///
/// Compile-time constant binding the Fiat-Shamir transcript to the precompile chiplet AIR set.
/// Keep this in sync with [`crate::ace::build_precompile_multi_air_ace_circuit`].
pub const PRECOMPILE_RELATION_DIGEST: RelationDigest = [
    Felt::new_unchecked(12794781063212927046),
    Felt::new_unchecked(9890233791820081176),
    Felt::new_unchecked(1897898501728194857),
    Felt::new_unchecked(10203667064001467379),
];
/// Default hash function for compatibility APIs such as
/// [`SessionTraces::prove`](crate::session::SessionTraces::prove).
pub const DEFAULT_HASH_FUNCTION: miden_core::proof::HashFunction =
    miden_core::proof::HashFunction::Poseidon2;

// PRECOMPILE PCS PARAMETERS
// ================================================================================================

/// PCS parameters for the precompile chiplet stack.
///
/// Mirrors `miden_air::config::pcs_params` in every parameter, including
/// `log_blowup = 3`. It exists as its own function to decouple the
/// precompile stack's PCS config from the core VM's, since the two need not
/// evolve together: every chiplet AIR in
/// [`ChipletAir`](crate::session::ChipletAir) closes at a `log_quotient_degree`
/// well under the core VM's degree-8 constraints (see the
/// `log_quotient_degrees_fit_the_blowup` test), so `log_blowup` could be
/// lowered independently of the core VM in the future. That has not been done
/// here, and doing so would need a dedicated security review of the
/// resulting FRI parameters before use outside benchmarking.
pub fn precompile_pcs_params() -> PcsParams {
    PcsParams::new(
        3,  // log_blowup (must be >= log_quotient_degree)
        2,  // log_folding_arity
        7,  // log_final_degree
        4,  // folding_pow_bits
        12, // deep_pow_bits
        27, // num_queries
        16, // query_pow_bits
    )
    .expect("invalid precompile PCS parameters")
}

// LEGACY TEST CONFIG
// ================================================================================================

/// Sponge state width in field elements.
const WIDTH: usize = 12;
/// Sponge rate (absorbable elements per permutation).
const RATE: usize = 8;
/// Sponge digest width in field elements.
const DIGEST: usize = 4;

/// Poseidon2 permutation type.
pub type Perm = Poseidon2Permutation256;

/// Stateful sponge for LMCS hashing.
pub type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

/// Compression function for Merkle tree construction.
pub type Compress = TruncatedPermutation<Perm, COMPRESSION_INPUTS, DIGEST, WIDTH>;

/// Duplex challenger for Fiat-Shamir.
pub type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

/// Algebraic LMCS for the Poseidon2 test/default config.
type AlgLmcs<P> = LmcsConfig<
    PackedFelt,
    PackedFelt,
    StatefulSponge<P, WIDTH, RATE, DIGEST>,
    TruncatedPermutation<P, COMPRESSION_INPUTS, DIGEST, WIDTH>,
    WIDTH,
    DIGEST,
>;

/// LMCS configuration for the Poseidon2 test/default config.
pub type Lmcs = AlgLmcs<Perm>;

/// DFT implementation.
pub type Dft = Radix2DitParallel<Felt>;

/// Full legacy test STARK configuration type.
pub type TestConfig = Poseidon2Config;

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

/// Create a fresh challenger for proving/verification under the legacy test
/// config.
pub fn test_challenger() -> Challenger {
    DuplexChallenger::new(Poseidon2Permutation256)
}

/// Create the LMCS instance for the legacy test config.
pub fn test_lmcs() -> Lmcs {
    LmcsConfig::new(Sponge::new(Poseidon2Permutation256), Compress::new(Poseidon2Permutation256))
}

/// Create the full legacy test STARK configuration.
pub fn test_config() -> TestConfig {
    GenericStarkConfig::new(test_pcs_params(), test_lmcs(), Dft::default(), test_challenger())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::{format, vec::Vec};

    use miden_ace_codegen::{AceConfig, LayoutKind};
    use miden_core::{Felt, crypto::hash::Poseidon2};

    use crate::{ace, session::NUM_CHIPLETS};

    const PROTOCOL_ID: u64 = 0;
    const REGEN_HINT: &str = "update PRECOMPILE_RELATION_DIGEST in precompiles-prover/src/stark_config.rs and accept the insta snapshot";

    /// Snapshot test: catches any precompile chiplet AIR change that alters the constraint circuit.
    #[test]
    fn precompile_relation_digest_matches_current_air() {
        let config = AceConfig {
            num_quotient_chunks: 8,
            layout: LayoutKind::Masm,
            num_airs: NUM_CHIPLETS,
        };
        let circuit = ace::build_precompile_multi_air_ace_circuit(config).unwrap();
        let encoded = circuit.to_ace().unwrap();
        let circuit_commitment: [Felt; 4] = encoded.circuit_hash().into();

        let input: Vec<Felt> = core::iter::once(Felt::new_unchecked(PROTOCOL_ID))
            .chain(circuit_commitment.iter().copied())
            .collect();
        let digest = Poseidon2::hash_elements(&input);
        let expected: Vec<u64> = digest.as_elements().iter().map(Felt::as_canonical_u64).collect();

        let snapshot = format!(
            "num_inputs: {}\nnum_eval_gates: {}\nrelation_digest: {:?}",
            encoded.num_vars(),
            encoded.num_eval_rows(),
            expected,
        );
        insta::assert_snapshot!(snapshot);

        let actual: Vec<u64> =
            super::PRECOMPILE_RELATION_DIGEST.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(
            actual, expected,
            "PRECOMPILE_RELATION_DIGEST in stark_config.rs is stale; {REGEN_HINT}"
        );
    }
}

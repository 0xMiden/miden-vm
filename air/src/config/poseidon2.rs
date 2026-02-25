//! Poseidon2 STARK configuration factory.
//!
//! This module provides a STARK configuration using the Poseidon2 hash function,
//! which is an algebraic hash function designed for STARK-friendly operations.

use miden_crypto::hash::poseidon2::Poseidon2Permutation256;
use p3_challenger::DuplexChallenger;
use p3_field::Field;
use p3_miden_lifted_stark::StarkConfig;
use p3_miden_lmcs::LmcsConfig;
use p3_miden_stateful_hasher::StatefulSponge;
use p3_symmetric::TruncatedPermutation;

use super::{Dft, LiftedConfig, PCS_PARAMS};
use crate::Felt;

const WIDTH: usize = 12;
const RATE: usize = 8;
const DIGEST: usize = 4;

/// Poseidon2 permutation
type Perm = Poseidon2Permutation256;

/// Packed field element type (for SIMD-friendly LMCS)
type PackedFelt = <Felt as Field>::Packing;

/// Poseidon2 sponge for LMCS leaf hashing
type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

/// Compression function using Poseidon2 (2-to-1 compression via truncated permutation)
type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;

/// LMCS commitment scheme using Poseidon2.
/// Note: Poseidon2 uses Felt (field elements) for digests, not u8 (bytes).
type LmcsType = LmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, WIDTH, DIGEST>;

/// Challenger for Fiat-Shamir using Poseidon2 (duplex sponge)
type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

/// Creates a Poseidon2-based STARK configuration.
///
/// This configuration uses:
/// - Poseidon2 hash function for LMCS commitments and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (arity 2)
///
/// # Returns
///
/// A `LiftedConfig` instance configured for Poseidon2-based proving.
pub fn create_poseidon2_config() -> LiftedConfig<LmcsType, Challenger> {
    let perm = Poseidon2Permutation256;
    let sponge = Sponge::new(perm);
    let compress = Compress::new(perm);
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();

    let config = StarkConfig { pcs: PCS_PARAMS, lmcs, dft };
    let challenger = Challenger::new(perm);

    LiftedConfig { config, challenger }
}

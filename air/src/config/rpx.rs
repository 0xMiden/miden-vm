//! RPX STARK configuration factory.
//!
//! This module provides a STARK configuration using the Rescue Prime eXtension (RPX)
//! hash function, which is Miden's native algebraic hash function with extension field rounds.

use miden_core::field::QuadFelt;
use miden_crypto::hash::rpx::RpxPermutation256;
use p3_challenger::DuplexChallenger;
use p3_field::Field;
use p3_miden_lifted_stark::GenericStarkConfig;
use p3_miden_lmcs::LmcsConfig;
use p3_miden_stateful_hasher::StatefulSponge;
use p3_symmetric::TruncatedPermutation;

use super::{Dft, PCS_PARAMS};
use crate::Felt;

const WIDTH: usize = 12;
const RATE: usize = 8;
const DIGEST: usize = 4;

/// RPX permutation
type Perm = RpxPermutation256;

/// Packed field element type (for SIMD-friendly LMCS)
type PackedFelt = <Felt as Field>::Packing;

/// RPX sponge for LMCS leaf hashing
type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

/// Compression function using RPX (2-to-1 compression via truncated permutation)
type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;

/// LMCS commitment scheme using RPX.
/// Note: RPX uses Felt (field elements) for digests, not u8 (bytes).
type LmcsType = LmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, WIDTH, DIGEST>;

/// Challenger for Fiat-Shamir using RPX (duplex sponge)
type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

/// Complete STARK configuration type for RPX.
pub type RpxConfig = GenericStarkConfig<Felt, QuadFelt, LmcsType, Dft, Challenger>;

/// Creates an RPX-based STARK configuration.
///
/// This configuration uses:
/// - RPX (Rescue Prime eXtension) hash function for LMCS commitments and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (arity 2)
pub fn create_rpx_config() -> RpxConfig {
    let perm = RpxPermutation256;
    let sponge = Sponge::new(perm);
    let compress = Compress::new(perm);
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();
    let challenger = Challenger::new(perm);

    GenericStarkConfig::new(PCS_PARAMS, lmcs, dft, challenger)
}

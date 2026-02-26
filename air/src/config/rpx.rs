//! RPX STARK configuration factory.
//!
//! This module provides a STARK configuration using the Rescue Prime eXtension (RPX)
//! hash function, which is Miden's native algebraic hash function with extension field rounds.

use miden_crypto::hash::rpx::RpxPermutation256;
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

/// Creates an RPX-based STARK configuration.
///
/// This configuration uses:
/// - RPX (Rescue Prime eXtension) hash function for LMCS commitments and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (arity 2)
///
/// # Advantages of RPX over RPO
///
/// - **Enhanced security**: RPX uses extension field rounds (E-rounds) that provide additional
///   algebraic structure and resistance to certain attacks.
/// - **Native to Miden VM**: Like RPO, RPX is an algebraic hash function that can be efficiently
///   verified within the Miden VM for recursive proof verification.
/// - **STARK-friendly**: The extension field operations are optimized for STARK circuits, providing
///   efficient constraint representation.
/// - **128-bit security**: Targets the same security level as RPO with improved cryptographic
///   properties.
///
/// # Returns
///
/// A `LiftedConfig` instance configured for RPX-based proving.
pub fn create_rpx_config() -> LiftedConfig<LmcsType, Challenger> {
    let perm = RpxPermutation256;
    let sponge = Sponge::new(perm);
    let compress = Compress::new(perm);
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();

    let config = StarkConfig { pcs: PCS_PARAMS, lmcs, dft };
    let challenger = Challenger::new(perm);

    LiftedConfig { config, challenger }
}

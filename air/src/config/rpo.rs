//! RPO STARK configuration factory.
//!
//! This module provides a STARK configuration using the Rescue Prime Optimized (RPO)
//! hash function, which is Miden's native algebraic hash function.

use miden_core::field::QuadFelt;
use miden_crypto::hash::rpo::RpoPermutation256;
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

/// RPO permutation
type Perm = RpoPermutation256;

/// Packed field element type (for SIMD-friendly LMCS)
type PackedFelt = <Felt as Field>::Packing;

/// RPO sponge for LMCS leaf hashing
type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

/// Compression function using RPO (2-to-1 compression via truncated permutation)
type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;

/// LMCS commitment scheme using RPO.
/// Note: RPO uses Felt (field elements) for digests, not u8 (bytes).
type LmcsType = LmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, WIDTH, DIGEST>;

/// Challenger for Fiat-Shamir using RPO (duplex sponge)
type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

/// Complete STARK configuration type for RPO.
pub type RpoConfig = GenericStarkConfig<Felt, QuadFelt, LmcsType, Dft, Challenger>;

/// Creates an RPO-based STARK configuration.
///
/// This configuration uses:
/// - RPO (Rescue Prime Optimized) hash function for LMCS commitments and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (arity 2)
pub fn create_rpo_config() -> RpoConfig {
    let perm = RpoPermutation256;
    let sponge = Sponge::new(perm);
    let compress = Compress::new(perm);
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();
    let challenger = Challenger::new(perm);

    GenericStarkConfig::new(PCS_PARAMS, lmcs, dft, challenger)
}

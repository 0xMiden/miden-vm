//! Keccak STARK configuration factory.

use alloc::vec;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_miden_lifted_stark::StarkConfig;
use p3_miden_lmcs::LmcsConfig;
use p3_miden_stateful_hasher::{SerializingStatefulSponge, StatefulSponge};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge};

use super::{Dft, LiftedConfig, PCS_PARAMS};
use crate::Felt;

const WIDTH: usize = 25;
const RATE: usize = 17;
const DIGEST: usize = 4;

/// Keccak sponge for LMCS leaf hashing (native u64 state)
type KeccakStatefulSponge = StatefulSponge<KeccakF, WIDTH, RATE, DIGEST>;

/// Serializing wrapper for the Keccak sponge (field element → u64 conversion)
type Sponge = SerializingStatefulSponge<KeccakStatefulSponge>;

/// Keccak optimized for u64 field elements (padding-free sponge, for Merkle tree compression)
type KeccakMmcsSponge = PaddingFreeSponge<KeccakF, WIDTH, RATE, DIGEST>;

/// Compression function derived from Keccak hasher
type Compress = CompressionFunctionFromHasher<KeccakMmcsSponge, 2, DIGEST>;

/// LMCS commitment scheme using Keccak.
/// PF = `[Felt; VECTOR_LEN]` and PD = `[u64; VECTOR_LEN]` for SIMD parallelization,
/// where `VECTOR_LEN` is platform-specific (1, 2, 4, or 8).
type LmcsType = LmcsConfig<[Felt; VECTOR_LEN], [u64; VECTOR_LEN], Sponge, Compress, WIDTH, DIGEST>;

/// Challenger for Fiat-Shamir using Keccak256
type Challenger = SerializingChallenger64<Felt, HashChallenger<u8, Keccak256Hash, 32>>;

/// Creates a Keccak-based STARK configuration.
///
/// This configuration uses:
/// - Keccak256 for the Fiat-Shamir challenger
/// - KeccakF permutation for field element hashing in LMCS commitments
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (arity 2)
///
/// # Returns
///
/// A `LiftedConfig` instance configured for Keccak-based proving.
pub fn create_keccak_config() -> LiftedConfig<LmcsType, Challenger> {
    let sponge = Sponge::new(StatefulSponge::new(KeccakF {}));
    let inner = KeccakMmcsSponge::new(KeccakF {});
    let compress = Compress::new(inner);
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();

    let config = StarkConfig { pcs: PCS_PARAMS, lmcs, dft };
    let challenger = Challenger::from_hasher(vec![], Keccak256Hash {});

    LiftedConfig { config, challenger }
}

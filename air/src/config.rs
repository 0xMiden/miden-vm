//! STARK configuration factories for different hash functions.
//!
//! Each factory creates a [`StarkConfig`](miden_crypto::stark::StarkConfig) bundling the
//! PCS parameters, LMCS commitment scheme, and Fiat-Shamir challenger for proving and verification.

use alloc::vec;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::Field,
    hash::{
        blake::Blake3Hasher, keccak::Keccak256Hash, poseidon2::Poseidon2Permutation256,
        rpo::RpoPermutation256, rpx::RpxPermutation256,
    },
    stark::{
        GenericStarkConfig,
        challenger::{CanObserve, DuplexChallenger, HashChallenger, SerializingChallenger64},
        dft::Radix2DitParallel,
        fri::PcsParams,
        hasher::{ChainingHasher, StatefulSponge},
        lmcs::LmcsConfig,
        symmetric::{CompressionFunctionFromHasher, Permutation, TruncatedPermutation},
    },
};

// PCS PARAMETERS
// ================================================================================================

/// Log2 of the FRI blowup factor (blowup = 8).
const LOG_BLOWUP: u8 = 3;
/// Log2 of the FRI folding arity (arity = 4).
pub const LOG_FOLDING_ARITY: u8 = 2;
/// Log2 of the final polynomial degree (degree = 128).
const LOG_FINAL_DEGREE: u8 = 7;
/// Proof-of-work bits for FRI folding challenges.
pub const FOLDING_POW_BITS: usize = 4;
/// Proof-of-work bits for DEEP composition polynomial.
pub const DEEP_POW_BITS: usize = 12;
/// Number of FRI query repetitions.
const NUM_QUERIES: usize = 27;
/// Proof-of-work bits for query phase.
const QUERY_POW_BITS: usize = 16;

/// Default PCS parameters shared by all hash function configurations.
pub fn pcs_params() -> PcsParams {
    PcsParams::new(
        LOG_BLOWUP,
        LOG_FOLDING_ARITY,
        LOG_FINAL_DEGREE,
        FOLDING_POW_BITS,
        DEEP_POW_BITS,
        NUM_QUERIES,
        QUERY_POW_BITS,
    )
    .expect("invalid PCS parameters")
}

// HASH FUNCTION PARAMETERS
// ================================================================================================

// Byte-oriented hashes (Blake3, Keccak).

/// Digest size in bytes for byte-oriented hashes.
const BYTE_DIGEST_SIZE: usize = 32;
/// Number of inputs to the Merkle compression function.
const COMPRESSION_INPUTS: usize = 2;

// Algebraic hashes (RPO, Poseidon2, RPX).

/// Sponge state width in field elements.
const SPONGE_WIDTH: usize = 12;
/// Sponge rate (absorbable elements per permutation).
const SPONGE_RATE: usize = 8;
/// Sponge digest width in field elements.
const DIGEST_WIDTH: usize = 4;

// SHARED TYPE ALIASES
// ================================================================================================

type PackedFelt = <Felt as Field>::Packing;

/// Miden VM STARK configuration with pre-filled common type parameters.
///
/// All Miden configurations use `Felt` as the base field, `QuadFelt` as the extension field,
/// and `Radix2DitParallel<Felt>` as the DFT. Only the LMCS commitment scheme (`L`) and
/// Fiat-Shamir challenger (`Ch`) vary by hash function.
pub type MidenStarkConfig<L, Ch> =
    GenericStarkConfig<Felt, QuadFelt, L, Radix2DitParallel<Felt>, Ch>;

/// Byte-oriented LMCS (for Blake3, Keccak).
type ByteLmcs<H> = LmcsConfig<
    Felt,
    u8,
    ChainingHasher<H>,
    CompressionFunctionFromHasher<H, COMPRESSION_INPUTS, BYTE_DIGEST_SIZE>,
    BYTE_DIGEST_SIZE,
    BYTE_DIGEST_SIZE,
>;

/// Byte-oriented challenger (for Blake3, Keccak).
type ByteChallenger<H> = SerializingChallenger64<Felt, HashChallenger<u8, H, BYTE_DIGEST_SIZE>>;

/// Algebraic LMCS (for RPO, Poseidon2, RPX).
type AlgLmcs<P> = LmcsConfig<
    PackedFelt,
    PackedFelt,
    StatefulSponge<P, SPONGE_WIDTH, SPONGE_RATE, DIGEST_WIDTH>,
    TruncatedPermutation<P, COMPRESSION_INPUTS, DIGEST_WIDTH, SPONGE_WIDTH>,
    SPONGE_WIDTH,
    DIGEST_WIDTH,
>;

/// Algebraic duplex challenger (for RPO, Poseidon2, RPX).
type AlgChallenger<P> = DuplexChallenger<Felt, P, SPONGE_WIDTH, SPONGE_RATE>;

// CONFIGURATION FACTORIES
// ================================================================================================

/// Creates a Blake3_256-based STARK configuration.
pub fn blake3_256_config(
    params: PcsParams,
) -> MidenStarkConfig<ByteLmcs<Blake3Hasher>, ByteChallenger<Blake3Hasher>> {
    let lmcs = LmcsConfig::new(
        ChainingHasher::new(Blake3Hasher),
        CompressionFunctionFromHasher::new(Blake3Hasher),
    );
    let challenger = SerializingChallenger64::from_hasher(vec![], Blake3Hasher);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

/// Creates a Keccak-based STARK configuration.
pub fn keccak_config(
    params: PcsParams,
) -> MidenStarkConfig<ByteLmcs<Keccak256Hash>, ByteChallenger<Keccak256Hash>> {
    let hash = Keccak256Hash {};
    let lmcs = LmcsConfig::new(ChainingHasher::new(hash), CompressionFunctionFromHasher::new(hash));
    let challenger = SerializingChallenger64::from_hasher(vec![], hash);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

/// Creates an RPO-based STARK configuration.
pub fn rpo_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<RpoPermutation256>, AlgChallenger<RpoPermutation256>> {
    let perm = RpoPermutation256;
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let challenger = DuplexChallenger::new(perm);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

/// Creates a Poseidon2-based STARK configuration.
pub fn poseidon2_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<Poseidon2Permutation256>, AlgChallenger<Poseidon2Permutation256>> {
    let perm = Poseidon2Permutation256;
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let challenger = DuplexChallenger::new(perm);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

/// Creates an RPX-based STARK configuration.
pub fn rpx_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<RpxPermutation256>, AlgChallenger<RpxPermutation256>> {
    let perm = RpxPermutation256;
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let challenger = DuplexChallenger::new(perm);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

// POSEIDON2 CONFIG TYPE ALIAS
// ================================================================================================

/// Concrete STARK configuration type for Poseidon2.
pub type Poseidon2Config =
    MidenStarkConfig<AlgLmcs<Poseidon2Permutation256>, AlgChallenger<Poseidon2Permutation256>>;

// DOMAIN-SEPARATED FIAT-SHAMIR TRANSCRIPT
// ================================================================================================

/// RELATION_DIGEST = Poseidon2::hash_elements([PROTOCOL_ID, CIRCUIT_COMMITMENT]).
///
/// Compile-time constant binding the Fiat-Shamir transcript to the Miden VM AIR.
/// Must match the constants in `crates/lib/core/asm/sys/vm/mod.masm`.
pub const RELATION_DIGEST: [Felt; 4] = [
    Felt::new(9663888320842941557),
    Felt::new(5569923100392661778),
    Felt::new(10686243500486164404),
    Felt::new(9017524969302659247),
];

/// Domain-separated Fiat-Shamir transcript initialization.
///
/// Constructs a fresh challenger whose internal state is cryptographically bound to:
/// 1. The relation identity (RELATION_DIGEST)
/// 2. The protocol parameters (num_queries, PoW bits, FRI config)
/// 3. The per-proof trace height (log_trace_height)
pub trait InitTranscript {
    fn seeded(log_trace_height: u64) -> Self;
}

/// Sponge capacity (SPONGE_WIDTH - SPONGE_RATE).
const SPONGE_CAPACITY: usize = SPONGE_WIDTH - SPONGE_RATE;

/// Range of capacity slots within the sponge state array.
const CAPACITY_RANGE: core::ops::Range<usize> = SPONGE_RATE..SPONGE_WIDTH;

/// Computes the seeded sponge state for sponge-based challengers.
///
/// Returns a `[Felt; SPONGE_WIDTH]` with capacity = PROOF_SEED and rate zeroed.
fn seed_sponge_state(
    log_trace_height: u64,
    permute: impl Fn(&mut [Felt; SPONGE_WIDTH]),
) -> [Felt; SPONGE_WIDTH] {
    let mut state = [Felt::ZERO; SPONGE_WIDTH];

    // Phase 1: RELATION_DIGEST (capacity) + PCS_PARAMS (rate) -> INSTANCE_SEED
    assert_eq!(RELATION_DIGEST.len(), SPONGE_CAPACITY);
    state[CAPACITY_RANGE].copy_from_slice(&RELATION_DIGEST);
    state[0] = Felt::new(NUM_QUERIES as u64);
    state[1] = Felt::new(QUERY_POW_BITS as u64);
    state[2] = Felt::new(DEEP_POW_BITS as u64);
    state[3] = Felt::new(FOLDING_POW_BITS as u64);
    state[4] = Felt::new(LOG_BLOWUP as u64);
    state[5] = Felt::new(LOG_FINAL_DEGREE as u64);
    state[6] = Felt::new(1_u64 << LOG_FOLDING_ARITY);
    // state[7] already zero
    permute(&mut state);

    // Phase 2: INSTANCE_SEED (capacity) + [lth, 0, ..., 0] (rate) -> PROOF_SEED
    state[..SPONGE_RATE].fill(Felt::ZERO);
    state[0] = Felt::new(log_trace_height);
    permute(&mut state);

    // Zero the rate, keep capacity = PROOF_SEED
    state[..SPONGE_RATE].fill(Felt::ZERO);

    state
}

impl InitTranscript for AlgChallenger<Poseidon2Permutation256> {
    fn seeded(log_trace_height: u64) -> Self {
        let state = seed_sponge_state(log_trace_height, |s| {
            Poseidon2Permutation256.permute_mut(s);
        });
        DuplexChallenger {
            sponge_state: state,
            input_buffer: vec![],
            output_buffer: vec![],
            permutation: Poseidon2Permutation256,
        }
    }
}

impl InitTranscript for AlgChallenger<RpoPermutation256> {
    fn seeded(log_trace_height: u64) -> Self {
        let state = seed_sponge_state(log_trace_height, |s| {
            RpoPermutation256.permute_mut(s);
        });
        DuplexChallenger {
            sponge_state: state,
            input_buffer: vec![],
            output_buffer: vec![],
            permutation: RpoPermutation256,
        }
    }
}

impl InitTranscript for AlgChallenger<RpxPermutation256> {
    fn seeded(log_trace_height: u64) -> Self {
        let state = seed_sponge_state(log_trace_height, |s| {
            RpxPermutation256.permute_mut(s);
        });
        DuplexChallenger {
            sponge_state: state,
            input_buffer: vec![],
            output_buffer: vec![],
            permutation: RpxPermutation256,
        }
    }
}

/// Helper for bit-oriented `InitTranscript` implementations.
///
/// Unlike the sponge-based algebraic challengers (RPO, Poseidon2, RPX) which seed the
/// capacity directly via `seed_sponge_state`, bit-oriented challengers observe the
/// RELATION_DIGEST, PCS parameters, and log_trace_height sequentially as a prefix.
fn init_transcript_hash(challenger: &mut impl CanObserve<Felt>, log_trace_height: u64) {
    challenger.observe_slice(&RELATION_DIGEST);
    challenger.observe(Felt::new(NUM_QUERIES as u64));
    challenger.observe(Felt::new(QUERY_POW_BITS as u64));
    challenger.observe(Felt::new(DEEP_POW_BITS as u64));
    challenger.observe(Felt::new(FOLDING_POW_BITS as u64));
    challenger.observe(Felt::new(LOG_BLOWUP as u64));
    challenger.observe(Felt::new(LOG_FINAL_DEGREE as u64));
    challenger.observe(Felt::new(1_u64 << LOG_FOLDING_ARITY));
    challenger.observe(Felt::new(log_trace_height));
}

impl InitTranscript for ByteChallenger<Blake3Hasher> {
    fn seeded(log_trace_height: u64) -> Self {
        let mut challenger = SerializingChallenger64::from_hasher(vec![], Blake3Hasher);
        init_transcript_hash(&mut challenger, log_trace_height);
        challenger
    }
}

impl InitTranscript for ByteChallenger<Keccak256Hash> {
    fn seeded(log_trace_height: u64) -> Self {
        let mut challenger = SerializingChallenger64::from_hasher(vec![], Keccak256Hash {});
        init_transcript_hash(&mut challenger, log_trace_height);
        challenger
    }
}

/// Absorbs variable-length public inputs into the challenger.
///
/// Each VLPI group is a flat slice of fixed-width messages. `message_widths[i]` gives the
/// width of each message in group `i`. Every message is zero-padded to the next multiple
/// of `SPONGE_RATE` and reversed before observation, matching the layout the MASM recursive
/// verifier's `mem_stream` + `horner_eval_base` expects.
pub fn observe_var_len_public_inputs<C: CanObserve<Felt>>(
    challenger: &mut C,
    var_len_public_inputs: &[&[Felt]],
    message_widths: &[usize],
) {
    assert_eq!(
        var_len_public_inputs.len(),
        message_widths.len(),
        "must provide one message width per VLPI group"
    );
    for (group, &msg_width) in var_len_public_inputs.iter().zip(message_widths) {
        assert!(msg_width > 0, "VLPI message width must be positive");
        let padded_width = msg_width.next_multiple_of(SPONGE_RATE);
        for message in group.chunks(msg_width) {
            assert_eq!(
                message.len(),
                msg_width,
                "VLPI group has trailing elements that don't form a complete message"
            );
            let mut padded = vec![Felt::ZERO; padded_width];
            for (i, &elem) in message.iter().enumerate() {
                padded[padded_width - 1 - i] = elem;
            }
            challenger.observe_slice(&padded);
        }
    }
}

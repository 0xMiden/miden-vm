//! VM protocol presets and generic protocol presets.
//! Generic configuration factories live in `miden_stark::config`.

pub use miden_stark::config::*;
use miden_stark::pcs::PcsParams;

// PCS PARAMETERS
// ================================================================================================

/// Base-two logarithm of the low-degree extension blowup used by canonical VM proofs.
pub const LOG_BLOWUP: u8 = 3;
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
/// Proof-of-work bits for the query phase. Together with 27 queries, this gives the query round
/// exactly 96 conjectured bits; lowering either value drops the preset below that target.
const QUERY_POW_BITS: usize = 17;

/// Default PCS parameters shared by all hash function configurations.
///
/// These are protocol constants. They must not depend on the process environment or benchmark
/// settings because the same factory is used by production provers and verifiers.
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

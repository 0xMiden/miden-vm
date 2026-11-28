//! Canonical STARK parameters and protocol version of the precompile relation.

pub use miden_stark::pcs::PcsParams;
pub const LOG_BLOWUP: u8 = 3;
pub const LOG_FOLDING_ARITY: u8 = 2;
/// Protocol version included in the PVM relation digest.
///
/// The circuit digest binds the generated circuit, but not external multi-AIR assertions such as
/// `ChipletMultiAir::eval_external`. Changes to those semantics require a protocol-version bump.
/// The Miden VM and PVM use distinct protocol versions.
pub const PROTOCOL_ID: u64 = 4;
pub fn precompile_pcs_params() -> PcsParams {
    PcsParams::new(
        LOG_BLOWUP, // must be >= log_quotient_degree
        LOG_FOLDING_ARITY,
        7,  // log_final_degree
        4,  // folding_pow_bits
        12, // deep_pow_bits
        27, // num_queries
        17, // query_pow_bits
    )
    .expect("invalid precompile PCS parameters")
}

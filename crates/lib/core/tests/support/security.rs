//! Test-side snapshot of the recursive verifier's accepted security-parameter envelope.
//!
//! Behavioral boundary tests pin these values to the MASM validators. Estimator tests consume the
//! same constants, so changing the verifier envelope requires one explicit review of both sides.

pub(crate) const NUM_QUERIES_MIN: u64 = 7;
pub(crate) const NUM_QUERIES_MAX: u64 = 150;
pub(crate) const POW_BITS_MAX: u64 = 31;

// Every MVM AIR has this lower bound, so it is also the smallest possible maximum height.
pub(crate) const MVM_LOG_HEIGHT_MIN: u64 = 6;
// The fixed BytePairLut AIR makes this the smallest possible PVM maximum height.
pub(crate) const PVM_LOG_HEIGHT_MIN: u64 = 16;
// Common inclusive upper bound for every AIR and for the descriptor's maximum height.
pub(crate) const LOG_HEIGHT_MAX: u64 = 29;

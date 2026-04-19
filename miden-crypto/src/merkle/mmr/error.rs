use alloc::string::String;

use thiserror::Error;

use crate::merkle::MerkleError;

#[derive(Debug, Error)]
pub enum MmrError {
    #[error("mmr does not contain position {0}")]
    PositionNotFound(usize),
    #[error("mmr peaks are invalid: {0}")]
    InvalidPeaks(String),
    #[error("mmr forest is out of bounds: requested {0} > current {1}")]
    ForestOutOfBounds(usize, usize),
    #[error("mmr forest size {requested} exceeds maximum {max}")]
    ForestSizeExceeded { requested: usize, max: usize },
    #[error("mmr peak does not match the computed merkle root of the provided authentication path")]
    PeakPathMismatch,
    #[error("requested peak index is {peak_idx} but the number of peaks is {peaks_len}")]
    PeakOutOfBounds { peak_idx: usize, peaks_len: usize },
    #[error("invalid mmr update")]
    InvalidUpdate,
    #[error("mmr does not contain a peak with depth {0}")]
    UnknownPeak(u8),
    #[error("invalid merkle path")]
    InvalidMerklePath(#[source] MerkleError),
    #[error("merkle root computation failed")]
    MerkleRootComputationFailed(#[source] MerkleError),
    #[error("inconsistent partial mmr: {0}")]
    InconsistentPartialMmr(String),
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SubtreeError {
    #[error("invalid hash data length: expected {expected} bytes, found {found} bytes")]
    BadHashLen { expected: usize, found: usize },
    #[error("hash data contains an invalid field element")]
    InvalidHashData,
    #[error("unused bitmask bits 510-511 must be zero")]
    InvalidBitmask,
    #[error("subtree data too short: found {found} bytes, need at least {min} bytes")]
    TooShort { found: usize, min: usize },
    #[error("missing subtree format magic header")]
    MissingFormatMagic,
    #[error("unsupported subtree format version: {found}")]
    UnsupportedVersion { found: u8 },
}

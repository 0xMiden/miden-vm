//! Commitments to the canonical fixed byte-pair setup for native verification.
//!
//! These reproduce the existing setup builders exactly. The Eidos identity remains the
//! AIR-owned accepted pin; the non-algebraic configurations commit the same fixed table.
pub(crate) use miden_air::precompile::protocol::PVM_PREPROCESSED_COMMITMENT as EIDOS;

pub(crate) const BLAKE3: [u8; 32] = [
    237, 165, 181, 150, 170, 183, 11, 117, 116, 34, 106, 27, 89, 68, 113, 212, 124, 97, 90, 201,
    199, 30, 220, 145, 185, 5, 104, 155, 67, 55, 138, 126,
];
pub(crate) const KECCAK: [u64; 4] = [
    8953595915908445159,
    18286975921588085812,
    1662605580119539545,
    8308041584975270064,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::preprocessed;

    #[test]
    fn native_commitments_match_independently_built_setups() {
        assert_eq!(<[u8; 32]>::from(preprocessed::blake3().commitment()), BLAKE3);
        assert_eq!(<[u64; 4]>::from(preprocessed::keccak().commitment()), KECCAK);
        assert_eq!(<[u64; 4]>::from(preprocessed::eidos().commitment()), EIDOS);
    }
}

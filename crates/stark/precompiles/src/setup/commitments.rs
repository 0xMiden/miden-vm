//! Pinned setup commitments used by native and recursive PVM verification.

pub(crate) use miden_air::precompiles::protocol::{
    PVM_BLAKE3_PREPROCESSED_COMMITMENT as BLAKE3, PVM_KECCAK_PREPROCESSED_COMMITMENT as KECCAK,
    PVM_PREPROCESSED_COMMITMENT as EIDOS,
};

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

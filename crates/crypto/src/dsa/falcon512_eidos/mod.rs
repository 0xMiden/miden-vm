//! Deterministic Falcon512 signatures using Eidos hashing.
//!
//! Eidos is used by the hash-to-point algorithm. Signing is deterministic and follows the approach
//! described in [1]: the secret key and message seed the pseudorandom generator used for trapdoor
//! sampling. The implementation must produce the same sample across supported hardware, compilers,
//! operating systems, and sampler implementations.
//!
//! The sampler uses only the built-in `f64` type. It avoids platform-specific floating-point
//! optimizations and standard-library operations whose documented precision may vary between
//! platforms.
//!
//! [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>

use super::falcon512_common::{
    self, FalconVariant, MODULUS, N, PREVERSIONED_NONCE_LEN, Polynomial,
};
#[cfg(test)]
use super::falcon512_common::{
    FalconFelt, LOG_N, SIG_NONCE_LEN, SIG_POLY_BYTE_LEN, SIG_SERIALIZED_LEN,
};
use crate::{Felt, Word};

mod hash_to_point;

#[cfg(test)]
mod tests;

/// Nonce used by deterministic Falcon512-Eidos signatures.
pub type Nonce = falcon512_common::Nonce<variant::Variant>;

/// Public key for Falcon512-Eidos signatures.
pub type PublicKey = falcon512_common::PublicKey<variant::Variant>;

/// Secret key for Falcon512-Eidos signatures.
pub type SecretKey = falcon512_common::SecretKey<variant::Variant>;

pub(super) mod variant {
    use super::{FalconVariant, Felt, Nonce, Polynomial, Word, hash_to_point};
    use crate::{
        dsa::falcon512_common::FalconFelt,
        hash::eidos::{Eidos, domains::FALCON_PUBLIC_KEY},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Variant;

    impl FalconVariant for Variant {
        const NONCE_VERSION_BYTE: u8 = super::NONCE_VERSION_BYTE;
        const PREVERSIONED_NONCE: [u8; super::PREVERSIONED_NONCE_LEN] = super::PREVERSIONED_NONCE;

        fn hash_message_to_point(message: Word, nonce: &Nonce) -> Polynomial<FalconFelt> {
            hash_to_point::hash_to_point_eidos(message, nonce)
        }

        fn public_key_commitment(elements: &[Felt]) -> Word {
            Eidos::hash_elements_in_domain(elements, FALCON_PUBLIC_KEY)
        }
    }
}

// CONSTANTS
// ================================================================================================

/// Current version of the fixed nonce.
///
/// Section 2.1 of [1] explains why the fixed nonce is versioned.
///
/// [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
const NONCE_VERSION_BYTE: u8 = 2;

/// The pre-versioned portion of the fixed nonce defined by [1].
///
/// Reference [1] calls this value a salt.
///
/// [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
const PREVERSIONED_NONCE: [u8; PREVERSIONED_NONCE_LEN] = [
    9, 70, 65, 76, 67, 79, 78, 45, 69, 73, 68, 79, 83, 45, 68, 69, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

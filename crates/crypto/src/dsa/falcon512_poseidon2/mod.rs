//! A deterministic Falcon512 Poseidon2 signature over a message.
//!
//! This version differs from the reference implementation in its use of the Poseidon2 algebraic
//! hash function in its hash-to-point algorithm.
//!
//! Another point of difference is the determinism in the signing process. The approach used to
//! achieve this is the one proposed in [1].
//! The main challenge in making the signing procedure deterministic is ensuring that the same
//! secret key is never used to produce two inequivalent signatures for the same `c`.
//! For a precise definition of equivalence of signatures see [1].
//! The reference implementation uses a random nonce per signature in order to make sure that,
//! with overwhelming probability, no two c-s will ever repeat and this non-repetition turns out
//! to be enough to make the security proof of the underlying construction go through in
//! the random-oracle model.
//!
//! Making the signing process deterministic means that we cannot rely on the above use of nonce
//! in the hash-to-point algorithm, i.e., the hash-to-point algorithm is deterministic. It also
//! means that we have to derandomize the trapdoor sampling process and use the entropy in
//! the secret key, together with the message, as the seed of a CPRNG. This is exactly the approach
//! taken in [2] but, as explained at length in [1], this is not enough. The reason for this
//! is that the sampling process during signature generation must be ensured to be consistent
//! across the entire computing stack i.e., hardware, compiler, OS, sampler implementations ...
//!
//! The sampler uses only the built-in `f64` type. It avoids platform-specific floating-point
//! optimizations and standard-library operations whose documented precision may vary between
//! platforms.
//!
//! [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
//! [2]: <https://datatracker.ietf.org/doc/html/rfc6979#section-3.5>

use super::falcon512_common::{self, FalconVariant, MODULUS, N, PREVERSIONED_NONCE_LEN};
#[cfg(test)]
use super::falcon512_common::{LOG_N, SIG_NONCE_LEN, SIG_POLY_BYTE_LEN, SIG_SERIALIZED_LEN};
use crate::{Felt, Word};

mod hash_to_point;

#[cfg(test)]
mod tests;

pub use super::falcon512_common::{PK_LEN, Polynomial, SK_LEN, SignatureHeader, SignaturePoly};

/// Nonce used by deterministic Falcon512-Poseidon2 signatures.
pub type Nonce = falcon512_common::Nonce<variant::Variant>;

/// Public key for Falcon512-Poseidon2 signatures.
pub type PublicKey = falcon512_common::PublicKey<variant::Variant>;

/// Secret key for Falcon512-Poseidon2 signatures.
pub type SecretKey = falcon512_common::SecretKey<variant::Variant>;

/// Deterministic Falcon512-Poseidon2 signature.
pub type Signature = falcon512_common::Signature<variant::Variant>;

pub(super) mod variant {
    use super::{FalconVariant, Felt, Nonce, Polynomial, Word, hash_to_point};
    use crate::{dsa::falcon512_common::FalconFelt, hash::poseidon2::Poseidon2};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Variant;

    impl FalconVariant for Variant {
        const NONCE_VERSION_BYTE: u8 = super::NONCE_VERSION_BYTE;
        const PREVERSIONED_NONCE: [u8; super::PREVERSIONED_NONCE_LEN] = super::PREVERSIONED_NONCE;

        fn hash_message_to_point(message: Word, nonce: &Nonce) -> Polynomial<FalconFelt> {
            hash_to_point::hash_to_point_poseidon2(message, nonce)
        }

        fn public_key_commitment(elements: &[Felt]) -> Word {
            Poseidon2::hash_elements(elements)
        }
    }
}

// CONSTANTS
// ================================================================================================

/// Current version of the fixed nonce.
///
/// The usefulness of the notion of versioned fixed nonce is discussed in Section 2.1 in [1].
///
/// [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
const NONCE_VERSION_BYTE: u8 = 1;

/// The preversioned portion of the fixed nonce constructed following [1].
///
/// Note that reference [1] uses the term salt instead of nonce.
///
/// [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
const PREVERSIONED_NONCE: [u8; PREVERSIONED_NONCE_LEN] = [
    9, 70, 65, 76, 67, 79, 78, 45, 80, 79, 83, 69, 73, 68, 79, 78, 50, 45, 68, 69, 84, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

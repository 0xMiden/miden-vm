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
//! This is made even more difficult by the extensive use of floating-point arithmetic by
//! the sampler. In relation to this point, the current implementation does not use any platform
//! specific optimizations (e.g., AVX2, NEON, FMA ...) and relies solely on the builtin `f64` type.
//! Moreover, as per the time of this writing, the implementation does not use any methods or
//! functions from `std::f64` that have non-deterministic precision mentioned in their
//! documentation.
//!
//! [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
//! [2]: <https://datatracker.ietf.org/doc/html/rfc6979#section-3.5>

use crate::{
    Felt, ZERO,
    hash::poseidon2::Poseidon2,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod hash_to_point;
mod keys;
mod math;
mod signature;

#[cfg(test)]
mod tests;

pub use self::{
    keys::{PublicKey, SecretKey},
    math::Polynomial,
    signature::{Signature, SignatureHeader, SignaturePoly},
};

// CONSTANTS
// ================================================================================================

// The Falcon modulus p.
const MODULUS: i16 = 12289;

// Number of bits needed to encode an element in the Falcon field.
const FALCON_ENCODING_BITS: u32 = 14;

// The Falcon parameters for Falcon-512. This is the degree of the polynomial `phi := x^N + 1`
// defining the ring `Z_p[x]/(phi)`.
const N: usize = 512;
const LOG_N: u8 = 9;

/// Length of nonce used for signature generation.
const SIG_NONCE_LEN: usize = 40;

/// Length of the preversioned portion of the fixed nonce.
///
/// Since we use one byte to encode the version of the nonce, this is equal to `SIG_NONCE_LEN - 1`.
const PREVERSIONED_NONCE_LEN: usize = 39;

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

/// Number of filed elements used to encode a nonce.
const NONCE_ELEMENTS: usize = 8;

/// Public key length as a u8 vector.
pub const PK_LEN: usize = 897;

/// Secret key length as a u8 vector.
pub const SK_LEN: usize = 1281;

/// Signature length as a u8 vector.
const SIG_POLY_BYTE_LEN: usize = 625;

/// Signature size when serialized as a u8 vector.
#[cfg(test)]
const SIG_SERIALIZED_LEN: usize = 1524;

/// Bound on the squared-norm of the signature.
const SIG_L2_BOUND: u64 = 34034726;

/// Standard deviation of the Gaussian over the lattice.
const SIGMA: f64 = 165.7366171829776;

// TYPE ALIASES
// ================================================================================================

type ShortLatticeBasis = [Polynomial<i16>; 4];

// NONCE
// ================================================================================================

/// Nonce of the Falcon signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; SIG_NONCE_LEN]);

impl Nonce {
    /// Returns a new deterministic [Nonce].
    ///
    /// This is used in deterministic signing following [1] and is composed of two parts:
    ///
    /// 1. a byte serving as a version byte,
    /// 2. a pre-versioned fixed nonce which is the UTF8 encoding of the domain separator
    ///    "FALCON-POSEIDON2-DET" padded with enough zeros to make it of size 39 bytes.
    ///
    /// The usefulness of the notion of versioned fixed nonce is discussed in Section 2.1 in [1].
    ///
    /// [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
    pub fn deterministic() -> Self {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        nonce_bytes[0] = NONCE_VERSION_BYTE;
        nonce_bytes[1..].copy_from_slice(&PREVERSIONED_NONCE);
        Self(nonce_bytes)
    }

    /// Returns a new [Nonce] drawn from the provided RNG.
    ///
    /// This is used only in testing against the test vectors of the reference (non-deterministic)
    /// Falcon DSA implementation.
    #[cfg(test)]
    pub fn random<R: rand::Rng>(rng: &mut R) -> Self {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        Self::from_bytes(nonce_bytes)
    }

    /// Returns the underlying concatenated bytes of this nonce.
    pub fn as_bytes(&self) -> [u8; SIG_NONCE_LEN] {
        self.0
    }

    /// Returns a `Nonce` given an array of bytes.
    pub fn from_bytes(nonce_bytes: [u8; SIG_NONCE_LEN]) -> Self {
        Self(nonce_bytes)
    }

    /// Converts byte representation of the nonce into field element representation.
    ///
    /// Nonce bytes are converted to field elements by taking consecutive 5 byte chunks
    /// of the nonce and interpreting them as field elements.
    pub fn to_elements(&self) -> [Felt; NONCE_ELEMENTS] {
        let mut buffer = [0_u8; 8];
        let mut result = [ZERO; 8];
        for (i, bytes) in self.as_bytes().chunks(5).enumerate() {
            buffer[..5].copy_from_slice(bytes);
            // we can safely (without overflow) create a new Felt from u64 value here since this
            // value contains at most 5 bytes
            result[i] = Felt::new_unchecked(u64::from_le_bytes(buffer));
        }

        result
    }
}

impl Serializable for &Nonce {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.0[0])
    }
}

impl Deserializable for Nonce {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let nonce_version: u8 = source.read()?;

        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        nonce_bytes[0] = nonce_version;
        nonce_bytes[1..].copy_from_slice(&PREVERSIONED_NONCE);

        Ok(Self(nonce_bytes))
    }
}

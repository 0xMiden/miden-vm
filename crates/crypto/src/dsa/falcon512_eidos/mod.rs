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

use crate::{
    Felt, ZERO,
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

/// Registered Eidos domain id for the Falcon hash-to-point construction.
pub const FALCON_HASH_TO_POINT_DOMAIN_ID: u32 = 0x000004;

/// Registered Eidos selector for the Falcon hash-to-point construction.
pub const FALCON_HASH_TO_POINT_SELECTOR: u32 = (FALCON_HASH_TO_POINT_DOMAIN_ID << 8) | 1;

/// Registered Eidos domain ID for the Falcon product-check transcript.
pub const FALCON_PRODUCT_CHECK_DOMAIN_ID: u32 = 0x000005;

/// Registered Eidos selector for the Falcon product-check transcript.
pub const FALCON_PRODUCT_CHECK_SELECTOR: u32 = (FALCON_PRODUCT_CHECK_DOMAIN_ID << 8) | 1;

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
    9, 70, 65, 76, 67, 79, 78, 45, 66, 76, 65, 75, 69, 71, 45, 68, 69, 84, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Number of field elements used to encode a nonce.
const NONCE_ELEMENTS: usize = 8;

/// Public key length in bytes.
pub const PK_LEN: usize = 897;

/// Secret key length in bytes.
pub const SK_LEN: usize = 1281;

/// Encoded signature polynomial length in bytes.
const SIG_POLY_BYTE_LEN: usize = 625;

/// Serialized signature length in bytes.
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
    /// Returns the deterministic protocol nonce.
    ///
    /// This is used in deterministic signing following [1] and is composed of two parts:
    ///
    /// 1. a byte serving as a version byte,
    /// 2. a pre-versioned fixed nonce containing the UTF-8 encoding of the protocol-defined domain
    ///    separator "FALCON-BLAKEG-DET" padded with enough zeros to make it 39 bytes. The separator
    ///    contributes to deterministic signature outputs and must remain stable.
    ///
    /// Section 2.1 of [1] explains why the fixed nonce is versioned.
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
    fn random<R: rand::Rng>(rng: &mut R) -> Self {
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

    /// Converts the nonce bytes into field elements.
    ///
    /// Nonce bytes are converted to field elements by taking consecutive 5-byte chunks
    /// of the nonce and interpreting them as field elements.
    pub fn to_elements(&self) -> [Felt; NONCE_ELEMENTS] {
        let mut buffer = [0_u8; 8];
        let mut result = [ZERO; 8];
        for (i, bytes) in self.as_bytes().chunks(5).enumerate() {
            buffer[..5].copy_from_slice(bytes);
            // This conversion cannot overflow because the value contains at most five bytes.
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

//! Shared implementation for the Miden Falcon512 variants.

use core::fmt::Debug;

use crate::{Felt, Word};

mod keys;
pub use keys::{PublicKey, SecretKey};

pub mod math;
pub use math::{FalconFelt, Polynomial};

mod nonce;
pub use nonce::Nonce;

mod signature;
pub use signature::{Signature, SignatureHeader, SignaturePoly};

#[cfg(test)]
pub(super) mod test_utils;

/// Supplies the hashing and nonce policy for a Falcon512 variant.
pub trait FalconVariant: Copy + Clone + Debug + Eq + PartialEq + Sized + 'static {
    const NONCE_VERSION_BYTE: u8;
    const PREVERSIONED_NONCE: [u8; PREVERSIONED_NONCE_LEN];

    fn hash_message_to_point(message: Word, nonce: &Nonce<Self>) -> Polynomial<FalconFelt>;

    fn public_key_commitment(elements: &[Felt]) -> Word;
}

// CONSTANTS
// ================================================================================================

/// The Falcon modulus.
pub(super) const MODULUS: i16 = 12289;

/// Number of bits used to encode a Falcon field element.
pub(super) const FALCON_ENCODING_BITS: u32 = 14;

/// Degree of the polynomial ring used by Falcon512.
pub(super) const N: usize = 512;

pub(super) const LOG_N: u8 = 9;
pub(super) const SIG_NONCE_LEN: usize = 40;
pub(super) const PREVERSIONED_NONCE_LEN: usize = SIG_NONCE_LEN - 1;
pub(super) const NONCE_ELEMENTS: usize = 8;

/// Serialized public-key length in bytes.
pub const PK_LEN: usize = 897;

/// Serialized secret-key length in bytes.
pub const SK_LEN: usize = 1281;

pub(super) const SIG_POLY_BYTE_LEN: usize = 625;

#[cfg(test)]
pub(super) const SIG_SERIALIZED_LEN: usize = 1524;

pub(super) const SIG_L2_BOUND: u64 = 34034726;
pub(super) const SIGMA: f64 = 165.7366171829776;

pub(super) type ShortLatticeBasis = [Polynomial<i16>; 4];

#[cfg(test)]
type TestVariant = crate::dsa::falcon512_eidos::variant::Variant;

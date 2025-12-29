use alloc::vec::Vec;
use core::{
    fmt::Debug,
    ops::{Bound, Range},
};

// RE-EXPORTS
// ================================================================================================
pub use miden_crypto::{
    hash::blake::{Blake3_256, Blake3Digest},
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
        uninit_vector,
    },
};
#[cfg(feature = "std")]
pub use winter_utils::ReadAdapter;
pub use winter_utils::group_slice_elements;

use crate::{Felt, Word};

pub mod math {
    pub use winter_math::batch_inversion;
}

// TO ELEMENTS
// ================================================================================================

pub trait ToElements {
    fn to_elements(&self) -> Vec<Felt>;
}

impl<const N: usize> ToElements for [u64; N] {
    fn to_elements(&self) -> Vec<Felt> {
        self.iter().map(|&v| Felt::new(v)).collect()
    }
}

impl ToElements for Vec<u64> {
    fn to_elements(&self) -> Vec<Felt> {
        self.iter().map(|&v| Felt::new(v)).collect()
    }
}

// TO WORD
// ================================================================================================

/// Hashes the provided string using the BLAKE3 hash function and converts the resulting digest into
/// a [`Word`].
pub fn hash_string_to_word<'a>(value: impl Into<&'a str>) -> Word {
    let digest_bytes: [u8; 32] = Blake3_256::hash(value.into().as_bytes()).into();
    [
        Felt::new(u64::from_le_bytes(digest_bytes[0..8].try_into().unwrap())),
        Felt::new(u64::from_le_bytes(digest_bytes[8..16].try_into().unwrap())),
        Felt::new(u64::from_le_bytes(digest_bytes[16..24].try_into().unwrap())),
        Felt::new(u64::from_le_bytes(digest_bytes[24..32].try_into().unwrap())),
    ]
    .into()
}

// INTO BYTES
// ================================================================================================

pub trait IntoBytes<const N: usize> {
    fn into_bytes(self) -> [u8; N];
}

impl IntoBytes<32> for [Felt; 4] {
    fn into_bytes(self) -> [u8; 32] {
        let mut result = [0; 32];

        result[..8].copy_from_slice(&self[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self[3].as_int().to_le_bytes());

        result
    }
}

// PUSH MANY
// ================================================================================================

pub trait PushMany<T> {
    fn push_many(&mut self, value: T, n: usize);
}

impl<T: Copy> PushMany<T> for Vec<T> {
    fn push_many(&mut self, value: T, n: usize) {
        let new_len = self.len() + n;
        self.resize(new_len, value);
    }
}

// RANGE
// ================================================================================================

/// Returns a [Range] initialized with the specified `start` and with `end` set to `start` + `len`.
pub const fn range(start: usize, len: usize) -> Range<usize> {
    Range { start, end: start + len }
}

/// Converts and parses a [Bound] into an included u64 value.
pub fn bound_into_included_u64<I>(bound: Bound<&I>, is_start: bool) -> u64
where
    I: Clone + Into<u64>,
{
    match bound {
        Bound::Excluded(i) => i.clone().into().saturating_sub(1),
        Bound::Included(i) => i.clone().into(),
        Bound::Unbounded => {
            if is_start {
                0
            } else {
                u64::MAX
            }
        },
    }
}

// ARRAY CONSTRUCTORS
// ================================================================================================

/// Returns an array of N vectors initialized with the specified capacity.
pub fn new_array_vec<T: Debug, const N: usize>(capacity: usize) -> [Vec<T>; N] {
    (0..N)
        .map(|_| Vec::with_capacity(capacity))
        .collect::<Vec<_>>()
        .try_into()
        .expect("failed to convert vector to array")
}

#[test]
#[should_panic]
fn debug_assert_is_checked() {
    // enforce the release checks to always have `RUSTFLAGS="-C debug-assertions".
    //
    // some upstream tests are performed with `debug_assert`, and we want to assert its correctness
    // downstream.
    //
    // for reference, check
    // https://github.com/0xMiden/miden-vm/issues/433
    debug_assert!(false);
}

// BYTE CONVERSIONS
// ================================================================================================

/// Number of bytes packed into each u32 field element.
///
/// Used for converting between byte arrays and u32-packed field elements in memory.
const BYTES_PER_U32: usize = core::mem::size_of::<u32>();

/// Converts bytes to field elements using u32 packing in little-endian format.
///
/// Each field element contains a u32 value representing up to 4 bytes. If the byte length
/// is not a multiple of 4, the final field element is zero-padded.
///
/// This is commonly used by precompile handlers (Keccak256, ECDSA) to convert byte data
/// into field element commitments.
///
/// # Arguments
/// - `bytes`: The byte slice to convert
///
/// # Returns
/// A vector of field elements, each containing 4 bytes packed in little-endian order.
///
/// # Examples
/// ```
/// # use miden_core::{Felt, utils::bytes_to_packed_u32_elements};
/// let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
/// let felts = bytes_to_packed_u32_elements(&bytes);
/// assert_eq!(felts, vec![Felt::from(0x04030201_u32), Felt::from(0x00000005_u32)]);
/// ```
pub fn bytes_to_packed_u32_elements(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(BYTES_PER_U32)
        .map(|chunk| {
            // Pack up to 4 bytes into a u32 in little-endian format
            let mut packed = [0u8; BYTES_PER_U32];
            packed[..chunk.len()].copy_from_slice(chunk);
            Felt::from(u32::from_le_bytes(packed))
        })
        .collect()
}

/// Converts u32-packed field elements back to bytes in little-endian format.
///
/// This is the inverse of [`bytes_to_packed_u32_elements`]. Each field element is expected
/// to contain a u32 value, which is unpacked into 4 bytes.
///
/// # Arguments
/// - `elements`: The field elements to convert
///
/// # Returns
/// A vector of bytes representing the unpacked data.
///
/// # Examples
/// ```
/// # use miden_core::{Felt, utils::{bytes_to_packed_u32_elements, packed_u32_elements_to_bytes}};
/// let original = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
/// let elements = bytes_to_packed_u32_elements(&original);
/// let bytes = packed_u32_elements_to_bytes(&elements);
/// assert_eq!(bytes, original);
/// ```
pub fn packed_u32_elements_to_bytes(elements: &[Felt]) -> Vec<u8> {
    elements
        .iter()
        .flat_map(|felt| {
            let value = felt.as_int() as u32;
            value.to_le_bytes()
        })
        .collect()
}

// FORMATTING
// ================================================================================================

pub use miden_formatting::hex::{DisplayHex, ToHex, to_hex};

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn proptest_packed_u32_elements_roundtrip(values in prop::collection::vec(any::<u32>(), 0..100)) {
            // Convert u32 values to Felts
            let felts: Vec<Felt> = values.iter().map(|&v| Felt::from(v)).collect();

            // Roundtrip: Felts -> bytes -> Felts
            let bytes = packed_u32_elements_to_bytes(&felts);
            let roundtrip_felts = bytes_to_packed_u32_elements(&bytes);

            // Should be equal
            prop_assert_eq!(felts, roundtrip_felts);
        }
    }
}

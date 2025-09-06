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

// TO EVENT UD
// ================================================================================================

/// Computes the canonical event identifier for the given `name`.
///
/// This function provides a stable, deterministic mapping from human-readable event names
/// to field elements that can be used as event identifiers in the VM. The mapping works by:
/// 1. Computing the BLAKE3 hash of the event name (produces 32 bytes)
/// 2. Taking the first 8 bytes of the hash
/// 3. Interpreting these bytes as a little-endian u64
/// 4. Reducing modulo the field prime to create a valid Felt
///
/// This ensures that identical event names always produce the same event ID, while
/// providing good distribution properties to minimize collisions between different names.
#[inline]
pub fn string_to_event_id<'a>(name: impl Into<&'a str>) -> Felt {
    let digest_bytes: [u8; 32] = Blake3_256::hash(name.into().as_bytes()).into();
    let event_bytes: [u8; 8] = digest_bytes[0..8].try_into().unwrap();
    Felt::new(u64::from_le_bytes(event_bytes))
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

// FORMATTING
// ================================================================================================

pub use miden_formatting::hex::{DisplayHex, ToHex, to_hex};

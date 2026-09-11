//! Nonce shared by the Miden Falcon512 variants.

use core::{fmt, marker::PhantomData};

use super::{FalconVariant, NONCE_ELEMENTS, SIG_NONCE_LEN};
use crate::{
    Felt, ZERO,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// Nonce of the Falcon signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce<V: FalconVariant>([u8; SIG_NONCE_LEN], PhantomData<fn() -> V>);

impl<V: FalconVariant> Nonce<V> {
    /// Returns the deterministic protocol nonce.
    pub fn deterministic() -> Self {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        nonce_bytes[0] = V::NONCE_VERSION_BYTE;
        nonce_bytes[1..].copy_from_slice(&V::PREVERSIONED_NONCE);
        Self::from_bytes(nonce_bytes)
    }

    /// Returns a nonce drawn from the provided RNG.
    ///
    /// This is used only by tests against the reference Falcon implementation.
    #[cfg(test)]
    pub(super) fn random<R: rand::Rng>(rng: &mut R) -> Self {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        Self::from_bytes(nonce_bytes)
    }

    /// Returns the nonce bytes.
    pub fn as_bytes(&self) -> [u8; SIG_NONCE_LEN] {
        self.0
    }

    /// Constructs a nonce from its byte representation.
    pub fn from_bytes(nonce_bytes: [u8; SIG_NONCE_LEN]) -> Self {
        Self(nonce_bytes, PhantomData)
    }

    /// Converts the nonce into field elements.
    ///
    /// Each consecutive five-byte chunk is interpreted as one field element.
    pub fn to_elements(&self) -> [Felt; NONCE_ELEMENTS] {
        let mut buffer = [0_u8; 8];
        let mut result = [ZERO; NONCE_ELEMENTS];
        for (i, bytes) in self.as_bytes().chunks(5).enumerate() {
            buffer[..5].copy_from_slice(bytes);
            // A five-byte value is smaller than the field modulus.
            result[i] = Felt::new_unchecked(u64::from_le_bytes(buffer));
        }

        result
    }
}

impl<V: FalconVariant> fmt::Debug for Nonce<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Nonce").field(&self.0).finish()
    }
}

impl<V: FalconVariant> Serializable for &Nonce<V> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.0[0])
    }
}

impl<V: FalconVariant> Deserializable for Nonce<V> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let nonce_version = source.read()?;
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        nonce_bytes[0] = nonce_version;
        nonce_bytes[1..].copy_from_slice(&V::PREVERSIONED_NONCE);
        Ok(Self::from_bytes(nonce_bytes))
    }
}

//! Public key types for the Miden Falcon512 variants.

use alloc::{string::ToString, vec::Vec};
use core::{fmt, marker::PhantomData, ops::Deref};

use num::Zero;

use super::{
    super::{FALCON_ENCODING_BITS, FalconVariant, LOG_N, N, PK_LEN},
    ByteReader, ByteWriter, Deserializable, DeserializationError, FalconFelt, Felt, Polynomial,
    Serializable, Signature,
};
use crate::{SequentialCommit, Word};

// PUBLIC KEY
// ================================================================================================

/// Public key represented as a polynomial with coefficients over the Falcon prime field.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey<V: FalconVariant>(Polynomial<FalconFelt>, PhantomData<fn() -> V>);

impl<V: FalconVariant> PublicKey<V> {
    /// Verifies the provided signature against the provided message and this public key.
    pub fn verify(&self, message: Word, signature: &Signature<V>) -> bool {
        signature.verify(message, self)
    }

    /// Returns the public key embedded in the signature.
    pub fn recover_from(_message: Word, signature: &Signature<V>) -> Self {
        signature.public_key().clone()
    }

    /// Returns this Falcon variant's commitment to the public key.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl<V: FalconVariant> SequentialCommit for PublicKey<V> {
    type Commitment = Word;

    fn to_commitment(&self) -> Self::Commitment {
        V::public_key_commitment(&self.to_elements())
    }

    fn to_elements(&self) -> Vec<Felt> {
        Into::<Polynomial<Felt>>::into(self.0.clone()).coefficients
    }
}

impl<V: FalconVariant> Deref for PublicKey<V> {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V: FalconVariant> From<Polynomial<FalconFelt>> for PublicKey<V> {
    fn from(pk_poly: Polynomial<FalconFelt>) -> Self {
        Self(pk_poly, PhantomData)
    }
}

impl<V: FalconVariant> fmt::Debug for PublicKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.0).finish()
    }
}

impl<V: FalconVariant> Serializable for &PublicKey<V> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut buf = [0_u8; PK_LEN];
        buf[0] = LOG_N;

        let mut acc = 0_u32;
        let mut acc_len: u32 = 0;

        let mut input_pos = 1;
        for c in self.0.coefficients.iter() {
            let c = c.value();
            acc = (acc << FALCON_ENCODING_BITS) | c as u32;
            acc_len += FALCON_ENCODING_BITS;
            while acc_len >= 8 {
                acc_len -= 8;
                buf[input_pos] = (acc >> acc_len) as u8;
                input_pos += 1;
            }
        }
        if acc_len > 0 {
            buf[input_pos] = (acc >> (8 - acc_len)) as u8;
        }

        target.write(buf);
    }
}

impl<V: FalconVariant> fmt::Display for PublicKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::utils::write_hex(f, &self.to_bytes())
    }
}

impl<V: FalconVariant> Deserializable for PublicKey<V> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let buf = source.read_array::<PK_LEN>()?;

        if buf[0] != LOG_N {
            return Err(DeserializationError::InvalidValue(format!(
                "Failed to decode public key: expected the first byte to be {LOG_N} but was {}",
                buf[0]
            )));
        }

        let mut acc = 0_u32;
        let mut acc_len = 0;

        let mut output = [FalconFelt::zero(); N];
        let mut output_idx = 0;

        for &byte in buf.iter().skip(1) {
            acc = (acc << 8) | (byte as u32);
            acc_len += 8;

            if acc_len >= FALCON_ENCODING_BITS {
                acc_len -= FALCON_ENCODING_BITS;
                let w = (acc >> acc_len) & 0x3fff;
                let element = w.try_into().map_err(|err| {
                    DeserializationError::InvalidValue(format!(
                        "Failed to decode public key: {err}"
                    ))
                })?;
                output[output_idx] = element;
                output_idx += 1;
            }
        }

        if (acc & ((1u32 << acc_len) - 1)) == 0 {
            Ok(Polynomial::new(output.to_vec()).into())
        } else {
            Err(DeserializationError::InvalidValue(
                "Failed to decode public key: input not fully consumed".to_string(),
            ))
        }
    }
}

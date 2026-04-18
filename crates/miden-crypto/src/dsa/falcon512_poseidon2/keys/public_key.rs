//! Public key types for the Poseidon2 Falcon 512 digital signature scheme used in Miden VM.

use alloc::{string::ToString, vec::Vec};
use core::ops::Deref;

use num::Zero;

use super::{
    super::{LOG_N, N, PK_LEN},
    ByteReader, ByteWriter, Deserializable, DeserializationError, FalconFelt, Felt, Polynomial,
    Serializable, Signature,
};
use crate::{SequentialCommit, Word, dsa::falcon512_poseidon2::FALCON_ENCODING_BITS};

// PUBLIC KEY
// ================================================================================================

/// Public key represented as a polynomial with coefficients over the Falcon prime field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Polynomial<FalconFelt>);

impl PublicKey {
    /// Verifies the provided signature against provided message and this public key.
    pub fn verify(&self, message: Word, signature: &Signature) -> bool {
        signature.verify(message, self)
    }

    /// Recovers from the signature the public key associated to the secret key used to sign
    /// a message.
    pub fn recover_from(_message: Word, signature: &Signature) -> Self {
        signature.public_key().clone()
    }

    /// Returns a commitment to the public key using the Poseidon2 hash function.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl SequentialCommit for PublicKey {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        Into::<Polynomial<Felt>>::into(self.0.clone()).coefficients
    }
}

impl Deref for PublicKey {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Polynomial<FalconFelt>> for PublicKey {
    fn from(pk_poly: Polynomial<FalconFelt>) -> Self {
        Self(pk_poly)
    }
}

impl Serializable for &PublicKey {
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

impl Deserializable for PublicKey {
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

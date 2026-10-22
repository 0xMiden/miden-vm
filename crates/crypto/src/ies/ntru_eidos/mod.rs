//! Encrypts Felt messages with the recipient's NTRU public key.
//!
//! The sender uses the recipient's public key and fresh randomness to produce a shared secret
//! and a capsule (KEM ciphertext), then derives an AEAD key and nonce and encrypts the message.
//! The recipient uses its private key to recover the shared secret from the capsule and derives
//! the same key and nonce. Context is authenticated but not encrypted; both parties supply the
//! same context.
//!
//! [`Envelope`] contains the capsule, encrypted message, and authentication tag. Its Felt
//! encoding is also the output of `crypto::ies::ntru_eidos::seal` in the core library.
//! Use [`super::SealingKey`] and [`super::UnsealingKey`] for byte or Felt messages.

use alloc::vec::Vec;

pub(super) mod adapter;

use rand::CryptoRng;

use crate::{
    Felt, Word,
    aead::aead_eidos::expanded::{
        checked_mac_input_len, decrypt_felts_expanded_authenticated,
        encrypt_felts_expanded_authenticated,
    },
    kem::ntru_hps509::{
        Ciphertext, PublicKey, SecretKey, SharedSecret,
        framing::{self, felt},
    },
    utils::zeroize::Zeroizing,
};

pub(crate) const HEADER_FELTS: usize = 4;
pub(crate) const ENCAPSULATION_FELTS: usize = 176;
pub(crate) const PAYLOAD_OFFSET: usize = HEADER_FELTS + ENCAPSULATION_FELTS;

/// An NTRU capsule, an encrypted Felt message, and its authentication tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    encapsulation: Ciphertext,
    ciphertext: Vec<Felt>,
    tag: [Felt; 2],
}

/// Seals a Felt message with fresh encapsulation randomness.
pub fn seal_with_rng(
    recipient: &PublicKey,
    rng: &mut impl CryptoRng,
    plaintext: &[Felt],
    context: &[Felt],
) -> Result<Envelope, Error> {
    check_lengths(plaintext.len(), context.len())?;
    let (encapsulation, secret) = recipient.encapsulate(rng);
    let digest = framing::fields(framing::CONTEXT, context);
    Ok(seal_inner(recipient, encapsulation, &secret, plaintext, context, digest))
}

/// Authenticates the envelope and context before returning any plaintext.
pub fn open(
    recipient: &SecretKey,
    context: &[Felt],
    envelope: &Envelope,
) -> Result<Vec<Felt>, Error> {
    check_lengths(envelope.ciphertext.len() / 2, context.len())?;
    let digest = framing::fields(framing::CONTEXT, context);
    open_inner(recipient, context, digest, envelope)
}

fn open_inner(
    recipient: &SecretKey,
    context: &[Felt],
    digest: Word,
    envelope: &Envelope,
) -> Result<Vec<Felt>, Error> {
    let secret = recipient.decapsulate(&envelope.encapsulation);
    let (key, nonce) = key_nonce(recipient.public_key(), &envelope.encapsulation, &secret, digest);
    decrypt_felts_expanded_authenticated(
        Word::new(key.map(felt)),
        Word::new(nonce.map(felt)),
        context,
        &envelope.ciphertext,
        envelope.tag,
    )
    .ok_or(Error::AuthenticationFailed)
}

pub(crate) fn check_lengths(plaintext_len: usize, context_len: usize) -> Result<(), Error> {
    let ciphertext_len = plaintext_len.checked_mul(2).ok_or(Error::InvalidLength)?;
    checked_mac_input_len(context_len, ciphertext_len).ok_or(Error::InvalidLength)?;
    Ok(())
}

fn seal_inner(
    public_key: &PublicKey,
    encapsulation: Ciphertext,
    secret: &SharedSecret,
    plaintext: &[Felt],
    context: &[Felt],
    context_digest: Word,
) -> Envelope {
    let (key, nonce) = key_nonce(public_key, &encapsulation, secret, context_digest);
    let (ciphertext, tag) = encrypt_felts_expanded_authenticated(
        Word::new(key.map(felt)),
        Word::new(nonce.map(felt)),
        context,
        plaintext,
    );
    Envelope { encapsulation, ciphertext, tag }
}

fn key_nonce(
    public_key: &PublicKey,
    encapsulation: &Ciphertext,
    secret: &SharedSecret,
    context_digest: Word,
) -> (framing::SecretDigest, framing::SecretDigest) {
    // Both hashes cover the shared secret, recipient commitment, context digest, and capsule
    // digest. Separate roles distinguish the key from the nonce.
    let mut payload = Zeroizing::new([0; 16]);
    payload[..4].copy_from_slice(secret.as_u64s());
    let public = [
        public_key.to_commitment(),
        context_digest,
        framing::bytes(framing::CIPHERTEXT, encapsulation.as_bytes()),
    ];
    for (dst, value) in payload[4..].iter_mut().zip(Word::words_as_elements(&public)) {
        *dst = value.as_canonical_u64();
    }
    (
        framing::secret_fields(framing::KEY, payload.as_ref()),
        framing::secret_fields(framing::NONCE, payload.as_ref()),
    )
}

impl Envelope {
    /// Returns the capsule needed to recover the shared secret.
    pub fn encapsulation(&self) -> &Ciphertext {
        &self.encapsulation
    }

    /// Returns two u32 ciphertext limbs per plaintext Felt.
    pub fn ciphertext(&self) -> &[Felt] {
        &self.ciphertext
    }

    /// Returns the authentication tag.
    pub fn tag(&self) -> [Felt; 2] {
        self.tag
    }

    /// Encodes the envelope in the Felt layout used by the core library's sealing procedure.
    ///
    /// ```text
    /// [magic, version, plaintext_len, 0]
    /// [encapsulation: 175 little-endian u32 Felts, 0]
    /// [encrypted message: 2 * plaintext_len u32 Felts]
    /// [tag: 2 Felts, zero padding to a multiple of four Felts]
    /// ```
    ///
    /// Capsule bytes are packed four per u32 Felt, with a zero byte in the last u32 and
    /// one additional zero Felt.
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut out = vec![
            felt(framing::MAGIC),
            Felt::ONE,
            felt((self.ciphertext.len() / 2) as u64),
            Felt::ZERO,
        ];
        out.extend(framing::packed_bytes(self.encapsulation.as_bytes()));
        out.resize(PAYLOAD_OFFSET, Felt::ZERO);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out.resize(out.len().next_multiple_of(4), Felt::ZERO);
        out
    }

    /// Decodes the complete word-aligned envelope, rejecting extra data and nonzero padding.
    pub fn from_elements(input: &[Felt]) -> Result<Self, Error> {
        if input.len() < PAYLOAD_OFFSET + 2
            || input[0] != felt(framing::MAGIC)
            || input[1] != Felt::ONE
            || input[3] != Felt::ZERO
            || input[PAYLOAD_OFFSET - 1] != Felt::ZERO
        {
            return Err(Error::InvalidEncoding);
        }
        let len = usize::try_from(input[2].as_canonical_u64()).map_err(|_| Error::InvalidLength)?;
        check_lengths(len, 0)?;
        let tag_offset = PAYLOAD_OFFSET + 2 * len;
        let end = tag_offset + 2;
        if input.len() != end.next_multiple_of(4) || input[end..].iter().any(|&x| x != Felt::ZERO) {
            return Err(Error::InvalidEncoding);
        }
        let mut bytes = Vec::with_capacity(700);
        for x in &input[HEADER_FELTS..PAYLOAD_OFFSET - 1] {
            bytes.extend_from_slice(
                &u32::try_from(x.as_canonical_u64())
                    .map_err(|_| Error::InvalidEncoding)?
                    .to_le_bytes(),
            );
        }
        if bytes.pop() != Some(0)
            || input[PAYLOAD_OFFSET..tag_offset]
                .iter()
                .any(|x| x.as_canonical_u64() > u32::MAX as u64)
        {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self {
            encapsulation: Ciphertext::from_bytes(&bytes).map_err(|_| Error::InvalidEncoding)?,
            ciphertext: input[PAYLOAD_OFFSET..tag_offset].to_vec(),
            tag: [input[tag_offset], input[tag_offset + 1]],
        })
    }
}

#[cfg(test)]
mod tests;

/// Invalid lengths, malformed envelopes, or failed authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid NTRU-Eidos envelope")]
    InvalidEncoding,
    #[error("NTRU-Eidos plaintext or context exceeds its supported length")]
    InvalidLength,
    #[error("NTRU-Eidos authentication failed")]
    AuthenticationFailed,
}

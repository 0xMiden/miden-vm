//! Encrypts a Felt message with the recipient's EcGFp5 public key.
//!
//! For generator `G`, recipient point `Q`, and fresh scalar `r`, the sender computes `R = rG`
//! and `S = rQ`. An Eidos extraction binds `S`, `R`, and `Q`.
//! Separate expansion domains derive the AEAD key and nonce from that secret and a context digest.
//! The full context is authenticated but not encrypted. The recipient recovers `S` from `R` and
//! its secret key, then derives the same key and nonce to open the message.
//!
//! Use [`seal_with_rng`] to sample a fresh scalar per message, or [`seal_with_scalar`] when the
//! caller supplies it. Sender authentication and replay protection belong to the application.
//!
//! This is an HPKE-style, single-message construction, not an RFC 9180 ciphersuite. Its envelope is
//! `[R(5), tag(2), plaintext_len, ciphertext(2*plaintext_len)]`. Ciphertext elements are u32 limbs.
//! The context is supplied separately.
//!
//! For the common byte and Felt APIs, use [`super::SealingKey::Ecgfp5Eidos`] and
//! [`super::UnsealingKey::Ecgfp5Eidos`]. An [`Envelope`] converts to and from
//! [`super::SealedMessage`] with `From` and `TryFrom`.

use alloc::vec::Vec;

use rand::CryptoRng;

pub(super) mod adapter;

use crate::{
    Felt, Word,
    aead::aead_eidos::{MAX_AUTHENTICATED_INPUT_FELTS, expanded},
    ecdh::ecgfp5::{PublicKey, SecretKey, SharedSecret},
    hash::eidos::{
        Eidos,
        domains::{ECGFP5_SEAL_CONTEXT, ECGFP5_SEAL_EXTRACT, ECGFP5_SEAL_KEY, ECGFP5_SEAL_NONCE},
    },
};

/// Maximum plaintext length with empty associated data. Context shares the AEAD input budget.
pub const MAX_PLAINTEXT_FELTS: usize = (MAX_AUTHENTICATED_INPUT_FELTS - 6) / 2;

/// Public output of one encryption, with no shared-secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    ephemeral_key: PublicKey,
    ciphertext: Vec<Felt>,
    tag: [Felt; 2],
}

impl Envelope {
    /// Returns the ephemeral public key needed for decryption.
    pub fn ephemeral_key(&self) -> PublicKey {
        self.ephemeral_key
    }

    /// Returns expanded ciphertext: two u32 limbs per plaintext Felt.
    pub fn ciphertext(&self) -> &[Felt] {
        &self.ciphertext
    }

    /// Returns the two-Felt authentication tag.
    pub fn tag(&self) -> [Felt; 2] {
        self.tag
    }

    /// Encodes the eight-Felt header followed by the expanded ciphertext.
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut result = Vec::with_capacity(8 + self.ciphertext.len());
        result.extend(self.ephemeral_key.to_elements());
        result.extend(self.tag);
        result.push(Felt::from_u32((self.ciphertext.len() / 2) as u32));
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Decodes an exact-length envelope, validating the point, length, and ciphertext limbs.
    /// Authentication is performed by [`open`], not by this structural decoder.
    pub fn from_elements(elements: &[Felt]) -> Result<Self, Error> {
        let header = elements.get(..8).ok_or(Error::InvalidEnvelope)?;
        let len =
            usize::try_from(header[7].as_canonical_u64()).map_err(|_| Error::InvalidEnvelope)?;
        if len > MAX_PLAINTEXT_FELTS || elements.len() != 8 + 2 * len {
            return Err(Error::InvalidEnvelope);
        }
        let ephemeral_key = PublicKey::from_elements(header[..5].try_into().unwrap())
            .map_err(|_| Error::InvalidEnvelope)?;
        let ciphertext = &elements[8..];
        if ciphertext.iter().any(|x| x.as_canonical_u64() > u64::from(u32::MAX)) {
            return Err(Error::InvalidEnvelope);
        }
        Ok(Self {
            ephemeral_key,
            ciphertext: ciphertext.to_vec(),
            tag: [header[5], header[6]],
        })
    }
}

/// Encrypts with a supplied ephemeral scalar, matching the deterministic MASM operation.
///
/// Use a fresh random scalar for each sealed envelope. Context is authenticated, not encrypted.
pub fn seal_with_scalar(
    recipient: &PublicKey,
    plaintext: &[Felt],
    context: &[Felt],
    ephemeral: &SecretKey,
) -> Result<Envelope, Error> {
    check_lengths(plaintext.len(), context.len())?;
    let context_digest = Eidos::hash_elements_in_domain(context, ECGFP5_SEAL_CONTEXT);
    Ok(seal_inner(recipient, plaintext, context, context_digest, ephemeral))
}

fn seal_inner(
    recipient: &PublicKey,
    plaintext: &[Felt],
    context: &[Felt],
    context_digest: Word,
    ephemeral: &SecretKey,
) -> Envelope {
    let ephemeral_key = ephemeral.public_key();
    let shared = ephemeral.diffie_hellman(recipient);
    let (key, nonce) = derive_key_nonce(&shared, ephemeral_key, *recipient, context_digest);
    let (ciphertext, tag) = expanded::encrypt_felts_expanded_authenticated(
        Word::new(key.0),
        Word::new(nonce.0),
        context,
        plaintext,
    );
    Envelope { ephemeral_key, ciphertext, tag }
}

/// Samples an ephemeral scalar with a cryptographic RNG, then encrypts with [`seal_with_scalar`].
pub fn seal_with_rng<R: CryptoRng>(
    recipient: &PublicKey,
    plaintext: &[Felt],
    context: &[Felt],
    rng: &mut R,
) -> Result<Envelope, Error> {
    check_lengths(plaintext.len(), context.len())?;
    seal_with_scalar(recipient, plaintext, context, &SecretKey::with_rng(rng))
}

/// Authenticates and decrypts a sealed message.
///
/// A different context or secret key causes authentication to fail. The returned plaintext is
/// sensitive and its owner is responsible for erasing it.
pub fn open(
    recipient: &SecretKey,
    context: &[Felt],
    sealed: &Envelope,
) -> Result<Vec<Felt>, Error> {
    check_lengths(sealed.ciphertext.len() / 2, context.len())?;
    let context_digest = Eidos::hash_elements_in_domain(context, ECGFP5_SEAL_CONTEXT);
    open_inner(recipient, context, context_digest, sealed)
}

fn open_inner(
    recipient: &SecretKey,
    context: &[Felt],
    context_digest: Word,
    sealed: &Envelope,
) -> Result<Vec<Felt>, Error> {
    let shared = recipient.diffie_hellman(&sealed.ephemeral_key);
    let (key, nonce) =
        derive_key_nonce(&shared, sealed.ephemeral_key, recipient.public_key(), context_digest);
    expanded::decrypt_felts_expanded_authenticated(
        Word::new(key.0),
        Word::new(nonce.0),
        context,
        &sealed.ciphertext,
        sealed.tag,
    )
    .ok_or(Error::AuthenticationFailed)
}

/// Invalid lengths, malformed envelopes, or failed authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("EcGFp5-Eidos plaintext and context exceed the AEAD input limit")]
    MessageTooLong,
    #[error("EcGFp5-Eidos context length must fit in a u32")]
    ContextTooLong,
    #[error("invalid EcGFp5-Eidos envelope")]
    InvalidEnvelope,
    #[error("EcGFp5-Eidos authentication failed")]
    AuthenticationFailed,
}

fn check_lengths(plaintext_len: usize, context_len: usize) -> Result<(), Error> {
    if plaintext_len > MAX_PLAINTEXT_FELTS {
        return Err(Error::MessageTooLong);
    }
    u32::try_from(context_len).map_err(|_| Error::ContextTooLong)?;
    expanded::checked_mac_input_len(context_len, 2 * plaintext_len).ok_or(Error::MessageTooLong)?;
    Ok(())
}

fn derive_key_nonce(
    shared: &SharedSecret,
    ephemeral: PublicKey,
    recipient: PublicKey,
    context: Word,
) -> (SecretFelts<4>, SecretFelts<4>) {
    // Extract from enc8(S) || enc8(R) || enc8(Q): three five-Felt points, each padded to eight.
    let mut extraction = SecretFelts([Felt::ZERO; 24]);
    extraction.0[..5].copy_from_slice(&shared.to_elements());
    extraction.0[8..13].copy_from_slice(&ephemeral.to_elements());
    extraction.0[16..21].copy_from_slice(&recipient.to_elements());

    // Expand prk || context_digest under separate key and nonce domains.
    let mut expansion = SecretFelts([Felt::ZERO; 8]);
    expansion.0[..4].copy_from_slice(
        Eidos::hash_elements_in_domain(&extraction.0, ECGFP5_SEAL_EXTRACT).as_elements(),
    );
    expansion.0[4..].copy_from_slice(context.as_elements());
    (
        SecretFelts(Eidos::hash_elements_in_domain(&expansion.0, ECGFP5_SEAL_KEY).into_elements()),
        SecretFelts(
            Eidos::hash_elements_in_domain(&expansion.0, ECGFP5_SEAL_NONCE).into_elements(),
        ),
    )
}

// Felt has no Zeroize implementation. Match the volatile erasure used by the AEAD secret key.
struct SecretFelts<const N: usize>([Felt; N]);

impl<const N: usize> Drop for SecretFelts<N> {
    fn drop(&mut self) {
        for element in &mut self.0 {
            // SAFETY: the pointer comes from an exclusive reference to a valid Felt.
            unsafe { core::ptr::write_volatile(element, Felt::ZERO) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests;

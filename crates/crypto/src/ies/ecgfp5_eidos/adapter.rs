//! Connects the EcGFp5 envelope to the common IES API and its byte encoding.

use alloc::vec::Vec;

use rand::CryptoRng;

use super::{Envelope, PublicKey, SecretKey, check_lengths, open, open_inner, seal_inner};
use crate::{
    Felt,
    aead::DataType,
    hash::eidos::{Eidos, domains::ECGFP5_SEAL_BYTE_CONTEXT},
    ies::{IesError, SealedMessage, eidos_envelope, keys::PublicEncapsulation},
    utils::{BINARY_CHUNK_SIZE, bytes_to_elements_with_padding, padded_elements_to_bytes},
};

pub(in crate::ies) fn seal_elements<R: CryptoRng>(
    recipient: &PublicKey,
    rng: &mut R,
    plaintext: &[Felt],
    context: &[Felt],
) -> Result<SealedMessage, IesError> {
    super::seal_with_rng(recipient, plaintext, context, rng)
        .map(Into::into)
        .map_err(|_| IesError::EncryptionFailed)
}

pub(in crate::ies) fn open_elements(
    recipient: &SecretKey,
    ephemeral_key: PublicKey,
    ciphertext: &[u8],
    context: &[Felt],
) -> Result<Vec<Felt>, IesError> {
    let sealed = decode(ephemeral_key, ciphertext, DataType::Elements)?;
    open(recipient, context, &sealed).map_err(|_| IesError::DecryptionFailed)
}

pub(in crate::ies) fn seal_bytes<R: CryptoRng>(
    recipient: &PublicKey,
    rng: &mut R,
    plaintext: &[u8],
    context: &[u8],
) -> Result<SealedMessage, IesError> {
    check_byte_lengths(plaintext.len().div_ceil(BINARY_CHUNK_SIZE), context.len())
        .map_err(|_| IesError::EncryptionFailed)?;
    let plaintext = bytes_to_elements_with_padding(plaintext);
    // The separate context domain binds the byte-message type, even with empty context.
    let context_digest = Eidos::hash_in_domain(context, ECGFP5_SEAL_BYTE_CONTEXT);
    let context = bytes_to_elements_with_padding(context);
    let sealed =
        seal_inner(recipient, &plaintext, &context, context_digest, &SecretKey::with_rng(rng));
    Ok(encode(sealed, DataType::Bytes))
}

pub(in crate::ies) fn open_bytes(
    recipient: &SecretKey,
    ephemeral_key: PublicKey,
    ciphertext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, IesError> {
    let sealed = decode(ephemeral_key, ciphertext, DataType::Bytes)?;
    check_byte_lengths(sealed.ciphertext.len() / 2, context.len())
        .map_err(|_| IesError::DecryptionFailed)?;
    let context_digest = Eidos::hash_in_domain(context, ECGFP5_SEAL_BYTE_CONTEXT);
    let context = bytes_to_elements_with_padding(context);
    let plaintext = open_inner(recipient, &context, context_digest, &sealed)
        .map_err(|_| IesError::DecryptionFailed)?;
    let bytes = padded_elements_to_bytes(&plaintext).ok_or(IesError::DecryptionFailed)?;
    // The decoder ignores unused bytes; re-encoding checks the complete padding.
    if bytes_to_elements_with_padding(&bytes) != plaintext {
        return Err(IesError::DecryptionFailed);
    }
    Ok(bytes)
}

fn check_byte_lengths(plaintext_felts: usize, context_bytes: usize) -> Result<(), super::Error> {
    u32::try_from(context_bytes).map_err(|_| super::Error::ContextTooLong)?;
    check_lengths(plaintext_felts, context_bytes.div_ceil(BINARY_CHUNK_SIZE))
}

impl From<Envelope> for SealedMessage {
    /// Wraps a Felt envelope, including one produced by either MASM sealing procedure.
    fn from(sealed: Envelope) -> Self {
        encode(sealed, DataType::Elements)
    }
}

impl TryFrom<SealedMessage> for Envelope {
    type Error = IesError;

    /// Extracts a Felt envelope. Byte messages and other IES schemes are rejected.
    fn try_from(message: SealedMessage) -> Result<Self, Self::Error> {
        let PublicEncapsulation::Ecgfp5Eidos(ephemeral_key) = message.encapsulation else {
            return Err(IesError::SchemeMismatch);
        };
        decode(ephemeral_key, &message.ciphertext, DataType::Elements)
    }
}

fn encode(sealed: Envelope, data_type: DataType) -> SealedMessage {
    SealedMessage {
        encapsulation: PublicEncapsulation::Ecgfp5Eidos(sealed.ephemeral_key),
        ciphertext: eidos_envelope::encode(&sealed.ciphertext, sealed.tag, data_type),
    }
}

fn decode(
    ephemeral_key: PublicKey,
    ciphertext: &[u8],
    expected_type: DataType,
) -> Result<Envelope, IesError> {
    let (ciphertext, tag) = eidos_envelope::decode(ciphertext, expected_type)?;
    Ok(Envelope { ephemeral_key, ciphertext, tag })
}

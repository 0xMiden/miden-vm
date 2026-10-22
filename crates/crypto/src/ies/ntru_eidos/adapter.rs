use alloc::vec::Vec;

use rand::CryptoRng;

use super::{Envelope, check_lengths, open, open_inner, seal_inner};
use crate::{
    Felt,
    aead::DataType,
    ies::{IesError, SealedMessage, eidos_envelope, keys::PublicEncapsulation},
    kem::ntru_hps509::{Ciphertext, PublicKey, SecretKey, framing},
    utils::{BINARY_CHUNK_SIZE, bytes_to_elements_with_padding, padded_elements_to_bytes},
};

pub(in crate::ies) fn seal_elements(
    recipient: &PublicKey,
    rng: &mut impl CryptoRng,
    plaintext: &[Felt],
    context: &[Felt],
) -> Result<SealedMessage, IesError> {
    super::seal_with_rng(recipient, rng, plaintext, context)
        .map(Into::into)
        .map_err(|_| IesError::EncryptionFailed)
}

pub(in crate::ies) fn open_elements(
    recipient: &SecretKey,
    encapsulation: Ciphertext,
    ciphertext: &[u8],
    context: &[Felt],
) -> Result<Vec<Felt>, IesError> {
    let sealed = decode(encapsulation, ciphertext, DataType::Elements)?;
    open(recipient, context, &sealed).map_err(|_| IesError::DecryptionFailed)
}

pub(in crate::ies) fn seal_bytes(
    recipient: &PublicKey,
    rng: &mut impl CryptoRng,
    plaintext: &[u8],
    context: &[u8],
) -> Result<SealedMessage, IesError> {
    check_byte_lengths(plaintext.len().div_ceil(BINARY_CHUNK_SIZE), context.len())?;
    let plaintext = bytes_to_elements_with_padding(plaintext);
    // Binding the raw byte context under its own role also separates byte and Felt messages.
    let digest = framing::bytes(framing::BYTE_CONTEXT, context);
    let context = bytes_to_elements_with_padding(context);
    let (encapsulation, secret) = recipient.encapsulate(rng);
    Ok(encode(
        seal_inner(recipient, encapsulation, &secret, &plaintext, &context, digest),
        DataType::Bytes,
    ))
}

pub(in crate::ies) fn open_bytes(
    recipient: &SecretKey,
    encapsulation: Ciphertext,
    ciphertext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, IesError> {
    let sealed = decode(encapsulation, ciphertext, DataType::Bytes)?;
    check_byte_lengths(sealed.ciphertext.len() / 2, context.len())
        .map_err(|_| IesError::DecryptionFailed)?;
    let digest = framing::bytes(framing::BYTE_CONTEXT, context);
    let context = bytes_to_elements_with_padding(context);
    let plaintext =
        open_inner(recipient, &context, digest, &sealed).map_err(|_| IesError::DecryptionFailed)?;
    let bytes = padded_elements_to_bytes(&plaintext).ok_or(IesError::DecryptionFailed)?;
    if bytes_to_elements_with_padding(&bytes) != plaintext {
        return Err(IesError::DecryptionFailed);
    }
    Ok(bytes)
}

fn check_byte_lengths(plaintext_felts: usize, context_bytes: usize) -> Result<(), IesError> {
    u32::try_from(context_bytes).map_err(|_| IesError::EncryptionFailed)?;
    check_lengths(plaintext_felts, context_bytes.div_ceil(BINARY_CHUNK_SIZE))
        .map_err(|_| IesError::EncryptionFailed)
}

impl From<Envelope> for SealedMessage {
    fn from(sealed: Envelope) -> Self {
        encode(sealed, DataType::Elements)
    }
}

impl TryFrom<SealedMessage> for Envelope {
    type Error = IesError;

    fn try_from(message: SealedMessage) -> Result<Self, Self::Error> {
        let PublicEncapsulation::NtruEidos(encapsulation) = message.encapsulation else {
            return Err(IesError::SchemeMismatch);
        };
        decode(encapsulation, &message.ciphertext, DataType::Elements)
    }
}

fn encode(sealed: Envelope, data_type: DataType) -> SealedMessage {
    SealedMessage {
        encapsulation: PublicEncapsulation::NtruEidos(sealed.encapsulation),
        ciphertext: eidos_envelope::encode(&sealed.ciphertext, sealed.tag, data_type),
    }
}

fn decode(
    encapsulation: Ciphertext,
    ciphertext: &[u8],
    data_type: DataType,
) -> Result<Envelope, IesError> {
    let (ciphertext, tag) = eidos_envelope::decode(ciphertext, data_type)?;
    Ok(Envelope { encapsulation, ciphertext, tag })
}

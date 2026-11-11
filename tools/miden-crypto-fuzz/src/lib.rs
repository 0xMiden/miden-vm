//! Shared Falcon path checks for the `signatures` fuzz target.

use miden_crypto::{
    Word,
    dsa::falcon512_eidos::{PK_LEN, PublicKey, Signature, SignaturePoly},
    utils::{Deserializable, Serializable},
};

/// Falcon512 signature-polynomial wire size, fixed by the compressed encoding.
pub const SIG_POLY_BYTE_LEN: usize = 625;
/// Number of bytes needed to describe 512 Falcon coefficients.
pub const SIG_POLY_COEFFICIENT_BYTES: usize = 2 * 512;
/// Serialized message prefix used by the signatures fuzz target.
pub const MESSAGE_BYTES: usize = Word::SERIALIZED_SIZE;

/// Records which Falcon paths an input reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FalconPathEvidence {
    pub constructor_accepted: bool,
    pub constructor_roundtrip: bool,
    pub verified: bool,
}

/// Exercises the coefficient constructor, the `PK_LEN` key split, and verification.
///
/// Accepted constructor values must serialize to the fixed wire size and decode back. Rejected
/// values are not serialized. The returned evidence lets the standalone test assert that a valid
/// seed actually reached verification through this same helper.
pub fn check_falcon_paths(data: &[u8]) -> FalconPathEvidence {
    let mut evidence = FalconPathEvidence::default();
    let (message_bytes, sig_key_bytes) = data.split_at(data.len().min(MESSAGE_BYTES));
    let mut word_bytes = [0u8; MESSAGE_BYTES];
    word_bytes[..message_bytes.len()].copy_from_slice(message_bytes);
    let message = Word::try_from(word_bytes).ok();

    // Decode 512 coefficient pairs. Masking into the allowed coefficient range keeps the
    // constructor path reachable while the sign bit covers both signs.
    if data.len() >= SIG_POLY_COEFFICIENT_BYTES {
        let mut coefficients = [0i16; 512];
        for (coefficient, pair) in
            coefficients.iter_mut().zip(data[..SIG_POLY_COEFFICIENT_BYTES].chunks_exact(2))
        {
            let raw = u16::from_le_bytes([pair[0], pair[1]]);
            let magnitude = (raw & 0x07ff) as i16;
            *coefficient = if raw & 0x8000 != 0 { -magnitude } else { magnitude };
        }

        if let Ok(poly) = SignaturePoly::try_from(&coefficients) {
            evidence.constructor_accepted = true;
            let bytes = poly.to_bytes();
            assert_eq!(bytes.len(), SIG_POLY_BYTE_LEN);
            let decoded = SignaturePoly::read_from_bytes(&bytes)
                .expect("serialized SignaturePoly must decode");
            assert_eq!(decoded, poly);
            evidence.constructor_roundtrip = true;
        }
    }

    // The key occupies exactly PK_LEN bytes and the signature follows it.
    if let (Ok(public_key), Ok(signature)) = (
        PublicKey::read_from_bytes(sig_key_bytes.get(..PK_LEN).unwrap_or(&[])),
        Signature::read_from_bytes(sig_key_bytes.get(PK_LEN..).unwrap_or(&[])),
    ) {
        if let Some(message) = message {
            evidence.verified = public_key.verify(message, &signature);
        }
    }

    evidence
}

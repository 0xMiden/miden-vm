use alloc::vec::Vec;

use super::IesError;
use crate::{
    Felt,
    aead::{DataType, aead_eidos::expanded::checked_mac_input_len},
    utils::{Deserializable, Serializable},
};

// [data_type: u8, tag: 2 canonical u64 Felts, ciphertext: u32 limbs].
// Two limbs encode one encrypted Felt, so the byte length determines the plaintext count.
const HEADER_BYTES: usize = 1 + 2 * Felt::NUM_BYTES;

pub(super) fn encode(ciphertext: &[Felt], tag: [Felt; 2], data_type: DataType) -> Vec<u8> {
    let mut output = Vec::with_capacity(HEADER_BYTES + 4 * ciphertext.len());
    output.push(data_type as u8);
    tag.write_into(&mut output);
    for limb in ciphertext {
        output.extend_from_slice(&(limb.as_canonical_u64() as u32).to_le_bytes());
    }
    output
}

pub(super) fn decode(input: &[u8], expected: DataType) -> Result<(Vec<Felt>, [Felt; 2]), IesError> {
    let header = input.get(..HEADER_BYTES).ok_or(IesError::DecryptionFailed)?;
    let limbs = &input[HEADER_BYTES..];
    if header[0] != expected as u8 || !limbs.len().is_multiple_of(8) {
        return Err(IesError::DecryptionFailed);
    }
    checked_mac_input_len(0, limbs.len() / 4).ok_or(IesError::DecryptionFailed)?;
    let tag = <[Felt; 2]>::read_from_bytes(&header[1..]).map_err(|_| IesError::DecryptionFailed)?;
    let ciphertext = limbs
        .as_chunks::<4>()
        .0
        .iter()
        .map(|limb| Felt::from_u32(u32::from_le_bytes(*limb)))
        .collect();
    Ok((ciphertext, tag))
}

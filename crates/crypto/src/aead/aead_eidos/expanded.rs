//! Low-level Eidos AEAD operations over expanded `u32` limbs.
//!
//! This module does not manage nonces. Callers must never reuse `(key, nonce)` and must not repeat
//! counter blocks under a fixed CTR key. The low-level decryption helper does not authenticate;
//! callers that need plaintext must use
//! [`decrypt_felts_expanded_authenticated`].
//!
//! The CTR and MAC keys are separate Eidos compressions of `key || nonce` under their registered
//! domains. Encryption XORs each pair of plaintext `u32` limbs with one pair from the raw Eidos
//! XOF. For authentication, adjacent elements of
//! `nonce || associated_data || ciphertext || [ad_len, ct_len] || padding` become coefficients in
//! the quadratic extension field. Horner evaluation starts with one, which binds the number of
//! coefficients. A final multiplication by the evaluation point makes every input coefficient
//! multiply a positive power of that point. The second half of the MAC key masks the result.
//!
//! [`decrypt_felts_expanded_authenticated`]:
//!     crate::aead::aead_eidos::expanded::decrypt_felts_expanded_authenticated

use alloc::vec::Vec;

use super::{AuthTag, MAX_AUTHENTICATED_INPUT_FELTS};
use crate::{
    Felt, Word,
    field::{BasedVectorSpace, BinomialExtensionField},
    hash::eidos::{
        BLOCK_LEN, Eidos,
        domains::{AEAD_CTR_KEY, AEAD_MAC_KEY},
        encoding,
    },
};

const FELTS_PER_CTR_BLOCK: usize = BLOCK_LEN;
const LIMBS_PER_CTR_BLOCK: usize = 2 * FELTS_PER_CTR_BLOCK;
const MAC_BATCH_FELTS: usize = BLOCK_LEN;
// Nonce plus the associated-data and ciphertext length fields.
const MAC_FIXED_INPUT_FELTS: usize = Word::NUM_ELEMENTS + 2;

type QuadFelt = BinomialExtensionField<Felt, 2>;

/// Domain-separates `(key, nonce)` and compresses to a CTR chaining value via
/// Eidos.
///
/// The returned word lies in Eidos's 252-bit output set and is used as the input CV for
/// keystream generation.
pub fn derive_ctr_key(key: Word, nonce: Word) -> Word {
    let init = Eidos::init_chaining_word(AEAD_CTR_KEY, 0);
    Eidos::compress(init, [key[0], key[1], key[2], key[3], nonce[0], nonce[1], nonce[2], nonce[3]])
}

/// Domain-separates `(key, nonce)` and compresses to a MAC key via Eidos.
///
/// The returned word is `[r0, r1, s0, s1]`, where `r = (r0, r1)` is the
/// quadratic-extension evaluation point and `s = (s0, s1)` is the final mask.
pub fn derive_mac_key(key: Word, nonce: Word) -> Word {
    let init = Eidos::init_chaining_word(AEAD_MAC_KEY, 0);
    Eidos::compress(init, [key[0], key[1], key[2], key[3], nonce[0], nonce[1], nonce[2], nonce[3]])
}

/// Returns sixteen raw u32 keystream limbs for one counter block.
///
/// The compression block is `[counter, 0, 0, 0, 0, 0, 0, 0]`, and all sixteen XOF lanes form the
/// keystream block.
pub fn keystream_block(ctr_key: Word, counter: u32) -> [u32; 16] {
    let mut counter_block = [Felt::ZERO; 8];
    counter_block[0] = Felt::from_u32(counter);

    Eidos::compress_xof_lanes(ctr_key, counter_block)
}

/// Encrypts canonical field elements as expanded u32 limbs.
///
/// Each plaintext Felt becomes two ciphertext Felts, each holding one u32 limb.
/// Security requires a unique `(key, nonce)` per message.
///
/// This operation produces no authentication tag. Use [`encrypt_felts_expanded_authenticated`]
/// for authenticated encryption.
///
/// # Panics
///
/// Panics if the plaintext requires more than `2^32` counter blocks or if the expanded ciphertext
/// length overflows `usize`.
pub fn encrypt_felts_expanded(key: Word, nonce: Word, plaintext: &[Felt]) -> Vec<Felt> {
    assert!(counter_fits_len(plaintext.len()), "AEAD supports at most 2^32 CTR blocks",);

    let ctr_key = derive_ctr_key(key, nonce);
    let ciphertext_len = plaintext
        .len()
        .checked_mul(2)
        .expect("Eidos AEAD ciphertext length overflows usize");
    let mut ciphertext = Vec::with_capacity(ciphertext_len);

    for (counter, chunk) in plaintext.chunks(FELTS_PER_CTR_BLOCK).enumerate() {
        let counter = u32::try_from(counter).expect("counter bound checked above");
        let keystream = keystream_block(ctr_key, counter);
        for (i, &felt) in chunk.iter().enumerate() {
            let (lo, hi) = encoding::unpack_felt(felt);
            ciphertext.push(Felt::from_u32(lo ^ keystream[2 * i]));
            ciphertext.push(Felt::from_u32(hi ^ keystream[2 * i + 1]));
        }
    }

    ciphertext
}

/// Decrypts expanded u32-limb ciphertext produced by [`encrypt_felts_expanded`].
///
/// This is a low-level, **unauthenticated** CTR operation. It must not be
/// used to release plaintext to a caller. Use [`decrypt_felts_expanded_authenticated`] for the
/// authenticated direction.
///
/// Returns `None` if the ciphertext is too long for the u32 counter, the length
/// is odd, a ciphertext limb is not a canonical u32 value, or the decrypted limb
/// pair is not a canonical Felt.
pub fn decrypt_felts_expanded(key: Word, nonce: Word, ciphertext: &[Felt]) -> Option<Vec<Felt>> {
    if !ciphertext.len().is_multiple_of(2) {
        return None;
    }

    if !counter_fits_len(ciphertext.len() / 2) {
        return None;
    }

    let ctr_key = derive_ctr_key(key, nonce);
    let mut plaintext = Vec::with_capacity(ciphertext.len() / 2);

    for (counter, chunk) in ciphertext.chunks(LIMBS_PER_CTR_BLOCK).enumerate() {
        let counter = u32::try_from(counter).ok()?;
        let keystream = keystream_block(ctr_key, counter);
        for (felt_in_block, pair) in chunk.chunks(2).enumerate() {
            let c_lo = u32_limb(pair[0])?;
            let c_hi = u32_limb(pair[1])?;
            let lo = c_lo ^ keystream[2 * felt_in_block];
            let hi = c_hi ^ keystream[2 * felt_in_block + 1];
            plaintext.push(pack_canonical(lo, hi)?);
        }
    }

    Some(plaintext)
}

/// Authenticates expanded u32-limb ciphertext.
///
/// Associated data is included before the ciphertext. Lengths are measured in Felts and appended
/// as `[ad_len, ct_len]`; the coefficient stream is padded to an 8-Felt boundary. The MAC
/// polynomial is evaluated over the quadratic extension by pairing adjacent Felts into one
/// extension coefficient. An implicit leading-one coefficient binds the polynomial length, and a
/// final multiplication by the evaluation point leaves the constant coefficient fixed at zero.
///
/// # Panics
///
/// Panics if the padded MAC input exceeds
/// [`MAX_AUTHENTICATED_INPUT_FELTS`], or if a ciphertext limb is not a canonical `u32` Felt.
pub fn auth_tag_expanded(
    key: Word,
    nonce: Word,
    associated_data: &[Felt],
    ciphertext: &[Felt],
) -> [Felt; 2] {
    let padded_input_len = checked_mac_input_len(associated_data.len(), ciphertext.len())
        .expect("Eidos AEAD authentication input exceeds its supported length");
    let associated_data_len =
        u32::try_from(associated_data.len()).expect("the authenticated-input limit fits in a u32");
    let ciphertext_len =
        u32::try_from(ciphertext.len()).expect("the authenticated-input limit fits in a u32");
    assert!(
        ciphertext.iter().all(|&limb| u32_limb(limb).is_some()),
        "expanded ciphertext limbs must be canonical u32 Felts",
    );

    let padding_len =
        padded_input_len - MAC_FIXED_INPUT_FELTS - associated_data.len() - ciphertext.len();
    // Pair across segment boundaries: odd-length associated data shares a coefficient with the
    // first ciphertext Felt, or with the encoded AD length when ciphertext is empty.
    let input = nonce
        .into_elements()
        .into_iter()
        .chain(associated_data.iter().copied())
        .chain(ciphertext.iter().copied())
        .chain([Felt::from_u32(associated_data_len), Felt::from_u32(ciphertext_len)])
        .chain(core::iter::repeat_n(Felt::ZERO, padding_len));

    let mac_key = derive_mac_key(key, nonce);
    let evaluation_point = quad_from_pair(mac_key[0], mac_key[1]);
    let mask = quad_from_pair(mac_key[2], mac_key[3]);
    let tag = evaluate_mac_polynomial(input, evaluation_point) + mask;
    let tag_coefficients = tag.as_basis_coefficients_slice();
    [tag_coefficients[0], tag_coefficients[1]]
}

/// Encrypts and authenticates field elements using expanded u32-limb ciphertext.
///
/// # Panics
///
/// Panics if the plaintext requires more than `2^32` counter blocks, if the expanded ciphertext
/// length overflows `usize`, or if the padded MAC input exceeds
/// [`MAX_AUTHENTICATED_INPUT_FELTS`].
pub fn encrypt_felts_expanded_authenticated(
    key: Word,
    nonce: Word,
    associated_data: &[Felt],
    plaintext: &[Felt],
) -> (Vec<Felt>, [Felt; 2]) {
    let ciphertext_len = plaintext
        .len()
        .checked_mul(2)
        .expect("Eidos AEAD ciphertext length overflows usize");
    assert!(
        checked_mac_input_len(associated_data.len(), ciphertext_len).is_some(),
        "Eidos AEAD authentication input exceeds its supported length",
    );
    let ciphertext = encrypt_felts_expanded(key, nonce, plaintext);
    let tag = auth_tag_expanded(key, nonce, associated_data, &ciphertext);
    (ciphertext, tag)
}

/// Authenticates expanded ciphertext before decrypting it.
///
/// Returns `None` without producing plaintext if the input lengths or limbs are invalid, or if the
/// supplied tag does not match `(key, nonce, associated_data, ciphertext)`.
pub fn decrypt_felts_expanded_authenticated(
    key: Word,
    nonce: Word,
    associated_data: &[Felt],
    ciphertext: &[Felt],
    tag: [Felt; 2],
) -> Option<Vec<Felt>> {
    checked_mac_input_len(associated_data.len(), ciphertext.len())?;
    if !ciphertext.len().is_multiple_of(2)
        || !ciphertext.iter().all(|&limb| u32_limb(limb).is_some())
    {
        return None;
    }
    let expected_tag = auth_tag_expanded(key, nonce, associated_data, ciphertext);
    if AuthTag(expected_tag) != AuthTag(tag) {
        return None;
    }
    decrypt_felts_expanded(key, nonce, ciphertext)
}

fn u32_limb(value: Felt) -> Option<u32> {
    u32::try_from(value.as_canonical_u64()).ok()
}

fn pack_canonical(lo: u32, hi: u32) -> Option<Felt> {
    Felt::new(((hi as u64) << 32) | lo as u64).ok()
}

fn counter_fits_len(num_felts: usize) -> bool {
    // ceil(num_felts / FELTS_PER_CTR_BLOCK) <= 2^32.
    let num_felts = num_felts as u64;
    let block_size = FELTS_PER_CTR_BLOCK as u64;
    let full_blocks = num_felts / block_size;
    let has_partial_block = u64::from(!num_felts.is_multiple_of(block_size));

    full_blocks + has_partial_block <= u64::from(u32::MAX) + 1
}

/// Returns the padded base-field length of the MAC input when it is within the supported bound.
///
/// Both input lengths are measured in base-field elements. The total includes the nonce and two
/// length fields and is rounded up to an 8-Felt boundary.
pub fn checked_mac_input_len(associated_data_len: usize, ciphertext_len: usize) -> Option<usize> {
    let unpadded_len = MAC_FIXED_INPUT_FELTS
        .checked_add(associated_data_len)?
        .checked_add(ciphertext_len)?;
    let padding = (MAC_BATCH_FELTS - unpadded_len % MAC_BATCH_FELTS) % MAC_BATCH_FELTS;
    let padded_len = unpadded_len.checked_add(padding)?;
    (padded_len <= MAX_AUTHENTICATED_INPUT_FELTS).then_some(padded_len)
}

fn evaluate_mac_polynomial(mut input: impl Iterator<Item = Felt>, alpha: QuadFelt) -> QuadFelt {
    let mut acc = quad_from_pair(Felt::ONE, Felt::ZERO);
    while let Some(c0) = input.next() {
        let c1 = input.next().expect("the MAC input is padded to an even length");
        acc = acc * alpha + quad_from_pair(c0, c1);
    }

    // Make every input coefficient multiply a positive power of alpha. Otherwise, changing the
    // last coefficient would change the tag by the same amount, independently of alpha.
    acc * alpha
}

fn quad_from_pair(c0: Felt, c1: Felt) -> QuadFelt {
    QuadFelt::new([c0, c1])
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn word(values: [u64; 4]) -> Word {
        Word::new(values.map(Felt::new_unchecked))
    }

    fn key() -> Word {
        word([1, 2, 3, 4])
    }

    fn nonce() -> Word {
        word([0x10, 0x20, 0x30, 0x40])
    }

    #[test]
    fn expanded_limb_encryption_roundtrips_edge_felts() {
        let plaintext = vec![
            Felt::ZERO,
            Felt::new_unchecked(1 << 63),
            Felt::new(Felt::ORDER - 1).unwrap(),
            Felt::new_unchecked(0x0123_4567_89ab_cdef),
            Felt::new_unchecked(42),
        ];

        let ciphertext = encrypt_felts_expanded(key(), nonce(), &plaintext);
        let decrypted = decrypt_felts_expanded(key(), nonce(), &ciphertext).unwrap();

        assert_eq!(ciphertext.len(), plaintext.len() * 2);
        assert!(ciphertext.iter().all(|&limb| u32_limb(limb).is_some()));
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn expanded_limb_decryption_rejects_malformed_ciphertext() {
        let odd_len = vec![Felt::from_u32(1)];
        assert!(decrypt_felts_expanded(key(), nonce(), &odd_len).is_none());

        let non_u32_limb = vec![Felt::new_unchecked(1u64 << 40), Felt::ZERO];
        assert!(decrypt_felts_expanded(key(), nonce(), &non_u32_limb).is_none());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn counter_limit_is_explicit() {
        let max_felts = (u64::from(u32::MAX) + 1) * FELTS_PER_CTR_BLOCK as u64;

        assert!(counter_fits_len(max_felts as usize));
        assert!(!counter_fits_len((max_felts + 1) as usize));
    }

    #[test]
    fn authentication_input_limit_is_explicit() {
        assert_eq!(checked_mac_input_len(0, 0), Some(MAC_BATCH_FELTS));

        let largest_unpadded_payload = MAX_AUTHENTICATED_INPUT_FELTS - MAC_FIXED_INPUT_FELTS;
        assert_eq!(
            checked_mac_input_len(largest_unpadded_payload, 0),
            Some(MAX_AUTHENTICATED_INPUT_FELTS),
        );
        assert_eq!(checked_mac_input_len(largest_unpadded_payload + 1, 0), None);
        assert_eq!(checked_mac_input_len(usize::MAX, 0), None);
    }

    #[test]
    fn reference_vector_for_expanded_limb_encryption() {
        let plaintext = vec![
            Felt::ZERO,
            Felt::new_unchecked(1 << 63),
            Felt::new(Felt::ORDER - 1).unwrap(),
            Felt::new_unchecked(0x0123_4567_89ab_cdef),
            Felt::new_unchecked(42),
        ];

        let ciphertext = encrypt_felts_expanded(key(), nonce(), &plaintext);
        let expected = vec![
            Felt::from_u32(0xbb25_603c),
            Felt::from_u32(0x19cf_6da5),
            Felt::from_u32(0xefac_9bbd),
            Felt::from_u32(0xc61c_cf91),
            Felt::from_u32(0xb375_27b5),
            Felt::from_u32(0x1414_a95b),
            Felt::from_u32(0xd9ff_7018),
            Felt::from_u32(0x7782_e039),
            Felt::from_u32(0x94b0_4b55),
            Felt::from_u32(0x0073_05bf),
        ];

        assert_eq!(ciphertext, expected);
        assert_eq!(decrypt_felts_expanded(key(), nonce(), &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn reference_vector_for_expanded_authentication() {
        let plaintext = vec![
            Felt::ZERO,
            Felt::new_unchecked(1 << 63),
            Felt::new(Felt::ORDER - 1).unwrap(),
            Felt::new_unchecked(0x0123_4567_89ab_cdef),
            Felt::new_unchecked(42),
        ];
        let associated_data = [Felt::new_unchecked(5), Felt::new_unchecked(6)];
        let ciphertext = encrypt_felts_expanded(key(), nonce(), &plaintext);
        let tag = auth_tag_expanded(key(), nonce(), &associated_data, &ciphertext);
        let expected = [
            Felt::new_unchecked(9878978564639456879),
            Felt::new_unchecked(13261684965002033322),
        ];

        assert_eq!(tag, expected);
    }

    #[test]
    fn streamed_mac_matches_buffered_reference_across_segment_boundaries() {
        let mac_key = derive_mac_key(key(), nonce());
        let alpha = quad_from_pair(mac_key[0], mac_key[1]);
        let mask = quad_from_pair(mac_key[2], mac_key[3]);

        // Cover odd and even AD/ciphertext lengths and every possible padding remainder.
        for ad_len in 0..=9 {
            let associated_data = (0..ad_len).map(Felt::from_u32).collect::<Vec<_>>();
            for ct_len in 0..=17 {
                let ciphertext = (0..ct_len).map(|i| Felt::from_u32(i * 0x101)).collect::<Vec<_>>();
                let mut input = nonce().into_elements().to_vec();
                input.extend_from_slice(&associated_data);
                input.extend_from_slice(&ciphertext);
                input.extend([Felt::from_u32(ad_len), Felt::from_u32(ct_len)]);
                while !input.len().is_multiple_of(8) {
                    input.push(Felt::ZERO);
                }
                let expected = input
                    .chunks_exact(2)
                    .fold(quad_from_pair(Felt::ONE, Felt::ZERO), |acc, pair| {
                        acc * alpha + quad_from_pair(pair[0], pair[1])
                    })
                    * alpha
                    + mask;

                let expected: &[Felt] = expected.as_basis_coefficients_slice();
                assert_eq!(
                    auth_tag_expanded(key(), nonce(), &associated_data, &ciphertext),
                    expected,
                    "AD length {ad_len}, ciphertext length {ct_len}",
                );
            }
        }
    }

    #[test]
    fn auth_tag_changes_with_ciphertext_and_lengths() {
        let plaintext = vec![
            Felt::ZERO,
            Felt::new_unchecked(1 << 63),
            Felt::new(Felt::ORDER - 1).unwrap(),
            Felt::new_unchecked(0x0123_4567_89ab_cdef),
            Felt::new_unchecked(42),
        ];
        let (ciphertext, tag) =
            encrypt_felts_expanded_authenticated(key(), nonce(), &[], &plaintext);

        let mut forged = ciphertext.clone();
        forged[0] += Felt::ONE;
        assert_ne!(auth_tag_expanded(key(), nonce(), &[], &forged), tag);

        let truncated = ciphertext[..ciphertext.len() - 2].to_vec();
        assert_ne!(auth_tag_expanded(key(), nonce(), &[], &truncated), tag);
    }

    #[test]
    fn authentication_binds_the_final_coefficient_to_the_evaluation_point() {
        let ciphertext =
            [Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)];
        let tag = auth_tag_expanded(key(), nonce(), &[], &ciphertext);

        // These inputs have the same padded length. Their encoded streams agree until the final
        // extension coefficient, which changes from (0, 0) to (0, 10).
        let extended_ciphertext = [
            Felt::from_u32(1),
            Felt::from_u32(2),
            Felt::from_u32(3),
            Felt::from_u32(4),
            Felt::ZERO,
            Felt::from_u32(4),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ];
        let translated_tag = [tag[0], tag[1] + Felt::from_u32(10)];

        assert_ne!(auth_tag_expanded(key(), nonce(), &[], &extended_ciphertext), translated_tag);
        assert!(
            decrypt_felts_expanded_authenticated(
                key(),
                nonce(),
                &[],
                &extended_ciphertext,
                translated_tag,
            )
            .is_none()
        );
    }

    #[test]
    fn mac_encoding_binds_leading_zero_blocks() {
        let zero_nonce = word([0, 0, 0, 0]);
        let short_ad = [Felt::ZERO, Felt::from_u32(7)];
        let long_ad = [Felt::ZERO; 7];
        let long_ciphertext = [Felt::ZERO; 2];

        // The longer stream has four additional leading zero extension coefficients. The
        // polynomial length must distinguish the two inputs.
        assert_ne!(
            auth_tag_expanded(key(), zero_nonce, &short_ad, &[]),
            auth_tag_expanded(key(), zero_nonce, &long_ad, &long_ciphertext),
        );
    }

    #[test]
    fn authenticated_decryption_rejects_before_releasing_plaintext() {
        let plaintext = [Felt::new_unchecked(1), Felt::new_unchecked(1 << 63)];
        let associated_data = [Felt::new_unchecked(9)];
        let (ciphertext, tag) =
            encrypt_felts_expanded_authenticated(key(), nonce(), &associated_data, &plaintext);

        assert_eq!(
            decrypt_felts_expanded_authenticated(
                key(),
                nonce(),
                &associated_data,
                &ciphertext,
                tag,
            ),
            Some(plaintext.to_vec()),
        );

        let mut forged_ciphertext = ciphertext.clone();
        forged_ciphertext[0] += Felt::ONE;
        assert_eq!(
            decrypt_felts_expanded_authenticated(
                key(),
                nonce(),
                &associated_data,
                &forged_ciphertext,
                tag,
            ),
            None,
        );

        for i in 0..tag.len() {
            let mut forged_tag = tag;
            forged_tag[i] += Felt::ONE;
            assert_eq!(
                decrypt_felts_expanded_authenticated(
                    key(),
                    nonce(),
                    &associated_data,
                    &ciphertext,
                    forged_tag,
                ),
                None,
            );
        }
    }
}

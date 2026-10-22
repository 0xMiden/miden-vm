//! NTRU-HPS-2048-509 polynomial encryption and recovery.
//!
//! The recipient's secret polynomials f and g have coefficients in {0, 1, -1}; g has 127
//! coefficients of each nonzero sign. Its public polynomial h satisfies f*h = 3g in
//! Rq = Z_2048[x]/(x^509 - 1), with coefficient sum zero modulo 2048.
//!
//! The sender samples two secret polynomials r and m and forms c = h*r + m in Rq. Both have
//! coefficients in {0, 1, -1}, and m has the same weight constraint as g. In trinary encodings,
//! 2 represents -1; lifting to Rq maps it to 2047.
//!
//! For a valid encapsulation, c*f = 3g*r + f*m in Rq. The integer sum 3g*r + f*m, reduced modulo
//! x^509 - 1, has coefficients of magnitude at most 3*254 + 254 = 1016 < 2048/2. Centering c*f's
//! coefficients therefore recovers this sum; reducing modulo 3 removes the 3g*r term. Multiplying
//! by f's inverse gives m; multiplying c - m by h's inverse then gives r. These inverses are modulo
//! Phi = 1 + x + ... + x^508, over Z_3 and Z_2048 respectively. The KEM layer hashes the recovered
//! pair if the encoding, trit, and weight checks pass, or selects a hash of the secret fallback
//! key and ciphertext otherwise.
//!
//! Multiplication uses a schoolbook convolution. Inversion and sampling use fixed
//! iteration counts and a sorting network, respectively.

mod encoding;
mod poly;
mod sample;
#[cfg(test)]
mod tests;

use self::poly::Poly;
use crate::utils::zeroize::Zeroizing;

pub(super) const N: usize = 509;
pub(super) const Q: u16 = 2048;
const WEIGHT: u16 = 254;
const TRINARY_BYTES: usize = 102;
pub(super) const POLY_BYTES: usize = 699;
pub(super) const SECRET_BYTES: usize = 2 * TRINARY_BYTES + POLY_BYTES;
pub(super) const PAIR_BYTES: usize = 2 * TRINARY_BYTES;
pub(super) const COIN_BYTES: usize = 2413;

pub(super) fn keypair(
    coins: &[u8; COIN_BYTES],
    public_key: &mut [u8; POLY_BYTES],
    secret_key: &mut [u8; SECRET_BYTES],
) {
    let (f, g) = sample::pair(coins);
    secret_key[..TRINARY_BYTES].copy_from_slice(&*f.encode_s3());
    secret_key[TRINARY_BYTES..PAIR_BYTES].copy_from_slice(&*f.invert_s3().encode_s3());
    let f = f.lift();
    let mut three_g = g.lift();
    for coefficient in &mut three_g.0 {
        *coefficient = coefficient.wrapping_mul(3) & (Q - 1);
    }

    // One inversion modulo Phi gives both h = 3g/f and its inverse f/(3g).
    let inverse = three_g.mul_rq(&f).invert_sq();
    let inverse_h = inverse.mul_rq(&f).mul_sq(&f);
    secret_key[PAIR_BYTES..].copy_from_slice(&*inverse_h.encode_q());
    let h = inverse.mul_rq(&three_g).mul_rq(&three_g);
    public_key.copy_from_slice(&*h.encode_q());
}

pub(super) fn public_polynomial(public_key: &[u8; POLY_BYTES]) -> [u16; N] {
    Poly::decode_rq0(public_key).0
}

/// Checks the stored key relations and recovers h from its inverse.
pub(super) fn restore_public_key(secret_key: &[u8; SECRET_BYTES]) -> Option<[u8; POLY_BYTES]> {
    let f = Poly::decode_s3(secret_key[..TRINARY_BYTES].try_into().unwrap());
    let inverse_f = Poly::decode_s3(secret_key[TRINARY_BYTES..PAIR_BYTES].try_into().unwrap());
    let inverse_h = Poly::decode_sq(secret_key[PAIR_BYTES..].try_into().unwrap());
    if f.encode_s3()[..] != secret_key[..TRINARY_BYTES]
        || inverse_f.encode_s3()[..] != secret_key[TRINARY_BYTES..PAIR_BYTES]
        || inverse_h.encode_q()[..] != secret_key[PAIR_BYTES..]
        || !f.mul_s3(&inverse_f).is_one()
    {
        return None;
    }

    let mut h = inverse_h.invert_sq();
    if !h.mul_sq(&inverse_h).is_one() {
        return None;
    }
    // All representatives modulo Phi differ by a constant in every coefficient.
    // Subtract sum(h)/N to select the unique one with h(1) = 0 modulo q.
    const INVERSE_N: u16 = 853; // 509 * 853 = 1 (mod 2048).
    let sum = h.0.iter().fold(0u16, |acc, &c| acc.wrapping_add(c));
    let shift = sum.wrapping_mul(INVERSE_N);
    for c in &mut h.0 {
        *c = c.wrapping_sub(shift) & (Q - 1);
    }

    // Recover g = f*h/3 and check its trits and balanced weight.
    const INVERSE_THREE: u16 = 683;
    let mut g = h.mul_rq(&f.lift());
    for c in &mut g.0 {
        *c = c.wrapping_mul(INVERSE_THREE) & (Q - 1);
    }
    if g.trinary_failure() != 0 || g.unlift().weight_failure() != 0 {
        return None;
    }
    Some(*h.encode_q())
}

pub(super) struct Encapsulation {
    pub ciphertext: [u8; POLY_BYTES],
    pub encoded_pair: Zeroizing<[u8; PAIR_BYTES]>,
    pub r: Zeroizing<[u16; N]>,
    pub m: Zeroizing<[u16; N]>,
}

pub(super) fn encapsulate(
    public_key: &[u8; POLY_BYTES],
    coins: &[u8; COIN_BYTES],
) -> Encapsulation {
    let (r, m) = sample::pair(coins);
    let h = Poly::decode_rq0(public_key);
    let mut ciphertext = r.lift().mul_rq(&h);
    let lifted_m = m.lift();
    for (c, &m) in ciphertext.0.iter_mut().zip(&lifted_m.0) {
        *c = c.wrapping_add(m) & (Q - 1);
    }
    let mut encoded_pair = Zeroizing::new([0; PAIR_BYTES]);
    encoded_pair[..TRINARY_BYTES].copy_from_slice(&*r.encode_s3());
    encoded_pair[TRINARY_BYTES..].copy_from_slice(&*m.encode_s3());
    Encapsulation {
        ciphertext: *ciphertext.encode_q(),
        encoded_pair,
        r: Zeroizing::new(r.0),
        m: Zeroizing::new(m.0),
    }
}

/// Returns the encoded candidate and a failure bit, without branching on validity.
pub(super) fn recover(
    ciphertext: &[u8; POLY_BYTES],
    secret_key: &[u8; SECRET_BYTES],
) -> (Zeroizing<[u8; PAIR_BYTES]>, u8) {
    let c = Poly::decode_rq0(ciphertext);
    let f = Poly::decode_s3(secret_key[..TRINARY_BYTES].try_into().unwrap()).lift();
    let inverse_f = Poly::decode_s3(secret_key[TRINARY_BYTES..PAIR_BYTES].try_into().unwrap());
    let m = c.mul_rq(&f).center_to_s3().mul_s3(&inverse_f);

    let lifted_m = m.lift();
    let mut remainder = Poly::zero();
    for ((b, &c), &m) in remainder.0.iter_mut().zip(&c.0).zip(&lifted_m.0) {
        *b = c.wrapping_sub(m) & (Q - 1);
    }
    let inverse_h = Poly::decode_sq(secret_key[PAIR_BYTES..].try_into().unwrap());
    let r = remainder.mul_sq(&inverse_h);

    // The encoding fixes c(1) = 0. Together with m's balanced weight and r's trits,
    // these checks establish that c is an encryption of the recovered pair.
    let mut invalid = (ciphertext[POLY_BYTES - 1] & 0xf0) as u16;
    invalid |= m.weight_failure();
    invalid |= r.trinary_failure();

    let mut encoded_pair = Zeroizing::new([0; PAIR_BYTES]);
    encoded_pair[..TRINARY_BYTES].copy_from_slice(&*r.unlift().encode_s3());
    encoded_pair[TRINARY_BYTES..].copy_from_slice(&*m.encode_s3());
    let failed = ((invalid | invalid.wrapping_neg()) >> 15) as u8;
    (encoded_pair, failed)
}

use super::{N, POLY_BYTES, Q, TRINARY_BYTES, poly::Poly};
use crate::utils::zeroize::Zeroizing;

impl Poly {
    /// Five little-endian base-3 digits per byte; the last byte contains three.
    pub fn encode_s3(&self) -> Zeroizing<[u8; TRINARY_BYTES]> {
        let mut bytes = Zeroizing::new([0; TRINARY_BYTES]);
        for (byte, trits) in bytes.iter_mut().zip(self.0[..N - 1].chunks(5)) {
            *byte = trits
                .iter()
                .rev()
                .fold(0u8, |acc, &c| acc.wrapping_mul(3).wrapping_add(c as u8));
        }
        bytes
    }

    pub fn decode_s3(bytes: &[u8; TRINARY_BYTES]) -> Self {
        let mut result = Self::zero();
        for (&byte, trits) in bytes.iter().zip(result.0[..N - 1].chunks_mut(5)) {
            let mut remaining = byte as u16;
            for c in trits {
                *c = remaining % 3;
                remaining /= 3;
            }
        }
        result
    }

    /// The first N-1 coefficients as consecutive little-endian 11-bit integers.
    ///
    /// The omitted coefficient must be zero for Sq or minus the sum of the others modulo q
    /// for Rq0. This routine does not change the polynomial's representative.
    pub fn encode_q(&self) -> Zeroizing<[u8; POLY_BYTES]> {
        let mut bytes = Zeroizing::new([0; POLY_BYTES]);
        for (i, &c) in self.0[..N - 1].iter().enumerate() {
            let offset = 11 * i;
            let value = ((c & (Q - 1)) as u32) << (offset % 8);
            for j in 0..(11 + offset % 8).div_ceil(8) {
                bytes[offset / 8 + j] |= (value >> (8 * j)) as u8;
            }
        }
        bytes
    }

    /// Sq represents a polynomial modulo Phi by setting its last coefficient to zero.
    pub fn decode_sq(bytes: &[u8; POLY_BYTES]) -> Self {
        let mut result = Self::zero();
        for (i, c) in result.0[..N - 1].iter_mut().enumerate() {
            let offset = 11 * i;
            let mut value = 0u32;
            for j in 0..(11 + offset % 8).div_ceil(8) {
                value |= (bytes[offset / 8 + j] as u32) << (8 * j);
            }
            *c = ((value >> (offset % 8)) as u16) & (Q - 1);
        }
        result
    }

    /// Rq0 determines the omitted coefficient by requiring the coefficient sum to be zero.
    pub fn decode_rq0(bytes: &[u8; POLY_BYTES]) -> Self {
        let mut result = Self::decode_sq(bytes);
        let sum = result.0.iter().fold(0u16, |acc, &c| acc.wrapping_add(c));
        result.0[N - 1] = sum.wrapping_neg() & (Q - 1);
        result
    }
}

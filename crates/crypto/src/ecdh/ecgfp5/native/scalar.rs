// Copyright (c) 2022 Thomas Pornin. MIT license; see LICENSE in this directory.
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// A scalar (integer modulo the prime group order n).
#[derive(Clone, Copy, Debug)]
pub struct Scalar([u64; 5]);

impl crate::utils::zeroize::Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Scalar {
    // IMPLEMENTATION NOTES:
    // ---------------------
    //
    // Group order n is slightly below 2^319. We store values over five
    // 64-bit limbs. We use Montgomery multiplication to perform
    // computations; however, we keep the limbs in normal
    // (non-Montgomery) representation, so that operations that do not
    // require any multiplication of scalars, just encoding and
    // decoding, are fastest.

    pub const ZERO: Self = Self([0, 0, 0, 0, 0]);

    pub const ONE: Self = Self([1, 0, 0, 0, 0]);

    // The modulus itself, stored in a Scalar structure (which
    // contravenes to the rules of a Scalar; this constant MUST NOT leak
    // outside the API).
    const N: Self = Self([
        0xe80fd996948bffe1,
        0xe8885c39d724a09c,
        0x7fffffe6cfb80639,
        0x7ffffff100000016,
        0x7ffffffd80000007,
    ]);

    // -1/N[0] mod 2^64
    const N0I: u64 = 0xd78bef72057b7bdf;

    /* not used
    // 2^320 mod n.
    const R: Self = Self([
        0x2FE04CD2D6E8003E,
        0x2EEF478C51B6BEC6,
        0x00000032608FF38C,
        0x0000001DFFFFFFD3,
        0x00000004FFFFFFF1,
    ]);
    */

    // 2^640 mod n.
    const R2: Self = Self([
        0xa01001dce33dc739,
        0x6c3228d33f62accf,
        0xd1d796cc91cf8525,
        0xaadfff5d1574c1d8,
        0x4aca13b28ca251f5,
    ]);

    // 2^632 mod n.
    const T632: Self = Self([
        0x2b0266f317ca91b3,
        0xec1d26528e984773,
        0x8651d7865e12db94,
        0xda2adff5941574d0,
        0x53caca12110ca256,
    ]);

    // raw addition (no reduction)
    fn add_inner(self, a: Self) -> Self {
        let mut r = Self::ZERO;
        let mut c: u64 = 0;
        for i in 0..5 {
            let z = (self.0[i] as u128).wrapping_add(a.0[i] as u128).wrapping_add(c as u128);
            r.0[i] = z as u64;
            c = (z >> 64) as u64;
        }
        // no extra carry, since inputs are supposed to fit on 319 bits.
        r
    }

    // raw subtraction (no reduction)
    // Final borrow is returned (0xFFFFFFFFFFFFFFFF if borrow, 0 otherwise).
    fn sub_inner(self, a: Self) -> (Self, u64) {
        let mut r = Self::ZERO;
        let mut c: u64 = 0;
        for i in 0..5 {
            let z = (self.0[i] as u128).wrapping_sub(a.0[i] as u128).wrapping_sub(c as u128);
            r.0[i] = z as u64;
            c = ((z >> 64) as u64) & 1;
        }
        (r, c.wrapping_neg())
    }

    /// If c == 0, return a0.
    /// If c == 0xFFFFFFFFFFFFFFFF, return a1.
    /// c MUST be equal to 0 or 0xFFFFFFFFFFFFFFFF.
    pub fn select(c: u64, a0: Self, a1: Self) -> Self {
        let mut r = Self::ZERO;
        for i in 0..5 {
            r.0[i] = a0.0[i] ^ (c & (a0.0[i] ^ a1.0[i]));
        }
        r
    }

    // Scalar addition.
    fn add(self, rhs: Self) -> Self {
        let r0 = self.add_inner(rhs);
        let (r1, c) = r0.sub_inner(Self::N);
        Self::select(c, r1, r0)
    }

    // Scalar subtraction.
    fn sub(self, rhs: Self) -> Self {
        let (r0, c) = self.sub_inner(rhs);
        let r1 = r0.add_inner(Self::N);
        Self::select(c, r0, r1)
    }

    // Scalar negation.
    fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    // Montgomery multiplication.
    // Returns (self*rhs)/2^320 mod n.
    // 'self' MUST be less than n (the other operand can be up to 2^320-1).
    fn montymul(self, rhs: Self) -> Self {
        let mut r = Self::ZERO;
        for i in 0..5 {
            // Iteration i computes r <- (r + self*rhs_i + f*n)/2^64.
            // Factor f is at most 2^64-1 and set so that the division
            // is exact.
            // On input:
            //    r <= 2^320 - 1
            //    self <= n - 1
            //    rhs_i <= 2^64 - 1
            //    f <= 2^64 - 1
            // Therefore:
            //    r + self*rhs_i + f*n <= 2^320-1 + (2^64 - 1) * (n - 1)
            //                            + (2^64 - 1) * n
            //                         < 2^384
            // Thus, the new r fits on 320 bits.
            let m = rhs.0[i];
            let f = self.0[0].wrapping_mul(m).wrapping_add(r.0[0]).wrapping_mul(Self::N0I);
            let mut cc1: u64 = 0;
            let mut cc2: u64 = 0;
            for j in 0..5 {
                let mut z = (self.0[j] as u128)
                    .wrapping_mul(m as u128)
                    .wrapping_add(r.0[j] as u128)
                    .wrapping_add(cc1 as u128);
                cc1 = (z >> 64) as u64;
                z = (f as u128)
                    .wrapping_mul(Self::N.0[j] as u128)
                    .wrapping_add((z as u64) as u128)
                    .wrapping_add(cc2 as u128);
                cc2 = (z >> 64) as u64;
                if j > 0 {
                    r.0[j - 1] = z as u64;
                }
            }
            // No overflow here since the new r fits on 320 bits.
            r.0[4] = cc1.wrapping_add(cc2);
        }

        // We computed (self*rhs + ff*n) / 2^320, with:
        //    self < n
        //    rhs < 2^320
        //    ff < 2^320
        // Thus, the value we obtained is lower than 2*n. Subtracting n
        // once (conditionally) is sufficient to achieve full reduction.
        let (r2, c) = r.sub_inner(Self::N);
        Self::select(c, r2, r)
    }

    fn mul(self, rhs: Self) -> Self {
        self.montymul(Self::R2).montymul(rhs)
    }

    /// Decode the provided byte slice into a scalar. The bytes are
    /// interpreted into an integer in little-endian unsigned convention.
    /// All slice bytes are read. Return value is (s, c):
    ///  - If the decoded integer is lower than the group order, then that value is returned as s,
    ///    and c == 0xFFFFFFFFFFFFFFFF.
    ///  - Otherwise, s is set to Scalar::ZERO, and c == 0.
    pub fn decode(buf: &[u8]) -> (Self, u64) {
        let n = buf.len();
        let mut r = Self::ZERO;
        let mut extra: u8 = 0;
        for i in 0..n {
            if i < 40 {
                r.0[i >> 3] |= (buf[i] as u64).wrapping_shl(((i as u32) & 7) << 3);
            } else {
                extra |= buf[i];
            }
        }

        // If input buffer is at most 39 bytes then the result is
        // necessarily in range; we can skip the reduction tests.
        if n <= 39 {
            return (r, 0xffffffffffffffff);
        }

        // Output is in the correct range if and only if extra == 0 and
        // the value is lower than n.
        let (_, mut c) = r.sub_inner(Self::N);
        c &= ((extra as u64).wrapping_add(0xff) >> 8).wrapping_sub(1);
        for i in 0..5 {
            r.0[i] &= c;
        }
        (r, c)
    }

    /// Decode the provided byte slice into a scalar. The bytes are
    /// interpreted into an integer in little-endian unsigned convention.
    /// All slice bytes are read, and the value is REDUCED modulo n. This
    /// function never fails; it accepts arbitrary input values.
    pub fn decode_reduce(buf: &[u8]) -> Self {
        // We inject the value by chunks of 312 bits, in high-to-low
        // order. We multiply by 2^312 the intermediate result, which
        // is equivalent to performing a Montgomery multiplication
        // by 2^632 mod n.

        // If buffer length is at most 39 bytes, then the plain decode()
        // function works.
        let n = buf.len();
        if n <= 39 {
            let (r, _) = Self::decode(buf);
            return r;
        }

        // We can now assume that we have at least 40 bytes of input.

        // Compute k as a multiple of 39 such that n-39 <= k < n. Since
        // n >= 40, this implies that k >= 1. We decode the top chunk
        // (which has length _at most_ 39 bytes) into acc.
        let mut k = ((n - 1) / 39) * 39;
        let (mut acc, _) = Self::decode(&buf[k..n]);
        while k > 0 {
            k -= 39;
            let (b, _) = Self::decode(&buf[k..k + 39]);
            acc = acc.montymul(Self::T632).add(b);
        }
        acc
    }

    /// Encode this scalar over exactly 40 bytes.
    pub fn encode(self) -> [u8; 40] {
        let mut r = [0u8; 40];
        for i in 0..5 {
            r[8 * i..8 * i + 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        r
    }

    // Recode a scalar into signed integers. For a window width of w
    // bits, returned integers are in the -(2^w-1) to +2^w range. The
    // provided slice is filled; if w*len(ss) >= 320, then the output
    // encodes the complete scalar value, and the top (last) signed
    // integer is nonnegative.
    // Window width MUST be between 2 and 10.
    pub(crate) fn recode_signed(self, ss: &mut [i32], w: i32) {
        Self::recode_signed_from_limbs(&self.0, ss, w);
    }

    fn recode_signed_from_limbs(limbs: &[u64], ss: &mut [i32], w: i32) {
        let mut acc: u64 = 0;
        let mut acc_len: i32 = 0;
        let mut j = 0;
        let mw = (1u32 << w) - 1;
        let hw = 1u32 << (w - 1);
        let mut cc: u32 = 0;
        for i in 0..ss.len() {
            // Get next w-bit chunk in bb.
            let mut bb: u32;
            if acc_len < w {
                if j < limbs.len() {
                    let nl = limbs[j];
                    j += 1;
                    bb = ((acc | (nl << acc_len)) as u32) & mw;
                    acc = nl >> (w - acc_len);
                } else {
                    bb = (acc as u32) & mw;
                    acc = 0;
                }
                acc_len += 64 - w;
            } else {
                bb = (acc as u32) & mw;
                acc_len -= w;
                acc >>= w;
            }

            // If bb is greater than 2^(w-1), subtract 2^w and
            // propagate a carry.
            bb += cc;
            cc = hw.wrapping_sub(bb) >> 31;
            ss[i] = (bb as i32).wrapping_sub((cc << w) as i32);
        }
    }

    /// Compare this scalar with zero. Returned value is 0xFFFFFFFFFFFFFFFF
    /// if this scalar is zero, or 0 otherwise.
    pub fn iszero(self) -> u64 {
        let x = self.0[0] | self.0[1] | self.0[2] | self.0[3] | self.0[4];
        ((x | x.wrapping_neg()) >> 63).wrapping_sub(1)
    }

    /// Compare this scalar with another one. Returned value is
    /// 0xFFFFFFFFFFFFFFFF if they are equal, or 0 otherwise.
    /// Equality is defined modulo n.
    pub fn equals(self, rhs: Self) -> u64 {
        let x = (self.0[0] ^ rhs.0[0])
            | (self.0[1] ^ rhs.0[1])
            | (self.0[2] ^ rhs.0[2])
            | (self.0[3] ^ rhs.0[3])
            | (self.0[4] ^ rhs.0[4]);
        ((x | x.wrapping_neg()) >> 63).wrapping_sub(1)
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar::add(self, other)
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, other: Scalar) {
        *self = Scalar::add(*self, other)
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        Scalar::sub(self, other)
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, other: Scalar) {
        *self = Scalar::sub(*self, other)
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar::neg(self)
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        Scalar::mul(self, other)
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, other: Scalar) {
        *self = Scalar::mul(*self, other)
    }
}

// ========================================================================
// Unit tests.

#[cfg(test)]
mod tests {
    use super::Scalar;

    #[test]
    fn scalar_ops() {
        let buf1: [u8; 50] = [
            0xe0, 0xff, 0x8b, 0x94, 0x96, 0xd9, 0x0f, 0xe8, 0x9c, 0xa0, 0x24, 0xd7, 0x39, 0x5c,
            0x88, 0xe8, 0x39, 0x06, 0xb8, 0xcf, 0xe6, 0xff, 0xff, 0x7f, 0x16, 0x00, 0x00, 0x00,
            0xf1, 0xff, 0xff, 0x7f, 0x07, 0x00, 0x00, 0x80, 0xfd, 0xff, 0xff, 0x7f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let buf2: [u8; 50] = [
            0xe1, 0xff, 0x8b, 0x94, 0x96, 0xd9, 0x0f, 0xe8, 0x9c, 0xa0, 0x24, 0xd7, 0x39, 0x5c,
            0x88, 0xe8, 0x39, 0x06, 0xb8, 0xcf, 0xe6, 0xff, 0xff, 0x7f, 0x16, 0x00, 0x00, 0x00,
            0xf1, 0xff, 0xff, 0x7f, 0x07, 0x00, 0x00, 0x80, 0xfd, 0xff, 0xff, 0x7f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let buf3: [u8; 50] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];
        for i in 0..51 {
            let (s1, c1) = Scalar::decode(&buf1[..i]);
            let (s2, c2) = Scalar::decode(&buf2[..i]);
            let (s3, c3) = Scalar::decode(&buf3[..i]);
            assert!(c1 == 0xffffffffffffffff);
            if i <= 40 {
                assert!(s1.encode()[..i] == buf1[..i]);
            } else {
                assert!(s1.encode()[..] == buf1[..40]);
            }
            if i <= 39 {
                assert!(c2 == 0xffffffffffffffff);
                assert!(s2.encode()[..i] == buf2[..i]);
            } else {
                assert!(c2 == 0);
            }
            if i <= 47 {
                assert!(c3 == 0xffffffffffffffff);
                if i <= 40 {
                    assert!(s3.encode()[..i] == buf3[..i]);
                } else {
                    assert!(s3.encode()[..] == buf3[..40]);
                }
            } else {
                assert!(c3 == 0);
            }
        }

        // buf4 = a randomly chosen 512-bit integer
        let buf4: [u8; 64] = [
            0xb5, 0xdd, 0x28, 0xb8, 0xd2, 0x9b, 0x6f, 0xf8, 0x15, 0x65, 0x3f, 0x89, 0xdb, 0x7b,
            0xa9, 0xde, 0x33, 0x7d, 0xa8, 0x27, 0x82, 0x26, 0xb4, 0xd6, 0x9e, 0x1f, 0xfa, 0x97,
            0x3d, 0x9e, 0x01, 0x9c, 0x77, 0xc9, 0x63, 0x5c, 0xb8, 0x34, 0xd8, 0x1a, 0x4d, 0xcb,
            0x03, 0x48, 0x62, 0xcd, 0xee, 0xc9, 0x8e, 0xc8, 0xc9, 0xa7, 0xb3, 0x6e, 0xda, 0xce,
            0x18, 0x75, 0x1b, 0xdd, 0x4f, 0x94, 0x67, 0xb5,
        ];
        // buf5 = buf4 mod n
        let buf5: [u8; 40] = [
            0x89, 0x01, 0x7a, 0x52, 0xbd, 0xdf, 0x45, 0x60, 0xce, 0x5b, 0xba, 0xe5, 0x5d, 0x25,
            0x96, 0x5a, 0x0a, 0x4f, 0x0a, 0x27, 0x1a, 0x7a, 0xe8, 0x1d, 0x7d, 0xbf, 0xe3, 0xe3,
            0xfa, 0x5e, 0x17, 0xe0, 0x44, 0xd9, 0xa5, 0x37, 0x9b, 0xf8, 0x38, 0x74,
        ];
        let s4 = Scalar::decode_reduce(&buf4[..]);
        assert!(s4.encode() == buf5);
        let (s5, c5) = Scalar::decode(&buf5[..]);
        assert!(c5 == 0xffffffffffffffff);
        assert!(s5.encode() == buf5);

        // buf6 = (buf4^256) mod n
        let buf6: [u8; 40] = [
            0x27, 0x7e, 0x2c, 0xab, 0x6d, 0xad, 0x8d, 0xa0, 0x15, 0x44, 0x02, 0x0f, 0xfa, 0xd5,
            0x4f, 0x15, 0xbf, 0x6d, 0x1d, 0x76, 0x22, 0x73, 0xcd, 0xda, 0x23, 0xfe, 0x5a, 0xed,
            0xca, 0x75, 0xd7, 0x04, 0x05, 0x66, 0x87, 0x3d, 0x37, 0x5b, 0x24, 0x13,
        ];
        let mut s6 = s4;
        for _ in 0..8 {
            s6 *= s6;
        }
        assert!(s6.encode() == buf6);

        // buf6 recoded in signed integers, w = 4
        let ref4: [i32; 80] = [
            7, 2, -2, 8, -4, 3, -5, -5, -2, 7, -3, -5, -2, -7, 1, -6, 6, 1, 4, 4, 2, 0, -1, 1, -6,
            0, 6, -3, 0, 5, 5, 1, -1, -4, -2, 7, -3, 2, 6, 7, 2, 2, 3, 7, -3, -3, -5, -2, 4, 2, -2,
            0, -5, 6, -3, -1, -5, -3, 6, 7, 7, -3, 5, 0, 5, 0, 6, 6, 7, 8, -3, 4, 7, 3, -5, 6, 4,
            2, 3, 1,
        ];
        // buf6 recoded in signed integers, w = 5
        let ref5: [i32; 64] = [
            7, -15, 0, -7, -13, -10, -9, 14, 13, 13, 3, 1, -6, 11, 16, 8, 2, -8, 4, -12, 0, 11, -1,
            10, -11, -7, 16, -5, -9, 15, -8, 15, 2, -7, -3, -5, 13, 13, 15, 4, -2, -8, -9, -5, 15,
            5, -9, 15, -9, 7, 1, 10, 0, -13, -2, -15, -2, -6, 14, -10, 6, -14, 13, 2,
        ];

        let mut ss4 = [0i32; 80];
        s6.recode_signed(&mut ss4[..], 4);
        assert!(ss4 == ref4);
        let mut ss5 = [0i32; 64];
        s6.recode_signed(&mut ss5[..], 5);
        assert!(ss5 == ref5);
    }
}

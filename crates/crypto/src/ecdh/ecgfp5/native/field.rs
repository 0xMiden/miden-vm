// Copyright (c) 2022 Thomas Pornin. MIT license; see LICENSE in this directory.
use core::{
    convert::TryFrom,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

// ========================================================================
// GF(p)

/// An element of GF(p).
#[derive(Clone, Copy, Debug)]
pub struct GFp(u64);

impl GFp {
    // IMPLEMENTATION NOTES:
    // ---------------------
    //
    // Let R = 2^64 mod p. Element x is represented by x*R mod p, in the
    // 0..p-1 range (Montgomery representation). Values are never outside
    // of that range.
    //
    // Everything is constant-time. There are specialized "Boolean"
    // functions such as iszero() and equals() that output a u64 which
    // happens, in practice, to have value 0 (for "false") or 2^64-1
    // (for "true").

    /// GF(p) modulus: p = 2^64 - 2^32 + 1
    pub const MOD: u64 = 0xffffffff00000001;

    /// Element 0 in GF(p).
    pub const ZERO: GFp = GFp::from_u64_reduce(0);

    /// Element 1 in GF(p).
    pub const ONE: GFp = GFp::from_u64_reduce(1);

    /// Element -1 in GF(p).
    pub const MINUS_ONE: GFp = GFp::from_u64_reduce(GFp::MOD - 1);

    // 2^128 mod p.
    const R2: u64 = 0xfffffffe00000001;

    // Montgomery reduction: given x <= p*2^64 - 1 = 2^128 - 2^96 + 2^64 - 1,
    // return x/2^64 mod p (in the 0 to p-1 range).
    #[inline(always)]
    const fn montyred(x: u128) -> u64 {
        // Write:
        //  x = x0 + x1*2^32 + xh*2^64
        // with x0 and x1 over 32 bits each (in the 0..2^32-1 range),
        // and 0 <= xh <= p-1 (since x < p*2^64).
        // Then:
        //  x/2^64 = xh + ((x0 + x1*2^32) / 2^64) mod p
        // Define:
        //  A = x0 + x1*2^32 + p*(2^64 - (x0 + (x0 + x1)*2^32))
        //    = (p - ((x0 + x1)*2^32 - x1))*2^64
        // Therefore:
        //  (x0 + x1*2^32)/2^64 = -((x0 + x1)*2^32 - x1) mod p
        // We thus want to compute (x0 + x1)*2^32 - x1, and subtract that
        // from xh, and reduce the result modulo p.

        let xl = x as u64;
        let xh = (x >> 64) as u64;
        let (a, e) = xl.overflowing_add(xl << 32);

        // At this point, we have:
        //  a = (x0 + x1)*2^32 + x0 - e*2^64
        // Note that floor(a / 2^32) = (x0 + x1) - e*2^32, since x0
        // fits on 32 bits.

        let b = a.wrapping_sub(a >> 32).wrapping_sub(e as u64);

        // We computed:
        //  b = a - (x0 + x1) + e*2^32 - e  mod 2^64
        //    = (x0 + x1)*2^32 + x0 - e*2^64 - (x0 + x1) + e*2^32 - e  mod 2^64
        //    = (x0 + x1)*2^32 - x1 - e*p  mod 2^64
        // If (x0 + x1) <= 2^32 - 1, then:
        //     e = 0
        //     (x0 + x1)*2^32 - x1 <= (x0 + x1)*2^32 <= 2^64 - 2^32 < p
        //     and thus b = (x0 + x1)*2^32 - x1, and in the 0..p-1 range.
        // Else:
        //     e = 1
        //     (x0 + x1)*2^32 - x1 - p = x0*2^32 + x1*(2^32 - 1) - p
        //     with:
        //         x0*2^32 <= (2^32 - 1)*2^32 < p
        //         x1*(2^32 - 1) <= (2^32 - 1)*(2^32 - 1) < p
        //         (x0 + x1)*2^32 - x1 >= 2^64 - (2^32 - 1) = p
        //     thus b = (x0 + x1)*2^32 - p, and in the 0..p-1 range.
        // In both cases, b contains exactly -((x0 + x1*2^32)/2^64) mod p,
        // properly reduced into the 0..p-1 range.
        //
        // Thanks to the input assumption on x, we know that xh is also
        // in the 0..p-1 range, and thus we only have to subtract b from
        // xh modulo p. This subtraction is done by first doing it over
        // the integers, and then adding back p in case there was a
        // borrow. Since p = 2^64 - (2^32 - 1), "adding p" is equivalent
        // to "subtracting 2^32 - 1" when working modulo p. The
        // expression "0u32.wrapping_sub(c as u32)" should translate as
        // "perform a subtract-with-carry from the value 0"; since
        // setting a register to zero has no cost at all on x86 (it is
        // done with a xor of a register with itself, and the CPU
        // recognizes that instruction specially and maps it to a
        // special case of the register renaming unit, no computation is
        // actually done), we may hope for this operation to be done
        // with 1-cycle latency.

        let (r, c) = xh.overflowing_sub(b);
        r.wrapping_sub(0u32.wrapping_sub(c as u32) as u64)

        // A multiplication in GF(p) is a 64x64->128 multiply, followed
        // by montyred(). On x86 (Intel Skylake+ core), the
        // multiplication should be a mulx, which yields the low half
        // (xl) after 3 cycles, and the high half (xh) after 4 cycles.
        // Operations above imply an extra 7-cycle latency over the
        // computation of xl, thus 10-cycle latency in total. We thus
        // expect a sequence of n dependent multiplications to
        // execute over 10*n cycles, which is corroborated by benchmarks
        // (on an Intel i5-8259U "Coffee Lake" core).
    }

    /// Build a GF(p) element from a 64-bit integer. Returned values
    /// are (r, c). If the source value v is lower than the modulus,
    /// then r contains the value v as an element of GF(p), and c is
    /// equal to 0xFFFFFFFFFFFFFFFF; otherwise, r contains zero (in
    /// GF(p)) and c is 0.
    pub fn from_u64(v: u64) -> (GFp, u64) {
        // Computation of c is a constant-time lower-than operation:
        // If v < 2^63 then v < p and its high bit it 0.
        // If v >= 2^63 then its high bit is 1, and v < p if and only
        // the high bit of z = v-p is 1 (since p >= 2^63 itself).
        let z = v.wrapping_sub(GFp::MOD);
        let c = ((v & !z) >> 63).wrapping_sub(1);
        (GFp::from_u64_reduce(v & c), c)
    }

    /// Build a GF(p) element from a 64-bit integer. The provided
    /// integer is implicitly reduced modulo p.
    #[inline(always)]
    pub const fn from_u64_reduce(v: u64) -> GFp {
        // R^2 = 2^64 - 2^33 + 1 mod p.
        // With v < 2^64, we have R*v < 2^128 - 2^97 + 2^64, which is in
        // range of montyred().
        GFp(GFp::montyred((v as u128) * (GFp::R2 as u128)))
    }

    /// Get the element as an integer, normalized in the 0..p-1
    /// range.
    #[inline(always)]
    pub const fn to_u64(self) -> u64 {
        // Conversion back to normal representation is only a matter of
        // dividing by 2^64 modulo p, and that is exactly what montyred()
        // computes.
        GFp::montyred(self.0 as u128)
    }

    /// Addition in GF(p)
    #[inline(always)]
    const fn add(self, rhs: Self) -> Self {
        // We compute a + b = a - (p - b).
        let (x1, c1) = self.0.overflowing_sub(GFp::MOD - rhs.0);
        let adj = 0u32.wrapping_sub(c1 as u32);
        GFp(x1.wrapping_sub(adj as u64))
    }

    /// Subtraction in GF(p)
    #[inline(always)]
    const fn sub(self, rhs: Self) -> Self {
        // See montyred() for details on the subtraction.
        let (x1, c1) = self.0.overflowing_sub(rhs.0);
        let adj = 0u32.wrapping_sub(c1 as u32);
        GFp(x1.wrapping_sub(adj as u64))
    }

    /// Negation in GF(p)
    #[inline(always)]
    const fn neg(self) -> Self {
        GFp::ZERO.sub(self)
    }

    /// Halving in GF(p) (division by 2).
    #[inline(always)]
    pub const fn half(self) -> Self {
        // If x is even, then this returned x/2.
        // If x is odd, then this returns (x-1)/2 + (p+1)/2 = (x+p)/2.
        GFp((self.0 >> 1).wrapping_add((self.0 & 1).wrapping_neg() & 0x7fffffff80000001))
    }

    /// Doubling in GF(p) (multiplication by 2).
    #[inline(always)]
    pub const fn double(self) -> Self {
        self.add(self)
    }

    /// Multiplication in GF(p) by a small integer (less than 2^31).
    #[inline(always)]
    pub const fn mul_small(self, rhs: u32) -> Self {
        // Since the 'rhs' value is not in Montgomery representation,
        // we need to do a manual reduction instead.
        let x = (self.0 as u128) * (rhs as u128);
        let xl = x as u64;
        let xh = (x >> 64) as u64;

        // Since rhs <= 2^31 - 1, we have xh <= 2^31 - 2, and
        // p - xh >= 2^64 - 2^32 - 2^31 + 3, which is close to 2^64;
        // thus, even if xl was not lower than p, the subtraction
        // will bring back the value in the proper range, and the
        // normal subtraction in GF(p) yields the proper result.
        let (r, c) = xl.overflowing_sub(GFp::MOD - ((xh << 32) - xh));
        GFp(r.wrapping_sub(0u32.wrapping_sub(c as u32) as u64))
    }

    /// Multiplication in GF(p)
    #[inline(always)]
    const fn mul(self, rhs: Self) -> Self {
        // If x < p and y < p, then x*y <= (p-1)^2, and is thus in
        // range of montyred().
        GFp(GFp::montyred((self.0 as u128) * (rhs.0 as u128)))
    }

    /// Squaring in GF(p)
    #[inline(always)]
    pub const fn square(self) -> Self {
        self.mul(self)
    }

    /// Multiple squarings in GF(p): return x^(2^n)
    pub fn msquare(self, n: u32) -> Self {
        let mut x = self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    /// Inversion in GF(p); if the input is zero, then zero is returned.
    pub fn invert(self) -> Self {
        // This uses Fermat's little theorem: 1/x = x^(p-2) mod p.
        // We have p-2 = 0xFFFFFFFEFFFFFFFF. In the instructions below,
        // we call 'xj' the value x^(2^j-1).
        let x = self;
        let x2 = x * x.square();
        let x4 = x2 * x2.msquare(2);
        let x5 = x * x4.square();
        let x10 = x5 * x5.msquare(5);
        let x15 = x5 * x10.msquare(5);
        let x16 = x * x15.square();
        let x31 = x15 * x16.msquare(15);
        let x32 = x * x31.square();
        return x32 * x31.msquare(33);
    }

    fn div(self, rhs: Self) -> Self {
        self * rhs.invert()
    }

    /// Test of equality with zero; return value is 0xFFFFFFFFFFFFFFFF
    /// if this value is equal to zero, or 0 otherwise.
    #[inline(always)]
    pub const fn iszero(self) -> u64 {
        // Since values are always canonicalized internally, 0 in GF(p)
        // is always represented by the integer 0.
        // x == 0 if and only if both x and -x have their high bit equal to 0.
        !((((self.0 | self.0.wrapping_neg()) as i64) >> 63) as u64)
    }

    /// Test of equality with one; return value is 0xFFFFFFFFFFFFFFFF
    /// if this value is equal to one, or 0 otherwise.
    #[inline(always)]
    pub const fn isone(self) -> u64 {
        self.equals(GFp::ONE)
    }

    /// Test of equality with minus one; return value is 0xFFFFFFFFFFFFFFFF
    /// if this value is equal to -1 mod p, or 0 otherwise.
    #[inline(always)]
    pub const fn isminusone(self) -> u64 {
        self.equals(GFp::MINUS_ONE)
    }

    /// Test of equality between two GF(p) elements; return value is
    /// 0xFFFFFFFFFFFFFFFF if the two values are equal, or 0 otherwise.
    #[inline(always)]
    pub const fn equals(self, rhs: Self) -> u64 {
        // Since internal representation is canonical, we can simply
        // do a xor between the two operands, and then use the same
        // expression as iszero().
        let t = self.0 ^ rhs.0;
        !((((t | t.wrapping_neg()) as i64) >> 63) as u64)
    }

    /// Legendre symbol: return x^((p-1)/2) (as a GF(p) element).
    pub fn legendre(self) -> GFp {
        // (p-1)/2 = 0x7FFFFFFF80000000
        let x = self;
        let x2 = x * x.square();
        let x4 = x2 * x2.msquare(2);
        let x8 = x4 * x4.msquare(4);
        let x16 = x8 * x8.msquare(8);
        let x32 = x16 * x16.msquare(16);
        x32.msquare(31)
    }

    // For g = 7^(2^32-1) mod p = 1753635133440165772 (a primitive 2^32 root
    // of 1 in GF(p)), we precompute GG[i] = g^(2^i) for i = 0 to 31.
    const GG: [GFp; 32] = [
        GFp::from_u64_reduce(1753635133440165772),
        GFp::from_u64_reduce(4614640910117430873),
        GFp::from_u64_reduce(9123114210336311365),
        GFp::from_u64_reduce(16116352524544190054),
        GFp::from_u64_reduce(6414415596519834757),
        GFp::from_u64_reduce(1213594585890690845),
        GFp::from_u64_reduce(17096174751763063430),
        GFp::from_u64_reduce(5456943929260765144),
        GFp::from_u64_reduce(9713644485405565297),
        GFp::from_u64_reduce(16905767614792059275),
        GFp::from_u64_reduce(5416168637041100469),
        GFp::from_u64_reduce(17654865857378133588),
        GFp::from_u64_reduce(3511170319078647661),
        GFp::from_u64_reduce(18146160046829613826),
        GFp::from_u64_reduce(9306717745644682924),
        GFp::from_u64_reduce(12380578893860276750),
        GFp::from_u64_reduce(6115771955107415310),
        GFp::from_u64_reduce(17776499369601055404),
        GFp::from_u64_reduce(16207902636198568418),
        GFp::from_u64_reduce(1532612707718625687),
        GFp::from_u64_reduce(17492915097719143606),
        GFp::from_u64_reduce(455906449640507599),
        GFp::from_u64_reduce(11353340290879379826),
        GFp::from_u64_reduce(1803076106186727246),
        GFp::from_u64_reduce(13797081185216407910),
        GFp::from_u64_reduce(17870292113338400769),
        GFp::from_u64_reduce(549755813888),
        GFp::from_u64_reduce(70368744161280),
        GFp::from_u64_reduce(17293822564807737345),
        GFp::from_u64_reduce(18446744069397807105),
        GFp::from_u64_reduce(281474976710656),
        GFp::from_u64_reduce(18446744069414584320),
    ];

    /// Square root in GF(p); returns (r, cc):
    ///  - If the input is a square, r = sqrt(self) and cc = 0xFFFFFFFFFFFFFFFF
    ///  - If the input is not a square, r = zero and cc = 0
    ///
    /// Which of the two square roots is obtained is unspecified.
    pub fn sqrt(self) -> (Self, u64) {
        // We use a constant-time Tonelli-Shanks.
        // Input: x
        // Output: (sqrt(x), -1) if x is QR, or (0, 0) otherwise
        // Definitions:
        //    modulus: p = q*2^n + 1 with q odd (here, q = 2^32 - 1 and n = 32)
        //    g is a primitive 2^n root of 1 in GF(p)
        //    GG[j] = g^(2^j)  (j = 0 to n-1, precomputed)
        // Init:
        //    r <- x^((q+1)/2)
        //    v <- x^q
        // Process:
        //    for i = n-1 down to 1:
        //        w = v^(2^(i-1))   (with i-1 squarings)
        //        if w == -1 then:
        //            v <- v*GG[n-i]
        //            r <- r*GG[n-i-1]
        //    if v == 0 or 1 then:
        //        return (r, -1)
        //    else:
        //        return (0, 0)  (no square root)

        let x = self;

        // r <- u^((q+1)/2)
        // v <- u^q
        let x2 = x * x.square();
        let x4 = x2 * x2.msquare(2);
        let x5 = x * x4.square();
        let x10 = x5 * x5.msquare(5);
        let x15 = x5 * x10.msquare(5);
        let x16 = x * x15.square();
        let x31 = x15 * x16.msquare(15);
        let mut r = x * x31;
        let mut v = x * x31.square();

        for i in (1..32).rev() {
            let w = v.msquare((i - 1) as u32);
            let cc = w.equals(GFp::MINUS_ONE);
            v = GFp(v.0 ^ (cc & (v.0 ^ (v * GFp::GG[32 - i]).0)));
            r = GFp(r.0 ^ (cc & (r.0 ^ (r * GFp::GG[31 - i]).0)));
        }
        let m = v.iszero() | v.equals(GFp::ONE);
        (GFp(r.0 & m), m)
    }

    /// Select a value: this function returns x0 if c == 0, or x1 if
    /// c == 0xFFFFFFFFFFFFFFFF.
    #[inline(always)]
    pub fn select(c: u64, x0: GFp, x1: GFp) -> GFp {
        GFp(x0.0 ^ (c & (x0.0 ^ x1.0)))
    }
}

// We implement all the needed traits to allow use of the arithmetic
// operators on GF(p) values.

impl Add<GFp> for GFp {
    type Output = GFp;

    #[inline(always)]
    fn add(self, other: GFp) -> GFp {
        GFp::add(self, other)
    }
}

impl AddAssign<GFp> for GFp {
    #[inline(always)]
    fn add_assign(&mut self, other: GFp) {
        *self = GFp::add(*self, other);
    }
}

impl Sub<GFp> for GFp {
    type Output = GFp;

    #[inline(always)]
    fn sub(self, other: GFp) -> GFp {
        GFp::sub(self, other)
    }
}

impl SubAssign<GFp> for GFp {
    #[inline(always)]
    fn sub_assign(&mut self, other: GFp) {
        *self = GFp::sub(*self, other);
    }
}

impl Neg for GFp {
    type Output = GFp;

    #[inline(always)]
    fn neg(self) -> GFp {
        GFp::neg(self)
    }
}

impl Mul<GFp> for GFp {
    type Output = GFp;

    #[inline(always)]
    fn mul(self, other: GFp) -> GFp {
        GFp::mul(self, other)
    }
}

impl MulAssign<GFp> for GFp {
    #[inline(always)]
    fn mul_assign(&mut self, other: GFp) {
        *self = GFp::mul(*self, other);
    }
}

impl Div<GFp> for GFp {
    type Output = GFp;

    #[inline(always)]
    fn div(self, other: GFp) -> GFp {
        GFp::div(self, other)
    }
}

impl DivAssign<GFp> for GFp {
    #[inline(always)]
    fn div_assign(&mut self, other: GFp) {
        *self = GFp::div(*self, other);
    }
}

// ========================================================================
// GF(p^5)

/// An element of GF(p^5).
#[derive(Clone, Copy, Debug)]
pub struct GFp5(pub [GFp; 5]);

impl GFp5 {
    // IMPLEMENTATION NOTES:
    // ---------------------
    //
    // The GF(p^5) element x0 + x1*z + x2*z^2 + x3*z^3 + x4*z^4 is
    // represented as (x0, x1, x2, x3, x4), with the coefficients being
    // elements of GF(p) (i.e. GFp structure instances).
    //
    // Primitive operations are implemented as modifying functions
    // (set_add(), set_mul()...). Arithmetic operators on GFp5 values
    // are supported with the usual traits, performing structure copies
    // as needed to offer an "immutable values" API; however, the
    // modifying operations ('+=', '*='...) will avoid any copy.

    /// Value zero in GF(p^5).
    pub const ZERO: GFp5 = GFp5([GFp::ZERO, GFp::ZERO, GFp::ZERO, GFp::ZERO, GFp::ZERO]);

    /// Value one in GF(p^5).
    pub const ONE: GFp5 = GFp5([GFp::ONE, GFp::ZERO, GFp::ZERO, GFp::ZERO, GFp::ZERO]);

    /// Create an instance over the five provided integers, interpreted
    /// as the five coefficients in GF(p) (by increasing degrees, 0 to 4).
    /// WARNING: the values are implicitly reduced modulo p = 2^64-2^32+1,
    /// thus non-canonical values are accepted. This function should mostly
    /// be used for hardcoded constants.
    #[inline(always)]
    pub const fn from_u64_reduce(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> Self {
        GFp5([
            GFp::from_u64_reduce(x0),
            GFp::from_u64_reduce(x1),
            GFp::from_u64_reduce(x2),
            GFp::from_u64_reduce(x3),
            GFp::from_u64_reduce(x4),
        ])
    }

    /// Create an instance over the five provided integers, interpreted
    /// as the five coefficients in GF(p) (by increasing degrees, 0 to 4).
    /// If all five values are in the proper range (less than the modulus
    /// p = 2^26-2^32+1), then the returned values are the new element,
    /// and the integer 0xFFFFFFFFFFFFFFFF; otherwise, the returned values
    /// are the zero element, and 0.
    pub fn from_u64(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> (Self, u64) {
        let (w0, c0) = GFp::from_u64(x0);
        let (w1, c1) = GFp::from_u64(x1);
        let (w2, c2) = GFp::from_u64(x2);
        let (w3, c3) = GFp::from_u64(x3);
        let (w4, c4) = GFp::from_u64(x4);
        let c = c0 & c1 & c2 & c3 & c4;
        (
            GFp5([GFp(w0.0 & c), GFp(w1.0 & c), GFp(w2.0 & c), GFp(w3.0 & c), GFp(w4.0 & c)]),
            c,
        )
    }

    /// Decode a GF(p^5) element from bytes. The input slice must have
    /// size exactly 40 bytes. The bytes are interpreted as 64-bit integers
    /// in unsigned little-endian convention; if any of them is outside
    /// of the 0..p-1 range, then the decoding fails. The five integers
    /// are used as the five coefficients of a GF(p^5) element.
    /// This function returns (r, c). On decoding success, r contains the
    /// decoded element, and c == 0xFFFFFFFFFFFFFFFF. On error, r contains
    /// the value zero, and c == 0.
    pub fn decode(buf: &[u8]) -> (Self, u64) {
        if buf.len() != 40 {
            // The memory access pattern cannot hide the fact that the
            // length is not exactly 40 bytes; thus, we can us a
            // conditional jump in that case.
            return (GFp5::ZERO, 0);
        }
        GFp5::from_u64(
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&buf[0..8]).unwrap()),
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&buf[8..16]).unwrap()),
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&buf[16..24]).unwrap()),
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&buf[24..32]).unwrap()),
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&buf[32..40]).unwrap()),
        )
    }

    /// Encode a GF(p^5) element into bytes. The five coefficients are
    /// encoded in low-to-high degree order, and each coefficient yields
    /// exactly 8 bytes (using unsigned little-endian convention).
    /// Encoding is always canonical.
    pub fn encode(self) -> [u8; 40] {
        let mut r = [0u8; 40];
        for i in 0..5 {
            r[8 * i..8 * i + 8].copy_from_slice(&self.0[i].to_u64().to_le_bytes());
        }
        r
    }

    #[inline]
    pub(crate) fn set_add(&mut self, rhs: &Self) {
        self.0[0] += rhs.0[0];
        self.0[1] += rhs.0[1];
        self.0[2] += rhs.0[2];
        self.0[3] += rhs.0[3];
        self.0[4] += rhs.0[4];
    }

    #[inline]
    pub(crate) fn set_sub(&mut self, rhs: &Self) {
        self.0[0] -= rhs.0[0];
        self.0[1] -= rhs.0[1];
        self.0[2] -= rhs.0[2];
        self.0[3] -= rhs.0[3];
        self.0[4] -= rhs.0[4];
    }

    #[inline]
    pub(crate) fn set_neg(&mut self) {
        self.0[0] = -self.0[0];
        self.0[1] = -self.0[1];
        self.0[2] = -self.0[2];
        self.0[3] = -self.0[3];
        self.0[4] = -self.0[4];
    }

    /// Halving in GF(p^5) (division by 2).
    #[inline(always)]
    pub fn half(self) -> Self {
        let mut r = self;
        r.set_half();
        r
    }

    #[inline]
    pub(crate) fn set_half(&mut self) {
        self.0[0] = self.0[0].half();
        self.0[1] = self.0[1].half();
        self.0[2] = self.0[2].half();
        self.0[3] = self.0[3].half();
        self.0[4] = self.0[4].half();
    }

    /// Doubling in GF(p^5) (multiplication by 2).
    #[inline(always)]
    pub fn double(self) -> Self {
        let mut r = self;
        r.set_double();
        r
    }

    #[inline]
    pub(crate) fn set_double(&mut self) {
        self.0[0] = self.0[0].double();
        self.0[1] = self.0[1].double();
        self.0[2] = self.0[2].double();
        self.0[3] = self.0[3].double();
        self.0[4] = self.0[4].double();
    }

    /// Multiply this element by a small integer (less than 2^31).
    #[inline(always)]
    pub fn mul_small(self, rhs: u32) -> Self {
        let mut r = self;
        r.set_mul_small(rhs);
        r
    }

    #[inline]
    pub(crate) fn set_mul_small(&mut self, rhs: u32) {
        self.0[0] = self.0[0].mul_small(rhs);
        self.0[1] = self.0[1].mul_small(rhs);
        self.0[2] = self.0[2].mul_small(rhs);
        self.0[3] = self.0[3].mul_small(rhs);
        self.0[4] = self.0[4].mul_small(rhs);
    }

    /// Multiply this element by a v*z where z is the symbolic variable
    /// of GF(p)[z], and v is a small integer (less than 2^29).
    #[inline(always)]
    pub fn mul_small_k1(self, rhs: u32) -> Self {
        let mut r = self;
        r.set_mul_small_k1(rhs);
        r
    }

    #[inline]
    pub(crate) fn set_mul_small_k1(&mut self, rhs: u32) {
        let d0 = self.0[4].mul_small(rhs * 3);
        let d1 = self.0[0].mul_small(rhs);
        let d2 = self.0[1].mul_small(rhs);
        let d3 = self.0[2].mul_small(rhs);
        let d4 = self.0[3].mul_small(rhs);
        self.0[0] = d0;
        self.0[1] = d1;
        self.0[2] = d2;
        self.0[3] = d3;
        self.0[4] = d4;
    }

    /// For two small integers v0 and v1 (both lower than 2^28),
    /// multiply this value by z*v1 - v0.
    #[inline(always)]
    pub fn mul_small_kn01(self, v0: u32, v1: u32) -> Self {
        let mut r = self;
        r.set_mul_small_kn01(v0, v1);
        r
    }

    #[inline]
    pub(crate) fn set_mul_small_kn01(&mut self, v0: u32, v1: u32) {
        let d0 = self.0[4].mul_small(3 * v1) - self.0[0].mul_small(v0);
        let d1 = self.0[0].mul_small(v1) - self.0[1].mul_small(v0);
        let d2 = self.0[1].mul_small(v1) - self.0[2].mul_small(v0);
        let d3 = self.0[2].mul_small(v1) - self.0[3].mul_small(v0);
        let d4 = self.0[3].mul_small(v1) - self.0[4].mul_small(v0);
        self.0[0] = d0;
        self.0[1] = d1;
        self.0[2] = d2;
        self.0[3] = d3;
        self.0[4] = d4;
    }

    /// Multiply this element by a value from the base field (GF(p)).
    #[inline(always)]
    pub fn mul_k0(self, rhs: GFp) -> GFp5 {
        let mut r = self;
        r.set_mul_k0(rhs);
        r
    }

    #[inline]
    pub(crate) fn set_mul_k0(&mut self, rhs: GFp) {
        self.0[0] *= rhs;
        self.0[1] *= rhs;
        self.0[2] *= rhs;
        self.0[3] *= rhs;
        self.0[4] *= rhs;
    }

    // mul_to_kJ(), for J = 0 to 4, returns the coefficient J of a
    // product in GF(p^5).

    #[inline(always)]
    fn mul_to_k0(&self, rhs: &Self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (rhs.0[0].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (rhs.0[4].0 as u128);
        let pp2 = (self.0[2].0 as u128) * (rhs.0[3].0 as u128);
        let pp3 = (self.0[3].0 as u128) * (rhs.0[2].0 as u128);
        let pp4 = (self.0[4].0 as u128) * (rhs.0[1].0 as u128);
        let zhi = (pp0 >> 64) + 3 * ((pp1 >> 64) + (pp2 >> 64) + (pp3 >> 64) + (pp4 >> 64));
        let zlo = ((pp0 as u64) as u128)
            + 3 * (((pp1 as u64) as u128)
                + ((pp2 as u64) as u128)
                + ((pp3 as u64) as u128)
                + ((pp4 as u64) as u128));
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline(always)]
    fn mul_to_k1(&self, rhs: &Self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (rhs.0[1].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (rhs.0[0].0 as u128);
        let pp2 = (self.0[2].0 as u128) * (rhs.0[4].0 as u128);
        let pp3 = (self.0[3].0 as u128) * (rhs.0[3].0 as u128);
        let pp4 = (self.0[4].0 as u128) * (rhs.0[2].0 as u128);
        let zhi = (pp0 >> 64) + (pp1 >> 64) + 3 * ((pp2 >> 64) + (pp3 >> 64) + (pp4 >> 64));
        let zlo = ((pp0 as u64) as u128)
            + ((pp1 as u64) as u128)
            + 3 * (((pp2 as u64) as u128) + ((pp3 as u64) as u128) + ((pp4 as u64) as u128));
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline(always)]
    fn mul_to_k2(&self, rhs: &Self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (rhs.0[2].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (rhs.0[1].0 as u128);
        let pp2 = (self.0[2].0 as u128) * (rhs.0[0].0 as u128);
        let pp3 = (self.0[3].0 as u128) * (rhs.0[4].0 as u128);
        let pp4 = (self.0[4].0 as u128) * (rhs.0[3].0 as u128);
        let zhi = (pp0 >> 64) + (pp1 >> 64) + (pp2 >> 64) + 3 * ((pp3 >> 64) + (pp4 >> 64));
        let zlo = ((pp0 as u64) as u128)
            + ((pp1 as u64) as u128)
            + ((pp2 as u64) as u128)
            + 3 * (((pp3 as u64) as u128) + ((pp4 as u64) as u128));
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline(always)]
    fn mul_to_k3(&self, rhs: &Self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (rhs.0[3].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (rhs.0[2].0 as u128);
        let pp2 = (self.0[2].0 as u128) * (rhs.0[1].0 as u128);
        let pp3 = (self.0[3].0 as u128) * (rhs.0[0].0 as u128);
        let pp4 = (self.0[4].0 as u128) * (rhs.0[4].0 as u128);
        let zhi = (pp0 >> 64) + (pp1 >> 64) + (pp2 >> 64) + (pp3 >> 64) + 3 * (pp4 >> 64);
        let zlo = ((pp0 as u64) as u128)
            + ((pp1 as u64) as u128)
            + ((pp2 as u64) as u128)
            + ((pp3 as u64) as u128)
            + 3 * ((pp4 as u64) as u128);
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline(always)]
    fn mul_to_k4(&self, rhs: &Self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (rhs.0[4].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (rhs.0[3].0 as u128);
        let pp2 = (self.0[2].0 as u128) * (rhs.0[2].0 as u128);
        let pp3 = (self.0[3].0 as u128) * (rhs.0[1].0 as u128);
        let pp4 = (self.0[4].0 as u128) * (rhs.0[0].0 as u128);
        let zhi = (pp0 >> 64) + (pp1 >> 64) + (pp2 >> 64) + (pp3 >> 64) + (pp4 >> 64);
        let zlo = ((pp0 as u64) as u128)
            + ((pp1 as u64) as u128)
            + ((pp2 as u64) as u128)
            + ((pp3 as u64) as u128)
            + ((pp4 as u64) as u128);
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline]
    pub(crate) fn set_mul(&mut self, rhs: &Self) {
        let d0 = self.mul_to_k0(rhs);
        let d1 = self.mul_to_k1(rhs);
        let d2 = self.mul_to_k2(rhs);
        let d3 = self.mul_to_k3(rhs);
        let d4 = self.mul_to_k4(rhs);
        self.0[0] = d0;
        self.0[1] = d1;
        self.0[2] = d2;
        self.0[3] = d3;
        self.0[4] = d4;
    }

    // square_to_kJ(), for J = 0 to 4, returns the coefficient J
    // of a squaring in GF(p^5).

    #[inline(always)]
    fn square_to_k0(&self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (self.0[0].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (self.0[4].0 as u128);
        let pp2 = (self.0[2].0 as u128) * (self.0[3].0 as u128);
        let zhi = (pp0 >> 64) + 6 * ((pp1 >> 64) + (pp2 >> 64));
        let zlo = ((pp0 as u64) as u128) + 6 * (((pp1 as u64) as u128) + ((pp2 as u64) as u128));
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline(always)]
    fn square_to_k1(&self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (self.0[1].0 as u128);
        let pp2 = (self.0[2].0 as u128) * (self.0[4].0 as u128);
        let pp3 = (self.0[3].0 as u128) * (self.0[3].0 as u128);
        let zhi = 2 * (pp0 >> 64) + 6 * (pp2 >> 64) + 3 * (pp3 >> 64);
        let zlo =
            2 * ((pp0 as u64) as u128) + 6 * ((pp2 as u64) as u128) + 3 * ((pp3 as u64) as u128);
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline(always)]
    fn square_to_k2(&self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (self.0[2].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (self.0[1].0 as u128);
        let pp3 = (self.0[3].0 as u128) * (self.0[4].0 as u128);
        let zhi = 2 * (pp0 >> 64) + (pp1 >> 64) + 6 * (pp3 >> 64);
        let zlo = 2 * ((pp0 as u64) as u128) + ((pp1 as u64) as u128) + 6 * ((pp3 as u64) as u128);
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline(always)]
    fn square_to_k3(&self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (self.0[3].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (self.0[2].0 as u128);
        let pp4 = (self.0[4].0 as u128) * (self.0[4].0 as u128);
        let zhi = 2 * ((pp0 >> 64) + (pp1 >> 64)) + 3 * (pp4 >> 64);
        let zlo =
            2 * (((pp0 as u64) as u128) + ((pp1 as u64) as u128)) + 3 * ((pp4 as u64) as u128);
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    #[inline(always)]
    fn square_to_k4(&self) -> GFp {
        let pp0 = (self.0[0].0 as u128) * (self.0[4].0 as u128);
        let pp1 = (self.0[1].0 as u128) * (self.0[3].0 as u128);
        let pp2 = (self.0[2].0 as u128) * (self.0[2].0 as u128);
        let zhi = 2 * ((pp0 >> 64) + (pp1 >> 64)) + (pp2 >> 64);
        let zlo = 2 * (((pp0 as u64) as u128) + ((pp1 as u64) as u128)) + ((pp2 as u64) as u128);
        GFp(GFp::montyred(zlo + (zhi << 32) - zhi))
    }

    /// Squaring in GF(p^5).
    #[inline(always)]
    pub fn square(self) -> Self {
        let mut r = self;
        r.set_square();
        r
    }

    #[inline]
    pub(crate) fn set_square(&mut self) {
        let d0 = self.square_to_k0();
        let d1 = self.square_to_k1();
        let d2 = self.square_to_k2();
        let d3 = self.square_to_k3();
        let d4 = self.square_to_k4();
        self.0[0] = d0;
        self.0[1] = d1;
        self.0[2] = d2;
        self.0[3] = d3;
        self.0[4] = d4;
    }

    /// Compute n successive squarings in GF(p^5) (i.e. raise to the
    /// power 2^n).
    #[inline(always)]
    pub fn msquare(self, n: u32) -> Self {
        let mut r = self;
        r.set_msquare(n);
        r
    }

    #[inline]
    pub(crate) fn set_msquare(&mut self, n: u32) {
        for _ in 0..n {
            self.set_square();
        }
    }

    /// Equality check (constant-time), returns 0xFFFFFFFFFFFFFFFF on
    /// equality, 0 otherwise.
    #[inline]
    pub fn equals(self, rhs: Self) -> u64 {
        // Since all the GF(p) elements are in canonical representation,
        // we can use a mutualized equal-to-zero on the bitwise or of
        // the coefficients of the xor of the two operands.
        let z = (self.0[0].0 ^ rhs.0[0].0)
            | (self.0[1].0 ^ rhs.0[1].0)
            | (self.0[2].0 ^ rhs.0[2].0)
            | (self.0[3].0 ^ rhs.0[3].0)
            | (self.0[4].0 ^ rhs.0[4].0);
        ((z | z.wrapping_neg()) >> 63).wrapping_sub(1)
    }

    /// Equality check (constant-time) with zero, returns
    /// 0xFFFFFFFFFFFFFFFF if this element is zero, 0 otherwise.
    #[inline]
    pub fn iszero(self) -> u64 {
        // GF(p) elements are canonical; we simply check that they all
        // have zero as internal representation.
        let z = self.0[0].0 | self.0[1].0 | self.0[2].0 | self.0[3].0 | self.0[4].0;
        ((z | z.wrapping_neg()) >> 63).wrapping_sub(1)
    }

    // Frobenius operator (raise this value to the power p).
    #[inline]
    fn set_frob1(&mut self) {
        self.0[1] *= GFp::from_u64_reduce(1041288259238279555);
        self.0[2] *= GFp::from_u64_reduce(15820824984080659046);
        self.0[3] *= GFp::from_u64_reduce(211587555138949697);
        self.0[4] *= GFp::from_u64_reduce(1373043270956696022);
    }

    // Frobenius operator, twice (raise this value to the power p^2).
    #[inline]
    fn set_frob2(&mut self) {
        self.0[1] *= GFp::from_u64_reduce(15820824984080659046);
        self.0[2] *= GFp::from_u64_reduce(1373043270956696022);
        self.0[3] *= GFp::from_u64_reduce(1041288259238279555);
        self.0[4] *= GFp::from_u64_reduce(211587555138949697);
    }

    /// Invert this element. If this value is zero, then zero is returned.
    #[inline(always)]
    pub fn invert(self) -> GFp5 {
        let mut r = self;
        r.set_invert();
        r
    }

    pub(crate) fn set_invert(&mut self) {
        // We are using the method first described by Itoh and Tsujii.
        //
        // Let r = 1 + p + p^2 + p^3 + p^4.
        // We have: p^5 - 1 = (p - 1)*r
        // For x != 0, we then have:
        //   x^(p^5-1) = (x^r)^(p-1)
        // Since x^(p^5-1) = 1 (the group of invertible elements has
        // order p^5-1), obtain that x^r is a root of the polynomial
        // X^(p-1) - 1. However, all non-zero elements of GF(p) are
        // roots of X^(p-1) - 1, and there are p-1 non-zero elements in
        // GF(p), and a polynomial of degre p-1 cannot have more than
        // p-1 roots in a field. Therefore, the roots of X^(p-1) - 1
        // are _exactly_ the elements of GF(p). It follows that x^r is
        // in GF(p), for any x != 0 in GF(p^5) (this also holds for x = 0).
        //
        // Given x != 0, we can write:
        //   1/x = x^(r-1) / x^r
        // Thus, we only need to compute x^(r-1) (in GF(p^5)), then x^r
        // (by multiplying x with x^(r-1)), then invert x^r in GF(p),
        // and multiply x^(r-1) by the inverse of x^r.
        //
        // We can compute efficiently x^(r-1) by using the Frobenius
        // operator: in GF(p^5), raising a value to the power p boils
        // down to multiplying four of the coefficients by precomputed
        // constants.
        // If we defined phi1(x) = x^p and phi2(x) = phi1(phi1(x)), then:
        //   x^(r-1) = x^(p + p^2 + p^3 + p^4)
        //           = x^(p + p^2) * phi2(x^(p + p^2))
        //           = phi1(x) * phi1(phi1(x)) * phi2(phi1(x) * phi1(phi1(x)))
        // which only needs three applications of phi1() or phi2(), and
        // two multiplications in GF(p^5).

        let t0 = *self;
        self.set_frob1();
        let mut t1 = *self;
        t1.set_frob1();
        self.set_mul(&t1);
        t1 = *self;
        self.set_frob2();
        self.set_mul(&t1);
        let x = self.mul_to_k0(&t0);
        self.set_mul_k0(x.invert());
    }

    #[inline]
    pub(crate) fn set_div(&mut self, rhs: &Self) {
        let mut d = *rhs;
        d.set_invert();
        self.set_mul(&d);
    }

    /// Return x^((p^5-1)/2) as an element of GF(p) (equal to 0 if x == 0,
    /// to 1 if x is a non-zero square, to -1 otherwise).
    pub fn legendre(self) -> GFp {
        // Using r = 1 + p + p^2 + p^3 + p^4, we have:
        //   (p^5 - 1)/2 = ((p - 1) / 2)*r
        // thus:
        //   x^((p^5 - 1)/2) = (x^r)^((p-1)/2)
        // i.e. the Legendre symbol of x is equal to the Legendre symbol
        // of x^r. Since x^r is in GF(p) and can be computed efficiently
        // (see set_invert()), this allows reducing this call to a
        // legendre() call on GF(p).

        let mut t0 = self;
        t0.set_frob1();
        let mut t1 = t0;
        t1.set_frob1();
        t0.set_mul(&t1);
        t1 = t0;
        t1.set_frob2();
        t0.set_mul(&t1);
        let x = self.mul_to_k0(&t0);
        x.legendre()
    }

    /// Square root in GF(p^5); returns (s, cc):
    ///  - If the input is a square, s = sqrt(self) and cc = 0xFFFFFFFFFFFFFFFF
    ///  - If the input is not a square, s = zero and cc = 0
    ///
    /// Which of the two square roots is obtained is unspecified.
    #[inline(always)]
    pub fn sqrt(self) -> (GFp5, u64) {
        let mut r = self;
        let c = r.set_sqrt();
        (r, c)
    }

    pub(crate) fn set_sqrt(&mut self) -> u64 {
        // Let r = 1 + p + p^2 + p^3 + p^4. For x != 0, we have:
        //   x = (x^r) / (x^(r-1))
        // and r-1 is even, therefore:
        //   sqrt(x) = sqrt(x^r) / x^((r-1)/2)
        // Since x^r is in GF(p), we use the GFp::sqrt() function for the
        // numerator. For the denominator:
        //   (r-1)/2 = (p + p^2 + p^3 + p^4)/2
        //           = p*(1 + p^2)*((p + 1)/2)
        // and thus:
        //   d <- x^((p+1)/2)
        //   e <- frob1(d * frob2(d))
        // which yields x^((r-1)/2) in e. We also use it to compute x^r
        // as: x^r = x * e^2
        let mut t = *self;
        let mut y = t;
        y.set_square();
        t.set_mul(&y); // t = x^3
        y = t;
        y.set_msquare(2);
        t.set_mul(&y); // t = x^(2^4-1)
        y = t;
        y.set_msquare(4);
        t.set_mul(&y); // t = x^(2^8-1)
        y = t;
        y.set_msquare(8);
        t.set_mul(&y); // t = x^(2^16-1)
        y = t;
        y.set_msquare(16);
        t.set_mul(&y); // t = x^(2^32-1)
        t.set_msquare(31);
        t.set_mul(self); // t = x^((p+1)/2)
        y = t;
        y.set_frob2();
        t.set_mul(&y);
        t.set_frob1(); // t = x^((r-1)/2)
        y = t;
        y.set_square();
        let a = self.mul_to_k0(&y); // a = x^r
        let (s, cc) = a.sqrt();
        *self = t;
        self.set_invert();
        self.set_mul_k0(s);
        cc
    }

    /// Select a value: this function returns x0 if c == 0, or x1 if
    /// c == 0xFFFFFFFFFFFFFFFF.
    #[inline(always)]
    pub fn select(c: u64, x0: GFp5, x1: GFp5) -> GFp5 {
        GFp5([
            GFp::select(c, x0.0[0], x1.0[0]),
            GFp::select(c, x0.0[1], x1.0[1]),
            GFp::select(c, x0.0[2], x1.0[2]),
            GFp::select(c, x0.0[3], x1.0[3]),
            GFp::select(c, x0.0[4], x1.0[4]),
        ])
    }

    // Partial lookup element. This function assumes that at least one
    // of the two following properties holds:
    //  - This value is zero.
    //  - c == 0.
    // Moreover, c MUST be either 0 or 0xFFFFFFFFFFFFFFFF.
    //
    // If c == 0, then this value is unchanged.
    // If c == 0xFFFFFFFFFFFFFFFF, then this value is set to a copy of 'y'.
    #[inline(always)]
    pub(crate) fn set_partial_lookup(&mut self, y: GFp5, c: u64) {
        self.0[0].0 |= c & y.0[0].0;
        self.0[1].0 |= c & y.0[1].0;
        self.0[2].0 |= c & y.0[2].0;
        self.0[3].0 |= c & y.0[3].0;
        self.0[4].0 |= c & y.0[4].0;
    }
}

// We implement all the needed traits to allow use of the arithmetic
// operators on GF(p^5) values. We support all combinations of operands
// either as GFp5 structures, or pointers to GFp5 structures.

impl Add<GFp5> for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn add(self, other: GFp5) -> GFp5 {
        let mut r = self;
        r.set_add(&other);
        r
    }
}

impl Add<&GFp5> for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn add(self, other: &GFp5) -> GFp5 {
        let mut r = self;
        r.set_add(other);
        r
    }
}

impl Add<GFp5> for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn add(self, other: GFp5) -> GFp5 {
        let mut r = *self;
        r.set_add(&other);
        r
    }
}

impl Add<&GFp5> for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn add(self, other: &GFp5) -> GFp5 {
        let mut r = *self;
        r.set_add(other);
        r
    }
}

impl AddAssign<GFp5> for GFp5 {
    #[inline(always)]
    fn add_assign(&mut self, other: GFp5) {
        self.set_add(&other);
    }
}

impl AddAssign<&GFp5> for GFp5 {
    #[inline(always)]
    fn add_assign(&mut self, other: &GFp5) {
        self.set_add(other);
    }
}

impl Sub<GFp5> for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn sub(self, other: GFp5) -> GFp5 {
        let mut r = self;
        r.set_sub(&other);
        r
    }
}

impl Sub<&GFp5> for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn sub(self, other: &GFp5) -> GFp5 {
        let mut r = self;
        r.set_sub(other);
        r
    }
}

impl Sub<GFp5> for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn sub(self, other: GFp5) -> GFp5 {
        let mut r = *self;
        r.set_sub(&other);
        r
    }
}

impl Sub<&GFp5> for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn sub(self, other: &GFp5) -> GFp5 {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}

impl SubAssign<GFp5> for GFp5 {
    #[inline(always)]
    fn sub_assign(&mut self, other: GFp5) {
        self.set_sub(&other);
    }
}

impl SubAssign<&GFp5> for GFp5 {
    #[inline(always)]
    fn sub_assign(&mut self, other: &GFp5) {
        self.set_sub(other);
    }
}

impl Neg for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn neg(self) -> GFp5 {
        let mut r = self;
        r.set_neg();
        r
    }
}

impl Neg for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn neg(self) -> GFp5 {
        let mut r = *self;
        r.set_neg();
        r
    }
}

impl Mul<GFp5> for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn mul(self, other: GFp5) -> GFp5 {
        let mut r = self;
        r.set_mul(&other);
        r
    }
}

impl Mul<&GFp5> for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn mul(self, other: &GFp5) -> GFp5 {
        let mut r = self;
        r.set_mul(other);
        r
    }
}

impl Mul<GFp5> for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn mul(self, other: GFp5) -> GFp5 {
        let mut r = *self;
        r.set_mul(&other);
        r
    }
}

impl Mul<&GFp5> for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn mul(self, other: &GFp5) -> GFp5 {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}

impl MulAssign<GFp5> for GFp5 {
    #[inline(always)]
    fn mul_assign(&mut self, other: GFp5) {
        self.set_mul(&other);
    }
}

impl MulAssign<&GFp5> for GFp5 {
    #[inline(always)]
    fn mul_assign(&mut self, other: &GFp5) {
        self.set_mul(other);
    }
}

impl Div<GFp5> for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn div(self, other: GFp5) -> GFp5 {
        let mut r = self;
        r.set_div(&other);
        r
    }
}

impl Div<&GFp5> for GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn div(self, other: &GFp5) -> GFp5 {
        let mut r = self;
        r.set_div(other);
        r
    }
}

impl Div<GFp5> for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn div(self, other: GFp5) -> GFp5 {
        let mut r = *self;
        r.set_div(&other);
        r
    }
}

impl Div<&GFp5> for &GFp5 {
    type Output = GFp5;

    #[inline(always)]
    fn div(self, other: &GFp5) -> GFp5 {
        let mut r = *self;
        r.set_div(other);
        r
    }
}

impl DivAssign<GFp5> for GFp5 {
    #[inline(always)]
    fn div_assign(&mut self, other: GFp5) {
        self.set_div(&other);
    }
}

impl DivAssign<&GFp5> for GFp5 {
    #[inline(always)]
    fn div_assign(&mut self, other: &GFp5) {
        self.set_div(other);
    }
}

// ========================================================================
// Unit tests.

#[cfg(test)]
mod tests {
    use super::{super::PRNG, GFp, GFp5};

    fn check_gfp_eq(a: GFp, r: u128) {
        assert!(a.to_u64() == (r % (GFp::MOD as u128)) as u64);
    }

    fn test_gfp_ops(a: u64, b: u64) {
        let x = GFp::from_u64_reduce(a);
        let y = GFp::from_u64_reduce(b);
        let wa = a as u128;
        let wb = b as u128;
        check_gfp_eq(x + y, wa + wb);
        check_gfp_eq(x - y, (wa + (GFp::MOD as u128) * 2) - wb);
        check_gfp_eq(-y, (GFp::MOD as u128) * 2 - wb);
        check_gfp_eq(x * y, wa * wb);
        check_gfp_eq(x.square(), wa * wa);
        if a == 0 || a == GFp::MOD {
            check_gfp_eq(x.invert(), 0);
        } else {
            check_gfp_eq(x * x.invert(), 1);
        }
        assert!(x.half().mul_small(2).equals(x) == 0xffffffffffffffff);
    }

    #[test]
    fn gfp_ops() {
        for i in 0..10 {
            let v: u64 = (i as u64) + 0xfffffffefffffffc;
            if i <= 4 {
                let (x, c) = GFp::from_u64(v);
                assert!(c == 0xffffffffffffffff);
                assert!(x.to_u64() == v);
                let y = GFp::from_u64_reduce(v);
                assert!(y.to_u64() == v);
            } else {
                let v2 = v - GFp::MOD;
                let (x, c) = GFp::from_u64(v);
                assert!(c == 0);
                assert!(x.to_u64() == 0);
                let y = GFp::from_u64_reduce(v);
                assert!(y.to_u64() == v2);
            }
        }

        test_gfp_ops(0, 0);
        test_gfp_ops(0, 1);
        test_gfp_ops(1, 0);
        test_gfp_ops(1, 1);
        test_gfp_ops(0, 0xffffffffffffffff);
        test_gfp_ops(0xffffffffffffffff, 0);
        test_gfp_ops(0xffffffffffffffff, 0xffffffffffffffff);
        test_gfp_ops(0, 0xffffffff00000000);
        test_gfp_ops(0xffffffff00000000, 0);
        test_gfp_ops(0xffffffff00000000, 0xffffffff00000000);
        let mut prng = PRNG(0);
        for _ in 0..10000 {
            let a = prng.next_u64();
            let b = prng.next_u64();
            test_gfp_ops(a, b);
        }
        assert!(GFp::ZERO.legendre().iszero() == 0xffffffffffffffff);
        let (s0, c0) = GFp::ZERO.sqrt();
        check_gfp_eq(s0, 0);
        assert!(c0 == 0xffffffffffffffff);
        for _ in 0..1000 {
            let x = GFp::from_u64_reduce((prng.next_u64() >> 1) + 1).square();
            assert!(x.legendre().equals(GFp::ONE) == 0xffffffffffffffff);
            let (r1, c1) = x.sqrt();
            assert!(r1.square().equals(x) == 0xffffffffffffffff);
            assert!(c1 == 0xffffffffffffffff);
            let y = x * GFp::from_u64_reduce(7);
            assert!(y.legendre().equals(GFp::MINUS_ONE) == 0xffffffffffffffff);
            let (r2, c2) = y.sqrt();
            assert!(r2.iszero() == 0xffffffffffffffff);
            assert!(c2 == 0);
        }
    }

    #[test]
    fn gfp5_ops() {
        let a = GFp5::from_u64_reduce(
            9788683869780751860,
            18176307314149915536,
            17581807048943060475,
            16706651231658143014,
            424516324638612383,
        );
        let b = GFp5::from_u64_reduce(
            1541862605911742196,
            5168181287870979863,
            10854086836664484156,
            11043707160649157424,
            943499178011708365,
        );
        let apb = GFp5::from_u64_reduce(
            11330546475692494056,
            4897744532606311078,
            9989149816192960310,
            9303614322892716117,
            1368015502650320748,
        );
        let amb = GFp5::from_u64_reduce(
            8246821263869009664,
            13008126026278935673,
            6727720212278576319,
            5662944071008985590,
            17927761216041488339,
        );
        let atb = GFp5::from_u64_reduce(
            5924286846078684570,
            12564682493825924142,
            17116577152380521223,
            5260948460973948760,
            15673927150284637712,
        );
        let adb = GFp5::from_u64_reduce(
            6854214528917216670,
            4676163378868226016,
            7338977912708396522,
            9922012834063967541,
            11413717840889184601,
        );

        assert!((a + b).equals(apb) == 0xffffffffffffffff);
        assert!((a - b).equals(amb) == 0xffffffffffffffff);
        assert!((a * b).equals(atb) == 0xffffffffffffffff);
        assert!(a.square().equals(a * a) == 0xffffffffffffffff);
        assert!(b.square().equals(b * b) == 0xffffffffffffffff);
        assert!((a / b).equals(adb) == 0xffffffffffffffff);

        assert!(GFp5::ZERO.legendre().iszero() == 0xffffffffffffffff);
        let (s0, c0) = GFp5::ZERO.sqrt();
        assert!(s0.iszero() == 0xffffffffffffffff);
        assert!(c0 == 0xffffffffffffffff);

        let mut prng = PRNG(0);
        for _ in 0..1000 {
            let x0 = prng.next_u64();
            let x1 = prng.next_u64();
            let x2 = prng.next_u64();
            let x3 = prng.next_u64();
            let x4 = prng.next_u64();
            let x = GFp5::from_u64_reduce(x0, x1, x2, x3, x4).square();
            if x.iszero() != 0 {
                // This does not actually happen, none of the 1000
                // pseudorandom values is zero.
                continue;
            }
            let ex = x.encode();
            let (dx, cc) = GFp5::decode(&ex);
            assert!(cc == 0xffffffffffffffff);
            assert!(dx.equals(x) == 0xffffffffffffffff);
            assert!(x.legendre().equals(GFp::ONE) == 0xffffffffffffffff);
            let (r1, c1) = x.sqrt();
            assert!(r1.square().equals(x) == 0xffffffffffffffff);
            assert!(c1 == 0xffffffffffffffff);
            let y = x.mul_k0(GFp::from_u64_reduce(7));
            assert!(y.legendre().equals(GFp::MINUS_ONE) == 0xffffffffffffffff);
            let (r2, c2) = y.sqrt();
            assert!(r2.iszero() == 0xffffffffffffffff);
            assert!(c2 == 0);

            let v0 = (prng.next_u64() as u32) & 0x0fffffff;
            let v1 = (prng.next_u64() as u32) & 0x0fffffff;
            let z = GFp5::from_u64_reduce(GFp::MOD - (v0 as u64), v1 as u64, 0, 0, 0);
            assert!(x.mul_small_kn01(v0, v1).equals(x * z) == 0xffffffffffffffff);
        }
    }
}

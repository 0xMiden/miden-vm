// Copyright (c) 2022 Thomas Pornin. MIT license; see LICENSE in this directory.
// We want uppercase X, Z, U and T to match formal descriptions of point
// addition formulas. In this file, lowercase 'x', 'u' and 'w' are for
// affine coordinates; uppercase is used for fractional coordinates.
#![allow(non_snake_case)]

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use super::{
    field::{GFp, GFp5},
    multab::{G0, G40, G80, G120, G160, G200, G240, G280},
    scalar::Scalar,
};
use crate::utils::zeroize::Zeroizing;

// ========================================================================

/// A curve point.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    // Internally, we use the (x,u) fractional coordinates: for curve
    // point (x,y), we have (x,u) = (x,x/y) = (X/Z,U/T) (for the neutral
    // N, the u coordinate is 0).
    X: GFp5,
    Z: GFp5,
    U: GFp5,
    T: GFp5,
}

impl Point {
    /// Maps a nonneutral point to the prime-order short-Weierstrass subgroup.
    ///
    /// For the double-odd coordinates (x,y), the map is
    /// (X,Y) = (b/x + a/3, -b*y/x^2). This combines translation by (0,0)
    /// with the change from y^2 = x*(x^2+a*x+b) to short-Weierstrass form.
    pub(crate) fn to_weierstrass(self) -> (GFp5, GFp5) {
        let inverse = (self.X * self.U).invert();
        let bz = self.Z.mul_small_k1(Self::B1);
        let x = bz * self.U * inverse + GFp5::from_u64_reduce(6148914689804861441, 0, 0, 0, 0);
        let y = -(bz * self.T * inverse);
        (x, y)
    }

    // Curve equation 'a' constant.
    const A: GFp5 = GFp5([GFp::from_u64_reduce(2), GFp::ZERO, GFp::ZERO, GFp::ZERO, GFp::ZERO]);

    // Curve equation 'b' constant is equal to B1*z.
    const B1: u32 = 263;

    /* unused
    // Curve equation 'b' constant.
    const B: GFp5 = GFp5([
        GFp::ZERO,
        GFp::from_u64_reduce(Self::B1 as u64),
        GFp::ZERO,
        GFp::ZERO,
        GFp::ZERO,
    ]);
    */

    // 4*b
    const B_MUL4: GFp5 = GFp5([
        GFp::ZERO,
        GFp::from_u64_reduce((4 * Self::B1) as u64),
        GFp::ZERO,
        GFp::ZERO,
        GFp::ZERO,
    ]);

    /// The neutral point (neutral of the group law).
    pub const NEUTRAL: Self = Self {
        X: GFp5::ZERO,
        Z: GFp5::ONE,
        U: GFp5::ZERO,
        T: GFp5::ONE,
    };

    /// The conventional generator (corresponding to encoding w = 4).
    pub const GENERATOR: Self = Self {
        X: GFp5::from_u64_reduce(
            12883135586176881569,
            4356519642755055268,
            5248930565894896907,
            2165973894480315022,
            2448410071095648785,
        ),
        Z: GFp5::ONE,
        U: GFp5::from_u64_reduce(13835058052060938241, 0, 0, 0, 0),
        T: GFp5::ONE,
    };

    /// Encode this point into a field element. Encoding is always
    /// canonical.
    pub fn encode(self) -> GFp5 {
        // Encoded form is the value w = 1/u. For the neutral (u == 0),
        // the encoded form is 0. Since our inversion over GF(p^5) already
        // yields 0 in that case, there is no need for any special code.
        self.T / self.U
    }

    /// Test whether a field element can be decoded into a point. Returned
    /// value is 0xFFFFFFFFFFFFFFFF if decoding would work, 0 otherwise.
    pub fn validate(w: GFp5) -> u64 {
        // Value w can be decoded if and only if it is zero, or
        // (w^2 - a)^2 - 4*b is a quadratic residue.
        let e = w.square() - Self::A;
        let delta = e.square() - Self::B_MUL4;
        w.iszero() | delta.legendre().isone()
    }

    /// Decode a point from a field element. Returned value is (P, c): if
    /// decoding succeeds, then P is the point, and c == 0xFFFFFFFFFFFFFFFF;
    /// otherwise, P is set to the neutral, and c == 0.
    pub fn decode(w: GFp5) -> (Self, u64) {
        // Curve equation is y^2 = x*(x^2 + a*x + b); encoded value
        // is w = y/x. Dividing by x, we get the equation:
        //   x^2 - (w^2 - a)*x + b = 0
        // We solve for x and keep the solution which is not itself a
        // square (if there are solutions, exactly one of them will be
        // a square, and the other will not be a square).

        let e = w.square() - Self::A;
        let delta = e.square() - Self::B_MUL4;
        let (r, c) = delta.sqrt();
        let x1 = (e + r).half();
        let x2 = (e - r).half();
        let x = GFp5::select(x1.legendre().isone(), x1, x2);

        // If c == 0, then we want to get the neutral here; note that if
        // w == 0, then delta = a^2 - 4*b, which is not a square, and
        // thus we also get c == 0.
        let X = GFp5::select(c, GFp5::ZERO, x);
        let Z = GFp5::ONE;
        let U = GFp5::select(c, GFp5::ZERO, GFp5::ONE);
        let T = GFp5::select(c, GFp5::ONE, w);

        // If w == 0 then this is in fact a success.
        (Self { X, Z, U, T }, c | w.iszero())
    }

    // General point addition. Formulas are complete (no special case).
    fn set_add(&mut self, rhs: &Self) {
        // cost: 10M
        let (X1, Z1, U1, T1) = (&self.X, &self.Z, &self.U, &self.T);
        let (X2, Z2, U2, T2) = (&rhs.X, &rhs.Z, &rhs.U, &rhs.T);

        let t1 = X1 * X2;
        let t2 = Z1 * Z2;
        let t3 = U1 * U2;
        let t4 = T1 * T2;
        let t5 = (X1 + Z1) * (X2 + Z2) - t1 - t2;
        let t6 = (U1 + T1) * (U2 + T2) - t3 - t4;
        let t7 = t1 + t2.mul_small_k1(Self::B1);
        let t8 = t4 * t7;
        let t9 = t3 * (t5.mul_small_k1(2 * Self::B1) + t7.double());
        let t10 = (t4 + t3.double()) * (t5 + t7);
        self.X = (t10 - t8).mul_small_k1(Self::B1);
        self.Z = t8 - t9;
        self.U = t6 * (t2.mul_small_k1(Self::B1) - t1);
        self.T = t8 + t9;
    }

    // Add a point in affine coordinates to this one.
    fn set_add_affine(&mut self, rhs: &PointAffine) {
        // cost: 8M
        let (X1, Z1, U1, T1) = (&self.X, &self.Z, &self.U, &self.T);
        let (x2, u2) = (&rhs.x, &rhs.u);

        let t1 = X1 * x2;
        let t2 = Z1;
        let t3 = U1 * u2;
        let t4 = T1;
        let t5 = X1 + x2 * Z1;
        let t6 = U1 + u2 * T1;
        let t7 = t1 + t2.mul_small_k1(Self::B1);
        let t8 = t4 * t7;
        let t9 = t3 * (t5.mul_small_k1(2 * Self::B1) + t7.double());
        let t10 = (t4 + t3.double()) * (t5 + t7);
        self.X = (t10 - t8).mul_small_k1(Self::B1);
        self.U = t6 * (t2.mul_small_k1(Self::B1) - t1);
        self.Z = t8 - t9;
        self.T = t8 + t9;
    }

    // Subtract a point in affine coordinates from this one.
    fn set_sub_affine(&mut self, rhs: &PointAffine) {
        self.set_add_affine(&PointAffine { x: rhs.x, u: -rhs.u })
    }

    fn set_neg(&mut self) {
        self.U.set_neg();
    }

    fn set_sub(&mut self, rhs: &Self) {
        self.set_add(&rhs.neg())
    }

    /// Specialized point doubling function (faster than using general
    /// addition on the point and itself).
    pub fn double(self) -> Self {
        let mut r = self;
        r.set_double();
        r
    }

    fn set_double(&mut self) {
        // cost: 4M+5S
        let (X, Z, U, T) = (&self.X, &self.Z, &self.U, &self.T);

        let t1 = Z * T;
        let t2 = t1 * T;
        let X1 = t2.square();
        let Z1 = t1 * U;
        let t3 = U.square();
        let W1 = t2 - (X + Z).double() * t3;
        let t4 = Z1.square();
        self.X = t4.mul_small_k1(4 * Self::B1);
        self.Z = W1.square();
        self.U = (W1 + Z1).square() - t4 - self.Z;
        self.T = X1.double() - t4.mul_small(4) - self.Z;
    }

    /// Multiply this point by 2^n (i.e. n successive doublings). This is
    /// faster than calling the double() function n times.
    pub fn mdouble(self, n: u32) -> Self {
        let mut r = self;
        r.set_mdouble(n);
        r
    }

    fn set_mdouble(&mut self, n: u32) {
        // Handle corner cases (0 or 1 double).
        if n == 0 {
            return;
        }
        if n == 1 {
            self.set_double();
            return;
        }

        // cost: n*(2M+5S) + 2M+1S
        let (X0, Z0, U0, T0) = (&self.X, &self.Z, &self.U, &self.T);
        let mut t1 = Z0 * T0;
        let mut t2 = t1 * T0;
        let X1 = t2.square();
        let Z1 = t1 * U0;
        let mut t3 = U0.square();
        let mut W1 = t2 - (X0 + Z0).double() * t3;
        let mut t4 = W1.square();
        let mut t5 = Z1.square();
        let mut X = t5.square().mul_small_k1(16 * Self::B1);
        let mut W = X1.double() - t5.mul_small(4) - t4;
        let mut Z = (W1 + Z1).square() - t4 - t5;

        for _ in 2..n {
            t1 = Z.square();
            t2 = t1.square();
            t3 = W.square();
            t4 = t3.square();
            t5 = (W + Z).square() - t1 - t3;
            Z = t5 * ((X + t1).double() - t3);
            X = (t2 * t4).mul_small_k1(16 * Self::B1);
            W = -t4 - t2.mul_small_kn01(4, 4 * Self::B1);
        }

        t1 = W.square();
        t2 = Z.square();
        t3 = (W + Z).square() - t1 - t2;
        W1 = t1 - (X + t2).double();
        self.X = t3.square().mul_small_k1(Self::B1);
        self.Z = W1.square();
        self.U = t3 * W1;
        self.T = t1.double() * (t1 - t2.double()) - self.Z;
    }

    /// Return 0xFFFFFFFFFFFFFFFF if this point is the neutral, 0 otherwise.
    pub fn isneutral(self) -> u64 {
        self.U.iszero()
    }

    /// Compare this point with another; returned value is 0xFFFFFFFFFFFFFFFF
    /// if the two points are equal, 0 otherwise.
    pub fn equals(self, rhs: Self) -> u64 {
        (self.U * rhs.T).equals(rhs.U * self.T)
    }

    // Convert points to affine coordinates. The source and destination
    // slices MUST have the same length.
    fn to_affine_array(src: &[Self], dst: &mut [PointAffine]) {
        // We use a trick due to Montgomery: to compute the inverse of
        // x and of y, a single inversion suffices, with:
        //    1/x = y*(1/(x*y))
        //    1/y = x*(1/(x*y))
        // This extends to the case of inverting n values, with a total
        // cost of 1 inversion and 3*(n-1) multiplications.
        let n = src.len();

        // Handle edge cases (empty slices, and 1-value slices).
        if n == 0 {
            return;
        }
        if n == 1 {
            let P = src[0];
            let m1 = (P.Z * P.T).invert();
            dst[0] = PointAffine { x: P.X * P.T * m1, u: P.U * P.Z * m1 };
            return;
        }

        // Compute product of all values to invert, and invert it.
        // We also use the x and u coordinates of the points in the
        // destination slice to keep track of the partial products.
        let mut m = src[0].Z * src[0].T;
        for i in 1..n {
            dst[i].x = m;
            m *= src[i].Z;
            dst[i].u = m;
            m *= src[i].T;
        }
        m = m.invert();

        // Propagate back inverses.
        for i in (1..n).rev() {
            dst[i].u = src[i].U * dst[i].u * m;
            m *= src[i].T;
            dst[i].x = src[i].X * dst[i].x * m;
            m *= src[i].Z;
        }
        dst[0].u = src[0].U * src[0].Z * m;
        m *= src[0].T;
        dst[0].x = src[0].X * m;
    }

    // Optimal window size should be 4 or 5 bits, depending on target
    // architecture. On an Intel i5-8259U ("Coffee Lake" core), a 5-bit
    // window seems very slightly better.
    const WINDOW: usize = 5;
    const WIN_SIZE: usize = 1 << ((Self::WINDOW - 1) as i32);

    fn make_window_affine(self) -> [PointAffine; Self::WIN_SIZE] {
        let mut tmp = [Self::NEUTRAL; Self::WIN_SIZE];
        tmp[0] = self;
        for i in 1..Self::WIN_SIZE {
            if (i & 1) == 0 {
                tmp[i] = self.add(tmp[i - 1]);
            } else {
                tmp[i] = tmp[i >> 1].double();
            }
        }
        let mut win = [PointAffine::NEUTRAL; Self::WIN_SIZE];
        Self::to_affine_array(&tmp, &mut win);
        win
    }

    // Multiply this point by a scalar.
    fn set_mul(&mut self, s: &Scalar) {
        // Make a window with affine points.
        let win = self.make_window_affine();
        let mut ss = Zeroizing::new([0i32; (319 + Self::WINDOW) / Self::WINDOW]);
        s.recode_signed(&mut ss[..], Self::WINDOW as i32);
        let n = ss.len() - 1;
        *self = PointAffine::lookup(&win, ss[n]).to_point();
        for i in (0..n).rev() {
            self.set_mdouble(Self::WINDOW as u32);
            *self += PointAffine::lookup(&win, ss[i]);
        }
    }

    /// Multiply the conventional generator by a scalar.
    /// This function is faster than using the multiplication operator
    /// on the generator point.
    pub fn mulgen(s: Scalar) -> Self {
        // Precomputed tables are for j*(2^(80*i))*G, for i = 0 to 3
        // and j = 1 to 16, i.e. 5-bit windows.
        let mut ss = Zeroizing::new([0i32; 64]);
        s.recode_signed(&mut ss[..], 5);
        let mut P = PointAffine::lookup(&G0, ss[7]).to_point();
        P += PointAffine::lookup(&G40, ss[15]);
        P += PointAffine::lookup(&G80, ss[23]);
        P += PointAffine::lookup(&G120, ss[31]);
        P += PointAffine::lookup(&G160, ss[39]);
        P += PointAffine::lookup(&G200, ss[47]);
        P += PointAffine::lookup(&G240, ss[55]);
        P += PointAffine::lookup(&G280, ss[63]);
        for i in (0..7).rev() {
            P.set_mdouble(5);
            P += PointAffine::lookup(&G0, ss[i]);
            P += PointAffine::lookup(&G40, ss[i + 8]);
            P += PointAffine::lookup(&G80, ss[i + 16]);
            P += PointAffine::lookup(&G120, ss[i + 24]);
            P += PointAffine::lookup(&G160, ss[i + 32]);
            P += PointAffine::lookup(&G200, ss[i + 40]);
            P += PointAffine::lookup(&G240, ss[i + 48]);
            P += PointAffine::lookup(&G280, ss[i + 56]);
        }
        P
    }
}

// A curve point in affine (x,u) coordinates. This is used internally
// to make "windows" that speed up point multiplications.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PointAffine {
    pub(crate) x: GFp5,
    pub(crate) u: GFp5,
}

impl PointAffine {
    const NEUTRAL: Self = Self { x: GFp5::ZERO, u: GFp5::ZERO };

    fn to_point(self) -> Point {
        Point {
            X: self.x,
            Z: GFp5::ONE,
            U: self.u,
            T: GFp5::ONE,
        }
    }

    fn set_neg(&mut self) {
        self.u.set_neg();
    }

    // Lookup a point in a window. The win[] slice must contain values
    // i*P for i = 1 to n (win[0] contains P, win[1] contains 2*P, and
    // so on). Index value k is an integer in the -n to n range; returned
    // point is k*P.
    fn set_lookup(&mut self, win: &[Self], k: i32) {
        // sign = 0xFFFFFFFF if k < 0, 0x00000000 otherwise
        let sign = (k >> 31) as u32;
        // ka = abs(k)
        let ka = ((k as u32) ^ sign).wrapping_sub(sign);
        // km1 = ka - 1
        let km1 = ka.wrapping_sub(1);

        let mut x = GFp5::ZERO;
        let mut u = GFp5::ZERO;
        for i in 0..win.len() {
            let m = km1.wrapping_sub(i as u32);
            let c = (((m | m.wrapping_neg()) >> 31) as u64).wrapping_sub(1);
            x.set_partial_lookup(win[i].x, c);
            u.set_partial_lookup(win[i].u, c);
        }

        // If k < 0, then we must negate the point.
        let c = (sign as u64) | ((sign as u64) << 32);
        self.x = x;
        self.u = GFp5::select(c, u, -u);
    }

    fn lookup(win: &[Self], k: i32) -> Self {
        let mut r = Self::NEUTRAL;
        r.set_lookup(win, k);
        r
    }
}

// We implement all the needed traits to allow use of the arithmetic
// operators on points. We support all combinations of operands
// either as Point structures, or pointers to Point structures. Some
// operations with PointAffine structures are also implemented.

impl Add<Point> for Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: Point) -> Point {
        let mut r = self;
        r.set_add(&other);
        r
    }
}

impl Add<&Point> for Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: &Point) -> Point {
        let mut r = self;
        r.set_add(other);
        r
    }
}

impl Add<Point> for &Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: Point) -> Point {
        let mut r = *self;
        r.set_add(&other);
        r
    }
}

impl Add<&Point> for &Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: &Point) -> Point {
        let mut r = *self;
        r.set_add(other);
        r
    }
}

impl Add<PointAffine> for Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: PointAffine) -> Point {
        let mut r = self;
        r.set_add_affine(&other);
        r
    }
}

impl Add<&PointAffine> for Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: &PointAffine) -> Point {
        let mut r = self;
        r.set_add_affine(other);
        r
    }
}

impl Add<PointAffine> for &Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: PointAffine) -> Point {
        let mut r = *self;
        r.set_add_affine(&other);
        r
    }
}

impl Add<&PointAffine> for &Point {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: &PointAffine) -> Point {
        let mut r = *self;
        r.set_add_affine(other);
        r
    }
}

impl Add<Point> for PointAffine {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: Point) -> Point {
        let mut r = other;
        r.set_add_affine(&self);
        r
    }
}

impl Add<&Point> for PointAffine {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: &Point) -> Point {
        let mut r = *other;
        r.set_add_affine(&self);
        r
    }
}

impl Add<Point> for &PointAffine {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: Point) -> Point {
        let mut r = other;
        r.set_add_affine(self);
        r
    }
}

impl Add<&Point> for &PointAffine {
    type Output = Point;

    #[inline(always)]
    fn add(self, other: &Point) -> Point {
        let mut r = *other;
        r.set_add_affine(self);
        r
    }
}

impl AddAssign<Point> for Point {
    #[inline(always)]
    fn add_assign(&mut self, other: Point) {
        self.set_add(&other);
    }
}

impl AddAssign<&Point> for Point {
    #[inline(always)]
    fn add_assign(&mut self, other: &Point) {
        self.set_add(other);
    }
}

impl AddAssign<PointAffine> for Point {
    #[inline(always)]
    fn add_assign(&mut self, other: PointAffine) {
        self.set_add_affine(&other);
    }
}

impl AddAssign<&PointAffine> for Point {
    #[inline(always)]
    fn add_assign(&mut self, other: &PointAffine) {
        self.set_add_affine(other);
    }
}

impl Sub<Point> for Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: Point) -> Point {
        let mut r = self;
        r.set_sub(&other);
        r
    }
}

impl Sub<&Point> for Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: &Point) -> Point {
        let mut r = self;
        r.set_sub(other);
        r
    }
}

impl Sub<Point> for &Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: Point) -> Point {
        let mut r = *self;
        r.set_sub(&other);
        r
    }
}

impl Sub<&Point> for &Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: &Point) -> Point {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}

impl Sub<PointAffine> for Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: PointAffine) -> Point {
        let mut r = self;
        r.set_sub_affine(&other);
        r
    }
}

impl Sub<&PointAffine> for Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: &PointAffine) -> Point {
        let mut r = self;
        r.set_sub_affine(other);
        r
    }
}

impl Sub<PointAffine> for &Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: PointAffine) -> Point {
        let mut r = *self;
        r.set_sub_affine(&other);
        r
    }
}

impl Sub<&PointAffine> for &Point {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: &PointAffine) -> Point {
        let mut r = *self;
        r.set_sub_affine(other);
        r
    }
}

impl Sub<Point> for PointAffine {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: Point) -> Point {
        let mut r = -other;
        r.set_add_affine(&self);
        r
    }
}

impl Sub<&Point> for PointAffine {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: &Point) -> Point {
        let mut r = -other;
        r.set_add_affine(&self);
        r
    }
}

impl Sub<Point> for &PointAffine {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: Point) -> Point {
        let mut r = -other;
        r.set_add_affine(self);
        r
    }
}

impl Sub<&Point> for &PointAffine {
    type Output = Point;

    #[inline(always)]
    fn sub(self, other: &Point) -> Point {
        let mut r = -other;
        r.set_add_affine(self);
        r
    }
}

impl SubAssign<Point> for Point {
    #[inline(always)]
    fn sub_assign(&mut self, other: Point) {
        self.set_sub(&other);
    }
}

impl SubAssign<&Point> for Point {
    #[inline(always)]
    fn sub_assign(&mut self, other: &Point) {
        self.set_sub(other);
    }
}

impl SubAssign<PointAffine> for Point {
    #[inline(always)]
    fn sub_assign(&mut self, other: PointAffine) {
        self.set_sub_affine(&other);
    }
}

impl SubAssign<&PointAffine> for Point {
    #[inline(always)]
    fn sub_assign(&mut self, other: &PointAffine) {
        self.set_sub_affine(other);
    }
}

impl Neg for Point {
    type Output = Point;

    #[inline(always)]
    fn neg(self) -> Point {
        let mut r = self;
        r.set_neg();
        r
    }
}

impl Neg for &Point {
    type Output = Point;

    #[inline(always)]
    fn neg(self) -> Point {
        let mut r = *self;
        r.set_neg();
        r
    }
}

impl Neg for PointAffine {
    type Output = PointAffine;

    #[inline(always)]
    fn neg(self) -> PointAffine {
        let mut r = self;
        r.set_neg();
        r
    }
}

impl Neg for &PointAffine {
    type Output = PointAffine;

    #[inline(always)]
    fn neg(self) -> PointAffine {
        let mut r = *self;
        r.set_neg();
        r
    }
}

impl Mul<Scalar> for Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Scalar) -> Point {
        let mut r = self;
        r.set_mul(&other);
        r
    }
}

impl Mul<&Scalar> for Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Scalar) -> Point {
        let mut r = self;
        r.set_mul(other);
        r
    }
}

impl Mul<Scalar> for &Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Scalar) -> Point {
        let mut r = *self;
        r.set_mul(&other);
        r
    }
}

impl Mul<&Scalar> for &Point {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Scalar) -> Point {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}

impl MulAssign<Scalar> for Point {
    #[inline(always)]
    fn mul_assign(&mut self, other: Scalar) {
        self.set_mul(&other);
    }
}

impl MulAssign<&Scalar> for Point {
    #[inline(always)]
    fn mul_assign(&mut self, other: &Scalar) {
        self.set_mul(other);
    }
}

impl Mul<Point> for Scalar {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Point) -> Point {
        let mut r = other;
        r.set_mul(&self);
        r
    }
}

impl Mul<&Point> for Scalar {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Point) -> Point {
        let mut r = *other;
        r.set_mul(&self);
        r
    }
}

impl Mul<Point> for &Scalar {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: Point) -> Point {
        let mut r = other;
        r.set_mul(self);
        r
    }
}

impl Mul<&Point> for &Scalar {
    type Output = Point;

    #[inline(always)]
    fn mul(self, other: &Point) -> Point {
        let mut r = *other;
        r.set_mul(self);
        r
    }
}

// ========================================================================
// Unit tests.

#[cfg(test)]
mod tests {
    use super::{
        super::{PRNG, field::GFp5, scalar::Scalar},
        Point, PointAffine,
    };

    #[test]
    fn ecgfp5_ops() {
        // Test vectors generated with Sage.
        // P0 is neutral of G.
        // P1 is a random point in G (encoded as w1)
        // P2 = e*P1 in G (encoded as w2)
        // P3 = P1 + P2 (in G) (encoded as w3)
        // P4 = 2*P1 (in G) (encoded as w4)
        // P5 = 2*P2 (in G) (encoded as w5)
        // P6 = 2*P1 + P2 (in G) (encoded as w6)
        // P7 = P1 + 2*P2 (in G) (encoded as w7)

        let w0 = GFp5::from_u64_reduce(0, 0, 0, 0, 0);
        let w1 = GFp5::from_u64_reduce(
            12539254003028696409,
            15524144070600887654,
            15092036948424041984,
            11398871370327264211,
            10958391180505708567,
        );
        let w2 = GFp5::from_u64_reduce(
            11001943240060308920,
            17075173755187928434,
            3940989555384655766,
            15017795574860011099,
            5548543797011402287,
        );
        let w3 = GFp5::from_u64_reduce(
            246872606398642312,
            4900963247917836450,
            7327006728177203977,
            13945036888436667069,
            3062018119121328861,
        );
        let w4 = GFp5::from_u64_reduce(
            8058035104653144162,
            16041715455419993830,
            7448530016070824199,
            11253639182222911208,
            6228757819849640866,
        );
        let w5 = GFp5::from_u64_reduce(
            10523134687509281194,
            11148711503117769087,
            9056499921957594891,
            13016664454465495026,
            16494247923890248266,
        );
        let w6 = GFp5::from_u64_reduce(
            12173306542237620,
            6587231965341539782,
            17027985748515888117,
            17194831817613584995,
            10056734072351459010,
        );
        let w7 = GFp5::from_u64_reduce(
            9420857400785992333,
            4695934009314206363,
            14471922162341187302,
            13395190104221781928,
            16359223219913018041,
        );

        // Values that should not decode successfully.
        let bww: [GFp5; 6] = [
            GFp5::from_u64_reduce(
                13557832913345268708,
                15669280705791538619,
                8534654657267986396,
                12533218303838131749,
                5058070698878426028,
            ),
            GFp5::from_u64_reduce(
                135036726621282077,
                17283229938160287622,
                13113167081889323961,
                1653240450380825271,
                520025869628727862,
            ),
            GFp5::from_u64_reduce(
                6727960962624180771,
                17240764188796091916,
                3954717247028503753,
                1002781561619501488,
                4295357288570643789,
            ),
            GFp5::from_u64_reduce(
                4578929270179684956,
                3866930513245945042,
                7662265318638150701,
                9503686272550423634,
                12241691520798116285,
            ),
            GFp5::from_u64_reduce(
                16890297404904119082,
                6169724643582733633,
                9725973298012340311,
                5977049210035183790,
                11379332130141664883,
            ),
            GFp5::from_u64_reduce(
                13777379982711219130,
                14715168412651470168,
                17942199593791635585,
                6188824164976547520,
                15461469634034461986,
            ),
        ];

        assert!(Point::validate(w0) == 0xffffffffffffffff);
        assert!(Point::validate(w1) == 0xffffffffffffffff);
        assert!(Point::validate(w2) == 0xffffffffffffffff);
        assert!(Point::validate(w3) == 0xffffffffffffffff);
        assert!(Point::validate(w4) == 0xffffffffffffffff);
        assert!(Point::validate(w5) == 0xffffffffffffffff);
        assert!(Point::validate(w6) == 0xffffffffffffffff);
        assert!(Point::validate(w7) == 0xffffffffffffffff);

        let (P0, c0) = Point::decode(w0);
        let (P1, c1) = Point::decode(w1);
        let (P2, c2) = Point::decode(w2);
        let (P3, c3) = Point::decode(w3);
        let (P4, c4) = Point::decode(w4);
        let (P5, c5) = Point::decode(w5);
        let (P6, c6) = Point::decode(w6);
        let (P7, c7) = Point::decode(w7);

        assert!(c0 == 0xffffffffffffffff);
        assert!(c1 == 0xffffffffffffffff);
        assert!(c2 == 0xffffffffffffffff);
        assert!(c3 == 0xffffffffffffffff);
        assert!(c4 == 0xffffffffffffffff);
        assert!(c5 == 0xffffffffffffffff);
        assert!(c6 == 0xffffffffffffffff);
        assert!(c7 == 0xffffffffffffffff);

        assert!(P0.isneutral() == 0xffffffffffffffff);
        assert!(P1.isneutral() == 0);
        assert!(P2.isneutral() == 0);
        assert!(P3.isneutral() == 0);
        assert!(P4.isneutral() == 0);
        assert!(P5.isneutral() == 0);
        assert!(P6.isneutral() == 0);
        assert!(P7.isneutral() == 0);

        assert!(P0.equals(P0) == 0xffffffffffffffff);
        assert!(P0.equals(P1) == 0);
        assert!(P1.equals(P0) == 0);
        assert!(P1.equals(P1) == 0xffffffffffffffff);
        assert!(P1.equals(P2) == 0);

        assert!(P0.encode().equals(w0) == 0xffffffffffffffff);
        assert!(P1.encode().equals(w1) == 0xffffffffffffffff);
        assert!(P2.encode().equals(w2) == 0xffffffffffffffff);
        assert!(P3.encode().equals(w3) == 0xffffffffffffffff);
        assert!(P4.encode().equals(w4) == 0xffffffffffffffff);
        assert!(P5.encode().equals(w5) == 0xffffffffffffffff);
        assert!(P6.encode().equals(w6) == 0xffffffffffffffff);
        assert!(P7.encode().equals(w7) == 0xffffffffffffffff);

        for w in bww.iter() {
            assert!(Point::validate(*w) == 0);
            let (P, c) = Point::decode(*w);
            assert!(P.isneutral() == 0xffffffffffffffff);
            assert!(c == 0);
        }

        assert!((P1 + P2).encode().equals(w3) == 0xffffffffffffffff);
        assert!((P1 + P1).encode().equals(w4) == 0xffffffffffffffff);
        assert!(P2.double().encode().equals(w5) == 0xffffffffffffffff);
        assert!((P1.double() + P2).encode().equals(w6) == 0xffffffffffffffff);
        assert!((P1 + P2 + P2).encode().equals(w7) == 0xffffffffffffffff);

        assert!((P0.double()).encode().iszero() == 0xffffffffffffffff);
        assert!((P0 + P0).encode().iszero() == 0xffffffffffffffff);
        assert!((P0 + P1).encode().equals(w1) == 0xffffffffffffffff);
        assert!((P1 + P0).encode().equals(w1) == 0xffffffffffffffff);

        for i in 0..10 {
            let Q1 = P1.mdouble(i);
            let mut Q2 = P1;
            for _ in 0..i {
                Q2 = Q2.double();
            }
            assert!(Q1.equals(Q2) == 0xffffffffffffffff);
        }

        let P2a = PointAffine { x: P2.X / P2.Z, u: P2.U / P2.T };
        assert!((P1 + P2a).equals(P1 + P2) == 0xffffffffffffffff);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn ecgfp5_affine_subtraction() {
        let points =
            [Point::NEUTRAL, Point::GENERATOR, Point::GENERATOR.double(), -Point::GENERATOR];
        let mut affine = [PointAffine::NEUTRAL; 4];
        Point::to_affine_array(&points, &mut affine);

        for (lhs, lhs_affine) in points.iter().zip(&affine) {
            for rhs in points {
                let expected = (*lhs + -rhs).encode();
                for difference in
                    [*lhs_affine - rhs, *lhs_affine - &rhs, lhs_affine - rhs, lhs_affine - &rhs]
                {
                    assert!(difference.encode().equals(expected) != 0);
                }
            }
        }
    }

    #[test]
    fn ecgfp5_affine_window() {
        let w = GFp5::from_u64_reduce(
            12539254003028696409,
            15524144070600887654,
            15092036948424041984,
            11398871370327264211,
            10958391180505708567,
        );
        let (P, c) = Point::decode(w);
        assert!(c == 0xffffffffffffffff);

        // Create an array of 8 points.
        let mut tab1 = [Point::NEUTRAL; 8];
        tab1[0] = P.double();
        for i in 1..tab1.len() {
            tab1[i] = tab1[0] + tab1[i - 1];
        }

        // Test conversion to affine coordinates.
        for n in 1..(tab1.len() + 1) {
            let mut tab2 = [PointAffine::NEUTRAL; 8];
            Point::to_affine_array(&tab1[0..n], &mut tab2[0..n]);
            for i in 0..n {
                assert!((tab1[i].Z * tab2[i].x).equals(tab1[i].X) != 0);
                assert!((tab1[i].T * tab2[i].u).equals(tab1[i].U) != 0);
            }
        }

        // Test lookup.
        let mut win = [PointAffine::NEUTRAL; 8];
        Point::to_affine_array(&tab1, &mut win);
        let Pa = PointAffine::lookup(&win, 0);
        assert!(Pa.x.iszero() != 0);
        assert!(Pa.u.iszero() != 0);
        for i in 1..9 {
            let Pb = PointAffine::lookup(&win, i as i32);
            assert!((tab1[i - 1].Z * Pb.x).equals(tab1[i - 1].X) != 0);
            assert!((tab1[i - 1].T * Pb.u).equals(tab1[i - 1].U) != 0);
            let Pc = PointAffine::lookup(&win, -(i as i32));
            assert!((tab1[i - 1].Z * Pc.x).equals(tab1[i - 1].X) != 0);
            assert!((tab1[i - 1].T * Pc.u).equals(-tab1[i - 1].U) != 0);
        }
    }

    #[test]
    fn ecgfp5_mul() {
        // w1 = encoding of a random point P1
        // ebuf = encoding of a random scalar e
        // w2 = encoding of P2 = e*P1
        let w1 = GFp5::from_u64_reduce(
            7534507442095725921,
            16658460051907528927,
            12417574136563175256,
            2750788641759288856,
            620002843272906439,
        );
        let ebuf: [u8; 40] = [
            0x1b, 0x18, 0x51, 0xc8, 0x1d, 0x22, 0xd4, 0x0d, 0x6d, 0x36, 0xec, 0xce, 0x54, 0x27,
            0x41, 0x66, 0x08, 0x14, 0x2f, 0x8f, 0xff, 0x64, 0xb4, 0x76, 0x28, 0xcd, 0x3f, 0xf8,
            0xaa, 0x25, 0x16, 0xd4, 0xba, 0xd0, 0xcc, 0x02, 0x1a, 0x44, 0x7c, 0x03,
        ];
        let w2 = GFp5::from_u64_reduce(
            9486104512504676657,
            14312981644741144668,
            5159846406177847664,
            15978863787033795628,
            3249948839313771192,
        );

        let (P1, c1) = Point::decode(w1);
        let (P2, c2) = Point::decode(w2);
        assert!(c1 == 0xffffffffffffffff);
        assert!(c2 == 0xffffffffffffffff);
        let (e, ce) = Scalar::decode(&ebuf);
        assert!(ce == 0xffffffffffffffff);
        let Q1 = P1 * e;
        assert!(Q1.equals(P2) == 0xffffffffffffffff);
        assert!(Q1.encode().equals(w2) == 0xffffffffffffffff);
        let Q2 = e * P1;
        assert!(Q2.equals(P2) == 0xffffffffffffffff);
        assert!(Q2.encode().equals(w2) == 0xffffffffffffffff);
    }

    #[test]
    fn ecgfp5_mulgen() {
        let mut prng = PRNG(0);
        for _ in 0..20 {
            let mut ebuf = [0u8; 48];
            prng.next(&mut ebuf);
            let e = Scalar::decode_reduce(&ebuf);
            let P1 = Point::GENERATOR * e;
            let P2 = Point::mulgen(e);
            assert!(P1.equals(P2) == 0xffffffffffffffff);
        }
    }
}

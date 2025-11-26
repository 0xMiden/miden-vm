use core::ops::{Add, Div, Mul, Neg, Sub};

use miden_utils_testing::{Felt, FieldElement, ONE, StarkField, ZERO, rand::rand_value};

// Given an element v ∈ Z_q | q = 2^64 - 2^32 + 1, this routine raises
// it to the power 2^n, by means of n successive squarings
//
// See https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L461-L469
fn msquare(v: Felt, n: usize) -> Felt {
    let mut v_ = v;
    for _ in 0..n {
        v_ = v_.square();
    }
    v_
}

// Given an element v ∈ Z_q | q = 2^64 - 2^32 + 1, this routine raises
// it to the power (p - 1) / 2
//
// See https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L448-L459
fn legendre(v: Felt) -> Felt {
    let v0 = msquare(v, 31);
    let v1 = msquare(v0, 32);

    v1 / v0
}

fn is_zero(a: Felt) -> Felt {
    Felt::new((a == ZERO) as u64)
}

fn is_one(a: Felt) -> Felt {
    Felt::new((a == ONE) as u64)
}

pub fn bv_or(a: Felt, b: Felt) -> Felt {
    let flg_a = (a == ZERO) | (a == ONE);
    let flg_b = (b == ZERO) | (b == ONE);

    assert!(flg_a & flg_b);

    let c = a.as_int() | b.as_int();
    Felt::new(c)
}

fn sqrt(x: Felt) -> (Felt, Felt) {
    const GG: [u64; 32] = [
        1753635133440165772,
        4614640910117430873,
        9123114210336311365,
        16116352524544190054,
        6414415596519834757,
        1213594585890690845,
        17096174751763063430,
        5456943929260765144,
        9713644485405565297,
        16905767614792059275,
        5416168637041100469,
        17654865857378133588,
        3511170319078647661,
        18146160046829613826,
        9306717745644682924,
        12380578893860276750,
        6115771955107415310,
        17776499369601055404,
        16207902636198568418,
        1532612707718625687,
        17492915097719143606,
        455906449640507599,
        11353340290879379826,
        1803076106186727246,
        13797081185216407910,
        17870292113338400769,
        549755813888,
        70368744161280,
        17293822564807737345,
        18446744069397807105,
        281474976710656,
        18446744069414584320,
    ];

    let mut u = msquare(x, 31);
    let mut v = u.square() / (x + is_zero(x));

    const N: usize = 32;
    for j in 1..N {
        let i = N - j;
        let w = msquare(v, i - 1);
        let cc = w == Felt::new(Felt::MODULUS - 1);

        v = if !cc { v } else { v * Felt::new(GG[N - i]) };
        u = if !cc { u } else { u * Felt::new(GG[N - i - 1]) };
    }

    let cc = bv_or(is_zero(v), is_one(v));
    (u * cc, cc)
}

#[derive(Eq, Copy, Clone, Debug)]
pub struct Ext5 {
    pub a0: Felt,
    pub a1: Felt,
    pub a2: Felt,
    pub a3: Felt,
    pub a4: Felt,
}

impl Ext5 {
    #[allow(dead_code)]
    pub fn new(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> Self {
        Self {
            a0: Felt::new(a0),
            a1: Felt::new(a1),
            a2: Felt::new(a2),
            a3: Felt::new(a3),
            a4: Felt::new(a4),
        }
    }

    pub fn zero() -> Self {
        Self {
            a0: ZERO,
            a1: ZERO,
            a2: ZERO,
            a3: ZERO,
            a4: ZERO,
        }
    }

    pub fn from_int(a: u64) -> Self {
        Self {
            a0: Felt::new(a),
            a1: ZERO,
            a2: ZERO,
            a3: ZERO,
            a4: ZERO,
        }
    }

    pub fn subk1(self, b: Felt) -> Self {
        Self {
            a0: self.a0,
            a1: self.a1 - b,
            a2: self.a2,
            a3: self.a3,
            a4: self.a4,
        }
    }

    pub fn rand() -> Self {
        Self {
            a0: rand_value::<Felt>(),
            a1: rand_value::<Felt>(),
            a2: rand_value::<Felt>(),
            a3: rand_value::<Felt>(),
            a4: rand_value::<Felt>(),
        }
    }

    pub fn square(self) -> Self {
        let two = Felt::new(2);
        let three = Felt::new(3);
        let six = two * three;

        Self {
            a0: self.a0 * self.a0 + six * (self.a1 * self.a4 + self.a2 * self.a3),
            a1: two * self.a0 * self.a1 + three * (self.a3 * self.a3 + two * self.a2 * self.a4),
            a2: self.a1 * self.a1 + two * self.a0 * self.a2 + six * self.a3 * self.a4,
            a3: two * (self.a0 * self.a3 + self.a1 * self.a2) + three * self.a4 * self.a4,
            a4: self.a2 * self.a2 + two * (self.a0 * self.a4 + self.a1 * self.a3),
        }
    }

    fn frobenius_once(self) -> Self {
        Self {
            a0: self.a0,
            a1: self.a1 * Felt::new(1041288259238279555),
            a2: self.a2 * Felt::new(15820824984080659046),
            a3: self.a3 * Felt::new(211587555138949697),
            a4: self.a4 * Felt::new(1373043270956696022),
        }
    }

    fn frobenius_twice(self) -> Self {
        Self {
            a0: self.a0,
            a1: self.a1 * Felt::new(15820824984080659046),
            a2: self.a2 * Felt::new(1373043270956696022),
            a3: self.a3 * Felt::new(1041288259238279555),
            a4: self.a4 * Felt::new(211587555138949697),
        }
    }

    pub fn inv(self) -> Self {
        let t0 = self.frobenius_once();
        let t1 = t0 * t0.frobenius_once();
        let t2 = t1 * t1.frobenius_twice();

        let t3 = self.a0 * t2.a0
            + Felt::new(3)
                * (self.a1 * t2.a4 + self.a2 * t2.a3 + self.a3 * t2.a2 + self.a4 * t2.a1);

        let flg = t3 == ZERO;
        let t3 = t3 + Felt::new(flg as u64);
        let t4 = ONE / t3;

        Self {
            a0: t4 * t2.a0,
            a1: t4 * t2.a1,
            a2: t4 * t2.a2,
            a3: t4 * t2.a3,
            a4: t4 * t2.a4,
        }
    }

    pub fn legendre(self) -> Felt {
        let t0 = self.frobenius_once();
        let t1 = t0 * t0.frobenius_once();
        let t2 = t1 * t1.frobenius_twice();

        let t3 = self.a0 * t2.a0
            + Felt::new(3)
                * (self.a1 * t2.a4 + self.a2 * t2.a3 + self.a3 * t2.a2 + self.a4 * t2.a1);

        legendre(t3)
    }

    pub fn msquare(self, n: usize) -> Self {
        let mut v_ = self;
        for _ in 0..n {
            v_ = v_.square();
        }
        v_
    }

    pub fn sqrt(self) -> (Self, Felt) {
        let v = self.msquare(31);
        let d = (self * v.msquare(32)) / v;
        let e = (d * d.frobenius_twice()).frobenius_once();
        let f = e.square();
        let g = self.a0 * f.a0
            + Felt::new(3) * (self.a1 * f.a4 + self.a2 * f.a3 + self.a3 * f.a2 + self.a4 * f.a1);
        let (s, c) = sqrt(g);
        let e = e.inv();

        (
            Ext5 {
                a0: e.a0 * s,
                a1: e.a1 * s,
                a2: e.a2 * s,
                a3: e.a3 * s,
                a4: e.a4 * s,
            },
            c,
        )
    }

    pub fn is_zero(self) -> Felt {
        let flg0 = self.a0 == ZERO;
        let flg1 = self.a1 == ZERO;
        let flg2 = self.a2 == ZERO;
        let flg3 = self.a3 == ZERO;
        let flg4 = self.a4 == ZERO;

        let flg = flg0 & flg1 & flg2 & flg3 & flg4;
        Felt::new(flg as u64)
    }
}

impl Add for Ext5 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a0: self.a0 + rhs.a0,
            a1: self.a1 + rhs.a1,
            a2: self.a2 + rhs.a2,
            a3: self.a3 + rhs.a3,
            a4: self.a4 + rhs.a4,
        }
    }
}

impl Neg for Ext5 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            a0: -self.a0,
            a1: -self.a1,
            a2: -self.a2,
            a3: -self.a3,
            a4: -self.a4,
        }
    }
}

impl Sub for Ext5 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            a0: self.a0 - rhs.a0,
            a1: self.a1 - rhs.a1,
            a2: self.a2 - rhs.a2,
            a3: self.a3 - rhs.a3,
            a4: self.a4 - rhs.a4,
        }
    }
}

impl Mul for Ext5 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self {
            a0: self.a0 * rhs.a0
                + Felt::new(3)
                    * (self.a1 * rhs.a4 + self.a2 * rhs.a3 + self.a3 * rhs.a2 + self.a4 * rhs.a1),
            a1: self.a0 * rhs.a1
                + self.a1 * rhs.a0
                + Felt::new(3) * (self.a2 * rhs.a4 + self.a3 * rhs.a3 + self.a4 * rhs.a2),
            a2: self.a0 * rhs.a2
                + self.a1 * rhs.a1
                + self.a2 * rhs.a0
                + Felt::new(3) * (self.a3 * rhs.a4 + self.a4 * rhs.a3),
            a3: self.a0 * rhs.a3
                + self.a1 * rhs.a2
                + self.a2 * rhs.a1
                + self.a3 * rhs.a0
                + Felt::new(3) * (self.a4 * rhs.a4),
            a4: self.a0 * rhs.a4
                + self.a1 * rhs.a3
                + self.a2 * rhs.a2
                + self.a3 * rhs.a1
                + self.a4 * rhs.a0,
        }
    }
}

impl Div for Ext5 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inv()
    }
}

impl PartialEq for Ext5 {
    fn eq(&self, other: &Self) -> bool {
        let flg0 = self.a0 == other.a0;
        let flg1 = self.a1 == other.a1;
        let flg2 = self.a2 == other.a2;
        let flg3 = self.a3 == other.a3;
        let flg4 = self.a4 == other.a4;

        flg0 & flg1 & flg2 & flg3 & flg4
    }
}

#[test]
fn test_ext5_add() {
    let source = "
    use std::math::ecgfp5::base_field

    begin
        exec.base_field::add
    end";

    let a = Ext5::rand();
    let b = Ext5::rand();
    let c = a + b;

    let mut stack = [
        a.a0.as_int(),
        a.a1.as_int(),
        a.a2.as_int(),
        a.a3.as_int(),
        a.a4.as_int(),
        b.a0.as_int(),
        b.a1.as_int(),
        b.a2.as_int(),
        b.a3.as_int(),
        b.a4.as_int(),
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], c.a0);
    assert_eq!(strace[1], c.a1);
    assert_eq!(strace[2], c.a2);
    assert_eq!(strace[3], c.a3);
    assert_eq!(strace[4], c.a4);
}

#[test]
fn test_ext5_sub() {
    let source = "
    use std::math::ecgfp5::base_field

    begin
        exec.base_field::sub
    end";

    let a = Ext5::rand();
    let b = Ext5::rand();
    let c = a - b;

    let mut stack = [
        a.a0.as_int(),
        a.a1.as_int(),
        a.a2.as_int(),
        a.a3.as_int(),
        a.a4.as_int(),
        b.a0.as_int(),
        b.a1.as_int(),
        b.a2.as_int(),
        b.a3.as_int(),
        b.a4.as_int(),
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], c.a0);
    assert_eq!(strace[1], c.a1);
    assert_eq!(strace[2], c.a2);
    assert_eq!(strace[3], c.a3);
    assert_eq!(strace[4], c.a4);
}

#[test]
fn test_ext5_mul() {
    let source = "
    use std::math::ecgfp5::base_field

    begin
        exec.base_field::mul
    end";

    let a = Ext5::rand();
    let b = Ext5::rand();
    let c = a * b;

    let mut stack = [
        a.a0.as_int(),
        a.a1.as_int(),
        a.a2.as_int(),
        a.a3.as_int(),
        a.a4.as_int(),
        b.a0.as_int(),
        b.a1.as_int(),
        b.a2.as_int(),
        b.a3.as_int(),
        b.a4.as_int(),
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], c.a0);
    assert_eq!(strace[1], c.a1);
    assert_eq!(strace[2], c.a2);
    assert_eq!(strace[3], c.a3);
    assert_eq!(strace[4], c.a4);
}

#[test]
fn test_ext5_square() {
    let source = "
    use std::math::ecgfp5::base_field

    begin
        exec.base_field::square
    end";

    let a = Ext5::rand();
    let b = a.square();

    let mut stack = [a.a0.as_int(), a.a1.as_int(), a.a2.as_int(), a.a3.as_int(), a.a4.as_int()];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], b.a0);
    assert_eq!(strace[1], b.a1);
    assert_eq!(strace[2], b.a2);
    assert_eq!(strace[3], b.a3);
    assert_eq!(strace[4], b.a4);
}

#[test]
fn test_ext5_inv() {
    let source = "
    use std::math::ecgfp5::base_field

    begin
        exec.base_field::inv
    end";

    let a = Ext5::rand();
    let b = a.inv();

    let mut stack = [a.a0.as_int(), a.a1.as_int(), a.a2.as_int(), a.a3.as_int(), a.a4.as_int()];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], b.a0);
    assert_eq!(strace[1], b.a1);
    assert_eq!(strace[2], b.a2);
    assert_eq!(strace[3], b.a3);
    assert_eq!(strace[4], b.a4);
}

#[test]
fn test_ext5_div() {
    let source = "
    use std::math::ecgfp5::base_field

    begin
        exec.base_field::div
    end";

    let a = Ext5::rand();
    let b = Ext5::rand();
    let c = a / b;

    let mut stack = [
        a.a0.as_int(),
        a.a1.as_int(),
        a.a2.as_int(),
        a.a3.as_int(),
        a.a4.as_int(),
        b.a0.as_int(),
        b.a1.as_int(),
        b.a2.as_int(),
        b.a3.as_int(),
        b.a4.as_int(),
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], c.a0);
    assert_eq!(strace[1], c.a1);
    assert_eq!(strace[2], c.a2);
    assert_eq!(strace[3], c.a3);
    assert_eq!(strace[4], c.a4);
}

#[test]
fn test_ext5_legendre() {
    let source = "
    use std::math::ecgfp5::base_field

    begin
        exec.base_field::legendre
    end";

    let a = Ext5::rand();
    let b = a.legendre();

    let mut stack = [a.a0.as_int(), a.a1.as_int(), a.a2.as_int(), a.a3.as_int(), a.a4.as_int()];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], b);
}

#[test]
fn test_ext5_sqrt() {
    let source = "
    use std::math::ecgfp5::base_field

    begin
        exec.base_field::sqrt
        movup.6 drop
    end";

    let a = Ext5::rand();
    let (b, c) = a.sqrt();

    let mut stack = [a.a0.as_int(), a.a1.as_int(), a.a2.as_int(), a.a3.as_int(), a.a4.as_int()];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], b.a0);
    assert_eq!(strace[1], b.a1);
    assert_eq!(strace[2], b.a2);
    assert_eq!(strace[3], b.a3);
    assert_eq!(strace[4], b.a4);
    assert_eq!(strace[5], c);
}

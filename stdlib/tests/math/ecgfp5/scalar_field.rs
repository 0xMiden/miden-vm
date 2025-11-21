use std::ops::Mul;

use miden_utils_testing::{push_inputs, rand::rand_value};

#[derive(Copy, Clone, Debug)]
struct Scalar {
    pub limbs: [u32; 10],
}

#[allow(dead_code)]
impl Scalar {
    const fn zero() -> Self {
        Self { limbs: [0u32; 10] }
    }

    const fn one() -> Self {
        Self { limbs: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] }
    }

    /// ECExt5 Scalar N =
    /// 1067993516717146951041484916571792702745057740581727230159139685185762082554198619328292418486241
    /// in radix-2^32 form
    ///
    /// Adapted from https://github.com/pornin/ecgfp5/blob/82325b9/rust/src/scalar.rs#L23-L32
    const fn get_n() -> Self {
        Self {
            limbs: [
                2492202977, 3893352854, 3609501852, 3901250617, 3484943929, 2147483622, 22,
                2147483633, 2147483655, 2147483645,
            ],
        }
    }

    /// = ((2 ^ 320) ^ 2) % N | N = get_n()
    ///
    /// Adapted from https://github.com/pornin/ecgfp5/blob/82325b9/rust/src/scalar.rs#L48-L55
    const fn get_r2() -> Self {
        Self {
            limbs: [
                3812476729, 2685403612, 1063431375, 1815226579, 2446296357, 3520566988, 359973336,
                2866806621, 2359448053, 1254757298,
            ],
        }
    }

    /// N = get_N()
    /// n0 = N[0]
    ///
    /// = -1/ n0 (mod 2^32)
    ///
    /// Adapted from https://github.com/pornin/ecgfp5/blob/82325b9/rust/src/scalar.rs#L34-L35
    const fn get_neg_n0_inv() -> u32 {
        91978719
    }

    /// Raw subtraction of a Scalar element from another one, without reduction
    ///
    /// Second return value, = 0xffff_ffff, if overflow has occurred
    ///                else  = 0, if no overflow during subtraction
    ///
    /// Adapted from https://github.com/pornin/ecgfp5/blob/82325b9/rust/src/scalar.rs#L80-L92
    fn sub_inner(&self, rhs: &Self) -> (Self, u32) {
        let mut r = Self::zero();
        let mut c = 0u32;

        for i in 0..10 {
            let (t0, flg0) = self.limbs[i].overflowing_sub(rhs.limbs[i]);
            let (t1, flg1) = t0.overflowing_sub(c);

            r.limbs[i] = t1;
            c = (flg0 | flg1) as u32;
        }
        (r, c.wrapping_neg())
    }

    /// Returns scalar based on value of c i.e. c == 0 ? a0 : a1
    ///
    /// Taken from https://github.com/pornin/ecgfp5/blob/82325b9/rust/src/scalar.rs#L94-L103
    fn select(c: u32, a0: Self, a1: Self) -> Self {
        let mut r = Self::zero();

        for i in 0..10 {
            r.limbs[i] = a0.limbs[i] ^ (c & (a0.limbs[i] ^ a1.limbs[i]));
        }

        r
    }

    /// Montgomery multiplication, returning (self * rhs) / 2^320 (mod N)
    ///
    /// Adapted from https://github.com/pornin/ecgfp5/blob/82325b9/rust/src/scalar.rs#L124-L171
    fn mont_mul(&self, rhs: &Self) -> Self {
        let mut r = Self::zero();

        for i in 0..10 {
            let m = rhs.limbs[i];
            let f = self.limbs[0]
                .wrapping_mul(m)
                .wrapping_add(r.limbs[0])
                .wrapping_mul(Self::get_neg_n0_inv());

            let mut cc1 = 0u32;
            let mut cc2 = 0u32;

            for j in 0..10 {
                let v0 = (self.limbs[j] as u64) * (m as u64);
                let (t0, flg0) = (v0 as u32, (v0 >> 32) as u32);
                let (t1, flg1) = t0.overflowing_add(r.limbs[j]);
                let (t2, flg2) = t1.overflowing_add(cc1);

                cc1 = flg0 + flg1 as u32 + flg2 as u32;

                let v1 = (f as u64) * (Self::get_n().limbs[j] as u64);
                let (t3, flg3) = (v1 as u32, (v1 >> 32) as u32);
                let (t4, flg4) = t3.overflowing_add(t2);
                let (t5, flg5) = t4.overflowing_add(cc2);

                cc2 = flg3 + flg4 as u32 + flg5 as u32;

                if j > 0 {
                    r.limbs[j - 1] = t5;
                }
            }
            r.limbs[9] = cc1.wrapping_add(cc2);
        }

        let (r2, c) = r.sub_inner(&Self::get_n());
        Self::select(c, r2, r)
    }

    /// Given a scalar in radix-2^32 form, this routine converts it to Montgomery form
    ///
    /// Inspired by https://github.com/itzmeanjan/secp256k1/blob/37b339d/field/scalar_field_utils.py#L235-L242
    fn convert_to_mont(self) -> Self {
        self.mont_mul(&Self::get_r2())
    }

    /// Given a scalar in Montgomery form, this routine converts it to radix-2^32 form
    ///
    /// Inspired by https://github.com/itzmeanjan/secp256k1/blob/37b339d/field/scalar_field_utils.py#L245-L251
    fn convert_from_mont(&self) -> Self {
        self.mont_mul(&Self::one())
    }

    /// Raises scalar field element to n -th power | n = exp i.e. represented in radix-2^32 form
    fn pow(self, exp: Self) -> Self {
        let s_mont = self.convert_to_mont();
        let mut r_mont = Self::one().convert_to_mont();

        for i in exp.limbs.iter().rev() {
            for j in (0u32..32).rev() {
                r_mont = r_mont.mont_mul(&r_mont);
                if ((*i >> j) & 1u32) == 1u32 {
                    r_mont = r_mont.mont_mul(&s_mont);
                }
            }
        }
        r_mont.convert_from_mont()
    }

    /// Computes multiplicative inverse ( say a' ) of scalar field element a | a * a' = 1 ( mod N )
    ///
    /// Note, if a = 0, then a' = 0.
    ///
    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654/field/scalar_field.py#L111-L129
    fn inv(self) -> Self {
        let exp = Self {
            limbs: [
                2492202975, 3893352854, 3609501852, 3901250617, 3484943929, 2147483622, 22,
                2147483633, 2147483655, 2147483645,
            ],
        };
        self.pow(exp)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mont_mul(&Self::get_r2()) // converted left operand to Montgomery form
            .mont_mul(&rhs) // result is in standard radix-2^32 form
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        let mut flg = false;

        for i in 0..10 {
            flg |= (self.limbs[i] ^ other.limbs[i]) != 0;
        }

        !flg
    }
}

#[test]
fn test_ec_ext5_scalar_arithmetic() {
    let a = Scalar {
        limbs: [
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
        ],
    };
    let b = a.inv();
    let c = a * b;

    assert_eq!(c, Scalar::one());
}

#[test]
fn test_ec_ext5_scalar_mont_mul() {
    let a = Scalar {
        limbs: [
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
        ],
    };
    let b = Scalar {
        limbs: [
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
        ],
    };
    let c = a.mont_mul(&b);

    let mut stack = [0u64; 20];
    for i in 0..10 {
        stack[i] = a.limbs[i] as u64;
        stack[i + 10] = b.limbs[i] as u64;
    }
    stack.reverse();

    let source = format!(
        "
    use std::math::ecgfp5::scalar_field
    use std::sys

    begin
        {inputs}
        exec.scalar_field::mont_mul

        exec.sys::truncate_stack
    end",
        inputs = push_inputs(&stack)
    );

    let test = build_test!(source, &[]);
    let strace = test.get_last_stack_state();

    for (i, limb) in c.limbs.iter().enumerate() {
        assert_eq!(strace[i].as_int(), *limb as u64);
    }
}

#[test]
fn test_ec_ext5_scalar_to_and_from_mont_repr() {
    let source = "
    use std::math::ecgfp5::scalar_field
    use std::sys

    begin
        exec.scalar_field::to_mont
        exec.scalar_field::from_mont

        exec.sys::truncate_stack
    end";

    let a = Scalar {
        limbs: [
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
        ],
    };
    let b = a.convert_to_mont();
    let c = b.convert_from_mont();

    assert_eq!(a, c);

    let mut stack = [0u64; 10];
    for (i, limb) in a.limbs.iter().enumerate() {
        stack[i] = *limb as u64;
    }
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    for (i, limb) in c.limbs.iter().enumerate() {
        assert_eq!(strace[i].as_int(), *limb as u64);
    }
}

#[test]
fn test_ec_ext5_scalar_inv() {
    let source = "
    use std::math::ecgfp5::scalar_field
    use std::sys

    begin
        exec.scalar_field::inv

        exec.sys::truncate_stack
    end";

    let a = Scalar {
        limbs: [
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
            rand_value::<u32>() >> 1,
        ],
    };
    let b = a.inv();

    let mut stack = [0u64; 10];
    for (i, limb) in a.limbs.iter().enumerate() {
        stack[i] = *limb as u64;
    }
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    for (i, limb) in b.limbs.iter().enumerate() {
        assert_eq!(strace[i].as_int(), *limb as u64);
    }
}

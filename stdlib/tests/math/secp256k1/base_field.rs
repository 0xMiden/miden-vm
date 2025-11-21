use core::ops::{Add, Mul, Neg, Sub};

use miden_utils_testing::rand::rand_array;

/// Secp256k1 base field element, kept in Montgomery form
#[derive(Copy, Clone, Debug)]
struct BaseField {
    limbs: [u32; 8],
}

impl BaseField {
    fn one() -> Self {
        Self { limbs: [977, 1, 0, 0, 0, 0, 0, 0] }
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field_utils.py#L41-L46
    fn mac(a: u32, b: u32, c: u32, carry: u32) -> (u32, u32) {
        let tmp = a as u64 + (b as u64 * c as u64) + carry as u64;
        ((tmp >> 32) as u32, tmp as u32)
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field_utils.py#L33-L38
    fn adc(a: u32, b: u32, carry: u32) -> (u32, u32) {
        let tmp = a as u64 + b as u64 + carry as u64;
        ((tmp >> 32) as u32, tmp as u32)
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field_utils.py#L49-L55
    fn sbb(a: u32, b: u32, borrow: u32) -> (u32, u32) {
        let tmp = (a as u64).wrapping_sub(b as u64 + (borrow >> 31) as u64);
        ((tmp >> 32) as u32, tmp as u32)
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field_utils.py#L65-L98
    fn u256xu32(a: &mut [u32], b: u32, c: &[u32]) {
        assert_eq!(a.len(), 9);
        assert_eq!(c.len(), 8);

        let mut carry: u32;

        let v = Self::mac(a[0], b, c[0], 0);
        carry = v.0;
        a[0] = v.1;

        let v = Self::mac(a[1], b, c[1], carry);
        carry = v.0;
        a[1] = v.1;

        let v = Self::mac(a[2], b, c[2], carry);
        carry = v.0;
        a[2] = v.1;

        let v = Self::mac(a[3], b, c[3], carry);
        carry = v.0;
        a[3] = v.1;

        let v = Self::mac(a[4], b, c[4], carry);
        carry = v.0;
        a[4] = v.1;

        let v = Self::mac(a[5], b, c[5], carry);
        carry = v.0;
        a[5] = v.1;

        let v = Self::mac(a[6], b, c[6], carry);
        carry = v.0;
        a[6] = v.1;

        let v = Self::mac(a[7], b, c[7], carry);
        a[8] = v.0;
        a[7] = v.1;
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field_utils.py#L118-L126
    fn u288_reduce(c: &[u32], pc: u32) -> [u32; 9] {
        assert_eq!(c.len(), 9);

        let prime: [u32; 8] = [
            4294966319, 4294967294, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
            4294967295,
        ];
        let mu: u32 = 3525653809;

        let q: u32 = mu.wrapping_mul(c[0]);
        let mut carry: u32;
        let mut d = [0u32; 9];

        let v = Self::mac(c[0], q, prime[0], 0);
        carry = v.0;

        let v = Self::mac(c[1], q, prime[1], carry);
        carry = v.0;
        d[0] = v.1;

        let v = Self::mac(c[2], q, prime[2], carry);
        carry = v.0;
        d[1] = v.1;

        let v = Self::mac(c[3], q, prime[3], carry);
        carry = v.0;
        d[2] = v.1;

        let v = Self::mac(c[4], q, prime[4], carry);
        carry = v.0;
        d[3] = v.1;

        let v = Self::mac(c[5], q, prime[5], carry);
        carry = v.0;
        d[4] = v.1;

        let v = Self::mac(c[6], q, prime[6], carry);
        carry = v.0;
        d[5] = v.1;

        let v = Self::mac(c[7], q, prime[7], carry);
        carry = v.0;
        d[6] = v.1;

        let v = Self::adc(c[8], pc, carry);
        d[8] = v.0;
        d[7] = v.1;

        d
    }
}

impl Mul for BaseField {
    type Output = BaseField;

    /// Modular multiplication of two secp256k1 base field elements, in Montgomery form.
    ///
    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field.py#L50-L55
    fn mul(self, rhs: Self) -> Self::Output {
        let mut c = [0u32; 16];
        let mut pc = 0u32;

        Self::u256xu32(&mut c[0..9], rhs.limbs[0], &self.limbs);

        let d = Self::u288_reduce(&c[0..9], pc);
        pc = d[8];
        c[1..9].copy_from_slice(&d[0..8]);

        Self::u256xu32(&mut c[1..10], rhs.limbs[1], &self.limbs);

        let d = Self::u288_reduce(&c[1..10], pc);
        pc = d[8];
        c[2..10].copy_from_slice(&d[0..8]);

        Self::u256xu32(&mut c[2..11], rhs.limbs[2], &self.limbs);

        let d = Self::u288_reduce(&c[2..11], pc);
        pc = d[8];
        c[3..11].copy_from_slice(&d[0..8]);

        Self::u256xu32(&mut c[3..12], rhs.limbs[3], &self.limbs);

        let d = Self::u288_reduce(&c[3..12], pc);
        pc = d[8];
        c[4..12].copy_from_slice(&d[0..8]);

        Self::u256xu32(&mut c[4..13], rhs.limbs[4], &self.limbs);

        let d = Self::u288_reduce(&c[4..13], pc);
        pc = d[8];
        c[5..13].copy_from_slice(&d[0..8]);

        Self::u256xu32(&mut c[5..14], rhs.limbs[5], &self.limbs);

        let d = Self::u288_reduce(&c[5..14], pc);
        pc = d[8];
        c[6..14].copy_from_slice(&d[0..8]);

        Self::u256xu32(&mut c[6..15], rhs.limbs[6], &self.limbs);

        let d = Self::u288_reduce(&c[6..15], pc);
        pc = d[8];
        c[7..15].copy_from_slice(&d[0..8]);

        Self::u256xu32(&mut c[7..16], rhs.limbs[7], &self.limbs);

        let d = Self::u288_reduce(&c[7..16], pc);
        pc = d[8];
        c[8..16].copy_from_slice(&d[0..8]);

        c[8] += pc * 977;
        c[9] += pc;

        Self::Output {
            limbs: c[8..16].try_into().expect("incorrect length"),
        }
    }
}

impl Add for BaseField {
    type Output = BaseField;

    /// Modular addition of two secp256k1 base field elements, in Montgomery form
    ///
    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field.py#L57-L76
    fn add(self, rhs: Self) -> Self::Output {
        let a = self.limbs;
        let b = rhs.limbs;

        let mut c = [0u32; 8];
        let mut carry = 0u32;

        let v = Self::adc(a[0], b[0], carry);
        carry = v.0;
        c[0] = v.1;

        let v = Self::adc(a[1], b[1], carry);
        carry = v.0;
        c[1] = v.1;

        let v = Self::adc(a[2], b[2], carry);
        carry = v.0;
        c[2] = v.1;

        let v = Self::adc(a[3], b[3], carry);
        carry = v.0;
        c[3] = v.1;

        let v = Self::adc(a[4], b[4], carry);
        carry = v.0;
        c[4] = v.1;

        let v = Self::adc(a[5], b[5], carry);
        carry = v.0;
        c[5] = v.1;

        let v = Self::adc(a[6], b[6], carry);
        carry = v.0;
        c[6] = v.1;

        let v = Self::adc(a[7], b[7], carry);
        carry = v.0;
        c[7] = v.1;

        c[0] += carry * 977;
        c[1] += carry;

        Self::Output { limbs: c }
    }
}

impl Neg for BaseField {
    type Output = BaseField;

    /// Computes additive inverse of one secp256k1 base field element, in Montgomery form
    ///
    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field.py#L78-L96
    fn neg(self) -> Self::Output {
        let mut b = [0u32; 8];
        let mut borrow = 0u32;

        let prime = [
            4294966319, 4294967294, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
            4294967295,
        ];

        let v = Self::sbb(prime[0], self.limbs[0], borrow);
        borrow = v.0;
        b[0] = v.1;

        let v = Self::sbb(prime[1], self.limbs[1], borrow);
        borrow = v.0;
        b[1] = v.1;

        let v = Self::sbb(prime[2], self.limbs[2], borrow);
        borrow = v.0;
        b[2] = v.1;

        let v = Self::sbb(prime[3], self.limbs[3], borrow);
        borrow = v.0;
        b[3] = v.1;

        let v = Self::sbb(prime[4], self.limbs[4], borrow);
        borrow = v.0;
        b[4] = v.1;

        let v = Self::sbb(prime[5], self.limbs[5], borrow);
        borrow = v.0;
        b[5] = v.1;

        let v = Self::sbb(prime[6], self.limbs[6], borrow);
        borrow = v.0;
        b[6] = v.1;

        let v = Self::sbb(prime[7], self.limbs[7], borrow);
        b[7] = v.1;

        Self::Output { limbs: b }
    }
}

impl Sub for BaseField {
    type Output = BaseField;

    /// Computes modular subtraction of one secp256k1 base field element, from another one, in
    /// Montgomery form
    ///
    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/base_field.py#L98-L102
    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl PartialEq for BaseField {
    /// Checks whether two secp256k1 base field elements are equal or not, in Montogomery form
    fn eq(&self, other: &Self) -> bool {
        let mut flg = false;

        for i in 0..8 {
            flg |= (self.limbs[i] ^ other.limbs[i]) != 0;
        }

        !flg
    }
}

#[test]
fn test_secp256k1_base_field_montgomery_repr() {
    let source = "
    use std::math::secp256k1::base_field

    begin
        exec.base_field::to_mont
        exec.base_field::from_mont
    end";

    let num_u32 = rand_array::<u32, 8>();
    let mut stack = num_u32.map(|v| v as u64);

    stack.reverse();
    let test = build_test!(source, &stack);
    stack.reverse();
    test.expect_stack(&stack);
}

#[test]
fn test_secp256k1_base_field_mul() {
    let source = "
    use std::math::secp256k1::base_field

    begin
        exec.base_field::mul
    end";

    let elm0 = BaseField { limbs: rand_array::<u32, 8>() };
    let elm1 = BaseField { limbs: rand_array::<u32, 8>() };
    let elm2 = elm0 * elm1;

    let mut stack = [0u64; 16];
    stack[..8].copy_from_slice(&elm0.limbs.map(|v| v as u64));
    stack[8..].copy_from_slice(&elm1.limbs.map(|v| v as u64));
    stack.reverse();

    let test = build_test!(source, &stack);
    test.expect_stack(&elm2.limbs.map(|v| v as u64));
}

#[test]
fn test_secp256k1_base_field_add() {
    let source = "
    use std::math::secp256k1::base_field

    begin
        exec.base_field::add
    end";

    let elm0 = BaseField { limbs: rand_array::<u32, 8>() };
    let elm1 = BaseField { limbs: rand_array::<u32, 8>() };
    let elm2 = elm0 + elm1;

    let mut stack = [0u64; 16];
    stack[..8].copy_from_slice(&elm0.limbs.map(|v| v as u64));
    stack[8..].copy_from_slice(&elm1.limbs.map(|v| v as u64));
    stack.reverse();

    let test = build_test!(source, &stack);
    test.expect_stack(&elm2.limbs.map(|v| v as u64));
}

#[test]
#[allow(clippy::needless_range_loop)]
fn test_secp256k1_base_field_neg() {
    let source = "
    use std::math::secp256k1::base_field

    begin
        exec.base_field::neg
    end";

    let elm0 = BaseField { limbs: rand_array::<u32, 8>() };
    let elm1 = -elm0;

    let mut stack = [0u64; 8];
    stack.copy_from_slice(&elm0.limbs.map(|v| v as u64));
    stack.reverse();

    let test = build_test!(source, &stack);
    test.expect_stack(&elm1.limbs.map(|v| v as u64));
}

#[test]
fn test_secp256k1_base_field_sub() {
    let source = "
    use std::math::secp256k1::base_field

    begin
        exec.base_field::sub
    end";

    let elm0 = BaseField { limbs: rand_array::<u32, 8>() };
    let elm1 = BaseField { limbs: rand_array::<u32, 8>() };
    let elm2 = elm0 - elm1;

    let mut stack = [0u64; 16];
    stack[..8].copy_from_slice(&elm0.limbs.map(|v| v as u64));
    stack[8..].copy_from_slice(&elm1.limbs.map(|v| v as u64));
    stack.reverse();

    let test = build_test!(source, &stack);
    test.expect_stack(&elm2.limbs.map(|v| v as u64));
}

#[test]
fn test_secp256k1_base_field_add_then_sub() {
    let source_add = "
    use std::math::secp256k1::base_field

    begin
        exec.base_field::add
    end";

    let source_sub = "
    use std::math::secp256k1::base_field

    begin
        exec.base_field::sub
    end";

    let elm0 = BaseField { limbs: rand_array::<u32, 8>() }; // a
    let elm1 = BaseField { limbs: rand_array::<u32, 8>() }; // b

    let mut stack = [0u64; 16];
    stack[..8].copy_from_slice(&elm0.limbs.map(|v| v as u64));
    stack[8..].copy_from_slice(&elm1.limbs.map(|v| v as u64));

    let elm2 = {
        let elm2 = elm0 + elm1; // c = a + b

        stack.reverse();
        let test = build_test!(source_add, &stack);
        test.expect_stack(&elm2.limbs.map(|v| v as u64));

        elm2
    };

    stack[..8].copy_from_slice(&elm2.limbs.map(|v| v as u64));
    stack[8..].copy_from_slice(&elm0.limbs.map(|v| v as u64));

    let elm3 = {
        let elm3 = elm2 - elm0; // d = c - a

        stack.reverse();
        let test = build_test!(source_sub, &stack);
        test.expect_stack(&elm3.limbs.map(|v| v as u64));

        elm3
    };

    assert_eq!(elm1, elm3);
}

#[test]
fn test_secp256k1_base_field_inv() {
    let source = "
    use std::math::secp256k1::base_field

    begin
        dupw.1
        dupw.1

        exec.base_field::inv
        exec.base_field::mul
    end";

    let elm0 = BaseField { limbs: rand_array::<u32, 8>() };
    let elm1 = BaseField::one();

    let mut stack = [0u64; 8];
    stack.copy_from_slice(&elm0.limbs.map(|v| v as u64));
    stack.reverse();

    let test = build_test!(source, &stack);
    test.expect_stack(&elm1.limbs.map(|v| v as u64));
}

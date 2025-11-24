use core::ops::Mul;

use miden_utils_testing::rand::rand_array;

/// Secp256k1 scalar field element, kept in Montgomery form
#[derive(Copy, Clone, Debug)]
struct ScalarField {
    limbs: [u32; 8],
}

impl ScalarField {
    fn one() -> Self {
        Self {
            limbs: [801750719, 1076732275, 1354194884, 1162945305, 1, 0, 0, 0],
        }
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/scalar_field_utils.py#L41-L46
    fn mac(a: u32, b: u32, c: u32, carry: u32) -> (u32, u32) {
        let tmp = a as u64 + (b as u64 * c as u64) + carry as u64;
        ((tmp >> 32) as u32, tmp as u32)
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/scalar_field_utils.py#L33-L38
    fn adc(a: u32, b: u32, carry: u32) -> (u32, u32) {
        let tmp = a as u64 + b as u64 + carry as u64;
        ((tmp >> 32) as u32, tmp as u32)
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/scalar_field_utils.py#L49-L55
    #[allow(dead_code)]
    fn sbb(a: u32, b: u32, borrow: u32) -> (u32, u32) {
        let tmp = (a as u64).wrapping_sub(b as u64 + (borrow >> 31) as u64);
        ((tmp >> 32) as u32, tmp as u32)
    }

    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/scalar_field_utils.py#L65-L98
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
            3493216577, 3218235020, 2940772411, 3132021990, 4294967294, 4294967295, 4294967295,
            4294967295,
        ];
        let mu: u32 = 1435021631;

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

    /// Raises scalar field element to N -th power | N  = exp i.e. represented in radix-2^32 form
    #[allow(dead_code)]
    fn pow(self, exp: Self) -> Self {
        let mut res = ScalarField::one();

        for i in exp.limbs.iter().rev() {
            for j in (0u32..32).rev() {
                res = res * res;

                if ((*i >> j) & 1u32) == 1u32 {
                    res = res * self;
                }
            }
        }

        res
    }

    /// Computes multiplicative inverse ( say a' ) of scalar field element a | a * a' = 1 ( mod P )
    ///
    /// Note, if a = 0, then a' = 0.
    ///
    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/scalar_field.py#L111-L129
    #[allow(dead_code)]
    fn inv(self) -> Self {
        let exp = ScalarField {
            limbs: [
                3493216575, 3218235020, 2940772411, 3132021990, 4294967294, 4294967295, 4294967295,
                4294967295,
            ],
        };
        self.pow(exp)
    }
}

impl Mul for ScalarField {
    type Output = ScalarField;

    /// Modular multiplication of two secp256k1 scalar field elements, in Montgomery form.
    ///
    /// See https://github.com/itzmeanjan/secp256k1/blob/6e5e654823a073add7d62b21ed88e9de9bb06869/field/scalar_field.py#L54-L59
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

        let mut one = Self::one().limbs;
        for limb in one.iter_mut() {
            *limb *= pc;
        }

        pc = 0;

        (pc, c[8]) = Self::adc(c[8], one[0], pc);
        (pc, c[9]) = Self::adc(c[9], one[1], pc);
        (pc, c[10]) = Self::adc(c[10], one[2], pc);
        (pc, c[11]) = Self::adc(c[11], one[3], pc);
        (pc, c[12]) = Self::adc(c[12], one[4], pc);
        (pc, c[13]) = Self::adc(c[13], one[5], pc);
        (pc, c[14]) = Self::adc(c[14], one[6], pc);
        (_, c[15]) = Self::adc(c[15], one[7], pc);

        Self::Output {
            limbs: c[8..16].try_into().expect("incorrect length"),
        }
    }
}

impl PartialEq for ScalarField {
    /// Checks whether two secp256k1 scalarfield elements are equal or not, in Montogomery form
    fn eq(&self, other: &Self) -> bool {
        let mut flg = false;

        for i in 0..8 {
            flg |= (self.limbs[i] ^ other.limbs[i]) != 0;
        }

        !flg
    }
}

#[test]
fn test_secp256k1_scalar_field_mul() {
    let source = "
    use std::math::secp256k1::scalar_field

    begin
        exec.scalar_field::mul
    end";

    let elm0 = ScalarField { limbs: rand_array::<u32, 8>() };
    let elm1 = ScalarField { limbs: rand_array::<u32, 8>() };
    let elm2 = elm0 * elm1;

    let mut stack = [0u64; 16];
    stack[..8].copy_from_slice(&elm0.limbs.map(|v| v as u64));
    stack[8..].copy_from_slice(&elm1.limbs.map(|v| v as u64));
    stack.reverse();

    let test = build_test!(source, &stack);
    test.expect_stack(&elm2.limbs.map(|v| v as u64));
}

#[test]
fn test_secp256k1_scalar_field_inv() {
    let source = "
    use std::math::secp256k1::scalar_field

    begin
        dupw.1
        dupw.1

        exec.scalar_field::inv
        exec.scalar_field::mul
    end";

    let elm0 = ScalarField { limbs: rand_array::<u32, 8>() };
    let elm1 = elm0.inv();

    let elm2 = elm0 * elm1;
    assert_eq!(elm2, ScalarField::one());

    let mut stack = [0u64; 8];
    stack.copy_from_slice(&elm0.limbs.map(|v| v as u64));
    stack.reverse();

    let test = build_test!(source, &stack);
    test.expect_stack(&elm2.limbs.map(|v| v as u64));
}

use alloc::string::String;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num::{One, Zero};

use super::{Inverse, MODULUS, fft::CyclotomicFourier};

/// An element of the Falcon base field Z_q for q = [`MODULUS`] = 12289 = 3 * 2^12 + 1, stored as
/// its canonical representative in [0, q).
///
/// The derived equality compares stored representatives, so every constructor must canonicalize —
/// [`Self::new`] reduces arbitrary signed inputs, and the arithmetic impls preserve canonicity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FalconFelt(u32);

impl FalconFelt {
    /// Reduces an arbitrary signed value into its canonical representative modulo q.
    pub const fn new(value: i16) -> Self {
        FalconFelt(value.rem_euclid(MODULUS) as u32)
    }

    /// Returns the canonical representative in [0, q).
    pub const fn value(self) -> i16 {
        self.0 as i16
    }

    /// Returns the balanced representative in (-q/2, q/2].
    pub fn balanced_value(self) -> i16 {
        let value = self.value();
        let g = (value > ((MODULUS) / 2)) as i16;
        value - (MODULUS) * g
    }

    /// Multiplies two field elements; the `const` twin of the `Mul` impl.
    ///
    /// The product of two canonical representatives is at most (q - 1)^2 < 2^32, so the u32
    /// multiplication cannot overflow.
    pub const fn multiply(self, other: Self) -> Self {
        FalconFelt((self.0 * other.0) % MODULUS as u32)
    }
}

impl Add for FalconFelt {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        let (s, _) = self.0.overflowing_add(rhs.0);
        let (d, n) = s.overflowing_sub(MODULUS as u32);
        let (r, _) = d.overflowing_add(MODULUS as u32 * (n as u32));
        FalconFelt(r)
    }
}

impl AddAssign for FalconFelt {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for FalconFelt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl SubAssign for FalconFelt {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Neg for FalconFelt {
    type Output = FalconFelt;

    fn neg(self) -> Self::Output {
        let is_nonzero = self.0 != 0;
        let r = MODULUS as u32 - self.0;
        FalconFelt(r * (is_nonzero as u32))
    }
}

impl Mul for FalconFelt {
    fn mul(self, rhs: Self) -> Self::Output {
        FalconFelt((self.0 * rhs.0) % MODULUS as u32)
    }

    type Output = Self;
}

impl MulAssign for FalconFelt {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for FalconFelt {
    type Output = FalconFelt;

    /// Field division via [`Inverse::inverse_or_zero`]; dividing by zero yields zero rather than
    /// panicking, mirroring the convention that gives `inverse_or_zero` its name.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse_or_zero()
    }
}

impl DivAssign for FalconFelt {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Zero for FalconFelt {
    fn zero() -> Self {
        FalconFelt::new(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl One for FalconFelt {
    fn one() -> Self {
        FalconFelt::new(1)
    }
}

impl Inverse for FalconFelt {
    /// Computes the multiplicative inverse as `a^(q-2)` (Fermat), or zero for zero input.
    ///
    /// The addition chain below tracks exponents in its variable names: `sixty_three` is `a^63`
    /// (six ones in binary), `all_ones` is `a^4095` (twelve ones), and the final product has
    /// exponent 8192 + 4095 = 12287 = q - 2.
    fn inverse_or_zero(self) -> Self {
        // q-2 = 0b10 11 11 11  11 11 11
        let two = self.multiply(self);
        let three = two.multiply(self);
        let six = three.multiply(three);
        let twelve = six.multiply(six);
        let fifteen = twelve.multiply(three);
        let thirty = fifteen.multiply(fifteen);
        let sixty = thirty.multiply(thirty);
        let sixty_three = sixty.multiply(three);

        let sixty_three_sq = sixty_three.multiply(sixty_three);
        let sixty_three_qu = sixty_three_sq.multiply(sixty_three_sq);
        let sixty_three_oc = sixty_three_qu.multiply(sixty_three_qu);
        let sixty_three_hx = sixty_three_oc.multiply(sixty_three_oc);
        let sixty_three_tt = sixty_three_hx.multiply(sixty_three_hx);
        let sixty_three_sf = sixty_three_tt.multiply(sixty_three_tt);

        let all_ones = sixty_three_sf.multiply(sixty_three);
        let two_e_twelve = all_ones.multiply(self);
        let two_e_thirteen = two_e_twelve.multiply(two_e_twelve);

        two_e_thirteen.multiply(all_ones)
    }
}

impl CyclotomicFourier for FalconFelt {
    /// Returns a primitive n-th root of unity for a power-of-two `n` up to 2^12.
    ///
    /// q - 1 = 3 * 2^12, so the 2-Sylow subgroup of Z_q* has order 2^12 = 4096, and 1331 generates
    /// it (a primitive 4096th root of unity). Squaring halves the order, so `12 - log2(n)`
    /// squarings yield a primitive n-th root.
    ///
    /// # Panics
    ///
    /// Panics if `n` is not a power of two in `1..=4096`.
    fn primitive_root_of_unity(n: usize) -> Self {
        assert!(
            n.is_power_of_two() && n <= 1 << 12,
            "root order must be a power of two at most 4096, got {n}"
        );
        let log2n = n.ilog2();
        // 1331 is a primitive 2^12-th root of unity.
        let mut a = FalconFelt::new(1331);
        let num_squarings = 12 - log2n;
        for _ in 0..num_squarings {
            a *= a;
        }
        a
    }
}

impl TryFrom<u32> for FalconFelt {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value >= MODULUS as u32 {
            Err(format!("value {value} is greater than or equal to the field modulus {MODULUS}"))
        } else {
            Ok(FalconFelt::new(value as i16))
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use num::{One, Zero};

    use super::{FalconFelt, Inverse, MODULUS};
    use crate::dsa::falcon512_poseidon2::math::fft::CyclotomicFourier;

    const Q: i64 = MODULUS as i64;

    /// The reference reduction every constructor and operation is checked against.
    fn canonical(value: i64) -> u32 {
        (((value % Q) + Q) % Q) as u32
    }

    /// A boundary-heavy sample of canonical representatives for pairwise operation checks.
    fn representatives() -> Vec<u32> {
        let mut values = vec![0, 1, 2, 3, (Q as u32) / 2, Q as u32 - 2, Q as u32 - 1];
        // A fixed stride walks the whole range without blowing up the pairwise product count.
        values.extend((0..Q as u32).step_by(97));
        values
    }

    #[test]
    fn new_canonicalizes_every_i16_input() {
        for value in i16::MIN..=i16::MAX {
            let felt = FalconFelt::new(value);
            assert_eq!(felt.0, canonical(value as i64), "wrong reduction for {value}");
        }
    }

    #[test]
    fn new_identifies_negative_multiples_of_q_with_zero() {
        // Regression: the previous branchless reduction mapped -q and -2q to the non-canonical
        // internal value q, so they compared unequal to zero.
        assert_eq!(FalconFelt::new(-(Q as i16)), FalconFelt::zero());
        assert_eq!(FalconFelt::new(-2 * Q as i16), FalconFelt::zero());
    }

    #[test]
    fn add_sub_neg_mul_agree_with_reference_arithmetic() {
        for &a in &representatives() {
            let fa = FalconFelt(a);
            assert_eq!((-fa).0, canonical(-(a as i64)), "neg failed for {a}");
            for &b in &representatives() {
                let fb = FalconFelt(b);
                let (a, b) = (a as i64, b as i64);
                assert_eq!((fa + fb).0, canonical(a + b), "add failed for {a} + {b}");
                assert_eq!((fa - fb).0, canonical(a - b), "sub failed for {a} - {b}");
                assert_eq!((fa * fb).0, canonical(a * b), "mul failed for {a} * {b}");
                assert_eq!(fa * fb, fa.multiply(fb), "const multiply disagrees with Mul");
            }
        }
    }

    #[test]
    fn every_nonzero_element_has_a_working_inverse() {
        for a in 1..Q as u32 {
            let fa = FalconFelt(a);
            let inv = fa.inverse_or_zero();
            assert_eq!(fa * inv, FalconFelt::one(), "a * a^-1 != 1 for a = {a}");
        }
        assert_eq!(FalconFelt::zero().inverse_or_zero(), FalconFelt::zero());
    }

    #[test]
    fn division_round_trips_and_division_by_zero_is_zero() {
        for &a in &representatives() {
            let fa = FalconFelt(a);
            for &b in &representatives() {
                let fb = FalconFelt(b);
                if b != 0 {
                    assert_eq!((fa / fb) * fb, fa, "a / b * b != a for {a}, {b}");
                }
            }
            assert_eq!(fa / FalconFelt::zero(), FalconFelt::zero());
        }
    }

    #[test]
    fn balanced_value_is_balanced_and_round_trips() {
        for a in 0..Q as u32 {
            let balanced = FalconFelt(a).balanced_value();
            assert!(
                -(Q as i16) / 2 <= balanced && balanced <= Q as i16 / 2,
                "balanced value {balanced} out of range for {a}"
            );
            assert_eq!(FalconFelt::new(balanced), FalconFelt(a), "round trip failed for {a}");
        }
    }

    #[test]
    fn primitive_roots_of_unity_have_exact_order() {
        for log2n in 0..=12u32 {
            let n = 1usize << log2n;
            let root = FalconFelt::primitive_root_of_unity(n);
            let mut power = FalconFelt::one();
            for _ in 0..n {
                power *= root;
            }
            assert_eq!(power, FalconFelt::one(), "root^n != 1 for n = {n}");
            if n > 1 {
                let mut half_power = FalconFelt::one();
                for _ in 0..n / 2 {
                    half_power *= root;
                }
                assert_eq!(
                    half_power,
                    -FalconFelt::one(),
                    "root^(n/2) != -1 for n = {n}: the root is not primitive"
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "power of two at most 4096")]
    fn primitive_root_rejects_an_unsupported_order() {
        let _ = FalconFelt::primitive_root_of_unity(3);
    }

    #[test]
    fn try_from_accepts_below_modulus_and_rejects_at_modulus() {
        assert_eq!(FalconFelt::try_from(0u32), Ok(FalconFelt::zero()));
        assert_eq!(FalconFelt::try_from(MODULUS as u32 - 1), Ok(FalconFelt(MODULUS as u32 - 1)));
        assert!(FalconFelt::try_from(MODULUS as u32).is_err());
        assert!(FalconFelt::try_from(u32::MAX).is_err());
    }
}
